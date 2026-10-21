//! The walks over a fake thread: a stack of dwords whose registrations the tests push as C code
//! does (`__try`/`__except`, `__try`/`__finally`, a raw handler on `fs:[0]`), handlers that are
//! closures raising and unwinding through the walks themselves, and the C stack's non-local jumps
//! (a handler taking an exception) as Rust panics caught at the frame that registered it.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::panic::{catch_unwind, panic_any, resume_unwind, AssertUnwindSafe};
use std::rc::Rc;

use super::*;

/// The fake stack: its base, and its limit (the TEB's).
const STACK_BASE: u32 = 0x0013_0000;
const STACK_LIMIT: u32 = 0x0012_0000;

/// The handlers of the dispatcher's own registrations (ExecuteHandler2's), by fake address.
const NESTED_HANDLER: u32 = 0x77F8_1000;
const COLLIDED_HANDLER: u32 = 0x77F8_1010;

/// A handler's call, as the platform makes it.
#[derive(Clone, Copy, Debug)]
struct Call {
    record: u32,
    frame: u32,
    #[allow(dead_code)]
    context: u32,
    dispatcher: u32,
}

type Handler = Rc<dyn Fn(&Fake, Call) -> u32>;

/// A handler taking an exception: the jump into the code of the frame that registered it, once
/// the chain is unwound to that frame.
struct Jump {
    frame: u32,
    code: u32,
}

/// The exception's second chance: the process ends with the code.
#[derive(Debug, PartialEq, Eq)]
struct Terminated(u32);

/// What a `__except` filter answers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Filter {
    /// EXCEPTION_EXECUTE_HANDLER: the frame takes the exception.
    Execute,
    /// EXCEPTION_CONTINUE_SEARCH.
    Search,
    /// EXCEPTION_CONTINUE_EXECUTION.
    Continue,
}

struct Fake {
    memory: RefCell<HashMap<u32, u32>>,
    head: Cell<u32>,
    sp: Cell<u32>,
    handlers: RefCell<HashMap<u32, Handler>>,
    next_handler: Cell<u32>,
    trail: RefCell<Vec<String>>,
}

impl Fake {
    fn new() -> Fake {
        Fake {
            memory: RefCell::new(HashMap::new()),
            head: Cell::new(END_OF_CHAIN),
            sp: Cell::new(STACK_BASE - 0x100),
            handlers: RefCell::new(HashMap::new()),
            next_handler: Cell::new(0x0040_1000),
            trail: RefCell::new(Vec::new()),
        }
    }

    fn mark(&self, what: &str) {
        self.trail.borrow_mut().push(what.to_string());
    }

    fn trail(&self) -> String {
        self.trail.borrow().join(", ")
    }

    /// Push `words` on the fake stack (the first lowest): their address.
    fn push(&self, words: &[u32]) -> u32 {
        let at = self.sp.get() - 4 * words.len() as u32;
        for (i, &word) in words.iter().enumerate() {
            self.write(at + 4 * i as u32, word);
        }
        self.sp.set(at);
        at
    }

    /// A handler's code, at a fresh fake address.
    fn handler(&self, body: impl Fn(&Fake, Call) -> u32 + 'static) -> u32 {
        let address = self.next_handler.get();
        self.next_handler.set(address + 0x10);
        self.handlers.borrow_mut().insert(address, Rc::new(body));
        address
    }

    /// Register a frame for `handler` (`extra` words above its two, as MSVC's frames carry), run
    /// `body`, and unlink the frame: its address is the body's first argument.
    fn registered<R>(&self, handler: u32, body: impl FnOnce(&Fake, u32) -> R) -> R {
        let saved = self.sp.get();
        let frame = self.push(&[self.head.get(), handler]);
        self.head.set(frame);
        let result = body(self, frame);
        assert_eq!(self.head.get(), frame, "the body leaves its frame on top");
        self.head.set(self.read(frame));
        self.sp.set(saved);
        result
    }

    /// `__try { body } __except (filter) { handler }`, as MSVC's frame handler runs it: the filter
    /// for a search, nothing for an unwind; a filter that executes the handler unwinds the chain to
    /// the frame (RtlUnwind) and jumps to the handler, the frame staying registered until the
    /// handler block ends.
    fn try_except(
        &self,
        body: impl FnOnce(&Fake),
        filter: impl Fn(&Fake, u32) -> Filter + 'static,
        handler: impl FnOnce(&Fake, u32),
    ) {
        let code = self.handler(move |fake, call| {
            if fake.read(call.record + record::FLAGS) & EXCEPTION_UNWIND != 0 {
                return EXCEPTION_CONTINUE_SEARCH;
            }
            match filter(fake, call.record) {
                Filter::Search => EXCEPTION_CONTINUE_SEARCH,
                Filter::Continue => EXCEPTION_CONTINUE_EXECUTION,
                Filter::Execute => {
                    let code = fake.read(call.record);
                    fake.rtl_unwind(call.frame, call.record);
                    panic_any(Jump {
                        frame: call.frame,
                        code,
                    })
                }
            }
        });
        let saved = self.sp.get();
        let frame = self.push(&[self.head.get(), code]);
        self.head.set(frame);
        let outcome = catch_unwind(AssertUnwindSafe(|| body(self)));
        let unlink = |fake: &Fake| {
            assert_eq!(
                fake.head.get(),
                frame,
                "the frame is on top (an unwind stops at it)"
            );
            fake.head.set(fake.read(frame));
        };
        match outcome {
            Ok(()) => unlink(self),
            Err(payload) => match payload.downcast::<Jump>() {
                // The handler block runs outside the scope (MSVC's frame drops to the enclosing
                // try level).
                Ok(jump) if jump.frame == frame => {
                    unlink(self);
                    self.sp.set(frame);
                    handler(self, jump.code);
                }
                Ok(jump) => resume_unwind(jump),
                Err(other) => resume_unwind(other),
            },
        }
        self.sp.set(saved);
    }

    /// `__try { body } __finally { finally(abnormal) }`: the finally runs from the frame's handler
    /// during an unwind, or after the body.
    fn try_finally(&self, body: impl FnOnce(&Fake), finally: impl Fn(&Fake, bool) + 'static) {
        let finally = Rc::new(finally);
        let unwinding = finally.clone();
        let code = self.handler(move |fake, call| {
            if fake.read(call.record + record::FLAGS) & EXCEPTION_UNWIND != 0 {
                unwinding(fake, true);
            }
            EXCEPTION_CONTINUE_SEARCH
        });
        self.registered(code, |fake, _| body(fake));
        finally(self, false);
    }

    /// RaiseException: a record and a context below the stack pointer, offered to the handlers
    /// (NtRaiseException's first chance, KiUserExceptionDispatcher). Returns when a handler
    /// continued it; an exception nobody takes ends the process.
    fn raise(&self, code: u32, flags: u32, chained: u32) {
        let saved = self.sp.get();
        let context = self.push(&[CONTEXT_FULL, 0, 0, 0]);
        let record = self.push(&[code, flags, chained, 0x7C4E_1234, 0]);
        if !dispatch(self, record, context) {
            panic_any(Terminated(code));
        }
        self.sp.set(saved);
    }

    /// RtlUnwind(target, 0, record, 0): the record its own (STATUS_UNWIND) without one. Returns
    /// once the chain is unwound to the target; the second chance ends the process.
    fn rtl_unwind(&self, target: u32, record: u32) {
        let saved = self.sp.get();
        let context = self.push(&[CONTEXT_FULL, 0, 0, 0]);
        let record = match record {
            0 => self.push(&[STATUS_UNWIND, 0, 0, 0x77F8_2000, 0]),
            record => record,
        };
        match unwind(self, target, record, context) {
            Unwound::Continue => self.sp.set(saved),
            Unwound::SecondChance => panic_any(Terminated(self.read(record))),
        }
    }

    fn flags(&self, record: u32) -> u32 {
        self.read(record + record::FLAGS)
    }
}

impl Frames for Fake {
    fn read(&self, address: u32) -> u32 {
        assert_eq!(address & 3, 0, "an aligned dword");
        *self
            .memory
            .borrow()
            .get(&address)
            .unwrap_or_else(|| panic!("{address:#x} was never written"))
    }

    fn write(&self, address: u32, value: u32) {
        self.memory.borrow_mut().insert(address, value);
    }

    fn head(&self) -> u32 {
        self.head.get()
    }

    fn set_head(&self, frame: u32) {
        self.head.set(frame);
    }

    fn stack_limits(&self) -> (u32, u32) {
        (STACK_LIMIT, STACK_BASE)
    }

    fn execute_handler(
        &self,
        unwind: bool,
        record: u32,
        frame: u32,
        context: u32,
        dispatcher: &mut u32,
        handler: u32,
    ) -> u32 {
        let saved = self.sp.get();
        let slot = self.push(&[*dispatcher]);
        let own = self.push(&[
            self.head.get(),
            if unwind {
                COLLIDED_HANDLER
            } else {
                NESTED_HANDLER
            },
            frame,
        ]);
        self.head.set(own);
        let disposition = self.call(
            handler,
            Call {
                record,
                frame,
                context,
                dispatcher: slot,
            },
        );
        *dispatcher = self.read(slot);
        // ExecuteHandler2's return: back to its registration, then off it.
        let top = self.head.get();
        self.head.set(self.read(top));
        self.sp.set(saved);
        disposition
    }

    fn raise_chained(&self, code: u32, chained: u32) -> ! {
        self.raise(code, EXCEPTION_NONCONTINUABLE, chained);
        unreachable!("a noncontinuable exception resumed its raiser")
    }
}

impl Fake {
    /// Call the handler at `address`: the dispatcher's own registrations' handlers, or a test's.
    fn call(&self, address: u32, call: Call) -> u32 {
        match address {
            NESTED_HANDLER => {
                own_frame_handler(self, false, call.record, call.frame, call.dispatcher)
            }
            COLLIDED_HANDLER => {
                own_frame_handler(self, true, call.record, call.frame, call.dispatcher)
            }
            _ => {
                let handler = self
                    .handlers
                    .borrow()
                    .get(&address)
                    .cloned()
                    .expect("a registered handler");
                handler(self, call)
            }
        }
    }
}

/// Run `test` on a fresh fake thread.
fn on_thread(test: impl FnOnce(&Fake)) -> Fake {
    let fake = Fake::new();
    test(&fake);
    assert_eq!(fake.head.get(), END_OF_CHAIN, "every frame unlinked");
    fake
}

/// What ended the process, when something did.
fn terminated(test: impl FnOnce(&Fake)) -> u32 {
    let fake = Fake::new();
    let ended = catch_unwind(AssertUnwindSafe(|| test(&fake))).expect_err("the process ends");
    ended
        .downcast::<Terminated>()
        .map(|t| t.0)
        .unwrap_or_else(|_| panic!("ended by something else"))
}

/// The record a filter sees: its code and flags.
fn seen(fake: &Fake, record: u32) -> (u32, u32) {
    (fake.read(record), fake.flags(record))
}

// --- the flat cases (runtime/seh) ----------------------------------------------------------------

/// The unwind order the runtime fixture pins: the search runs the filters innermost first, the
/// unwind the finally blocks between the raise and the frame that takes the exception, then its
/// handler.
#[test]
fn the_search_then_the_unwind_run_in_order() {
    let fake = on_thread(|fake| {
        fake.try_except(
            |fake| {
                fake.try_except(
                    |fake| {
                        fake.try_finally(
                            |fake| {
                                fake.mark("inner try");
                                fake.raise(0xE000_0001, 0, 0);
                                fake.mark("resumed (never)");
                            },
                            |fake, abnormal| {
                                fake.mark(if abnormal {
                                    "inner finally (abnormal)"
                                } else {
                                    "inner finally"
                                })
                            },
                        );
                    },
                    |fake, _| {
                        fake.mark("middle filter (continue search)");
                        Filter::Search
                    },
                    |fake, _| fake.mark("middle handler (never)"),
                );
            },
            |fake, _| {
                fake.mark("outer filter");
                Filter::Execute
            },
            |fake, code| fake.mark(&format!("outer handler {code:#x}")),
        );
    });
    assert_eq!(
        fake.trail(),
        "inner try, middle filter (continue search), outer filter, inner finally (abnormal), outer handler 0xe0000001"
    );
}

/// A filter that continues execution resumes the raise; the frames stay as they were.
#[test]
fn a_continued_exception_resumes_the_raiser() {
    let fake = on_thread(|fake| {
        fake.try_except(
            |fake| {
                fake.raise(0xE000_0002, 0, 0);
                fake.mark("raise returned");
            },
            |_, _| Filter::Continue,
            |fake, _| fake.mark("handler (never)"),
        );
    });
    assert_eq!(fake.trail(), "raise returned");
}

/// No handler takes it: the second chance ends the process with the code; so does an empty chain.
#[test]
fn an_unhandled_exception_ends_the_process() {
    assert_eq!(
        terminated(|fake| fake.raise(0xE000_0003, 0, 0)),
        0xE000_0003
    );
    assert_eq!(
        terminated(|fake| fake.try_except(
            |fake| fake.raise(0xC000_0005, 0, 0),
            |_, _| Filter::Search,
            |_, _| {}
        )),
        0xC000_0005
    );
}

// --- what a handler sees of the dispatcher (seh/chain) -------------------------------------------

/// While a handler runs, `fs:[0]` is the dispatcher's own registration: below the handler's,
/// linked to it, its handler the dispatcher's; the DispatcherContext lies between the two. The
/// handler is given its own registration.
#[test]
fn a_handler_runs_under_the_dispatchers_registration() {
    let seen: Rc<RefCell<Vec<u32>>> = Rc::default();
    let log = seen.clone();
    on_thread(|fake| {
        let handler = fake.handler(move |fake, call| {
            let top = fake.head();
            log.borrow_mut().extend([
                top,
                fake.read(top),
                fake.read(top + 4),
                call.frame,
                call.dispatcher,
            ]);
            EXCEPTION_CONTINUE_EXECUTION
        });
        fake.registered(handler, |fake, frame| {
            fake.raise(0xE000_0040, 0, 0);
            let seen = seen.borrow();
            let [top, next, own_handler, given, dispatcher] = seen[..] else {
                panic!("called once: {seen:?}")
            };
            assert!(top < frame, "below the handler's registration");
            assert_eq!(next, frame, "linked to the handler's registration");
            assert_eq!(own_handler, NESTED_HANDLER, "the dispatcher's handler");
            assert_eq!(given, frame, "the handler is given its own registration");
            assert!(
                dispatcher > top && dispatcher < frame,
                "the DispatcherContext lies between"
            );
        });
    });
}

// --- nested exceptions (seh/nested) --------------------------------------------------------------

/// A filter raising and handling an exception of its own, then searching on: its own exception
/// never reaches the outer frames, and the outer handler sees the first exception, unflagged.
#[test]
fn a_filter_handling_its_own_then_searching_on() {
    let outer: Rc<Cell<(u32, u32)>> = Rc::default();
    let sees = outer.clone();
    let fake = on_thread(|fake| {
        fake.try_except(
            |fake| {
                fake.try_except(
                    |fake| fake.raise(0xE000_0010, 0, 0),
                    |fake, _| {
                        fake.try_except(
                            |fake| {
                                fake.mark("filter raises its own");
                                fake.raise(0xE000_0011, 0, 0);
                            },
                            |_, _| Filter::Execute,
                            |fake, _| fake.mark("filter's own handled"),
                        );
                        fake.mark("filter searches on");
                        Filter::Search
                    },
                    |fake, _| fake.mark("inner handler (never)"),
                );
            },
            move |fake, record| {
                sees.set(seen(fake, record));
                Filter::Execute
            },
            |fake, _| fake.mark("outer handler"),
        );
    });
    assert_eq!(
        fake.trail(),
        "filter raises its own, filter's own handled, filter searches on, outer handler"
    );
    assert_eq!(outer.get(), (0xE000_0010, 0));
}

/// A filter raising an exception it does not handle: the dispatcher's registration marks it
/// nested; the frames from the head to the one whose filter raised are searched again, flagged
/// EXCEPTION_NESTED_CALL, and the flag clears past that frame — the outer handler takes the second
/// exception unflagged, and the unwind runs the inner frame's handler once more.
#[test]
fn a_filter_raising_an_exception_it_does_not_handle() {
    let calls = Rc::new(Cell::new(0));
    let inner_flags: Rc<RefCell<Vec<(u32, u32)>>> = Rc::default();
    let outer: Rc<Cell<(u32, u32)>> = Rc::default();
    let (count, log, sees) = (calls.clone(), inner_flags.clone(), outer.clone());
    let fake = on_thread(|fake| {
        fake.try_except(
            |fake| {
                fake.try_except(
                    |fake| fake.raise(0xE000_0012, 0, 0),
                    move |fake, record| {
                        log.borrow_mut().push(seen(fake, record));
                        count.set(count.get() + 1);
                        if count.get() == 1 {
                            fake.mark("filter raises, unhandled");
                            fake.raise(0xE000_0013, 0, 0);
                            fake.mark("filter resumed (never)");
                        }
                        Filter::Search
                    },
                    |fake, _| fake.mark("inner handler (never)"),
                );
            },
            move |fake, record| {
                sees.set(seen(fake, record));
                Filter::Execute
            },
            |fake, code| fake.mark(&format!("outer handler {code:#x}")),
        );
    });
    assert_eq!(
        fake.trail(),
        "filter raises, unhandled, outer handler 0xe0000013"
    );
    assert_eq!(
        *inner_flags.borrow(),
        [(0xE000_0012, 0), (0xE000_0013, EXCEPTION_NESTED_CALL)],
        "the inner frame searched again for the nested exception, flagged"
    );
    assert_eq!(
        outer.get(),
        (0xE000_0013, 0),
        "the flag cleared past the inner frame"
    );
}

/// An exception raised inside a handler block, after its unwind: an ordinary exception of the
/// enclosing frames.
#[test]
fn a_handler_raising() {
    let outer: Rc<Cell<(u32, u32)>> = Rc::default();
    let sees = outer.clone();
    let fake = on_thread(|fake| {
        fake.try_except(
            |fake| {
                fake.try_except(
                    |fake| fake.raise(0xE000_0014, 0, 0),
                    |_, _| Filter::Execute,
                    |fake, _| {
                        fake.mark("inner handler raises");
                        fake.raise(0xE000_0015, 0, 0);
                    },
                );
            },
            move |fake, record| {
                sees.set(seen(fake, record));
                Filter::Execute
            },
            |fake, _| fake.mark("outer handler"),
        );
    });
    assert_eq!(fake.trail(), "inner handler raises, outer handler");
    assert_eq!(outer.get(), (0xE000_0015, 0));
}

// --- unwinds meeting exceptions (seh/finally, seh/collide) ---------------------------------------

/// A finally block that raises and handles an exception of its own while the unwind of another
/// runs it: its own exception stays inside it, and the unwind goes on.
#[test]
fn a_finally_handling_its_own_during_the_unwind() {
    let fake = on_thread(|fake| {
        fake.try_except(
            |fake| {
                fake.try_finally(
                    |fake| {
                        fake.mark("try raises");
                        fake.raise(0xE000_0020, 0, 0);
                    },
                    |fake, abnormal| {
                        fake.mark(if abnormal {
                            "finally (abnormal)"
                        } else {
                            "finally"
                        });
                        fake.try_except(
                            |fake| {
                                fake.mark("finally raises its own");
                                fake.raise(0xE000_0021, 0, 0);
                            },
                            |_, _| Filter::Execute,
                            |fake, _| fake.mark("finally's own handled"),
                        );
                        fake.mark("finally done");
                    },
                );
                fake.mark("caller resumed (never)");
            },
            |_, _| Filter::Execute,
            |fake, code| fake.mark(&format!("outer handler {code:#x}")),
        );
    });
    assert_eq!(
        fake.trail(),
        "try raises, finally (abnormal), finally raises its own, finally's own handled, finally done, outer handler 0xe0000020"
    );
}

/// A finally block whose own exception, raised while an unwind runs it, is taken above that
/// unwind's target: the second unwind meets the first's registration (a collided unwind), goes on
/// past the frame the first was unwinding — whose handler does not run again — and the outer
/// handler takes the second exception.
#[test]
fn a_collided_unwind() {
    let finally_calls = Rc::new(Cell::new(0));
    let count = finally_calls.clone();
    let outer: Rc<Cell<(u32, u32)>> = Rc::default();
    let sees = outer.clone();
    let fake = on_thread(|fake| {
        fake.try_except(
            |fake| {
                fake.try_except(
                    |fake| {
                        fake.try_finally(
                            |fake| {
                                fake.mark("try raises the first");
                                fake.raise(0xE000_0030, 0, 0);
                            },
                            move |fake, abnormal| {
                                count.set(count.get() + 1);
                                fake.mark(if abnormal {
                                    "finally (abnormal) raises the second"
                                } else {
                                    "finally"
                                });
                                fake.raise(0xE000_0031, 0, 0);
                                fake.mark("finally resumed (never)");
                            },
                        );
                    },
                    |fake, record| {
                        let first = fake.read(record) == 0xE000_0030;
                        fake.mark(if first {
                            "middle filter sees the first"
                        } else {
                            "middle filter sees another"
                        });
                        if first {
                            Filter::Execute
                        } else {
                            Filter::Search
                        }
                    },
                    |fake, _| fake.mark("middle handler (never)"),
                );
            },
            move |fake, record| {
                sees.set(seen(fake, record));
                Filter::Execute
            },
            |fake, code| fake.mark(&format!("outer handler {code:#x}")),
        );
    });
    assert_eq!(
        fake.trail(),
        "try raises the first, middle filter sees the first, finally (abnormal) raises the second, \
         middle filter sees another, outer handler 0xe0000031"
    );
    assert_eq!(
        finally_calls.get(),
        1,
        "the collided frame's handler runs once"
    );
    assert_eq!(outer.get(), (0xE000_0031, 0));
}

/// The collided-unwind handler answers only an unwind, the nested-exception one only a search;
/// either writes the running handler's frame into the DispatcherContext.
#[test]
fn the_dispatchers_own_handlers() {
    let fake = Fake::new();
    let own = fake.push(&[END_OF_CHAIN, 0, 0x0012_F000]);
    let dispatcher = fake.push(&[0]);
    for (unwind_call, flags, expected) in [
        (false, 0, EXCEPTION_NESTED_EXCEPTION),
        (false, EXCEPTION_UNWINDING, EXCEPTION_CONTINUE_SEARCH),
        (true, EXCEPTION_UNWINDING, EXCEPTION_COLLIDED_UNWIND),
        (
            true,
            EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND,
            EXCEPTION_COLLIDED_UNWIND,
        ),
        (true, 0, EXCEPTION_CONTINUE_SEARCH),
    ] {
        fake.write(dispatcher, 0);
        let record = fake.push(&[0xE000_0000, flags, 0, 0, 0]);
        assert_eq!(
            own_frame_handler(&fake, unwind_call, record, own, dispatcher),
            expected,
            "{unwind_call} {flags:#x}"
        );
        let written = if expected == EXCEPTION_CONTINUE_SEARCH {
            0
        } else {
            0x0012_F000
        };
        assert_eq!(fake.read(dispatcher), written);
    }
}

// --- the walks' own exceptions -------------------------------------------------------------------

/// A filter continuing a noncontinuable exception raises STATUS_NONCONTINUABLE_EXCEPTION (itself
/// noncontinuable), the original chained to it; the outer handler takes that one.
#[test]
fn continuing_a_noncontinuable_exception() {
    let outer: Rc<Cell<(u32, u32, u32)>> = Rc::default();
    let sees = outer.clone();
    let fake = on_thread(|fake| {
        fake.try_except(
            |fake| {
                fake.try_except(
                    |fake| {
                        fake.raise(0xE000_0050, EXCEPTION_NONCONTINUABLE, 0);
                        fake.mark("resumed after the raise (never)");
                    },
                    // It continues the exception it raised only: continuing the one that follows
                    // too would raise another, without end.
                    |fake, record| {
                        if fake.read(record) != 0xE000_0050 {
                            return Filter::Search;
                        }
                        let noncontinuable = fake.flags(record) & EXCEPTION_NONCONTINUABLE != 0;
                        fake.mark(if noncontinuable {
                            "filter continues a noncontinuable"
                        } else {
                            "filter continues"
                        });
                        Filter::Continue
                    },
                    |fake, _| fake.mark("inner handler (never)"),
                );
            },
            move |fake, record| {
                let chained = fake.read(record + record::RECORD);
                sees.set((fake.read(record), fake.flags(record), fake.read(chained)));
                Filter::Execute
            },
            |fake, _| fake.mark("outer handler"),
        );
    });
    assert_eq!(
        fake.trail(),
        "filter continues a noncontinuable, outer handler"
    );
    assert_eq!(
        outer.get(),
        (
            STATUS_NONCONTINUABLE_EXCEPTION,
            EXCEPTION_NONCONTINUABLE,
            0xE000_0050
        )
    );
}

/// Continuing a noncontinuable exception with nobody above: the second exception ends the process.
#[test]
fn continuing_a_noncontinuable_exception_unhandled() {
    let code = terminated(|fake| {
        // It continues its own exception only (continuing every one would recurse without end).
        let handler = fake.handler(|fake, call| match fake.read(call.record) {
            0xE000_0051 => EXCEPTION_CONTINUE_EXECUTION,
            _ => EXCEPTION_CONTINUE_SEARCH,
        });
        fake.registered(handler, |fake, _| {
            fake.raise(0xE000_0051, EXCEPTION_NONCONTINUABLE, 0)
        });
    });
    assert_eq!(code, STATUS_NONCONTINUABLE_EXCEPTION);
}

/// A disposition that is none of the four raises STATUS_INVALID_DISPOSITION, noncontinuable, the
/// exception chained to it.
#[test]
fn a_bad_disposition() {
    let outer: Rc<Cell<(u32, u32, u32)>> = Rc::default();
    let sees = outer.clone();
    on_thread(|fake| {
        fake.try_except(
            |fake| {
                let handler = fake.handler(|fake, call| match fake.read(call.record) {
                    0xE000_0060 => 7,
                    _ => EXCEPTION_CONTINUE_SEARCH,
                });
                fake.registered(handler, |fake, _| fake.raise(0xE000_0060, 0, 0));
            },
            move |fake, record| {
                let chained = fake.read(record + record::RECORD);
                sees.set((fake.read(record), fake.flags(record), fake.read(chained)));
                Filter::Execute
            },
            |_, _| {},
        );
    });
    assert_eq!(
        outer.get(),
        (
            STATUS_INVALID_DISPOSITION,
            EXCEPTION_NONCONTINUABLE,
            0xE000_0060
        )
    );
}

/// A frame outside the stack, or misaligned, stops the search: the record is marked
/// EXCEPTION_STACK_INVALID and the exception takes its second chance; frames above it ran.
#[test]
fn a_broken_chain_stops_the_search() {
    for bad in [STACK_BASE - 4, STACK_LIMIT - 0x100, 0x0012_F002] {
        let fake = Fake::new();
        let ran = Rc::new(Cell::new(false));
        let ran_too = ran.clone();
        let handler = fake.handler(move |_, _| {
            ran_too.set(true);
            EXCEPTION_CONTINUE_SEARCH
        });
        fake.head.set(bad);
        let frame = fake.push(&[bad, handler]);
        fake.head.set(frame);
        let context = fake.push(&[0; 4]);
        let record = fake.push(&[0xC000_0005, 0, 0, 0, 0]);
        assert!(!dispatch(&fake, record, context), "{bad:#x}");
        assert!(ran.get());
        assert_eq!(fake.flags(record), EXCEPTION_STACK_INVALID);
    }
}

// --- RtlUnwind -----------------------------------------------------------------------------------

/// An unwind without a record of its own carries STATUS_UNWIND marked unwinding; each handler down
/// to the target sees it, and leaves the chain; the target stays the head.
#[test]
fn an_unwind_runs_the_handlers_down_to_the_target() {
    let seen: Rc<RefCell<Vec<(u32, u32)>>> = Rc::default();
    on_thread(|fake| {
        let target_handler = fake.handler(|_, _| panic!("the target's handler does not run"));
        fake.registered(target_handler, |fake, target| {
            let log = seen.clone();
            let handler = fake.handler(move |fake, call| {
                log.borrow_mut()
                    .push((fake.read(call.record), fake.flags(call.record)));
                EXCEPTION_CONTINUE_SEARCH
            });
            let middle = fake.push(&[fake.head(), handler]);
            let inner = fake.push(&[middle, handler]);
            fake.set_head(inner);
            fake.rtl_unwind(target, 0);
            assert_eq!(fake.head(), target);
        });
    });
    assert_eq!(*seen.borrow(), [(STATUS_UNWIND, EXCEPTION_UNWINDING); 2]);
}

/// An exit unwind (no target) runs every handler, flagged EXIT_UNWIND, then takes the second
/// chance; unwinding to the chain's end empties the chain and returns.
#[test]
fn an_exit_unwind_ends_in_the_second_chance() {
    let seen: Rc<RefCell<Vec<u32>>> = Rc::default();
    let log = seen.clone();
    let code = terminated(move |fake| {
        let handler = fake.handler(move |fake, call| {
            log.borrow_mut().push(fake.flags(call.record));
            EXCEPTION_CONTINUE_SEARCH
        });
        fake.registered(handler, |fake, _| fake.rtl_unwind(0, 0));
    });
    assert_eq!(code, STATUS_UNWIND);
    assert_eq!(
        *seen.borrow(),
        [EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND]
    );
    let fake = Fake::new();
    let handler = fake.handler(|_, _| EXCEPTION_CONTINUE_SEARCH);
    let frame = fake.push(&[END_OF_CHAIN, handler]);
    fake.set_head(frame);
    fake.rtl_unwind(END_OF_CHAIN, 0);
    assert_eq!(fake.head(), END_OF_CHAIN);
}

/// A target below the head (already passed) raises STATUS_INVALID_UNWIND_TARGET; a frame outside
/// the stack on the way raises STATUS_BAD_STACK. Both chain the unwind's record and are
/// noncontinuable: unhandled, the process ends with them.
#[test]
fn a_bad_target_or_stack_raises() {
    let code = terminated(|fake| {
        let handler = fake.handler(|_, _| EXCEPTION_CONTINUE_SEARCH);
        fake.registered(handler, |fake, frame| fake.rtl_unwind(frame - 0x40, 0));
    });
    assert_eq!(code, STATUS_INVALID_UNWIND_TARGET);
    let code = terminated(|fake| {
        let handler = fake.handler(|_, _| EXCEPTION_CONTINUE_SEARCH);
        let frame = fake.push(&[END_OF_CHAIN, handler]);
        let broken = fake.push(&[frame, 0]);
        fake.set_head(broken + 2);
        fake.rtl_unwind(frame, 0);
    });
    assert_eq!(code, STATUS_BAD_STACK);
}

/// An unwind handler answering something else raises STATUS_INVALID_DISPOSITION.
#[test]
fn a_bad_unwind_disposition() {
    let code = terminated(|fake| {
        let target_handler = fake.handler(|_, _| EXCEPTION_CONTINUE_SEARCH);
        fake.registered(target_handler, |fake, target| {
            let handler =
                fake.handler(
                    |fake, call| match fake.flags(call.record) & EXCEPTION_UNWIND {
                        0 => EXCEPTION_CONTINUE_SEARCH,
                        _ => EXCEPTION_CONTINUE_EXECUTION,
                    },
                );
            fake.registered(handler, |fake, _| fake.rtl_unwind(target, 0));
        });
    });
    assert_eq!(code, STATUS_INVALID_DISPOSITION);
}
