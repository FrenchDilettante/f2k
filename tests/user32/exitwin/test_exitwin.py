"""exitwin: one test per block of its capture; tests/user32/exitwin/fixture.toml declares the comparison
(every block skipped on F2K)."""
from f2kboot import corpus_test

test_exitwin = corpus_test("exitwin")
