"""exitwin: one test per block of its capture; tests/user32/exitwin/fixture.toml declares the comparison
(the blocks a missing privilege refuses skipped on F2K, the undefined bits' run)."""
from f2kboot import corpus_test

test_exitwin = corpus_test("exitwin")
