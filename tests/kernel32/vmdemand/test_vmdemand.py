"""vmdemand: one test per block of its capture; tests/kernel32/vmdemand/fixture.toml declares the
comparison (the blocks pending until the behavior they pin is served)."""
from f2kboot import corpus_test

test_vmdemand = corpus_test("vmdemand")
