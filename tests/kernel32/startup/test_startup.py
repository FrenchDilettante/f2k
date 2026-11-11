"""startup: one test per block of its capture; tests/kernel32/startup/fixture.toml declares the
comparison (the block pending until GetStartupInfoA converts the parameters' strings)."""
from f2kboot import corpus_test

test_startup = corpus_test("startup")
