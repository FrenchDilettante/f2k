"""ntquery: one test per block of its capture; tests/kernel32/ntquery/fixture.toml declares the
comparison (the scm block pending until a service manager exists or the divergence is accepted)."""
from f2kboot import corpus_test

test_ntquery = corpus_test("ntquery")
