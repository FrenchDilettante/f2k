"""vmedge: one test per block of its capture; tests/kernel32/vmedge/fixture.toml declares the
comparison (the divergent blocks pending until the kernel is fixed)."""
from f2kboot import corpus_test

test_vmedge = corpus_test("vmedge")
