"""lcid: one test per block of its capture; tests/kernel32/lcid/fixture.toml declares the comparison
(the block pending until CompareString validates the LCID)."""
from f2kboot import corpus_test

test_lcid = corpus_test("lcid")
