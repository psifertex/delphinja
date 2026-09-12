import unittest


class SignatureSelectionTests(unittest.TestCase):
    def test_each_delphi_layout_selects_only_its_shipped_era(self):
        from delphinja.integration import signatures

        for slots, expected in signatures.DELPHI_ERAS.items():
            layout = type("Layout", (), {"n_virtuals": slots})()
            with self.subTest(slots=slots):
                self.assertEqual(signatures.delphi_tags(layout), expected)

    def test_unknown_layout_falls_back_to_every_declared_library_once(self):
        from delphinja.integration import signatures

        selected = signatures.delphi_tags()
        self.assertEqual(selected, signatures.DELPHI_LIBRARIES)
        self.assertEqual(len(selected), len(set(selected)))


class NameClaimTests(unittest.TestCase):
    def test_shallow_owner_wins_and_unrelated_ties_are_dropped(self):
        from delphinja.rtti.apply import NameClaims

        claims = NameClaims()
        claims.claim(0x1000, "TChild.Free", 3, owner="child")
        claims.claim(0x1000, "TObject.Free", 1, owner="root")
        claims.claim(0x2000, "TFoo.Run", 2)
        claims.claim(0x2000, "TBar.Run", 2)

        self.assertEqual(list(claims.resolved()),
                         [(0x1000, "TObject.Free", "root", True, 2)])
        self.assertEqual(claims.conflicts, 1)

    def test_identical_tied_claims_settle_without_a_conflict(self):
        from delphinja.rtti.apply import NameClaims

        claims = NameClaims()
        claims.claim(0x1000, "TObject.Free", 1)
        claims.claim(0x1000, "TObject.Free", 1)

        self.assertEqual(len(list(claims.resolved())), 1)
        self.assertEqual(claims.conflicts, 0)


if __name__ == "__main__":
    unittest.main()
