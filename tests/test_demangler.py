import unittest


class BorlandDemanglerTests(unittest.TestCase):
    def test_documented_method_decodes_name_signature_and_self(self):
        from delphinja import demangler

        decoded = demangler.demangle_name(
            "@Forms@TApplication@HandleException$qqrp14System@TObject")

        self.assertEqual(decoded.name,
                         "Forms::TApplication::HandleException")
        self.assertEqual(decoded.kind, "function")
        self.assertEqual(decoded.self_class, ["Forms", "TApplication"])
        self.assertIn("System::TObject *", decoded.text())

    def test_non_borland_and_truncated_symbols_are_total(self):
        from delphinja import demangler

        for symbol in (None, "", "_Z3foov", "?foo@@YAXXZ", "@fastcall@12",
                       "@", "@Forms@%"):
            with self.subTest(symbol=symbol):
                self.assertIsNone(demangler.demangle_name(symbol))

    def test_bad_signature_keeps_the_recovered_qualified_name(self):
        from delphinja import demangler

        decoded = demangler.demangle_name("@Classes@TReader@ReadIdent$qqr#")
        self.assertEqual(decoded.name, "Classes::TReader::ReadIdent")
        self.assertIsNone(decoded.signature)


if __name__ == "__main__":
    unittest.main()
