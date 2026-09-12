import json
import os
import stat
import sys
import unittest
from pathlib import Path


class IsolatedEnvironmentTests(unittest.TestCase):
    def test_01_profile_contains_only_test_inputs(self):
        user = Path(os.environ["BN_USER_DIRECTORY"])
        source = Path(os.environ["DELPHINJA_REAL_USER_DIRECTORY"])
        expected = {
            "corePlugins.warp",
            "delphinja.commands",
            "delphinja.mechanism",
            "delphinja.signatures",
            "network.enableUpdates",
        }
        with (user / "settings.json").open() as fh:
            settings = json.load(fh)
        self.assertLessEqual(set(settings), expected | {"enterprise.server.url"})
        self.assertTrue(expected.issubset(settings))
        self.assertNotEqual(user.resolve(), source.resolve())
        self.assertEqual(stat.S_IMODE(user.stat().st_mode), 0o700)

        licence = user / "license.dat"
        self.assertTrue(licence.is_file(), "the real profile has no license.dat")
        self.assertEqual(stat.S_IMODE(licence.stat().st_mode), 0o600)

    def test_02_checkout_is_the_only_user_plugin(self):
        user = Path(os.environ["BN_USER_DIRECTORY"])
        links = list((user / "plugins").iterdir())
        self.assertEqual(len(links), 1)
        self.assertTrue(links[0].is_symlink())
        self.assertEqual(links[0].resolve(), Path(os.environ["DELPHINJA_ROOT"]))

    def test_03_binary_ninja_loads_the_linked_plugin(self):
        import binaryninja as bn

        self.assertEqual(Path(bn.user_directory()).resolve(),
                         Path(os.environ["BN_USER_DIRECTORY"]).resolve())
        self.assertEqual(Path(bn.user_plugin_path()).resolve(),
                         Path(os.environ["BN_USER_DIRECTORY"], "plugins").resolve())
        bn._init_plugins()
        self.assertIn("delphinja", sys.modules)
        plugin = Path(sys.modules["delphinja"].__file__).resolve()
        self.assertEqual(plugin, Path(os.environ["DELPHINJA_ROOT"],
                                      "__init__.py"))


if __name__ == "__main__":
    unittest.main()
