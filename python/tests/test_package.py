import unittest

import observatory_policies


class PackageSetupTest(unittest.TestCase):
    def test_package_version_is_available(self):
        self.assertEqual(observatory_policies.__version__, "0.1.0")


if __name__ == "__main__":
    unittest.main()
