import unittest
from test.e2e import util


class VersionTests(unittest.TestCase):
    def test_return_code(self):
        args = "--version"
        o = util.run_asadm(args)
        self.assertEqual(o.returncode, 0)
