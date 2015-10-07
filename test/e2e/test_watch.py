'''
Created on 18-Sep-2015

@author: gslab
'''
import test_util
import unittest2 as unittest
import lib.util as util
import lib.controller as controller


class TestWatch(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        TestWatch.rc = controller.RootController()
        actual_out = util.capture_stdout(TestWatch.rc.execute, ['watch', '1', '3', 'info', 'network'])
        TestWatch.output_list = test_util.get_separate_output(actual_out, 'Information')

    def test_watch(self):
        info_counter = 0
        for item in TestWatch.output_list:
            if "~~Network Information~~" in item:
                info_counter += 1
        self.assertEqual(info_counter, 3)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()