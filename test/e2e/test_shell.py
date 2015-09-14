'''
Created on 07-Sep-2015

@author: gslab
'''
import unittest2 as unittest
from lib.controllerlib import *
from lib.controller import *
import lib.util as util
import subprocess 

class TestController(unittest.TestCase):
    
    def test_shell_command(self):
        sc = ShellController()
        actual_out = util.capture_stdout(sc._do_default, ["ls"])
        p = subprocess.Popen(['sh', '-c', "ls"]
                             , stdout=subprocess.PIPE
                             , stderr=subprocess.PIPE)
        
        expected_out, err = p.communicate()
        self.assertEqual(expected_out.strip(), actual_out.strip())
    
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()