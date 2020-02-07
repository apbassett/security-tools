import unittest
import subprocess
import sys

class TestShellcodeLinux(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    if sys.version_info[0] < 3.5:
      print("ERROR: Current Python version < 3.5.  Exiting.")
      exit()
    print("Preparing to run test suite for Linux machines.\n" +
          "IMPORTANT: MAKE SURE gcc-multilib is installed.")
  
  def test_invalid_args(self):
    cmd = "python --version"
    

  def test_shellcode_fromsrc_print(self):

  def test_shellcode_fromsrc_run(self):
  
  def test_shellcode_exec_print(self):

  def test_shellcode_exec_run(self):
