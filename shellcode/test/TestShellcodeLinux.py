import unittest
import subprocess
import sys
import contextlib
import io

# Tests the basic functionality of the shellcode.py script for Linux machines
# Not a true unit test as it does not test as the function level, but rather
# provides a number of comprehensive system tests to ensure correct output
# and basic input validation.
#
# PRECONDITIONS: Running on Linux; installed Python3; installed gcc-multilib
#
# @author Andrew Bassett
#
class TestShellcodeLinux(unittest.TestCase):

  # If the system has two Python versions installed, store the correct command for Python3 here
  py_to_use = None

  # Setup the test cases (runs before all, once)
  @classmethod
  def setUpClass(cls):
    if 'Python 2' in cls.output_capture(cls, ['python', '--version']):
      cls.py_to_use = 'python3'
    else:
      cls.py_to_use = 'python'

    if sys.version_info[0] < 3:
      print('ERROR: Current Python version must be >= 3.5.  Exiting.')
      exit()
    print('Preparing to run test suite for Linux machines.\n' +
          'IMPORTANT: MAKE SURE gcc-multilib is installed.')

  # Runs once after all tests execute to remove created test dirs and files
  @classmethod
  def tearDownClass(cls):
    subprocess.call(['rm', 'output.txt'], stderr=subprocess.DEVNULL)
    subprocess.call(['rm', '-r', 'shellcode-files'], stderr=subprocess.DEVNULL)

  # Helper function to capture the output of a subprocess
  def output_capture(self, cmd):
    w_fd = open('output.txt', 'w')
    subprocess.call(cmd, stdout=w_fd, stderr=w_fd)
    r_fd = open('output.txt', 'r')
    out_string = r_fd.read()
    r_fd.close()
    w_fd.close()
    return out_string

  # Gets the expected shellcode for test-files/shellcode1.s
  def get_expected1(self):
    s1_fd = open('test-files/shellcode1', 'r')
    s1 = s1_fd.read()
    s1_fd.close()
    return s1

  # Gets the expected shellcode for test-files/shellcode2.s
  def get_expected2(self):
    s2_fd = open('test-files/shellcode2', 'r')
    s2 = s2_fd.read()
    s2_fd.close()
    return s2
 
  # Tests program output given invalid command-line arguments
  def test_invalid_args(self):
    self.assertTrue('Usage instructions:' in self.output_capture([self.py_to_use, '../shellcode.py']))
    self.assertTrue('Usage instructions:' in self.output_capture([self.py_to_use, '../shellcode.py', '-help']))
    self.assertTrue('Usage instructions:' in self.output_capture([self.py_to_use, '../shellcode.py', '-garbage']))
    self.assertTrue('Usage instructions:' in self.output_capture([self.py_to_use, '../shellcode.py', '-src', 'test-files/shellcode1.s', '-exec']))
    self.assertTrue('Usage instructions:' in self.output_capture([self.py_to_use, '../shellcode.py', '-exec', '-subroutines', '-main', '-exit']))
    self.assertTrue('Usage instructions:' in self.output_capture([self.py_to_use, '../shellcode.py', '-src', 'test-files/shellcode1.s', '-subroutines', 'main', 'get_addr', 'printunity', '-m99']))
    self.assertTrue('NOT FOUND' in self.output_capture([self.py_to_use, '../shellcode.py', '-src', 'test-files/doesntexist.asm', '-subroutines', 'main', 'exit', '-m32']))

  # Tests printing shellcode from a source code file
  def test_shellcode_fromsrc_print(self):
    self.assertTrue(str(self.get_expected1()) in self.output_capture([self.py_to_use, '../shellcode.py', '-src', 'test-files/shellcode1.s', '-subroutines', 'main', 'get_addr', 'printunity', '-print-only']))
    self.assertTrue(str(self.get_expected2()) in self.output_capture([self.py_to_use, '../shellcode.py', '-src', 'test-files/shellcode2.s', '-subroutines', 'main', 'exit', '-print-only']))

  # Tests executing shellcode from a source code file
  def test_shellcode_fromsrc_run(self):
    self.assertTrue('apbassett' in self.output_capture([self.py_to_use, '../shellcode.py', '-src', 'test-files/shellcode1.s', '-subroutines', 'main', 'get_addr', 'printunity']))
    self.assertTrue('apbassett' in self.output_capture([self.py_to_use, '../shellcode.py', '-src', 'test-files/shellcode2.s', '-subroutines', 'main', 'exit']))
 
  # Tests printing shellcode from a binary
  def test_shellcode_exec_print(self):
    self.assertTrue(str(self.get_expected1()) in self.output_capture([self.py_to_use, '../shellcode.py', '-exec', 'test-files/shellcode1bin', '-subroutines', 'main', 'get_addr', 'printunity', '-print-only']))
    self.assertTrue(str(self.get_expected2()) in self.output_capture([self.py_to_use, '../shellcode.py', '-exec', 'test-files/shellcode2bin', '-subroutines', 'main', 'exit', '-print-only']))

  # Tests executing shellcode from a binary
  def test_shellcode_exec_run(self):
    self.assertTrue('apbassett' in self.output_capture([self.py_to_use, '../shellcode.py', '-exec', 'test-files/shellcode1bin', '-subroutines', 'main', 'get_addr', 'printunity']))
    self.assertTrue('apbassett' in self.output_capture([self.py_to_use, '../shellcode.py', '-exec', 'test-files/shellcode2bin', '-subroutines', 'main', 'exit']))

if __name__ == '__main__':
    unittest.main()
