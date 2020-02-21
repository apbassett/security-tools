import unittest
import subprocess
import sys
import contextlib
import io

class TestShellcodeLinux(unittest.TestCase):
  py_to_use = None

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

  @classmethod
  def tearDownClass(cls):
    subprocess.call(['rm', 'output.txt'], stderr=subprocess.DEVNULL)
    subprocess.call(['rm', '-r', 'shellcode-files'], stderr=subprocess.DEVNULL)

  def output_capture(self, cmd):
    w_fd = open('output.txt', 'w')
    subprocess.call(cmd, stdout=w_fd, stderr=w_fd)
    r_fd = open('output.txt', 'r')
    out_string = r_fd.read()
    r_fd.close()
    w_fd.close()
    return out_string

  def get_expected1(self):
    s1_fd = open('test-files/shellcode1', 'r')
    s1 = s1_fd.read()
    s1_fd.close()
    return s1

  def get_expected2(self):
    s2_fd = open('test-files/shellcode2', 'r')
    s2 = s2_fd.read()
    s2_fd.close()
    return s2
  
  def test_invalid_args(self):
    self.assertTrue('Usage instructions:' in self.output_capture([self.py_to_use, '../shellcode.py']))
    self.assertTrue('Usage instructions:' in self.output_capture([self.py_to_use, '../shellcode.py', '-help']))
    self.assertTrue('Usage instructions:' in self.output_capture([self.py_to_use, '../shellcode.py', '-garbage']))
    self.assertTrue('Usage instructions:' in self.output_capture([self.py_to_use, '../shellcode.py', '-src', 'test-files/shellcode1.s', '-exec']))
    self.assertTrue('Usage instructions:' in self.output_capture([self.py_to_use, '../shellcode.py', '-exec', '-subroutines', '-main', '-exit']))
    self.assertTrue('Usage instructions:' in self.output_capture([self.py_to_use, '../shellcode.py', '-src', 'test-files/shellcode1.s', '-subroutines', 'main', 'get_addr', 'printunity', '-m99']))
    self.assertTrue('NOT FOUND' in self.output_capture([self.py_to_use, '../shellcode.py', '-src', 'test-files/doesntexist.asm', '-subroutines', 'main', 'exit', '-m32']))

  def test_shellcode_fromsrc_print(self):
    self.assertTrue(str(self.get_expected1()) in self.output_capture([self.py_to_use, '../shellcode.py', '-src', 'test-files/shellcode1.s', '-subroutines', 'main', 'get_addr', 'printunity', '-print-only']))
    self.assertTrue(str(self.get_expected2()) in self.output_capture([self.py_to_use, '../shellcode.py', '-src', 'test-files/shellcode2.s', '-subroutines', 'main', 'exit', '-print-only']))

  def test_shellcode_fromsrc_run(self):
    self.assertTrue('apbassett' in self.output_capture([self.py_to_use, '../shellcode.py', '-src', 'test-files/shellcode1.s', '-subroutines', 'main', 'get_addr', 'printunity']))
    self.assertTrue('apbassett' in self.output_capture([self.py_to_use, '../shellcode.py', '-src', 'test-files/shellcode2.s', '-subroutines', 'main', 'exit']))
  
  def test_shellcode_exec_print(self):
    self.assertTrue(str(self.get_expected1()) in self.output_capture([self.py_to_use, '../shellcode.py', '-exec', 'test-files/shellcode1bin', '-subroutines', 'main', 'get_addr', 'printunity', '-print-only']))
    self.assertTrue(str(self.get_expected2()) in self.output_capture([self.py_to_use, '../shellcode.py', '-exec', 'test-files/shellcode2bin', '-subroutines', 'main', 'exit', '-print-only']))

  def test_shellcode_exec_run(self):
    self.assertTrue('apbassett' in self.output_capture([self.py_to_use, '../shellcode.py', '-exec', 'test-files/shellcode1bin', '-subroutines', 'main', 'get_addr', 'printunity']))
    self.assertTrue('apbassett' in self.output_capture([self.py_to_use, '../shellcode.py', '-exec', 'test-files/shellcode2bin', '-subroutines', 'main', 'exit']))

if __name__ == '__main__':
    unittest.main()
