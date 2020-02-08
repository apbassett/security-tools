import unittest
import subprocess
import sys
import contextlib
import io

class TestShellcodeLinux(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    if sys.version_info[0] < 3:
      print(sys.version_info[0])
      print('ERROR: Current Python version must be >= 3.5.  Exiting.')
      exit()
    print('Preparing to run test suite for Linux machines.\\n' +
          'IMPORTANT: MAKE SURE gcc-multilib is installed.')

  @classmethod
  def tearDownClass(cls):
    subprocess.call('rm output.txt 2> /dev/null')
    subprocess.call('rm -r ../shellcode-files 2> /dev/null')

  def output_capture(self, cmd):
    subprocess.call(cmd, shell=True)
    output = open('output.txt', 'r') 
    out_string = output.read()
    output.close()
    return out_string

  def get_expected1(self):
    return '\\xeb\\x20\\x5e\\xb8\\x04\\x00\\x00\\x00\\xbb\\x01\\x00\\x00\\x00\\x89\\xf1' + 
           '\\xba\\x09\\x00\\x00\\x00\\xcd\\x80\\xb8\\x01\\x00\\x00\\x00\\xbb\\x00\\x00' +
           '\\x00\\x00\\xcd\\x80\\xe8\\xdb\\xff\\xff\\xff\\x61\\x70\\x62\\x61\\x73\\x73' + 
           '\\x65\\x74\\x0a\\x00\\x66\\x90\\x66\\x90'

  def get_expected2(self):
    return '\\x6a\\x68\\xb8\\x04\\x00\\x00\\x00\\xbb\\x01\\x00\\x00\\x00\\xba\\x01\\x00' +
           '\\x00\\x00\\x83\\x34\\x24\\x09\\x89\\xe1\\xcd\\x80\\x6a\\x63\\xb8\\x04\\x00' +
           '\\x00\\x00\\xbb\\x01\\x00\\x00\\x00\\xba\\x01\\x00\\x00\\x00\\x83\\x34\\x24' +
           '\\x13\\x89\\xe1\\xcd\\x80\\x6a\\x6b\\xb8\\x04\\x00\\x00\\x00\\xbb\\x01\\x00' +
           '\\x00\\x00\\xba\\x01\\x00\\x00\\x00\\x83\\x34\\x24\\x09\\x89\\xe1\\xcd\\x80' +
           '\\x6a\\x65\\xb8\\x04\\x00\\x00\\x00\\xbb\\x01\\x00\\x00\\x00\\xba\\x01\\x00' +
           '\\x00\\x00\\x83\\x34\\x24\\x04\\x89\\xe1\\xcd\\x80\\x6a\\x72\\xb8\\x04\\x00' +
           '\\x00\\x00\\xbb\\x01\\x00\\x00\\x00\\xba\\x01\\x00\\x00\\x00\\x83\\x34\\x24' +
           '\\x01\\x89\\xe1\\xcd\\x80\\x6a\\x74\\xb8\\x04\\x00\\x00\\x00\\xbb\\x01\\x00' +
           '\\x00\\x00\\xba\\x01\\x00\\x00\\x00\\x83\\x34\\x24\\x07\\x89\\xe1\\xcd\\x80' +
           '\\x6a\\x69\\xb8\\x04\\x00\\x00\\x00\\xbb\\x01\\x00\\x00\\x00\\xba\\x01\\x00' +
           '\\x00\\x00\\x83\\x34\\x24\\x0c\\x89\\xe1\\xcd\\x80\\x6a\\x6d\\xb8\\x04\\x00' +
           '\\x00\\x00\\xbb\\x01\\x00\\x00\\x00\\xba\\x01\\x00\\x00\\x00\\x83\\x34\\x24' +
           '\\x19\\x89\\xe1\\xcd\\x80\\x6a\\x65\\xb8\\x04\\x00\\x00\\x00\\xbb\\x01\\x00' +
           '\\x00\\x00\\xba\\x01\\x00\\x00\\x00\\x83\\x34\\x24\\x6f\\x89\\xe1\\xcd\\x80' +
           '\\xb8\\x01\\x00\\x00\\x00\\xbb\\x00\\x00\\x00\\x00\\xcd\\x80\\x66\\x90\\x66' +
           '\\x90\\x66\\x90\\x66\\x90'
  
  def test_invalid_args(self):
    self.assertTrue('Usage instructions:' in self.output_capture('python ../shellcode.py > output.txt'))
    self.assertTrue('Usage instructions:' in self.output_capture('python ../shellcode.py -help > output.txt'))
    self.assertTrue('Usage instructions:' in self.output_capture('python ../shellcode.py -garbage> output.txt'))
    self.assertTrue('Usage instructions:' in self.output_capture('python ../shellcode.py -src test/test-files/shellcode1.s -exec > output.txt'))
    self.assertTrue('Usage instructions:' in self.output_capture('python ../shellcode.py -exec -subroutines -main -exit > output.txt'))
    self.assertTrue('Usage instructions:' in self.output_capture('python ../shellcode.py -src test/test-files/shellcode1.s -subroutines main get_addr printunity -m99> output.txt'))
    self.assertTrue('NOT FOUND' in self.output_capture('python ../shellcode.py -src test/test-files/doesntexist.asm -subroutines main exit -m32 > output.txt'))

  #def test_shellcode_fromsrc_print(self):

  #def test_shellcode_fromsrc_run(self):
  
  #def test_shellcode_exec_print(self):

  #def test_shellcode_exec_run(self):

if __name__ == '__main__':
    unittest.main()
