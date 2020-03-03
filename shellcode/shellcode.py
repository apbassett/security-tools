# Automatically runs or prints shellcode extracted from an assembler source code file or binary.
# Designed and tested for Linux machines.  Must have Python3 and gcc-multilib installed.  Default
# compilation settings specify 32 bit assmebler code.  Must have permission to create files and
# dirs, and compile/execute.
#
# Andrew Bassett @ NC State University
#

import sys
import os.path
import subprocess
import re

# Encapsulation for arguments specified on the command-line
# Performs some printing and vadliation
class Arguments:

  # Whether to extract shellcode from an assembler source file (probably .s or .asm)
  src = True
  # The name/path of the file to extract from
  filename = None
  # The subroutines in the source code to extract shellcode from
  subroutines = []
  # Whether to simply print the shellcode rather than execute it
  print_only = False
  # Whether to compile gcc with the -m32 (32 bits) option
  m32 = True
  
  def __init__(self, argv):
    if (len(argv) < 4 and len(argv) != 1):
      self.usage()

    i = 0

    for arg in argv:
      if arg == "-help":
        self.usage()
      elif i == 0:
        if arg == "-exec":
          self.src = False
        elif arg != "-src":
          self.usage()
      elif i == 1:
        self.filename = arg
      elif i == 2:
        if arg != "-subroutines":
          self.usage()
        for sr in argv[3:]:
          if (sr[:1] != "-"):
            self.subroutines.append(sr)
          else:
            break
        if len(self.subroutines) == 0:
          self.usage()
      else:
        if arg == "-print-only":
          self.print_only = True
        elif arg == "-m64":
          self.m32 = False
        elif arg != "-m32" and arg not in self.subroutines:
          self.usage()
      i += 1

    print("Extracting shellcode with options...")
    if self.src:
      print("File type: assembly source")
    else:
      print("file type: executable")
    print("Filename: " + self.filename)
    subrstr = "Subroutines:"
    for sr in self.subroutines:
      subrstr += " " + sr
    print(subrstr)
    print("Compiling assembler file as 32 bits: " + str(self.m32))
    print("Executing test C program on shellcode: " + str(not self.print_only))

    print("\nChecking for required files...")
    if os.path.isfile(self.filename):
      print(self.filename + ": FOUND")
    else:
      print(self.filename + ": NOT FOUND")
      print("Please make sure that you have the necessary files in the directory.")

  # Displays usage information and exits the program
  def usage(self):
    print("\nThis program takes an assembler source file or executable and extracts shellcode that" + 
           "\nis then tested in a C program automatically compiled and executed.\n\nPreconditions:" +
           "\nintalled gcc-multilib\n")
    print("Usage instructions: ")
    print("<-help> ................................ See this page")
    print("FIRST ARGUMENT: choose")
    print("<-exec> ................................ The assembler file to extract the shellcode" +
           " from is already an executable")
    print("<-src> ................................. Compile source file with gcc-multilib and then" +
           " extract shellcode")
    print("SECOND ARGUMENT: assembler source/executable file path")
    print("THIRD ARGUMENT:")
    print("<-subroutines> ......................... the procedures/subroutines to extract" +
           " shellcode from.\nList them after this argument; at least one required. For example, " +
           "\"-subroutines main loop exit\"")
    print("FOURTH\FIFTH ARGUMENT:")
    print("<-print-only> .......................... Do not execute the shellcode in the test " +
           "program, just print it to stdout")
    print("<-m32> ................................. Compile the assembler source file as 32 bits" +
           " (default if not specified)")
    print("<-m64> ................................. Compile the assembler source file as 64 bits\n")
    exit()

# Compiles an assembler source file
def compile_asm(args):
  if args.m32:
    subprocess.run(["gcc", "-m32", args.filename, "-o", "shellcode-files/" + args.filename[args.filename.rfind('/') + 1:] + ".out"])
  else:
    subprocess.run(["gcc", "-m64", args.filename, "-o", "shellcode-files/" + args.filename[args.filename.rfind('/') + 1:] + ".out"])

  get_shellcode_from_asm(args)

# Extracts shellcode from a binary
def get_shellcode_from_asm(args):
  for i, sr in enumerate(args.subroutines, 0):
    args.subroutines[i] = '<' + sr + '>'
  if args.src:
    cmd = "objdump -d " + "shellcode-files/" + args.filename[args.filename.rfind('/') + 1:] + ".out" + " > shellcode-files/dissasembly.dump"
  else:
    cmd = "objdump -d " + args.filename + " > shellcode-files/dissasembly.dump"
  subprocess.call(cmd, shell = True)
  file_obj = open("shellcode-files/dissasembly.dump", 'r')
  objdump = file_obj.read().split('\n\n')

  # Isolate the required sections only
  sects = []
  for sect in objdump:
          if any(req_sect in sect for req_sect in args.subroutines):
                  sects.append(sect)

  # Convert them to a string
  sects = ''.join(sects)

  # Transform the required sections of the objectdump into shellcode
  shellcode = ''.join(re.findall(r'(\t.*\t)', sects))
  shellcode = re.sub(r'\s+','\\x', shellcode.rstrip())
  shell_array = shellcode.split()

  file_obj.close()

  print("\n****************************** YOUR SHELLCODE ******************************\n")
  print(shellcode)
  print("\n****************************************************************************\n")

  if args.print_only:
    exit()

  shelltester_file = open("shellcode-files/shelltester.c", 'w')
  shelltester_file.write("#include<stdio.h>\n#include<string.h>\n")
  shelltester_file.write("\nunsigned char shellcode[] = \"" + shellcode + "\";\n")
  shelltester_file.write("\nint main() {\n  int (*ret)() = (int(*)())shellcode;\n  ret();\n}")

  shelltester_file.close()

  if args.m32:
    cmd = "gcc shellcode-files/shelltester.c -o ./shellcode-files/shelltester -fno-stack-protector -z execstack -no-pie -m32"
  else:
    cmd = "gcc shellcode-files/shelltester.c -o ./shellcode-files/shelltester -fno-stack-protector -z execstack -no-pie"

  subprocess.call(cmd, shell = True)

  cmd = "./shellcode-files/shelltester"
  print("Testing your shellcode...\n\n******************************** YOUR OUTPUT ********************************\n")
  subprocess.call(cmd, shell = True)
  print("\n*****************************************************************************\n")
  exit()

# Parses command-line args and orchestrates shellcode extraction
def main(argv):
  args = Arguments(argv)

  if not os.path.isdir("shellcode-files"):
    subprocess.call("mkdir shellcode-files", shell = True)

  if args.src:
    compile_asm(args)
  else:
    get_shellcode_from_asm(args)

if __name__ == "__main__":
  main(sys.argv[1:])
