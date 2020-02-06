# Automatically runs or prints shellcode extracted from an assembler source code file or binary.
# Designed and tested for Linux machines.  Must have Python3 and gcc-multilib installed.  Default
# compilation settings specify 32 bit assmebler code.  Must have permission to create files and
# dirs, and compile/execute.
#
# Andrew Bassett @ NC State University
# Initial version 2/3/2020
#

import sys
import os.path
import subprocess
import re

# Displays usage information and exits the program
def usage():
  print("\nThis program takes an assembler source file or executable and extracts shellcode that" + 
         "\nis then tested in a C program automatically compiled and executed.\n\nPreconditions:" +
         "\nintalled gcc-multilib\n")
  print("Usage instructions: ")
  print("<-help> ................................ See this page")
  print("FIRST ARGUMENT: choose")
  print("<-exec> ................................ The assembler file to extract the shellcode" +
         " from is already an executable")
  print("<-src> ................................. Compile source file with gcc-multilib and then" +
         "extract shellcode")
  print("SECOND ARGUMENT: assembler source/executable file path")
  print("THIRD ARGUMENT:")
  print("<-subroutines> ......................... the procedures/subroutines to extract" +
         "shellcode from.\nList them after this argument; at least one required. For example, " +
         "-subroutines main loop exit")
  print("FOURTH\FIFTH ARGUMENT:")
  print("<-print-only> .......................... Do not execute the shellcode in the test " +
         "program, just print it to stdout")
  print("<-m32> ................................. Compile the assembler source file as 32 bits" +
         "(default if not specified)")
  print("<-m64> ................................. Compile the assembler source file as 64 bits\n")
  exit()

# Compiles an assembler source file
def compile_asm(filename, bits_32, subroutines, print_only):
  if bits_32:
    subprocess.run(["gcc", "-m32", filename, "-o", "shellcode-files/" + filename + ".out"])
  else:
    subprocess.run(["gcc", "-m64", filename, "-o", "shellcode-files/" + filename + ".out"])

  get_shellcode_from_asm(filename + ".out", bits_32, subroutines, print_only)

# Extracts shellcode from a binary
def get_shellcode_from_asm(filename, bits_32, subroutines, print_only):
  for i, sr in enumerate(subroutines, 0):
    subroutines[i] = '<' + sr + '>'

  cmd = "objdump -d " + "shellcode-files/" + filename + " > shellcode-files/dissasembly.dump"
  subprocess.call(cmd, shell = True)
  file_obj = open("shellcode-files/dissasembly.dump", 'r')
  objdump = file_obj.read().split('\n\n')

  # Isolate the required sections only
  sects = []
  for sect in objdump:
          if any(req_sect in sect for req_sect in subroutines):
                  sects.append(sect)

  # Convert them to a string
  sects = ''.join(sects)

  # Transform the required sections of the objectdump into shellcode
  shellcode = ''.join(re.findall(r'(\t.*\t)', sects))
  shellcode = re.sub(r'\s+','\\x', shellcode.rstrip())
  shell_array = shellcode.split()

  file_obj.close()

  if print_only:
    print("\n****************************** YOUR SHELLCODE ******************************\n")
    print(shellcode)
    print("\n****************************************************************************\n")
    exit()

  shelltester_file = open("shellcode-files/shelltester.c", 'w')
  shelltester_file.write("#include<stdio.h>\n#include<string.h>\n")
  shelltester_file.write("\nunsigned char shellcode[] = \"" + shellcode + "\";\n")
  shelltester_file.write("\nint main() {\n  int (*ret)() = (int(*)())shellcode;\n  ret();\n}")

  shelltester_file.close()

  if bits_32:
    cmd = "gcc shellcode-files/shelltester.c -o ./shellcode-files/shelltester -fno-stack-protector -z execstack -no-pie -m32"
  else:
    cmd = "gcc shellcode-files/shelltester.c -o ./shellcode-files/shelltester -fno-stack-protector -z execstack -no-pie"

  subprocess.call(cmd, shell = True)

  cmd = "./shellcode-files/shelltester"
  print("\n****************************** YOUR OUTPUT *******************************\n")
  subprocess.call(cmd, shell = True)
  print("\n**************************************************************************\n")
  exit()

# Parses command-line args and orchestrates shellcode extraction
def main(argv):
  src = True
  filename = None
  subroutines = []
  print_only = False
  m32 = True
  i = 0

  if (len(argv) < 4 and len(argv) != 1):
    usage()

  for arg in argv:
    if arg == "-help":
      usage()
    elif i == 0:
      if arg == "-exec":
        src = False
      elif arg != "-src":
        usage()
    elif i == 1:
      filename = arg
    elif i == 2:
      if arg != "-subroutines":
        usage()
      for sr in argv[3:]:
        if (sr[:1] != "-"):
          subroutines.append(sr)
        else:
          break
      if len(subroutines) == 0:
        usage()
    else:
      if arg == "-print-only":
        print_only = True
      elif arg == "-m64":
        m32 = False
      elif arg != "-m32" and arg not in subroutines:
        usage()
    i += 1

  print("Extracting shellcode with options...")
  if src:
    print("File type: assembly source")
  else:
    print("file type: executable")
  print("Filename: " + filename)
  subrstr = "Subroutines:"
  for sr in subroutines:
    subrstr += " " + sr
  print(subrstr)
  print("Compiling assembler file as 32 bits: " + str(m32))
  print("Executing test C program on shellcode: " + str(print_only))

  print("\nChecking for required files...")
  if os.path.isfile(filename):
    print(filename + ": FOUND")
  else:
    print(filename + ": NOT FOUND")
    print("Please make sure that you have the necessary files in the directory.")
    exit()

  if not os.path.isdir("shellcode-files"):
    subprocess.call("mkdir shellcode-files", shell = True)

  if src:
    compile_asm(filename, m32, subroutines, print_only)
  else:
    get_shellcode_from_asm(filename, m32, subroutines, print_only)

if __name__ == "__main__":
  main(sys.argv[1:])
