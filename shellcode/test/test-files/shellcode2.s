##################################################
# Produces shellcode that prints 'apbasset'
# without storing the corresponding ascii hex
# characters in a sequence.  Two strings are
# XOR'd together to produce the output string;
# one is the key, 'hckertime', and one is
# garbage produced by the original XOR of
# 'apbasset' and 'hckertime.'
# 
# @author Andrew Bassett
#
##################################################
.text                   
.global main            
##################################################
# Jump to get_addr before going back to the
# functional code.  This is so that we can
# save the address of the key string in
# memory.  
###################################################
# XOR the key string with the garbage and
# print out the target string byte-by-byte.
###################################################
main:
  push $0x68
  mov $4, %eax                                    # Opcode for write system call
  mov $1, %ebx                                    # First arg: fd = 1
  mov $1, %edx                                    # Third arg: length of the string to print 
  xor $0x09, (%esp)                               # XOR 0x09 (literal) and 0x68 (value on stack) by references the value of the addr at esi: prints 'a'
  mov %esp, %ecx                                  # Second arg: copy the string's addr into ecx
  int $0x80                                       # System call interrupt
###################################################
# Print 'p'
###################################################
  push $0x63
  mov $4, %eax                                    # Opcode for write system call
  mov $1, %ebx                                    # First arg: fd = 1
  mov $1, %edx                                    # Third arg: length of the string to print 
  xor $0x13, (%esp)
  mov %esp, %ecx
  int $0x80
##################################################
# Print 'b'
##################################################
  push $0x6b
  mov $4, %eax                                    # Opcode for write system call
  mov $1, %ebx                                    # First arg: fd = 1
  mov $1, %edx                                    # Third arg: length of the string to print 
  xor $0x09, (%esp)
  mov %esp, %ecx
  int $0x80
##################################################
# Print 'a'
##################################################
  push $0x65
  mov $4, %eax                                    # Opcode for write system call
  mov $1, %ebx                                    # First arg: fd = 1
  mov $1, %edx                                    # Third arg: length of the string to print 
  xor $0x04, (%esp)
  mov %esp, %ecx
  int $0x80
##################################################
# Print 's'
##################################################
  push $0x72
  mov $4, %eax                                    # Opcode for write system call
  mov $1, %ebx                                    # First arg: fd = 1
  mov $1, %edx                                    # Third arg: length of the string to print 
  xor $0x01, (%esp)
  mov %esp, %ecx
  int $0x80
##################################################
# Print 's'
##################################################
  push $0x74
  mov $4, %eax                                    # Opcode for write system call
  mov $1, %ebx                                    # First arg: fd = 1
  mov $1, %edx                                    # Third arg: length of the string to print 
  xor $0x07, (%esp)
  mov %esp, %ecx
  int $0x80
##################################################
# Print 'e'
##################################################
  push $0x69
  mov $4, %eax                                    # Opcode for write system call
  mov $1, %ebx                                    # First arg: fd = 1
  mov $1, %edx                                    # Third arg: length of the string to print 
  xor $0x0c, (%esp)
  mov %esp, %ecx
  int $0x80
##################################################
# Print 't'
##################################################
  push $0x6d
  mov $4, %eax                                    # Opcode for write system call
  mov $1, %ebx                                    # First arg: fd = 1
  mov $1, %edx                                    # Third arg: length of the string to print 
  xor $0x19, (%esp)
  mov %esp, %ecx
  int $0x80
##################################################
# Print a newline character
##################################################
  push $0x65
  mov $4, %eax                                    # Opcode for write system call
  mov $1, %ebx                                    # First arg: fd = 1
  mov $1, %edx                                    # Third arg: length of the string to print 
  xor $0x6f, (%esp)
  mov %esp, %ecx
  int $0x80
###################################################
# Exit the program.
##################################################
exit:
  mov $1, %eax                                    # Opcode for exit
  mov $0, %ebx                                    # First arg: exit(0)
  int $0x80                                       # System call interrupt
###################################################
# The following, for reference, are the garbage
# produced from the original XOR, and the key
# string, respectively.
###################################################
# 0x0913090401070c196f # Each byte XOR'd from 'apbasset' and 'hckertime'
# 0x68636b657274696d65 # 'hckertime' in hex (separate bytes for each char, NOT one digit total)
##################################################
