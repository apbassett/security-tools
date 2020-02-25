#########################
# Produces shellcode    #
# to print 'apbassett'  #
# to the console.       #
#                       # 
# @author apbassett     #
# @author A.K.          #
# (code structure       #
#  sourced from in-     #
#  class example)       #
#########################
.text                   #
.global main            #
main:                   #
  jmp get_addr          # Jump to where the string is to put its addr on the stack
printunity:             #
  pop %esi              # Pop the string's addr off the stack
  mov $4, %eax          # Opcode for write system call
  mov $1, %ebx          # First arg: fd = 1
  mov %esi, %ecx        # Second arg: copy the string's addr into ecx
  mov $10, %edx         # Third arg: length of the string to print 
  int $0x80             # System call interrupt
  mov $1, %eax          # Opcode for exit
  mov $0, %ebx          # First arg: exit(0)
  int $0x80             # System call interrupt
get_addr:               #
  call printunity       # Calls the main subroutine
  .string "apbassett\n" # The string to print
#########################
