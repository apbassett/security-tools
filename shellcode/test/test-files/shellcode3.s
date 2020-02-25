###################################
# Produces shellcode that       
# executes 'ls' via execve on the 
# console.                        
#                               
# @author apbasset                
# @author A.K.                    
# (code structure                 
#  sourced from in-               
#  class example)               
###################################
.text                             #
.global main                      #
main:                             #
  pushl $0x00                     # First push some null bytes to the stack
  pushl $0x00736c2f               # Then push '\0ls/'
  pushl $0x6e69622f               # '/nib/' (it's backwards b/c x86 is Little-Endian)
  mov $0xb, %eax                  # Move the code for execve to eax
  movl %esp, %ebx                 # Move the pointer to the string to ebx
  pushl $0x00                     # Push some more null bytes
  pushl %ebx                      # Push the address of the pointer to the string
  movl %esp, %ecx                 # Move that address into ecx 
  leal 0x08(%ebx), %edx           # Set edx to point to a null word
  int $0x80                       # System call interrupt
exit:                             # Exits the program
  mov $1, %eax                    # Opcode for exit
  mov $0, %ebx                    # First arg: exit(0)
  int $0x80                       # System call interrupt
###################################
