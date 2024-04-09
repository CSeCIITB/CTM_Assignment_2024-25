main:
lea rdi, [rip+tester]
jmp rdi

fib:
/*
;# base case handled in `int 0x07; ret`
;# if(rax <= 2) -> Exec< mov rax, 1; ret>
;# Just follow this behavior, don't worry about how this internally works
*/
int 0x07
ret
nop
dummy:

int 0x03
;# <insert> your code here!
ret

tester:
int 0x03
;# Code is now in the sandbox!

.macro unroll ctr=@NUM_INPUTS
.if \ctr > 0
  ;# get the input value in RAX
  int 0x05
  call fib
  ;# Check if the output is correct
  int 0x04
unroll "(\ctr-1)"
.endif
.endm
  
unroll

exit:

int 0x04
int 0x04

int 0x2a

hlt
