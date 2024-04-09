;# recursive case of `long fib(long n)`

  ;# prologue start
  push rbp
  mov rbp, rsp
  sub rsp, 0x10
  ;# prologue end
  mov [rsp+0x8], rdi

  sub rdi, 1
 
  call fib
  mov [rsp], rax

  mov rdi, [rsp+0x8]
  sub rdi, 2

  call fib
  add rax, [rsp]
  
  ;# epilogue start
  add rsp, 0x10
  pop rbp
  ;# epilogue end
