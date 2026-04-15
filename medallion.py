import ctypes, mmap, subprocess, tempfile, os

# Raw bytes from NSA Codebreaker Challenge medallion
shellcode = bytes([
    0xEB, 0x32, 0x5B, 0x48,
    0x89, 0xDA, 0xB9, 0x1A,
    0x00, 0x00, 0x00, 0x80,
    0x33, 0xAA, 0x48, 0xFF,
    0xC3, 0x48, 0xFF, 0xC9,
    0x75, 0xF5, 0xB8, 0x01,
    0x00, 0x00, 0x00, 0xBF,
    0x01, 0x00, 0x00, 0x00,
    0x48, 0x89, 0xD6, 0xBA,
    0x1A, 0x00, 0x00, 0x00,
    0x0F, 0x05, 0xB8, 0x3C,
    0x00, 0x00, 0x00, 0x48,
    0x31, 0xFF, 0x0F, 0x05,
    0xE8, 0xC9, 0xFF, 0xFF,
    0xFF, 0xE4, 0xF9, 0xEB,
    0x8A, 0xE9, 0xC5, 0xCE,
    0xCF, 0xC8, 0xD8, 0xCF,
    0xCB, 0xC1, 0xCF, 0xD8,
    0x8A, 0xE9, 0xC2, 0xCB,
    0xC6, 0xC6, 0xCF, 0xC4,
    0xCD, 0xCF, 0xA0,
    ]) # 83 bytes

# Disassemble shellcode
with tempfile.NamedTemporaryFile(delete=False) as f:
    f.write(shellcode)
    tmp = f.name

try:
    result = subprocess.run(
        ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', '-Mintel', tmp],
        capture_output=True
    )
    print(result.stdout.decode())
finally:
    os.unlink(tmp)

# Output disassembly
'''
Disassembly of section .data:

0000000000000000 <.data>:
   0:   eb 32                   jmp    0x34
   2:   5b                      pop    rbx
   3:   48 89 da                mov    rdx,rbx
   6:   b9 1a 00 00 00          mov    ecx,0x1a
   b:   80 33 aa                xor    BYTE PTR [rbx],0xaa
   e:   48 ff c3                inc    rbx
  11:   48 ff c9                dec    rcx
  14:   75 f5                   jne    0xb
  16:   b8 01 00 00 00          mov    eax,0x1
  1b:   bf 01 00 00 00          mov    edi,0x1
  20:   48 89 d6                mov    rsi,rdx
  23:   ba 1a 00 00 00          mov    edx,0x1a
  28:   0f 05                   syscall
  2a:   b8 3c 00 00 00          mov    eax,0x3c
  2f:   48 31 ff                xor    rdi,rdi
  32:   0f 05                   syscall
  34:   e8 c9 ff ff ff          call   0x2
  39:   e4 f9                   in     al,0xf9
  3b:   eb 8a                   jmp    0xffffffffffffffc7
  3d:   e9 c5 ce cf c8          jmp    0xffffffffc8cfcf07
  42:   d8 cf                   fmul   st,st(7)
  44:   cb                      retf
  45:   c1 cf d8                ror    edi,0xd8
  48:   8a e9                   mov    ch,cl
  4a:   c2 cb c6                ret    0xc6cb
  4d:   c6                      (bad)
  4e:   cf                      iret
  4f:   c4                      (bad)
  50:   cd cf                   int    0xcf
  52:   a0                      .byte 0xa0
'''

# Shellcode analysis
'''
; jmp-call-pop to dynamically load encoded data
jmp 0x34              ; jump to call
call 0x2              ; push next addr (encoded data), jump back
pop rbx               ; rbx = pointer to encoded data
mov rdx, rbx          ; save pointer
mov ecx, 0x1a         ; counter = 26
xor [rbx], 0xaa       ; decode byte (0xb)
inc rbx               ; next byte
dec rcx               ; decrement counter
jne 0xb               ; loop back to xor if counter != 0
; write(1, rdx, 26)
mov eax, 0x1
mov edi, 0x1
mov rsi, rdx
mov edx, 0x1a
syscall
; exit(0)
mov eax, 0x3c
xor rdi, rdi
syscall
'''
# Encoded data
'''
e4 f9 eb 8a e9 c5 ce cf c8 d8 cf cb c1 cf d8 8a e9 c2 cb c6 c6 cf c4 cd cf a0
N  S  A     C  o  d  e  b  r  e  a  k  e  r     C  h  a  l  l  e  n  g  e  \n
'''

# Run shellcode
m = mmap.mmap(-1, len(shellcode), prot=7)
m.write(shellcode); m.seek(0)
print("Shellcode output:")
ctypes.cast(ctypes.c_void_p(ctypes.addressof(ctypes.c_char.from_buffer(m))), ctypes.CFUNCTYPE(None))()
