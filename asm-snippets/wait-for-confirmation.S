0:
	mov x24, sp
	and x25, x24, 0xffffffffffffc000
	ldr x24, 2f
	str x24, [x25]
1:
	ldr x24, [x25]
	cbnz x24, 1b
2:	sub sp, sp, #0xc0
	b 0xd59154 - 0xd57378 + 0b
