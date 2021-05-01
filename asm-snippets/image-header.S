	nop
	b primary_entry
	.quad 0
	.quad 256 * 1024 * 1024	// image size, to be fixed by code
	.quad 0
	.quad 0
	.quad 0
	.quad 0
	.ascii "ARMd"
	.long 0xe
primary_entry:
	isb
	b 1f
bootargs:
	.quad 0xd1e7d1e7d1e7d1e7 // bootargs argument, to be fixed by code
1:
	adr x1, stack
	sub x1, x1, #16
	mov x0, x1
	mov sp, x0
	bl 1f
	.p2align 12
	.rept 0x1000
	.byte 0
	.endr
stack:

1:
	mov x1, #0xbd
	lsl x1, x1, #12
	add x1, x1, #0xf44
	lsl x1, x1, #16
	add x1, x1, #0x8000
	mov w0, #0xff00
0:
	str w0, [x1, #0x00]
	str w0, [x1, #0x04]
	str w0, [x1, #0x08]
	str w0, [x1, #0x0c]
	add x1, x1, #16
	mov x1, #0xbe
	lsl x1, x1, #12
	add x1, x1, #0x03d
	lsl x1, x1, #16
	add x1, x1, #0x8000
	mov sp, x1
	adr x25, argdummy
	ldr x26, [x25]
