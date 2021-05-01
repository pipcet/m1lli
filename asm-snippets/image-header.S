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
	cbnz x0, 2f
	adr x0, bootargs
	str x1, [x0]
2:
	adr x1, stack
	sub x1, x1, #16
	mov sp, x1
	bl 1f
	.p2align 12
	.rept 0x1000
	.byte 0
	.endr
stack:
	adr x10, bootargs
