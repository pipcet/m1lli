0:
	.rept 29
	nop
	.endr
	ldp x0, x30, [sp]
	add sp, sp, 16
	b 0b
