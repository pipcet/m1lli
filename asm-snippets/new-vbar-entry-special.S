0:
	b 1f
3:
	b	0b - . + 0xc03110 - 0xc02080
1:
	msr spsel,#0
	stp	x29,x30,[sp,-16]!
	stp	x0,x1,[sp,-16]!
	ldr	x0,2f
	ldr	x1,3f
	blr	x0
	ldp	x0,x1,[sp],#16
	ldp	x29,x30,[sp],#16
	msr spsel, #1
	b	3b
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	.align	3
2:	.quad	0xfffffff800000000
4:	.quad	0xfffffff000002000
3:	.quad	0x00
