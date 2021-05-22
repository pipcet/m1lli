0:
	b 1f
3:
	b	0b - . + 0xc03110 - 0xc02080
1:
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
	nop
	nop
	stp	x29,x30,[sp,-16]
	stp	x0,x1,[sp,-32]
	add	sp,sp,-32
	nop
	ldr	x0,2f
5:	ldr	x1,3f
	cbz	x1,5b
	blr	x0
	ldp	x0,x1,[sp],#16
	ldp	x29,x30,[sp],#16
	b 3b
	.align 3
2:
	.quad	0xfffffff800000000
3:
	.quad	0x00
