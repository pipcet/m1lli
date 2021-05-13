0:
	b 1f
3:
	b	0b - . + 0xc03110 - 0xc02080
1:
	stp	x29,x30,[sp,-16]!
	stp	x0,x1,[sp,-16]!
	ldr	x0,2f
	ldr	x1,3f
	blr	x0
	ldp	x29,x30,[sp]
	add	sp,sp,16
	b	3b
	ret
	.align	3
2:
	.quad	0xfffffff800000000
3:
	.quad	0x00
