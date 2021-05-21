0:
	b 1f
3:
	b	0b - . + 0xc03110 - 0xc02080
1:
	str	x0,[sp,8]
	mov	x0,sp
	str	x0,[sp,16]
	ldr	x0,4f
	add	sp,x0,#0x2000
	stp	x29,x30,[sp,-16]!
	b .
	ldr	x0,2f
	blr	x0
	ldp	x29,x30,[sp]
	add	sp,sp,16-4096
	b	3b
	.align	3
2:
	.quad	0xfffffff800000000
3:
	.quad	0x00
4:	.quad	0xfffffff000002000
