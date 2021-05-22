0:
	b 1f
3:
	b	0b - . + 0xc03110 - 0xc02080
1:
	nop
	nop
	str	x0,[sp,8]
	mov	x0,sp
	str	x0,[sp,16]
	ldr	x0,4f
	stp	x29,x30,[x0,-16]!
	mov	sp,x0
	stp	x0,x1,[sp,-16]!
	ldr	x0,2f
	ldr	x1,3f
	blr	x0
	ldp	x29,x30,[sp]
	add	sp,sp,16-4096
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
	.align	3
2:	.quad	0xfffffff800000000
4:	.quad	0xfffffff000002000
3:	.quad	0x00
