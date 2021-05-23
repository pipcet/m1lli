0:
	b 1f
3:
	b	0b - . + 0xc03110 - 0xc02080
1:
	msr spsel,#1
	str	x0,[sp,/*864*/8]
	str	x1,[sp,/*872*/16]
	ldr	x1,4f
	mov	x0,sp
	stp	x0,x1,[x1,-16]
	stp	x29,x30,[x1,-32]!
	mov	sp,x1
	ldr	x0,2f
	ldr	x1,3f
	blr	x0
	add	sp,sp,16
	ldp	x29,x30,[sp],#16
	ldp	x0,x1,[sp],#16
	mov	sp,x0
	ldr x0, [sp, 8]
	ldr x1, [sp, 16]
	b	.
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
