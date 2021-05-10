0:
	stp	x0,x1,[sp,-16]!
	mov	x0,#0x800000000
	str	x0,[x0]
	ldp	x0,x1,[sp]
	add	sp,sp,16
	b	0b - . + 0xc03110 - 0xc02080
	.align	4
addr:	.quad 0xb00000000
1:	
	// __DATA at 0xfffffe000b914000 / 0x4190000
	// __TEXT at 0xfffffe0070004000 / 0x8000
	// 
