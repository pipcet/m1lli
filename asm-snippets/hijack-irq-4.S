0:
	stp	x0,x1,[sp,-16]!
	mov	x0,#0x800000000
	orr	x0,x0,#0xfffffff000000000
	mrs	x1,vbar_el1
	str	x1,[x0]
	ldp	x0,x1,[sp]
	add	sp,sp,16
	b	0b - . + 0xc03110 - 0xc02080
	mrs	x1,tcr_el1
	.align	4
addr:	.quad 0xb00000000
1:	
	// __DATA at 0xfffffe000b914000 / 0x4190000
	// __TEXT at 0xfffffe0070004000 / 0x8000
	// 
