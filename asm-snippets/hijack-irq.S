0:
	stp	x0,x1,[sp,-16]!
	//adrp	x0, . - 0xc02084 + 0x4914000
	add	x0, sp, -1024
	and	x0, x0, #0xffffffffffffc000
	ldr	x1, addr
	str	x1, [x0]
	//add	x0,x0,#-8
	//	mrs	x1,vbar_el1
	mrs	x1,ttbr1_el3
	ldp	x0,x1,[sp]
	add	sp,sp,16
	b	0b - . + 0xc03110 - 0xc02080
	.align	4
addr:	.quad 0xb00000000
1:	
	// __DATA at 0xfffffe000b914000 / 0x4190000
	// __TEXT at 0xfffffe0070004000 / 0x8000
	// 
