	msr	spsel, #1
	nop
	nop
	nop
2:	nop
	mov	x0,sp
	and	x0,x0,#0xffffffffffffc000
	mrs	x1,ttbr1_el2
	str	x1,[x0,#8]
	mrs	x1,ttbr0_el2
	str	x1,[x0,#16]
	ldr	x1,1f
	str	x1,[x0]
	nop
2:	b	2b
	.align	3
1:	.quad 0xd547fdfeceade631
