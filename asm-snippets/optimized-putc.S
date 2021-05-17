2:	stp	x14,x15,[sp,#-16]!
	mov	x15,#0
0:	lsr	w14,w12,w15
	sbfx	w14,w14,#0,#1
	strb	w14,[x11,x15]
	add	x15,x15,#1
	cmp	x15,#8
	b.ne	0b
#if 0
	nop
	nop
	nop
#else
	mov	x14,#0x10000
1:	add	x14,x14,#-1
	cbnz	x14,1b
#endif
	ldp	x14,x15,[sp],#16
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
	nop
	.if (. - 2b) != (28 * 4)
	.error "foo"
	.endif
