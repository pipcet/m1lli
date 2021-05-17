0:
	mov x1, #0x3e08
	movk x1, #0x9000, lsl #16
	movk x1, #0xb, lsl #32
	str x0, [x1]
	dmb sy
	dsb sy
	isb
	ic iallu
	b 0b
