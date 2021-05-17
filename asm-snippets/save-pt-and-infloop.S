	mov x1, #0xe80
	movk x1, #0x9000, lsl #16
	movk x1, #0xb, lsl #32
	str x0, [x1]
	b .
