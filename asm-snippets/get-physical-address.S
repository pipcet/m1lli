	adr x3, 1f
	ldr x1, [x0, #8]
	ldr x2, [x0, #16]
	sub x3, x3, x1
	add x3, x3, x2
	br x3
1:	isb
