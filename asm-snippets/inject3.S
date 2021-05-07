	add x20, x20, x22
	mov x0, #0x10000
	movk x0, #0xa, lsl #32
	mov x22, sp
	str x22, [x0]
	mov sp, x0
	stp x29, x30, [sp, #-16]!
	mov x0, #0x20000
	movk x0, #0xa, lsl #32
	blr x0
	ldp x29, x30, [sp]
	add sp, sp, 16
	mov x0, #0x10000
	movk x0, #0xa, lsl #32
	ldr x22, [x0]
	mov sp, x22
	sub x0, x20, x23
	ret
	mrs x0, vbar_el1
	mov x22, #0x2080
	movk x22, #0xa, lsl #32
	str x0, [x22]
	mov x0, #0
	movk x0, #0xa, lsl #32
	msr vbar_el1, x0
	ret
