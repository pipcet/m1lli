	ldp x0, x1, [sp]
	add sp, sp, 16
	stp x30, x0, [sp, #-16]!
	stp x28, x29, [sp, #-16]!
	stp x26, x27, [sp, #-16]!
	stp x24, x25, [sp, #-16]!
	stp x22, x23, [sp, #-16]!
	stp x20, x21, [sp, #-16]!
	stp x18, x19, [sp, #-16]!
	stp x16, x17, [sp, #-16]!
	stp x14, x15, [sp, #-16]!
	stp x12, x13, [sp, #-16]!
	stp x10, x11, [sp, #-16]!
	stp x8, x9, [sp, #-16]!
	stp x6, x7, [sp, #-16]!
	stp x4, x5, [sp, #-16]!
	stp x2, x3, [sp, #-16]!
	stp x0, x1, [sp, #-16]!
	mov x0, sp

	bl 2f
	cbz x0, 3f

	ldp x0, x1, [sp]
	add sp, sp, #16
        ldp x2, x3, [sp]
	add sp, sp, #16
        ldp x4, x5, [sp]
	add sp, sp, #16
        ldp x6, x7, [sp]
	add sp, sp, #16
        ldp x8, x9, [sp]
	add sp, sp, #16
        ldp x10, x11, [sp]
	add sp, sp, #16
        ldp x12, x13, [sp]
	add sp, sp, #16
        ldp x14, x15, [sp]
	add sp, sp, #16
        ldp x16, x17, [sp]
	add sp, sp, #16
        ldp x18, x19, [sp]
	add sp, sp, #16
        ldp x20, x21, [sp]
	add sp, sp, #16
        ldp x22, x23, [sp]
	add sp, sp, #16
        ldp x24, x25, [sp]
	add sp, sp, #16
        ldp x26, x27, [sp]
	add sp, sp, #16
        ldp x28, x29, [sp]
	add sp, sp, #16
        ldr x30, [sp]
	add sp, sp, #16

	ldp x29, x30, [sp]
	add sp, sp, #0x10
	eret
3:
	ldp x0, x1, [sp]
	add sp, sp, #16
        ldp x2, x3, [sp]
	add sp, sp, #16
        ldp x4, x5, [sp]
	add sp, sp, #16
        ldp x6, x7, [sp]
	add sp, sp, #16
        ldp x8, x9, [sp]
	add sp, sp, #16
        ldp x10, x11, [sp]
	add sp, sp, #16
        ldp x12, x13, [sp]
	add sp, sp, #16
        ldp x14, x15, [sp]
	add sp, sp, #16
        ldp x16, x17, [sp]
	add sp, sp, #16
        ldp x18, x19, [sp]
	add sp, sp, #16
        ldp x20, x21, [sp]
	add sp, sp, #16
        ldp x22, x23, [sp]
	add sp, sp, #16
        ldp x24, x25, [sp]
	add sp, sp, #16
        ldp x26, x27, [sp]
	add sp, sp, #16
        ldp x28, x29, [sp]
	add sp, sp, #16
        ldr x30, [sp]
	add sp, sp, #16

	ret

	.align 3
1:
	.quad 0xfffffff000000100
2:
