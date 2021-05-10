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

	mov x3, x1
	cmp x3, #0x80
	beq 4f
	msr daifset, #0xf
	and x0, x3, #0xf8000000
	lsr x0, x0, #24
	cmp x0, #0x90
	bne 4f
	mrs x3, elr_el2
	mrs x0, esr_el2
	mrs x2, esr_el1
	ldr x1, 1f
	stp x0,x1,[x1]
	stp x2,x3,[x1,16]
	ldr x0,[x1,40]
	add x0, x0, 1
	str x0,[x1,40]
	mrs x2, far_el2
	mrs x3, elr_el2
	stp x2,x3,[x1,48]
4:

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
        ldr x18, [sp]
	add sp, sp, #16

	ret

	.align 3
1:
	.quad 0xfffffff000000100
