0:
	bti	jc
	b	0b
	mov	x1,lr
	stp	x1,x2, [sp,#-16]!
	bl	1f
	ldp	x1,x2, [sp], #16
#if 0
	ldp	x29, x30, [sp, #352]
	ldp	x20, x19, [sp, #336]
	ldp	x22, x21, [sp, #320]
	ldp	x24, x23, [sp, #304]
	ldp	x26, x25, [sp, #288]
	ldp	x28, x27, [sp, #272]
	add	sp, sp, #0x170
	retab
#else
	ldp	x29, x30, [sp, #160]
	ldp	x20, x19, [sp, #144]
	ldp	x22, x21, [sp, #128]
	ldp	x24, x23, [sp, #112]
	ldp	x26, x25, [sp, #96]
	ldp	x28, x27, [sp, #80]
	b	.
	ret	x1
	add	sp, sp, #0xb0
	retab
#endif
	.p2align 4
1:
