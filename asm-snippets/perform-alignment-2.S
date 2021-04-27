	.arch armv8.4-a+crc
	.file	"perform-alignment-2.c"
	.text
	.section	.text,"ax",@progbits
	.align	2
	.global	perform_alignment
	.type	perform_alignment, %function
perform_alignment:
.LFB0:
	.cfi_startproc
#APP
// 6 "m1lli/asm-snippets/perform-alignment-2.c" 1
	adr x2, perform_alignment
// 0 "" 2
#NO_APP
	and	x0, x2, -16384
	mov	x1, 2097151
	add	x3, x0, x1
	and	x3, x3, -2097152
	cmp	x0, x3
	beq	.L1
	ldr	x1, [x0, 16]
	sub	x4, x0, #1
	add	x1, x0, x1
.L3:
	sub	x1, x1, #1
	cmp	x4, x1
	bne	.L4
	sub	x2, x2, x0
	add	x2, x2, x3
#APP
// 14 "m1lli/asm-snippets/perform-alignment-2.c" 1
	br x2
// 0 "" 2
#NO_APP
.L4:
	sub	x5, x1, x0
	ldrb	w6, [x1]
	strb	w6, [x5, x3]
	b	.L3
.L1:
	.cfi_endproc
.LFE0:
	.size	perform_alignment, .-perform_alignment
	.ident	"GCC: (Debian 10.2.1-6) 10.2.1 20210110"
	.section	.note.GNU-stack,"",@progbits
