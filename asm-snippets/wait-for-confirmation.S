0:
#if 1
	mov x24, sp
	and x25, x24, 0xffffffffffffc000
	ldr x23, 2f
	nop
	stp x23, x24, [x25]
1:
	ldr x24, [x25]
2:
	cbnz x24, 1b
#else
	mov x29, #0xb00000000
	movk x29, #0x9000, lsl #16
	movk x29, #0x8000, lsl #0
	msr ttbr0_el1, x29
	nop//movk x0, #0xc000, lsl #0
	nop//msr ttbr1_el1, x0
	nop
#endif
	b 0xd5966c - 0xd57378 + 0b
