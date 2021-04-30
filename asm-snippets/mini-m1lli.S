	mov x1, x0		// copy arg
	mov x2, #0		// zero for Linux
	mov x3, #0		// zero for Linux
	adr x8, image		// x8 holds unaligned image address
	and x4, x8, 0x1ffff0	// x4 holds alignment offset
	cbz x4, image
	mov x5, 0x200000
	sub x4, x5, x4		// x4 holds delta
	add x11, x8, x4		// x11 holds aligned image address
	ldr x12, [x8, 16]	// x12 holds image size
	add x13, x11, x12	// x13 holds aligned end of image
	add x14, x8, x12	// x14 holds unaligned end of image
.L3:
	ldp x6, x7, [x14, -16]!
	stp x6, x7, [x13, -16]!
	sub x0, x14, x8		// x0 holds zero if we copied the entire image
	cbnz x0, .L3		// if x0 nonzero, repeat
	isb
	br x11			// jump to aligned image, passing x0 = 0
image:
