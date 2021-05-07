	.p2align 12
0:
	.rept 32
1:
/* From m1n1. */

#define WDT_BASE 0x23d2b0000
#define WDT_COUNT 0x10
#define WDT_ALARM 0x14
#define WDT_CTL 0x1c

    ldr x1, =WDT_BASE
    mov w0, #0x100000
    str w0, [x1, #WDT_ALARM]
    mov w0, #0
    str w0, [x1, #WDT_COUNT]
    mov w0, #4
    str w0, [x1, #WDT_CTL]
    b .
	stp x0, x30, [sp, #-16]
	mov x30, #0x4000
	movk x30, #0xa, lsl #32
	ldr x30, [x30]
	add x30, x30, 1b - 0b
	add x30, x30, 29 * 4
	bl 0 + 0x8000
	br x30
	.p2align 7
	.endr
	.p2align 12
