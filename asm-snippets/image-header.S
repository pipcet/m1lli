	nop
	b primary_entry
	.quad 0
	.quad 256 * 1024 * 1024	// image size, to be fixed by code
	.quad 0
	.quad 0
	.quad 0
	.quad 0
	.ascii "ARMd"
	.long 0
primary_entry:
	nop
	b 1f
	.globl argdummy
argdummy:
	.quad 0x806640000 // bootargs argument, to be fixed by code
	adr x1, argdummy
	str x0, [x1]
1:
	adr x1, stack
	sub x1, x1, #16
	mov x0, x1
	mov sp, x0
	bl 1f
stack:
	.p2align 12
	.rept 0xe38
	.byte 0
	.endr
fdt:
	.rept 0x1c4
	.ascii "x"
	.endr
	adr x0, fdt

1:
	mov x1, #0xbd
	lsl x1, x1, #12
	add x1, x1, #0xf44
	lsl x1, x1, #16
	add x1, x1, #0x8000
	mov w0, #0xff00
0:
	str w0, [x1, #0x00]
	str w0, [x1, #0x04]
	str w0, [x1, #0x08]
	str w0, [x1, #0x0c]
	add x1, x1, #16
	mov x1, #0xbe
	lsl x1, x1, #12
	add x1, x1, #0x03d
	lsl x1, x1, #16
	add x1, x1, #0x8000
	mov sp, x1
	ldr x1, [argdummy]
	bl boot_macho_init
	nop

	.p2align 7
smpentry:
	adr x1, rvbar
	add x1, x1, :lo12:rvbar
	ldr x1, [x1]
	br x1
	.p2align 7
rvbar:
	.quad 0
end_smpentry:
	.p2align 7
upentry:

	adrp x1, upentry
	add x1, x1, :lo12:upentry
	add x2, x1, #-2048
	mov x4, #256
0:
	ldr x3, [x2]
	str x3, [x1]
	add x1, x1, 8
	add x2, x2, 8
	add x4, x4, -1
	cbnz x4, 0b
	f
	adr x1, smpentry
	add x1, x1, #0x2000
	add x1, x1, -0x104
	br x1
end_upentry:
	.rept 8192
	.quad 0
	.endr
counter_start:
	nop
	adr x0, counter
	ldr x1, [x0]
	add x1, x1, 1
	str x1, [x0]
	b counter_start
counter:
	.quad 0

	mov x0, #0
	orr x0, x0, 1
	lsl x0, x0, 1
	br x0
