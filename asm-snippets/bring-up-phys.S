	mov	x0, 8
	mov	w1, 15
	movk	x0, 0x2a9, lsl 16
	movk	w1, 0x1c1, lsl 16
	movk	x0, 0x5, lsl 32
	mov	x2, -49148
	str	w1, [x0]
	mov	w1, 3
	str	w1, [x0, -4]
	mov	w1, 2067
	str	wzr, [x0, -4]
	movk	w1, 0x8c, lsl 16
	str	w1, [x0, 20]
	mov	w1, 2
	str	w1, [x0, -8]
	add	x0, x0, x2
	str	w1, [x0]
	mov	w1, 34
	str	w1, [x0]
	mov	w1, 33
	str	w1, [x0, 16]
	mov	w1, 37682
	str	w1, [x0, 20]
	mov	x0, 49152
	movk	x0, 0x228, lsl 16
	movk	x0, 0x5, lsl 32
	ldr	w1, [x0, 1796]
	orr	w1, w1, 1073741824
	str	w1, [x0, 1796]
	ldr	w1, [x0, 272]
	orr	w1, w1, 2048
	str	w1, [x0, 272]
	ldr	w1, [x0, 704]
	orr	w1, w1, -2147483648
	str	w1, [x0, 704]
	ldr	w1, [x0, 512]
	orr	w1, w1, -2147483648
	str	w1, [x0, 512]
	ldr	w1, [x0, 704]
	and	w1, w1, 2147483647
	str	w1, [x0, 704]
	ldr	w1, [x0, 512]
	and	w1, w1, 2147483647
	str	w1, [x0, 512]
	ldr	w1, [x0, 272]
	and	w1, w1, -2049
	str	w1, [x0, 272]
	ldr	w1, [x0, 272]
	and	w1, w1, -57
	str	w1, [x0, 272]
