	msr ttbr1_el1, x0
	mrs x0, elr_el2
	add x0, x0, 4
	msr elr_el2, x0
	eret
