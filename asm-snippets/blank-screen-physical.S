/* from preloader-m1. */

fill_rect:
    //ldr x8, [x24, #0x28]
    //ldr x9, [x24, #0x38]
    mov x8, #0xbe
    lsl x8, x8, #12
    add x8, x8, #0x3d
    lsl x8, x8, #16
    add x8, x8, #8, lsl #12
    mov x9, #0xfa
    lsl x9, x9, #12
    mov w12, w4
    mul x10, x1, x9
    add x8, x8, x0, lsl #2
    add x8, x8, x10
    mov x10, x3
1:  mov x11, x2
2:  str w12, [x8], #4
    sub x11, x11, #1
    cbnz x11, 2b
    add x8, x8, x9
    sub x8, x8, x2, lsl #2
    sub x10, x10, #1
    cbnz x10, 1b
    ret
