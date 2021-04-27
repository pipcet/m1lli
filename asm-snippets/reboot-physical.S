/* From m1n1. */

#define WDT_BASE 0x23d2b0000
#define WDT_COUNT 0x10
#define WDT_ALARM 0x14
#define WDT_CTL 0x1c

.globl reboot
.type reboot, @function
reboot:
    ldr x1, =WDT_BASE
    mov w0, #0x100000
    str w0, [x1, #WDT_ALARM]
    mov w0, #0
    str w0, [x1, #WDT_COUNT]
    mov w0, #4
    str w0, [x1, #WDT_CTL]
    b .
