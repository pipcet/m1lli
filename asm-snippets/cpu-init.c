void cpuinit(void) __attribute__((section(".text")));

#define BIT(i) (1LL << (i))

#define SR_H13_MIGSTS		s3_4_c15_c0_4
#define SR_H13_HID0		s3_0_c15_c0_0
#define SR_H13_HID1		s3_0_c15_c1_0
#define SR_H13_HID3		s3_0_c15_c3_0
#define SR_H13_HID4		s3_0_c15_c4_0
#define SR_H13_EHID4		s3_0_c15_c4_1
#define SR_H13_HID5		s3_0_c15_c5_0
#define SR_H13_HID6		s3_0_c15_c6_0
#define SR_H13_HID7		s3_0_c15_c7_0
#define SR_H13_HID9		s3_0_c15_c9_0
#define SR_H13_EHID10		s3_0_c15_c10_1
#define SR_H13_HID11		s3_0_c15_c11_0
#define SR_H13_CYC_CFG		s3_5_c15_c4_0
#define SR_H13_CYC_OVRD		s3_5_c15_c5_0
#define SR_H13_LLC_ERR_STS	s3_3_c15_c8_0
#define SR_H13_LLC_ERR_ADR	s3_3_c15_c9_0
#define SR_H13_LLC_ERR_INF	s3_3_c15_c10_0
#define SR_H13_LSU_ERR_STS	s3_3_c15_c2_0
#define SR_H13_LSU_ERR_STS_P	s3_3_c15_c0_0
#define SR_H13_FED_ERR_STS	s3_4_c15_c0_2
#define SR_H13_FED_ERR_STS_P	s3_4_c15_c0_0
#define SR_H13_MMU_ERR_STS	s3_6_c15_c2_0
#define SR_H13_MMU_ERR_STS_P	s3_6_c15_c0_0
#define SR_H13_DPC_ERR_STS	s3_5_c15_c0_5
#define SR_H13_KTRR_LOCK	s3_4_c15_c2_2
#define SR_H13_KTRR_MODE	s3_4_c15_c2_5
#define SR_H13_KTRR_LOWER	s3_4_c15_c2_3
#define SR_H13_KTRR_UPPER	s3_4_c15_c2_4

#define STR(x) #x
#define msr(reg,val) asm volatile("msr " STR(reg) ", %0" : : "r" (val))
#define mrs(reg) ({ long x; asm volatile("mrs %0," STR(reg) : "=r" (x)); x; })
#define msrs(reg,clr,set) msr(reg,(mrs(reg)|(set)) &~ (clr))

#include "snippet.h"

START_SNIPPET {
  msr(oslar_el1, 0);
  msr(s3_6_c15_c1_0, 1);
  asm volatile("tlbi vmalle1");
  msr(s3_6_c15_c1_6, 0x2020a505f020f0f0);
  msr(s3_6_c15_c1_0, 0);
  asm volatile("tlbi vmalle1");

  if ((mrs(midr_el1) & 0xfff0) == 0x220) {
    while (!(mrs(s3_6_c15_c12_4) & 1));

    msrs(SR_H13_MIGSTS, 0x6, 0x11);
    if (!(mrs(SR_H13_MIGSTS) & 0x10))
      msrs(SR_H13_MIGSTS, 0, 2);

    msrs(SR_H13_EHID4,  0,     0x100000000800);
    msrs(SR_H13_HID5,   0, 0x2000000000000000);
    msrs(SR_H13_EHID10, 0,   0x20000100000000);
    msrs(s3_0_c15_c1_2, 0x100000000, 0);
    msrs(s3_0_c15_c9_1, 0, 0x8000);
    msrs(s3_0_c15_c1_2, 0, 0x10000);
    msrs(s3_0_c15_c1_2, 0, 0x600000);
    msr(s3_4_c15_c5_0, mrs(mpidr_el1) & 3);
    msrs(s3_4_c15_c1_4, ~0L, 0x100);
    msrs(SR_H13_CYC_OVRD, 0xf00000, 0);
    msrs(actlr_el1, 0, 0x200);
    msrs(SR_H13_CYC_CFG, 0, 0xc);
    msrs(SR_H13_LLC_ERR_STS, ~0L, 0);
  } else {
    msr(oslar_el1, 0);
    msr(s3_6_c15_c1_0, 1);
    asm volatile("tlbi vmalle1");
    msr(s3_6_c15_c1_6, 0x2020a505f020f0f0);
    msr(s3_6_c15_c1_0, 0);
    asm volatile("tlbi vmalle1");

    while (!(mrs(s3_6_c15_c12_4) & 1));

    msrs(s3_0_c15_c14_0, 0xf000000000000000, 0xc000000000000000);
    msrs(SR_H13_MIGSTS, 0x6, 0x11);
    if (!(mrs(SR_H13_MIGSTS) & 0x10))
      msrs(SR_H13_MIGSTS, 0, 2);

    msrs(SR_H13_HID4,   0,     0x100000000800);
    msrs(SR_H13_HID5,   0, 0x2000000000000000);
    msrs(s3_0_c15_c14_0, 0x3c000, 0x10000);
    msrs(SR_H13_HID0,   0,     0x200000000000);
    msrs(SR_H13_HID3,  0,  0x100000000000 | 0x8000000000000000);
    msrs(s3_0_c15_c15_2, 0, 0x6900000000000000);
    msrs(SR_H13_HID9, 0, 0x4000000);
    msrs(SR_H13_HID11, 0, 0x800000000000000);
    msrs(SR_H13_HID0, 0, 0x1010000000);
    msrs(SR_H13_HID6, 0x3e0, 0);
    msrs(SR_H13_HID7, 0, 0x3180000);
    msrs(SR_H13_HID9, 0, 0x10000020000000);
    msrs(s3_0_c15_c11_2, 0, 0x4000);
    msrs(s3_0_c15_c1_3, 0x80000, 0);
    msrs(SR_H13_HID4, 0, 0x22000000000000);
    msrs(SR_H13_HID9, 0, 0x80000000000000);
    msrs(SR_H13_HID11, 0, 0x8000);
    msrs(s3_0_c15_c1_3, 0, 0x2000000000000);

    msrs(SR_H13_CYC_OVRD, 0xf00000, 0);
    msrs(actlr_el1, 0, 0x200);
    msrs(SR_H13_CYC_CFG, 0, 0xc);
    msrs(SR_H13_LLC_ERR_STS, ~0LL, 0);
  }
} END_SNIPPET
