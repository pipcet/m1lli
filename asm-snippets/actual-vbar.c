#include "snippet.h"

START_SNIPPET {
  asm volatile(".p2align 12");
  {
  register long address asm("r30");
  address = 0xa00002080;
  address = *(volatile long *)address;
  asm volatile("br %0" : "=r" (address) : "r" (address));
  }
  asm volatile(".p2align 9");
  {
  register long address asm("r30");
  address = 0xa00002080;
  address = *(volatile long *)address + 0x200;
  asm volatile("br %0" : "=r" (address) : "r" (address));
  asm volatile(".p2align 7");
  }
  register long address asm("r30");
  address = *(volatile long *)0xa00002080 + 0x280;
  asm volatile("br %0" : "=r" (address) : "r" (address));
  asm volatile(".p2align 7");
  address = *(volatile long *)0xa00002080 + 0x300;
  asm volatile("br %0" : "=r" (address) : "r" (address));
  asm volatile(".p2align 7");
  address = *(volatile long *)0xa00002080 + 0x380;
  asm volatile("br %0" : "=r" (address) : "r" (address));
  asm volatile(".p2align 7");
  address = *(volatile long *)0xa00002080 + 0x380;
  asm volatile("br %0" : "=r" (address) : "r" (address));
  asm volatile(".p2align 7");
  address = *(volatile long *)0xa00002080 + 0x400;
  asm volatile("br %0" : "=r" (address) : "r" (address));
} END_SNIPPET
