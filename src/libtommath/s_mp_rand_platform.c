
#include <errno.h>
#include "tommath_private.h"

static unsigned long long riscv_clock(void)
{
    unsigned long long n;
    asm volatile(
        "rdtime %0"
        : "=r"(n));
   return (n/10);
}

#define SEL4CLOCK riscv_clock

static int mp_rng_ansic(unsigned char *buf, unsigned long len)
{
   volatile unsigned long long t1;
   int l, acc, bits, a, b;
   l = len;
   bits = 8;
   acc  = a = b = 0;
   while (len--) {
       while (bits--) {
          do {
               t1 = SEL4CLOCK();
             do {
                 a ^= 1;
             } while (t1 == SEL4CLOCK());
             t1 = SEL4CLOCK();
             do {
                 b ^= 1;
             } while (t1 == SEL4CLOCK());
          } while (a == b);
          acc = (acc << 1) | a;
       }
       *buf++ = acc;
       acc  = 0;
       bits = 8;
   }
   return 0;
}

mp_err s_mp_rand_platform(void *p, size_t n)
{
   return mp_rng_ansic(p, n);
}