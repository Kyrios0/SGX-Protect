#define SMS4DBG

#include <string.h>

/* reserved for saving interface */
/*#include "sms4.h"*/

#ifndef unlong
typedef unsigned long unlong;
#endif /* unlong */

#ifndef unchar
typedef unsigned char unchar;
#endif /* unchar */

unlong *SMS4SetKey(unlong *ulkey, unlong flag);
unlong *SMS4Encrypt(unlong *psrc, unlong lgsrc, unlong rk[]);
unlong *SMS4Decrypt(unlong *psrc, unlong lgsrc, unlong derk[]);
void SMS4Encrypt1M();