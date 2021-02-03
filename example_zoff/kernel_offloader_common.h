#ifndef _KERNEL_OFFLOADER_COMMON_H
#define _KERNEL_OFFLOADER_COMMON_H

/* return values */
#define KERNEL_OFFLOADER_OK           0
#define KERNEL_OFFLOADER_UNAVAILABLE  1 /* function is implemented, but the chosen operation is not implemented */
#define KERNEL_OFFLOADER_ERROR        2 /* ran, but could not complete */
#define KERNEL_OFFLOADER_BAD_RESULT   3 /* ran, but failed a check on a result */
/* No "not implemented" return value because if a function returns that value, the function is implemented. Also, zoff.c should handle unimplemented functions. */

#endif
