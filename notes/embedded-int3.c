/* used to help test the int3 events
 *  Provides ability to test both 0xCC and 0xCD03
 *  variants of the INT3 breakpoint.
 *
 * Author: Steve Maresca <steve@zentific.com>
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int main()
{
    printf("pid %d\n", getpid());

    sleep(10);

#ifndef int3imm8
    /* default int3 with a 1 byte opcode */
    asm("int $3");
#else
    /* non-standard int3 with a 2-byte instruction of INTNN imm8 style
     *	As far as I know gcc won't emit that, so need to do this
     * 	manually
     */
    asm __volatile__ (".byte 0xcd; .byte 0x03;");
#endif
    printf("Hello World\n");
    return 0;
}
