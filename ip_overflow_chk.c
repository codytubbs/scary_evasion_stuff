/*
 * ip_overflow_chk.c
 * Random code that's been a part of my journey to evade IDS/IPS/WAF and other `smart' gear.
 *
 * Compare 32-bit unsigned long int, hex, and octal presented overflow
 * IPv4 addresses against a given quad-dotted octet IP address.
 * Base 10 (256^4 * n)
 *
 * This will also compare and (in)validate non-overflow, but strangely
 * formatted IPv4 addresses against a given quad-dotted octet IP.
 *
 * On vulnerable systems, you can bypass this tool and test by simply
 * using `ping' to see the (im)proper translation.
 * e.g. OS X Sierra 10.12.4, etc.
 *
 * Usage examples:
 * $ dig +short hax.gs
 * 74.52.118.29
 * $ ./ip_overflow_chk 74.52.118.29 22719788573
 * $ ./ip_overflow_chk 74.52.118.29 430741681693
 * $ ./ip_overflow_chk 74.52.118.29 011215073035
 * $ ./ip_overflow_chk 74.52.118.29 0171215073035
 * $ ./ip_overflow_chk 74.52.118.29 0221452163004000011215073035
 * $ ./ip_overflow_chk 74.52.118.29 0xdeadbeef4a34761d
 * $ ./ip_overflow_chk 74.52.118.29 0xdeadc0de4a34761d
 * $ ./ip_overflow_chk 74.52.118.29 0xbadcafe4a34761d
 * ... many others ...
 *
 * e.g. From Firefox, goto: http://0xbadcafe4a34761d
 *
 * -Cody Tubbs :: Started in 2015, updated and published on 2018-04-13
 * codytubbs@gmail.com aka lh@hax.gs
 *
 *
 * Based on buggy sourcecode: inet_addr.c from OpenBSD and OpenSSH
 * SSH_VERSION "OpenSSH_7.5" and SSH_PORTABLE "p1-snap20170527" to
 * be exact.  The bug was introduced well before this version/copy.
 * headers below this are for historical && copyright purposes.
*/

/* $OpenBSD: inet_addr.c,v 1.9 2005/08/06 20:30:03 espie Exp $	*/
/* OPENBSD ORIGINAL: lib/libc/net/inet_addr.c */
/*
 * Copyright (c) 1983, 1990, 1993
 *    The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * -
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * -
 * --Copyright--
 */

#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>

extern int printf (const char *, ...);
extern void exit(int) __attribute__((noreturn));
extern char *strerror(int);

int inet_aton(const char *, struct in_addr *);

int main(int argc, char **argv){
    if (argc < 3) {
        printf("Usage: %s <base IP> <test IP>\n", argv[0]);
        exit(1);
    }
    char *valid_ip = argv[1];
    char *test_ip = argv[2];
    char valid_addr[INET_ADDRSTRLEN];
    char test_addr[INET_ADDRSTRLEN];
    struct in_addr val;
    struct in_addr tst;

    if (inet_aton(valid_ip, &val)) {
        if (inet_ntop(AF_INET, &(val.s_addr), valid_addr, INET_ADDRSTRLEN) == NULL) { // Returns NULL / sets errno
            printf("error during base IP -> inet_ntop(): %s", strerror(errno));
            exit(1);
        } else {
            printf("BASE IP: inet_aton() -> inet_ntop(): %s\n", valid_addr);
            if (inet_aton(test_ip, &tst)) {
                if (inet_ntop(AF_INET, &(tst.s_addr), test_addr, INET_ADDRSTRLEN) == NULL) { // Returns NULL / sets errno
                    printf("error during test IP -> inet_ntop(): %s", strerror(errno));
                    exit(1);
                } else {
                    printf("TEST IP: inet_aton() -> inet_ntop(): %s\n", test_addr); // prints the dotted-quad/octet IP
                }
            }
        }
    }
    if(val.s_addr == tst.s_addr) {
        printf("\n%s == %s\n", valid_ip, test_ip);
    } else {
        printf("\n%s != %s\n", valid_ip, test_ip);
    }
}


/*
 * Ascii internet address interpretation routine.
 * The value returned is in network order.
 */
in_addr_t inet_addr(const char *cp){
    struct in_addr val;
    if (inet_aton(cp, &val))
        return (val.s_addr);
    return (INADDR_NONE);
}

/*
 * Check whether "cp" is a valid ascii representation
 * of an Internet address and convert to a binary address.
 * Returns 1 if the address is valid, 0 if not.
 * This replaces inet_addr, the return value from which
 * cannot distinguish between failure and a local broadcast address.
 */
int inet_aton(const char *cp, struct in_addr *addr){
    u_int32_t val;
    int base, n;
    char c;
    u_int parts[4];
    u_int *pp = parts;

    c = *cp;
    for (;;) {
        /*
         * Collect number up to ``.''.
         * Values are specified as for C:
         * 0x=hex, 0=octal, isdigit=decimal.
         */
        if (!isdigit(c))
            return (0);
        val = 0; base = 10;
        if (c == '0') {
            c = *++cp;
            if (c == 'x' || c == 'X')
                base = 16, c = *++cp;
            else
                base = 8;
        }
        for (;;) {
            if (isascii(c) && isdigit(c)) {
                val = (val * base) + (c - '0');
                c = *++cp;
            } else if (base == 16 && isascii(c) && isxdigit(c)) {
                val = (val << 4) |
                      (c + 10 - (islower(c) ? 'a' : 'A'));
                c = *++cp;
            } else
                break;
        }
        if (c == '.') {
            /*
             * Internet format:
             *	a.b.c.d
             *	a.b.c	(with c treated as 16 bits)
             *	a.b	(with b treated as 24 bits)
             */
            if (pp >= parts + 3)
                return (0);
            *pp++ = val;
            c = *++cp;
        } else
            break;
    }
    /*
     * Check for trailing characters.
     */
    if (c != '\0' && (!isascii(c) || !isspace(c)))
        return (0);
    /*
     * Concoct the address according to the number of parts specified.
     */
    n = pp - parts + 1;
    switch (n) {

        case 0:
            return (0);		/* initial nondigit */

        case 1:				/* a -- 32 bits */
            // CT: This doesn't check if 32bit, just assumes! should return if val > 0xffffffff
            // CT: uncomment next line to patch this bug... wait, it doesn't work, because it's at/below the struct level, HEH.
            //if((val >= 0xffffffff) || (parts[0] >= 0xffffffff)) { printf("no\n"); return (0);} // DOESN'T WORK...
            break;

        case 2:				/* a.b -- 8.24 bits */
            if ((val > 0xffffff) || (parts[0] > 0xff))
                return (0);
            val |= parts[0] << 24;
            break;

        case 3:				/* a.b.c -- 8.8.16 bits */
            if ((val > 0xffff) || (parts[0] > 0xff) || (parts[1] > 0xff))
                return (0);
            val |= (parts[0] << 24) | (parts[1] << 16);
            break;

        case 4:				/* a.b.c.d -- 8.8.8.8 bits */
            if ((val > 0xff) || (parts[0] > 0xff) || (parts[1] > 0xff) || (parts[2] > 0xff))
                return (0);
            val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
            break;
    }
    if (addr)
        addr->s_addr = htonl(val);
    return (1);
}