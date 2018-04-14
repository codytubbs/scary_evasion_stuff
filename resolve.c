
/*
   Demonstration of several functions that accept wild IPs and convert back to dotted-quad/octet.
   ... Random code that's been a part of my journey to evade IDS/IPS/WAF and other `smart' gear.

   Usage examples:
   $ dig +short hax.gs
   74.52.118.29
   $ ./resolve 0112.064.0166.035
   $ ./resolve 1244952093
   $ ./resolve 22719788573
   $ ./resolve 430741681693
   $ ./resolve 011215073035
   $ ./resolve 0171215073035
   $ ./resolve 0221452163004000011215073035
   $ ./resolve 0x4a.0x34.0x76.0x1d
   $ ./resolve 0xdeadbeef4a34761d
   $ ./resolve 0xdeadc0de4a34761d
   $ ./resolve 0xbadcafe4a34761d
   ... many others ...

   e.g. From Firefox, goto: http://0xbadcafe4a34761d

   Functions currently tested and used:
1) inet_addr():	Accepts and passes the wild IP // IPv4 only (semi-officially obsolete?)
2) inet_aton():	Accepts and passes the wild IP // IPv4 only (semi-officially obsolete?)
3) inet_ntoa():	Transforms the wild IP back to dotted-quad/octet and return it // IPv4 only (semi-officially obsolete?)

   Tested/verified on both IPv4 and IPv6
1) inet_pton(): (Only accepts quad-dotted/decimal, unlike inet_addr and inet_aton)
                (Verified this is accurate on OS X.12.4, but still acts as the others on Ubuntu 14.04.5!!)
                http://man7.org/linux/man-pages/man3/inet_pton.3.html
                ( TODO: ^ Test on other UNIX flavors )
                Takes and possibly transforms IP (Presentation TO Network) returns -1 on error, 0 if bad address
2) inet_ntop(): Accepts IP (Network TO Presentation/Printable)


 -Cody Tubbs :: Started in 2015, updated and published on 2018-04-13
 codytubbs@gmail.com aka lh@hax.gs

*/

#include <arpa/inet.h>
#include <stdio.h>  // printf, nested include for NULL macro
#include <stdlib.h> // exit
#include <string.h> // strlen, strerror
#include <errno.h>  // errno macro

/****************** external variable declarations ********************/
//int printf (const char *, ...) __attribute__((format(printf, 1, 2)));
//int printf (const char *, ...);
//extern void exit(int) __attribute__((noreturn));
//unsigned long strlen(const char *);
//char *strerror(int);

/************ local prototypes *************/
void restricted();
void err_print(char *, const char *);
void err_exit(char *, const char *);
void msg_exit(char *);
void msg_print(char *);

//#define PF_INET            2       // IP Protocol family version 4
//#define AF_INET           PF_INET  // IPv4: internetwork: TCP, UDP, etc.
//#define PF_INET6          10     // IP protocol family version 6 // on my colo
//#define PF_INET6          30     // IP protocol family version 6 // on my osx laptop
//#define AF_INET6          PF_INET6 // IPv6: internetwork: ... this isn't static, caused major issues.
//#define INET_ADDRSTRLEN   16       // macro for largest IPv4 address
//#define INET6_ADDRSTRLEN  46       // macro for largest IPv6 address
//#define NULL      ((void *)0)

//typedef unsigned int   uint32_t;  // unsigned 32-bit integer: 256^4  (0 - 4294967295)
//typedef unsigned short uint16_t;  // unsigned 16-bit integer: 256^3  (0 - 65535)
//typedef unsigned char	 uint8_t;   // unsigned  8-bit integer: 256^2  (0 - 255)

//typedef uint32_t	socklen_t;  // 32-bit IP length??
//typedef uint32_t	in_addr_t;  // 32-bit IP
//typedef uint16_t	in_port_t;  // 16-bit PORT
//typedef unsigned short int sa_family_t; // uint8_t

// IPv4 & IPv6 structure that holds socket address information for many types of sockets
/*struct sockaddr {
    sa_family_t sa_family;   // address family:	AF_INET, AF_INET6, etc.
    char        sa_data[14]; // 14 bytes of protocol address
};*/

// IPv4-only internet address structure.
/*struct in_addr {
        in_addr_t s_addr;
};*/
// IPv4-only socket address structure
/*struct sockaddr_in {
    sa_family_t     sin_family;  // socket address family:	AF_INET
//    short           sin_family;  // socket address family:	AF_INET ///// TEMP
    in_port_t       sin_port;    // port number:		network byte order (Big Endian)
	struct in_addr	sin_addr;    // internet address:	network byte order (Big Endian
    unsigned char   sin_zero[8]; // same size as struct sockaddr
};*/

/*** external network function declarations ***/
//int         inet_pton(int, const char *, void *);
//extern int  inet_aton(const char *, struct in_addr *);
//extern char *inet_ntoa(struct in_addr);
//in_addr_t   inet_addr(const char *);
//const char  *inet_ntop(int, const void *, char *, socklen_t); // socklen_t is one reason why the length isn't capped?

// IPv6 internet address structure
/*struct in6_addr {
    //unsigned char s6_addr[16]; // IPv6 address
    uint8_t s6_addr[16];
};*/
/*
struct in6_addr {
    union {
        uint8_t s6_addr8[16];
        uint16_t s6_addr16[8];
        uint32_t s6_addr32[4];
    } s6_addr;
}; */
/* struct in6_addr {
    union {
        uint8_t __u6_addr8[16];
#if defined __USE_MISC || defined __USE_GNU
        uint16_t __u6_addr16[8];
        uint32_t __u6_addr32[4];
#endif
    } __in6_u;
}; */

// IPv6 socket address structure
/*struct sockaddr_in6 {
    uint16_t        sin6_family;   // socket address family, AF_INET6
    in_port_t       sin6_port;     // port number:		network byte order (Big Endian)
	//uint16_t        sin6_port;   // port number:		network byte order (Big Endian)
	uint32_t        sin6_flowinfo; // IPv6 flow information
	struct in6_addr sin6_addr;     // IPv6 address
	uint32_t        sin6_scope_id; // Scope ID ? more info ?
};*/

/*****************************************************************************/
/******************************   M  A  I  N   *******************************/
/*****************************************************************************/

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <IP>\n", argv[0]);
        exit(1);
    }

    char *wild_ip = argv[1];
    char *wild6_ip = argv[1];
    char ip_buf[INET_ADDRSTRLEN];
    char ip6_buf[INET6_ADDRSTRLEN];
    char *ip_addr;
    int retval;

    struct sockaddr_in sock;   // sock.sin_addr.s_addr (required over in_addr due to net_ntoa() retval, argh)
    //struct in_addr sock;     // sock.s_addr
    struct sockaddr_in6 sock6; // sock6.sin6_addr.?(anon union)
    //struct in6_addr sock6;   // sock6.s_addr

    // TODO: Ensure to clear re-used data-types after (or before) each use: ip_addr, ip_buf, sock, etc.
    // TODO: Add exception handling on everything possible: return values, errno display, etc.

    /************   IPv4: TEST #1  inet_pton() -> inet_ntop()   ************/
    printf("TEST #1: [inet_pton() -> inet_ntop()] ");
    retval = inet_pton(AF_INET, wild_ip, &(sock.sin_addr)); // IPv4  errno,
    //printf("DEBUG: %d\n", retval1);
    switch(retval) { // 1=valid, 0=not parseable in addr fam, -1=error/sets error
        case 0:
            msg_print("IPv4: inet_pton(): IP not parseable within the defined address family (AF_INET)");
            break;
        case -1:
            err_print("inet_pton()", strerror(errno));
            break;
        case 1:
            if (inet_ntop(AF_INET, &(sock.sin_addr), ip_buf, INET_ADDRSTRLEN) == NULL) { // Returns NULL / sets errno
                    err_print("inet_ntop()", strerror(errno));
            } else {
                printf("IPv4: %s\n", ip_buf);
            }
        default: // acts as 'ensure' unless case breaks
            break;
    }
    sock = (const struct sockaddr_in) {0}; // zero struct before re-use
    sock.sin_addr.s_addr = htonl(0x00000000); // another way to zero before re-use
    memset(ip_buf,0,strlen(ip_buf)); // clear before re-use, zeroes up to first null

    /************   IPv4: TEST #2  inet_pton() -> inet_ntoa()   ************/
    printf("TEST #2: [inet_pton() -> inet_ntoa()] ");
    retval = inet_pton(AF_INET, wild_ip, &(sock.sin_addr)); // IPv4  errno,
    //printf("DEBUG: %d\n", retval1);
    switch(retval) { // 1=valid, 0=not parseable in addr fam, -1=error/sets error
        case 0:
            msg_print("IPv4: inet_pton(): IP not parseable within the defined address family (AF_INET)");
            break;
        case -1:
            err_print("inet_pton()", strerror(errno));
            break;
        case 1:
            ip_addr = inet_ntoa(sock.sin_addr); // return the sane IP after wild transformation
            printf("IPv4: %s\n", ip_addr);

        default: // acts as 'ensure' unless case breaks
            break;
    }
    sock = (const struct sockaddr_in) {0}; // zero struct before re-use
    memset(ip_buf,0,strlen(ip_buf)); // clear before re-use, zeroes up to first null

    /* IPv4: TEST #2.5  test inet_lnaof() */
    //sock.sin_addr.s_addr = inet_lnaof(sock.sin_addr);
    //printf("inet_lnaof() test: %d\n", sock.sin_addr.s_addr);

    /************   IPv4: TEST #3  inet_addr() -> inet_ntop()   ************/
    printf("TEST #3: [inet_addr() -> inet_ntop()] ");
    sock.sin_addr.s_addr = inet_addr(wild_ip);  // INET_ADDR(), accept wild IP
    if (inet_ntop(AF_INET, &(sock.sin_addr), ip_buf, INET_ADDRSTRLEN) == NULL) { // Returns NULL / sets errno
        err_print("inet_ntop()", strerror(errno));
    } else {
        printf("IPv4: %s\n", ip_buf);
    }
    sock = (const struct sockaddr_in){ 0 };    // Null struct before re-use
    memset(ip_buf,0,strlen(ip_buf)); // clear before re-use, zeroes up to first null

    /************   IPv4: TEST #4  inet_addr() -> inet_ntoa()   ************/
    printf("TEST #4: [inet_addr() -> inet_ntoa()] ");
    sock.sin_addr.s_addr = inet_addr(wild_ip);  // INET_ADDR(), accept wild IP
    ip_addr = inet_ntoa(sock.sin_addr);        // return the sane IP after wild transformation
    printf("IPv4: %s\n", ip_addr);   // prints the dotted-quad/octet IP
    sock = (const struct sockaddr_in){ 0 };    // Null struct before re-use
    memset(ip_addr,0,strlen(ip_addr)); // clear before re-use, zeroes up to first null

    /************   IPv4: TEST #5  inet_network() -> inet_ntop()   ************/
    // inet_network() prints in host byte order, unlike the others that use network byte order
    // TODO: Also print that the IP will be 255.255.255.255 if input is invalid.
    // TODO: '' because inet_network passes -1 as the address which translates to 255.~
    printf("TEST #5: [inet_network() -> inet_ntop()] ");
    sock.sin_addr.s_addr = inet_network(wild_ip);  // inet_network(), accept wild IP??
    if (sock.sin_addr.s_addr == -1){
        msg_print("IPv4: inet_network(): input was invalid");
    } else {
        if (inet_ntop(AF_INET, &(sock.sin_addr), ip_buf, INET_ADDRSTRLEN) == NULL) { // Returns NULL / sets errno
            err_print("inet_ntop()", strerror(errno));
        } else {
            printf("IPv4: (host byte order (reversed)): %s\n", ip_buf);
            memset(ip_buf,0,strlen(ip_buf)); // clear before re-use, zeroes up to first null
        }
    }
    sock = (const struct sockaddr_in){ 0 };    // Null struct before re-use

    /************   IPv4: TEST #6  inet_network() -> inet_ntoa()   ************/
    // inet_network() prints in host byte order, unlike the others that use network byte order
    // TODO: Also print that the IP will be 255.255.255.255 if input is invalid.
    // TODO: '' because inet_network passes -1 as the address which translates to 255.~
    printf("TEST #6: [inet_network() -> inet_ntoa()] ");
    sock.sin_addr.s_addr = inet_network(wild_ip);  // inet_network(), accept wild IP??
    if (sock.sin_addr.s_addr == -1){
        msg_print("IPv4: inet_network(): input was invalid");
    } else {
        ip_addr = inet_ntoa(sock.sin_addr);        // return the sane IP after wild transformation
        printf("IPv4: (host byte order (reversed)): %s\n", ip_addr);   // prints the dotted-quad/octet IP
        printf("TEST #6a IPv4: inet_network() -> printf, and htonl(): ");
        printf("HBO: 0x%08lx, NBO:0x%08lx, ", // %08hu (hu = unsigned short)
               (unsigned long)sock.sin_addr.s_addr,
               (unsigned long)htonl(sock.sin_addr.s_addr));
        printf("INT: %d\n", (int)sock.sin_addr.s_addr);
        memset(ip_addr,0,strlen(ip_addr)); // clear before re-use, zeroes up to first null
    }
    sock = (const struct sockaddr_in){ 0 };    // Null struct before re-use

    /************   IPv4: TEST #7  inet_aton() -> inet_ntop()   ************/
    printf("TEST #7: [inet_aton() -> inet_ntop()] ");
    retval = inet_aton(wild_ip, &sock.sin_addr);        // INET_ATON(), accept wild IP
    if(retval == 0){
        msg_print("IPv4: inet_aton(): input was invalid");
    }
    if (inet_ntop(AF_INET, &(sock.sin_addr), ip_buf, INET_ADDRSTRLEN) == NULL) { // Returns NULL / sets errno
        err_print("inet_ntop()", strerror(errno));
    } else {
        printf("IPv4: %s\n", ip_buf);
    }
    sock = (const struct sockaddr_in){ 0 };    // Null struct before re-use
    memset(ip_buf,0,strlen(ip_buf)); // clear before re-use, zeroes up to first null

    /************   IPv4: TEST #8  inet_aton() -> inet_ntoa()   ************/
    printf("TEST #8: [inet_aton() -> inet_ntoa()] ");
    retval = inet_aton(wild_ip, &sock.sin_addr);        // INET_ATON(), accept wild IP
    if(retval == 0){
        msg_print("IPv4: inet_aton(): input was invalid");
    }
    ip_addr = inet_ntoa(sock.sin_addr);        // return the sane IP after wild transformation
    printf("IPv4: %s\n", ip_addr);   // prints the dotted-quad/octet IP
    sock = (const struct sockaddr_in){ 0 };    // Null struct before re-use
    memset(ip_addr,0,strlen(ip_addr)); // clear before re-use, zeroes up to first null

    /**** inet_lnaof() prints the network number part of the IP as unsigned long int ****/
    unsigned long int host_id;
    inet_aton(wild_ip, &sock.sin_addr);
    host_id = inet_lnaof(sock.sin_addr);
    //printf("IPv4: inet_lnaof(): %lu\n", host_id);

    /*************** IPv6 function tests below here **************/

    /************   IPv6: TEST #9  inet_pton() -> inet_ntop()   ************/
    printf("TEST #9: [inet_pton() -> inet_ntop()] ");
    retval = inet_pton(AF_INET6, wild6_ip, (&sock6.sin6_addr)); // IPv6 TODO put back to sin6
    switch(retval) {
        case 0:
            msg_print("IPv6: inet_pton(): IP not parseable within the defined address family (AF_INET6)");
            break;
        case -1:
            err_print("inet_pton()", strerror(errno));
            break;
        case 1:
            printf("IPv6: inet_ntop(): strlen(): %d\n", (int)strlen(ip6_buf)); // DEBUG
            if (inet_ntop(AF_INET6, &(sock6.sin6_addr), ip6_buf, INET6_ADDRSTRLEN) == NULL) { // TODO back to sin6
                err_print("inet_ntop()", strerror(errno));
            } else {
                printf("IPv6: inet_pton() -> inet_ntop(): %s \n", ip6_buf);
            }
        default:
            break;
    }
    sock6 = (const struct sockaddr_in6){ 0 }; // Null struct before re-use
    memset(ip6_buf,0,strlen(ip6_buf)); // clear before re-use, zeroes up to first null

    //return(1);
    exit(0);
}

// unused atm
void restricted(){
    //uint32_t ip = 1244952093; // Works
    //uint32_t ip = 0100002004; // Doesn't work, doesn't pick up Octal
    uint32_t ip = 0x4a34761d;   // Works but limits to 32-bit unsigned integer limit
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;
    printf("The IP address is %s\n", inet_ntoa(ip_addr));
}

/*** print custom message and errno message and continue ***/
void err_print(char *msg, const char *errmsg) {
    printf("ERR_CONT: %s, errno: %s\n", msg, errmsg);
    //return(1);
}

/*** print custom message and errno messages and exit ***/
void err_exit(char *msg, const char *errmsg) {
    printf("ERR_EXIT: %s, %s\n\n", msg, errmsg);
    exit(1);
}

/*** print custom message and exit ***/
void msg_exit(char *msg) {
    printf("MSG_EXIT: %s\n\n", msg);
    exit(1);
}

/*** print (warning) message and continue ***/
void msg_print(char *msg) {
    printf("WARN_MSG: %s\n", msg);
    //return(1);
}