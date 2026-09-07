/* Test packet framing without a privileged utun: UNIX datagram socket pair. */
#include "utun.h"
#include <sys/socket.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
int g_verbose=0;
int main(void) {
    int fd[2]; assert(socketpair(AF_UNIX,SOCK_DGRAM,0,fd)==0);
    uint8_t ip[1500]={0x45}, out[1600]; uint32_t af=htonl(AF_INET);
    assert(utun_write_ip(fd[0],ip,sizeof(ip))==0);
    int n=(int)read(fd[1],out,sizeof(out));
    assert(n==1504 && !memcmp(out,&af,4) && !memcmp(out+4,ip,1500));
    assert(write(fd[0],out,n)==n);
    memset(out,0,sizeof(out));
    assert(utun_read_ip(fd[1],out,sizeof(out))==1500 && !memcmp(out,ip,1500));
    assert(utun_write_ip(fd[0],ip,sizeof(ip))==0);
    assert(utun_read_ip(fd[1],out,10)==-1);
    af=htonl(AF_INET6); memcpy(out,&af,4);
    assert(write(fd[0],out,24)==24 && utun_read_ip(fd[1],out,sizeof(out))==0);
    assert(fcntl(fd[1],F_SETFL,O_NONBLOCK)==0);
    assert(utun_read_ip(fd[1],out,sizeof(out))==0);
    close(fd[0]); close(fd[1]);
    puts("ok vectored utun I/O, full MTU, truncation, IPv6 filtering and EAGAIN");
}
