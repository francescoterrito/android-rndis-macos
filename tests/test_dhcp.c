/* Lease state machine with an injected clock: no sleeps, USB or root. */
#include "dhcp.h"
#include "net_util.h"
#include "usb.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int g_verbose = 0;
int usb_bulk_out(struct rndis_usb_dev *d, const uint8_t *b, size_t n, unsigned t) {
    (void)d; (void)b; (void)n; (void)t; return -1;
}
int usb_bulk_in(struct rndis_usb_dev *d, uint8_t *b, size_t n, size_t *g, unsigned t) {
    (void)d; (void)b; (void)n; (void)g; (void)t; return -1;
}
static const uint8_t peer[6] = {2,9,8,7,6,5};
static struct dhcp_result lease(void) {
    struct dhcp_result n = {.ip={10,0,0,2}, .mask={255,255,255,0}, .gw={10,0,0,1},
        .dns={1,1,1,1}, .dns2={8,8,8,8}, .have_dns2=1, .server={10,0,0,3},
        .client_mac={2,1,2,3,4,5}, .lease_sec=3600, .obtained_at=100};
    return n;
}
static void opt32(uint8_t **p, uint8_t code, uint32_t v) {
    *(*p)++=code; *(*p)++=4;
    *(*p)++=v>>24; *(*p)++=v>>16; *(*p)++=v>>8; *(*p)++=v;
}
static size_t reply(struct dhcp_client *c, uint8_t *out, int type, int options,
                    const uint8_t *router) {
    memset(out, 0, 600);
    memcpy(out, c->net.client_mac, 6); memcpy(out+6, peer, 6);
    out[12]=8; out[14]=0x45; out[23]=17;
    uint8_t *udp=out+34;
    put_be16(udp,67); put_be16(udp+2,68);
    struct dhcp_fixed *d=(struct dhcp_fixed *)(udp+8);
    d->op=2; d->htype=1; d->hlen=6;
    d->xid[0]=c->xid>>24; d->xid[1]=c->xid>>16; d->xid[2]=c->xid>>8; d->xid[3]=c->xid;
    memcpy(d->chaddr,c->net.client_mac,6);
    if(type!=6) memcpy(d->yiaddr,c->net.ip,4);
    memcpy(d->magic,"\x63\x82\x53\x63",4);
    uint8_t *p=(uint8_t *)(d+1);
    *p++=53; *p++=1; *p++=type;
    *p++=54; *p++=4; memcpy(p,c->net.server,4); p+=4;
    if(options & DHCP_OPT_LEASE) opt32(&p,51,3600);
    if(options & DHCP_OPT_T1) opt32(&p,58,1200);
    if(options & DHCP_OPT_T2) opt32(&p,59,3000);
    if(options & DHCP_OPT_DNS) opt32(&p,6,0x09090909);
    if(router) { *p++=3; *p++=4; memcpy(p,router,4); p+=4; }
    *p++=255;
    size_t len=(size_t)(p-out);
    put_be16(out+16,(uint16_t)(len-14)); put_be16(udp+4,(uint16_t)(len-34));
    return len;
}
int main(void) {
    struct dhcp_client c;
    struct dhcp_result n=lease();
    uint8_t frame[600];
    assert(dhcp_client_start(&c,&n,123)==0);
    assert(c.renew_at==1900 && c.rebind_at==3250 && c.expires_at==3700);
    assert(dhcp_client_tick(&c,1899,peer,frame,sizeof(frame))==0);
    int len=dhcp_client_tick(&c,1900,peer,frame,sizeof(frame));
    assert(len>0 && c.phase==DHCP_RENEWING && c.next_request==2575);
    struct dhcp_fixed *d=(struct dhcp_fixed *)(frame+42);
    assert(!memcmp(frame,peer,6) && !memcmp(frame+26,n.ip,4) && !memcmp(frame+30,n.server,4));
    assert(!memcmp(d->ciaddr,n.ip,4) && d->flags[0]==0);
    const uint8_t *o=(const uint8_t *)(d+1);
    while(*o!=255) { int code=*o++, size=*o++; assert(code!=50 && code!=54); o+=size; }
    assert(ip_checksum(frame+14,20)==0);
    assert(udp_checksum_ipv4(frame+26,frame+30,frame+34,(size_t)len-34)==0xffff);
    puts("ok T1 sends unicast renewal with ciaddr, valid checksums, no options 50/54");
    assert(dhcp_client_tick(&c,2500,peer,frame,sizeof(frame))==0);
    assert(dhcp_client_tick(&c,2575,peer,frame,sizeof(frame))>0);
    len=(int)reply(&c,frame,5,DHCP_OPT_LEASE|DHCP_OPT_T1|DHCP_OPT_T2,NULL);
    assert(dhcp_client_receive(&c,frame,len,2580)==2);
    assert(c.phase==DHCP_BOUND && c.renewals==1 && c.expires_at==5500);
    assert(c.renew_at==3100 && c.rebind_at==4900);
    assert(!memcmp(c.net.gw,n.gw,4) && !memcmp(c.net.mask,n.mask,4));
    assert(c.net.have_dns2 && !memcmp(c.net.dns2,n.dns2,4));
    puts("ok ACK renews in place, preserves omitted config, honors server T1/T2");
    dhcp_client_renew_now(&c,2581);
    assert(dhcp_client_tick(&c,2581,peer,frame,sizeof(frame))>0);
    len=(int)reply(&c,frame,5,DHCP_OPT_LEASE|DHCP_OPT_DNS,NULL);
    d=(struct dhcp_fixed *)(frame+42);
    d->xid[3]^=1; assert(dhcp_client_receive(&c,frame,len,2582)==0); d->xid[3]^=1;
    d->chaddr[5]^=1; assert(dhcp_client_receive(&c,frame,len,2582)==0); d->chaddr[5]^=1;
    frame[sizeof(struct dhcp_fixed)+42+3+2+3]^=1;
    assert(dhcp_client_receive(&c,frame,len,2582)==0);
    len=(int)reply(&c,frame,5,DHCP_OPT_LEASE|DHCP_OPT_DNS,NULL);
    assert(dhcp_client_receive(&c,frame,len,2582)==2);
    assert(!memcmp(c.net.dns,"\x09\x09\x09\x09",4) && !c.net.have_dns2);
    puts("ok stale XID, wrong client/server ignored; new DNS replaces old DNS");
    assert(dhcp_client_start(&c,&n,1)==0);
    assert(dhcp_client_tick(&c,3250,peer,frame,sizeof(frame))>0);
    assert(c.phase==DHCP_REBINDING && !memcmp(frame,"\xff\xff\xff\xff\xff\xff",6));
    assert(!memcmp(frame+30,"\xff\xff\xff\xff",4));
    len=(int)reply(&c,frame,5,DHCP_OPT_LEASE,NULL);
    frame[sizeof(struct dhcp_fixed)+42+3+2+3]^=1;
    assert(dhcp_client_receive(&c,frame,len,3251)==2);
    puts("ok missed T1/sleep jumps to broadcast rebind and accepts a new server");
    assert(dhcp_client_start(&c,&n,1)==0);
    assert(dhcp_client_tick(&c,3700,peer,frame,sizeof(frame))==-1);
    assert(c.phase==DHCP_EXPIRED);
    assert(dhcp_client_tick(&c,3701,peer,frame,sizeof(frame))==-1);
    puts("ok expiry immediately invalidates the address, including after sleep");
    assert(dhcp_client_start(&c,&n,1)==0);
    dhcp_client_tick(&c,1900,peer,frame,sizeof(frame));
    len=(int)reply(&c,frame,6,0,NULL);
    assert(dhcp_client_receive(&c,frame,len,1901)==-1 && c.phase==DHCP_EXPIRED);
    puts("ok matching NAK invalidates the lease");
    n.renew_sec=3500; n.rebind_sec=20;
    assert(dhcp_client_start(&c,&n,1)==0 && c.renew_at==1900 && c.rebind_at==3250);
    n.lease_sec=UINT32_MAX;
    assert(dhcp_client_start(&c,&n,1)==0 && dhcp_client_tick(&c,1e10,peer,frame,sizeof(frame))==0);
    n.lease_sec=0; assert(dhcp_client_start(&c,&n,1)==-1);
    puts("ok invalid timers normalized; infinite and zero leases handled");
    n=lease(); n.lease_sec=4;
    dhcp_client_start(&c,&n,1);
    assert(dhcp_client_tick(&c,102,peer,frame,sizeof(frame))>0);
    assert(dhcp_client_tick(&c,103.5,peer,frame,sizeof(frame))>0);
    assert(dhcp_client_tick(&c,104,peer,frame,sizeof(frame))==-1);
    puts("ok short leases cross T2/expiry despite the 60-second retry minimum");
    n=lease();
    assert(dhcp_client_start(&c,&n,1)==0);
    assert(dhcp_client_tick(&c,1900,peer,frame,sizeof(frame))>0);
    uint8_t new_gw[4]={10,0,0,9};
    len=(int)reply(&c,frame,5,DHCP_OPT_LEASE,new_gw);
    assert(dhcp_client_receive(&c,frame,len,1901)==2);
    assert(!memcmp(c.net.gw,new_gw,4) && !memcmp(c.net.ip,n.ip,4));
    puts("ok ACK with a new router updates the gateway and keeps the address");
    return 0;
}
