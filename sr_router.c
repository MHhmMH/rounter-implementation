/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  uint16_t arp_or_ip = ethertype_arp(packet);
  if (arp_or_ip == ethertype_arp)
  {
      sr_handlearp(sr,packet,len,interface);
  }
  if (arp_or_ip == ethertype_ip)
  {
      sr_handleip(sr,packet,len,interface);

  }
}/* end sr_ForwardPacket */

void sr_handlearp(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
{
    sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t *)packet;
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    // find the receiver interface
    struct sr_if * receiver = sr_get_interface(sr,interface);
    uint16_t ar_op = arp_hdr->ar_op;
    if (ar_op == arp_op_request)
    {
        sr_handlearprequest(sr,ether_hdr,arp_hdr,receiver);
    }
    if (ar_op == arp_op_reply)
    {
        sr_handlearpreply(sr,arp_hdr,receiver);
    }

}
// This function is used to handle arp request
void sr_handlearprequest(struct sr_instance* sr,sr_ethernet_hdr_t *source_ether,sr_arp_hdr_t * source_acp, struct sr_if * current_interface)
{
    // create a new packet its cotains arp header and ethernet header
    unsinged int packer_len = sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t);
    uint8_t * reply_packet = malloc(packer_len);
    sr_ethernet_hdr_t* reply_ether = (sr_ethernet_hdr_t *) reply_packet;
    sr_arp_hdr_t* reply_arp = (sr_arp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
    reply_ether->ether_type = source_ether->ether_type;
    // the reply source address is the address of current interface
    memcpy(reply_ether->ether_shost,current_interface->addr,ETHER_ADDR_LEN);
    // the reply destination address is the source address of request arp
    memcpy(reply_ether->ether_dhost,source_ether->ether_shost,ETHER_ADDR_LEN);
    // the reply arp sourc address is the source address of current interface
    memcpy(reply_arp->ar_sha,current_interface->addr,ETHER_ADDR_LEN);
    //  the reply destination address is the source address of request arp
    memcpy(reply_arp->ar_tha,source_acp->ar_sha,ETHER_ADDR_LEN);
    reply_arp->ar_hln = source_acp->ar_hln;
    reply_arp->ar_hrd = source_acp->ar_hrd;
    reply_arp->ar_pln = source_acp->ar_pln;
    reply_arp->ar_pro = source_acp->ar_pro;
    reply_arp->ar_sip = current_interface->ip;
    reply_arp->ar_tip = source_acp->ar_sip;
    reply_arp->ar_op = arp_op_reply;
    // send the arp reply back
    sr_send_packet(sr,reply_packet,packer_len,current_interface->name);
}
void sr_handlearpreply(struct sr_instance* sr,sr_arp_hdr_t * source_acp, struct sr_if * current_interface)
{
    // the packet is for me
    if (source_acp->ar_tip == current_interface->ip)
    {
        struct sr_arpreq* request = sr_arpcache_insert(sr->cache,source_acp->ar_sha,source_acp->ar_sip);
        // if there is any packet wait for this request we send it
        if (request)
        {
            struct sr_packet * current_packet = request->packets;
            // iterate all the packet and send them
            while (current_packet)
            {
            uint8_t *reply_packet= current_packet->buf;
            sr_ethernet_hdr_t* reply_ether = (sr_ethernet_hdr_t *) reply_packet;
            sr_ip_hdr_t* reply_ip = (sr_ip_hdr_t *)(reply_ether + sizeof(sr_ethernet_hdr_t));
            // the reply source address is the address of current interface
            memcpy(reply_ether->ether_shost,current_interface->addr,ETHER_ADDR_LEN);
            // the reply destination address is the source address of request arp
            memcpy(reply_ether->ether_dhost,source_ether->ether_shost,ETHER_ADDR_LEN);
            // fill the field for reply ip
            reply_ip->ip_sum = cksum(reply_ip,sizeof(sr_ip_hdr_t));
            sr_send_packet(sr,reply_packet,current_packet->len,current_interface->name);
            current_packet = current_packet->next;
            }
            // remove the request queue from this arp cache
            sr_arpcache_destroy(sr->cache,request);
        }
    }
}

 