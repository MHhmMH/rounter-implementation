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
#include <string.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include <stdlib.h>
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
    /* to handle ip or arp */
  sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t *)packet;
  uint16_t arp_or_ip = ntohs(ether_header->ether_type);
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
    /* find the receiver interface */
    struct sr_if * receiver = sr_get_interface(sr,interface);
    uint16_t ar_op = ntohs(arp_hdr->ar_op);
    if (ar_op == arp_op_request)
    {
        sr_handlearprequest(sr,ether_hdr,arp_hdr,receiver);
    }
    if (ar_op == arp_op_reply)
    {
        sr_handlearpreply(sr,arp_hdr,receiver);
    }
}
/* This function is used to handle arp request */
void sr_handlearprequest(struct sr_instance* sr,sr_ethernet_hdr_t *source_ether,sr_arp_hdr_t * source_acp, struct sr_if * current_interface)
{
    /* create a new packet its cotains arp header and ethernet header */
    unsigned int packet_len = sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t);
    uint8_t * reply_packet = malloc(packet_len);
    sr_ethernet_hdr_t* reply_ether = (sr_ethernet_hdr_t *) reply_packet;
    sr_arp_hdr_t* reply_arp = (sr_arp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
    reply_ether->ether_type = source_ether->ether_type;
    /* the reply source address is the address of current interface */
    memcpy(reply_ether->ether_shost,current_interface->addr,ETHER_ADDR_LEN);
    /* the reply destination address is the source address of request arp*/
    memcpy(reply_ether->ether_dhost,source_ether->ether_shost,ETHER_ADDR_LEN);
    /* the reply arp sourc address is the source address of current interface */
    memcpy(reply_arp->ar_sha,current_interface->addr,ETHER_ADDR_LEN);
    /*  the reply destination address is the source address of request arp */
    memcpy(reply_arp->ar_tha,source_acp->ar_sha,ETHER_ADDR_LEN);
    reply_arp->ar_hln = source_acp->ar_hln;
    reply_arp->ar_hrd = source_acp->ar_hrd;
    reply_arp->ar_pln = source_acp->ar_pln;
    reply_arp->ar_pro = source_acp->ar_pro;
    reply_arp->ar_sip = current_interface->ip;
    reply_arp->ar_tip = source_acp->ar_sip;
    /* change the arp type to arp reply */
    reply_arp->ar_op = htons(arp_op_reply);
    /* send the arp reply back */
    sr_send_packet(sr,reply_packet,packet_len,current_interface->name);

    /* free the memomory*/
    free(reply_packet);
}
void sr_handlearpreply(struct sr_instance* sr,sr_arp_hdr_t * source_acp, struct sr_if * current_interface)
{
    /* the packet is for me */
    if (source_acp->ar_tip == current_interface->ip)
    {
        struct sr_arpreq* request = sr_arpcache_insert(&sr->cache,source_acp->ar_sha,source_acp->ar_sip);
        /* if there is any packet wait for this request we send it */

        if (request)
        {
            struct sr_packet * current_packet = request->packets;
            /* iterate all the packet and send them */
            /* first reverse the packet list because we need to send fifo*/
            reverse(&current_packet);

            while (current_packet)
            {
            uint8_t *reply_packet= current_packet->buf;
            sr_ethernet_hdr_t* reply_ether = (sr_ethernet_hdr_t *) reply_packet;
            sr_ip_hdr_t* reply_ip = (sr_ip_hdr_t *)(reply_ether + sizeof(sr_ethernet_hdr_t));
            /* the reply source address is the address of current interface */
            memcpy(reply_ether->ether_shost,current_interface->addr,ETHER_ADDR_LEN);
            /* the reply destination address is the source address of request arp */
            memcpy(reply_ether->ether_dhost,source_acp->ar_sha,ETHER_ADDR_LEN);

            /* change the checksum for reply-ip */
            reply_ip->ip_sum = 0;
            reply_ip->ip_sum = cksum(reply_ip,sizeof(sr_ip_hdr_t));

            sr_send_packet(sr,reply_packet,current_packet->len,current_interface->name);
            /* add free reply */
            current_packet = current_packet->next;
            }
            /* remove the request queue from this arp cache */
            sr_arpreq_destroy(&sr->cache,request);
        }
    }
}
void sr_handleip(struct sr_instance* sr,uint8_t * packet, unsigned len,char * interface)
{
    struct sr_if * receiver = sr_get_interface(sr,interface);
    sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t *) packet;
    sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* create a new packet its cotains arp header and ethernet header and icmp header */
    unsigned int packet_len = sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t0_hdr_t);
    uint8_t * reply_packet = malloc(packet_len);
    sr_ethernet_hdr_t* reply_ether = (sr_ethernet_hdr_t *) reply_packet;
    sr_ip_hdr_t* reply_ip = (sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t0_hdr_t * reply_icmp = (sr_icmp_t0_hdr_t *)(reply_packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));


    /* to check the length of the ip packet */
    if (len < sizeof(ether_header) + sizeof(ip_header))
    {
        return;
    }
    uint16_t check_sum = ip_header->ip_sum;
    ip_header->ip_sum = 0;
    if (check_sum != cksum(ip_header, sizeof(sr_ip_hdr_t)))
    {
        ip_header->ip_sum = check_sum;
        return;
    }
    ip_header->ip_sum = check_sum;
    struct sr_if * current_interface = sr->if_list;
    /* traverse all the interface in the list */
    while (current_interface)
    {
        /* the packet if for this interface */
        if (current_interface->ip == ip_header->ip_dst)
        {
            /* the message is icmp message */
            if (ip_header->ip_p == ip_protocol_icmp)
            {
                sr_icmp_t0_hdr_t * icmp_header = (sr_icmp_t0_hdr_t *)(packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
                /* the message is icmp request */
                if (icmp_header->icmp_type == 0x08)
                {
                    struct sr_rt * match_entry  = LongestPrefixMatch(sr,ip_header->ip_src);
                    if (match_entry == NULL)
                    {
                        return;
                    }
                    struct sr_if * reply_interface = sr_get_interface(sr,match_entry->interface);
                    /* After the while loop we have found the longest prefix that matches */
                    reply_ether->ether_type = ether_header->ether_type;
                    /* create reply ether header */
                    memcpy(reply_ether->ether_shost,reply_interface->addr,ETHER_ADDR_LEN);
                    /* the reply destination address is the source address of request icmp */
                    memcpy(reply_ether->ether_dhost,ether_header->ether_shost,ETHER_ADDR_LEN);

                    /* create and fill in the ip header field */
                    reply_ip->ip_hl = ip_header->ip_hl;
                    reply_ip->ip_v = ip_header->ip_v;
                    reply_ip->ip_tos = ip_header->ip_tos;
                    reply_ip->ip_p = ip_header->ip_p;
                    reply_ip->ip_id = ip_header->ip_id;
                    reply_ip->ip_off = ip_header->ip_off;
                    reply_ip->ip_ttl = INIT_TTL;
                    reply_ip->ip_src = reply_interface->ip;
                    reply_ip->ip_dst = ip_header->ip_src;
                    reply_ip->ip_len = htons(packet_len - sizeof(sr_ethernet_hdr_t));
                    reply_ip->ip_sum = 0;
                    reply_ip->ip_sum = cksum(reply_ip, sizeof(sr_ip_hdr_t));

                    /* create rely icmp header */
                    reply_icmp->icmp_type = 0x00;
                    reply_icmp->icmp_code = 0x00;
                    reply_icmp->identifier = icmp_header->identifier;
                    reply_icmp->seqnumber = icmp_header->seqnumber;
                    reply_icmp->icmp_sum = 0;
                    reply_icmp->icmp_sum = cksum(reply_icmp, sizeof(sr_icmp_t0_hdr_t));
                    memcpy(reply_icmp->data,icmp_header->data,ICMP_DATA_SIZE);
                    sr_send_packet(sr,reply_packet,packet_len,reply_interface->name);
                    free(reply_packet);
                    return;
                }
            }
        /* handle the case for tcp/udp */
        else
            {
                sr_handleicmperror(sr,packet,0x03,0x03,receiver);
                return;
            }
        }
        current_interface = current_interface->next;
    }
    ip_header->ip_ttl -= 1;
    if(ip_header->ip_ttl == 0)
    {
        /* handle time out */
        sr_handleicmperror(sr,packet,11,0x00,receiver);
        return;
    }
    sr_forward_ip(sr,packet,len,receiver);
}
void sr_handleicmperror(struct sr_instance *sr, uint8_t* source_packet, uint8_t icmp_type, uint8_t icmp_code, struct sr_if* current_interface)
{
    unsigned packet_len = sizeof(sr_icmp_t11_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    uint8_t * reply_packet = malloc(packet_len);
    /* create reply and source ethernet header */
    sr_ethernet_hdr_t * source_ether = (sr_ethernet_hdr_t * ) source_packet;
    sr_ethernet_hdr_t * reply_ether = (sr_ethernet_hdr_t * )  reply_packet;
    /* create reply and source  ip header */
    sr_ip_hdr_t * source_ip  = (sr_ip_hdr_t * )(source_packet + sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t * reply_ip  = (sr_ip_hdr_t * )(reply_packet + sizeof(sr_ethernet_hdr_t));
    /* create reply icmp header */
    sr_icmp_t11_hdr_t * reply_icmp = (sr_icmp_t11_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    /* LPM */
    struct sr_rt * match_entry  = LongestPrefixMatch(sr,source_ip->ip_src);
    if (match_entry == NULL)
    {
        return;
    }
    struct sr_if * reply_interface = sr_get_interface(sr,match_entry->interface);
    reply_ether->ether_type = source_ether->ether_type;
    /* After the while loop we have found the longest prefix that matches */
    /* change ether header*/
    memcpy(reply_ether->ether_shost,reply_interface->addr,ETHER_ADDR_LEN);
    /* the reply destination address is the source address of request icmp */
    memcpy(reply_ether->ether_dhost,source_ether->ether_shost,ETHER_ADDR_LEN);

    /* create and fill in the ip field */
    reply_ip->ip_hl = source_ip->ip_hl;
    reply_ip->ip_v = source_ip->ip_v;
    reply_ip->ip_tos = source_ip->ip_tos;
    reply_ip->ip_p = ip_protocol_icmp;
    reply_ip->ip_id = source_ip->ip_id;
    reply_ip->ip_off = source_ip->ip_off;
    reply_ip->ip_ttl = INIT_TTL;
    reply_ip->ip_src = reply_interface->ip;
    reply_ip->ip_dst = source_ip->ip_src;

    reply_ip->ip_len = htons((packet_len - sizeof(sr_ethernet_hdr_t)));
    reply_ip->ip_sum = 0;
    reply_ip->ip_sum = cksum(reply_ip, sizeof(sr_ip_hdr_t));

    /* create and fill the icmp field */
    reply_icmp->icmp_code = icmp_code;
    reply_icmp->icmp_type = icmp_type;
    reply_icmp->unused = 0;
    memcpy(reply_icmp->data,source_ip,ICMP_DATA_SIZE);
    reply_icmp->icmp_sum = 0;
    reply_icmp->icmp_sum = cksum(reply_icmp, sizeof(sr_icmp_t11_hdr_t));

    /* send the packet */
    sr_send_packet(sr,reply_packet,packet_len,reply_interface->name);
    free(reply_packet);
}
void sr_forward_ip(struct sr_instance* sr,uint8_t * packet, unsigned len,struct sr_if * current_interface)
{
    sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t *) packet;
    sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    /* LPM */
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
    struct sr_rt * match_entry  = LongestPrefixMatch(sr,ip_header->ip_dst);
    if (match_entry)
    {
        struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache,ip_header->ip_dst);
        struct sr_if * reply_interface = sr_get_interface(sr,match_entry->interface);
        if(entry)
        {
            memcpy(ether_header->ether_shost,reply_interface->addr,ETHER_ADDR_LEN);
            memcpy(ether_header->ether_dhost,entry->mac,ETHER_ADDR_LEN);

            sr_send_packet(sr,packet,len,reply_interface->name);
            free(entry);
            return;

        }
        /* put the packet under the queue */
        else
        {
            struct sr_arpreq* request = sr_arpcache_queuereq(&sr->cache,ip_header->ip_dst,packet,len,reply_interface->name);
            sr_handle_arpreq(sr,request);
            return;
        }
    }
    else
    {
        sr_handleicmperror(sr,packet,0x03,0x00,current_interface);
        Debug("haha");
    }
}
struct sr_rt * LongestPrefixMatch(struct sr_instance * sr, uint32_t ip)
{
    struct sr_rt * current_router = sr->routing_table;
    struct sr_rt * match_entry = NULL;
    uint32_t largest_mask_now = 0;
    while (current_router)
    {
        uint32_t dist_ip = current_router->mask.s_addr & ip;
        uint32_t match_ip = current_router->mask.s_addr & current_router->dest.s_addr;
        if ((dist_ip == match_ip) && (current_router->mask.s_addr > largest_mask_now))
        {
            match_entry = current_router;
            largest_mask_now = current_router->mask.s_addr;
        }
        current_router = current_router->next;
    }
    return match_entry;
}
/* This function is used as a untiliity function to reverse a linklist*/
void reverse(struct sr_packet ** header_packet)
{
    struct sr_packet * prev  = NULL;
    struct sr_packet * current = *header_packet;
    struct sr_packet * next = NULL;
    while (current !=  NULL)
    {
        next  = current->next;
        current->next = prev;
        prev = current;
        current = next;
    }
    * header_packet = prev;
}