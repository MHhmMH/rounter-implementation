CSE123 project 2 

Authored by  Minghao Han



This is simple implementation of router in C and VMware fusion including ARP,IP,ICMP proctocol

 In sr_router.c
 
 The function handle packet is served as a main function to handle a packet 
 
 we check the type of the incoming packet 
 if it is arp we call the function  sr_handlearp
 if it is ip we call the function sr_handleip
The function handle arp check the ar_op field of arp packet 

if it is arp_request we call the function sr_handlearprequest
if it is arp_reply we call the function sr_handlearpreply

The function handlearp_request

receive the arp request and send back arp reply include mac and ip address 

The function handle arp_reply 
if this arp packet is for this ip we send all the packet out in order if there is any watiing for this requsest

The function sr_handleip

if this is a ip packet,
we traverse all the interface of this instance, if  the packet is for this interface and if is a icmp 8 we reply icmp 0 back
if it is not icmp 8 then it should be a tcp/udp packet used by traceroute, we handle the icmp 3 error for his packet.
else we forward the ip out.

The function sr_handleicmperror handle type 3 and type 11 icmp error for host unreachabla and timeout 

The function sr_forward_ip check the routing tabla and do longest prefix match, if we find that entry we send out reply packet 
else queue this request under this ip 
 
 In sr sr_arpcache.c 
 
 handle_arpreq check the time sent field of the packet if it is larger or greate than 5 handle host unreachable for this packet
 else we add time sent field 
 
 
