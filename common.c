﻿#include <stdlib.h>
#include <inttypes.h>

#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>

#include "common.h"

uint16_t send_pkts(struct rte_mbuf **mbufs, uint8_t tx_port, uint16_t tx_q, uint16_t nb_pkts){
    
    uint16_t nb_tx;
    uint16_t buf;

    nb_tx = rte_eth_tx_burst(tx_port,tx_q,
        mbufs,nb_pkts);

    if(unlikely(nb_tx < nb_pkts)){
        for(buf = nb_tx ; buf < nb_pkts ; buf++)
            rte_pktmbuf_free(mbufs[buf]);
    }

    return nb_tx;
}

void common_print_ipv4_5tuple(struct ipv4_5tuple *tuple){
    printf("==== IPv4 5-Tuple ==== : <ipsrc: 0x%08" PRIx32 ", ipdst: 0x%08" PRIx32 ", proto: 0x%02" PRIx8
        ", psrc: 0x%04" PRIx16 ", pdst: 0x%04" PRIx16 ">\n",tuple->src_ip,tuple->dst_ip,tuple->proto,
        tuple->src_port,tuple->dst_port);
}

void common_ipv4_get_5tuple(struct rte_mbuf *mbuf, struct ipv4_5tuple *tuple, uint16_t offset){
    struct ipv4_hdr *ipv4_hdr;
    struct tcp_hdr *tcp_hdr;
    struct udp_hdr *udp_hdr;

    ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf,struct ipv4_hdr *,
                    (offset + sizeof(struct ether_hdr)));

    tuple->src_ip = rte_be_to_cpu_32(ipv4_hdr->src_addr);
    tuple->dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
    tuple->proto  = ipv4_hdr->next_proto_id;

    switch(tuple->proto){
        case IP_PROTO_UDP:
            udp_hdr = (struct udp_hdr *) ( (unsigned char*) ipv4_hdr + sizeof(struct ipv4_hdr));
            tuple->src_port = rte_be_to_cpu_16(udp_hdr->src_port);
            tuple->dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
            break;
        case IP_PROTO_TCP:
            tcp_hdr = (struct tcp_hdr *) ( (unsigned char*) ipv4_hdr + sizeof(struct ipv4_hdr));
            tuple->src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
            tuple->dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
            break;
        default:
            break;

    }  
}

void common_ipv4_get_5tuple_bulk(struct rte_mbuf **mbufs, struct ipv4_5tuple *tuples, 
    struct ipv4_5tuple **tuples_ptrs, uint16_t nb_pkts)
{
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ipv4_hdr;
    struct tcp_hdr *tcp_hdr;
    struct udp_hdr *udp_hdr;
    struct ipv4_5tuple *curr_tuple;
    //uint16_t eth_type;

    int i;

    for(i = 0 ; i < nb_pkts ; i++){
        
        curr_tuple = &tuples[i];
        tuples_ptrs[i] = curr_tuple;

        eth_hdr = rte_pktmbuf_mtod(mbufs[i], struct ether_hdr *);        

        if(RTE_ETH_IS_IPV4_HDR(mbufs[i]->packet_type)){
            ipv4_hdr = (struct ipv4_hdr *) (eth_hdr + sizeof(struct ether_hdr));
            curr_tuple->src_ip = ipv4_hdr->src_addr;
            curr_tuple->dst_ip = ipv4_hdr->dst_addr;
            curr_tuple->proto = ipv4_hdr->next_proto_id;

            switch(curr_tuple->proto){
                case IP_PROTO_UDP:
                    udp_hdr = (struct udp_hdr *) (ipv4_hdr + sizeof(struct ipv4_hdr));
                    curr_tuple->src_port = udp_hdr->src_port;
                    curr_tuple->dst_port = udp_hdr->dst_port;
                    break;
                case IP_PROTO_TCP:
                    tcp_hdr = (struct tcp_hdr *) (ipv4_hdr + sizeof(struct ipv4_hdr));
                    curr_tuple->src_port = tcp_hdr->src_port;
                    curr_tuple->dst_port = tcp_hdr->dst_port;
                    break;
                default:
                    break;
            }
            
            common_print_ipv4_5tuple(curr_tuple);
        }else{
            ;/* Currently only treating IPv4 payloads*/
        }
    }

    if(unlikely(nb_pkts > 0))
        printf("Finishing ipv4_get_5tuple_bulk()!\n ");
}



void common_mac_update(struct rte_mbuf *mbuf, struct ether_addr *dest){
    struct ether_hdr *eth_hdr;

    eth_hdr = rte_pktmbuf_mtod(mbuf,struct ether_hdr *);

    ether_addr_copy(&eth_hdr->d_addr,&eth_hdr->s_addr);
    ether_addr_copy(dest,&eth_hdr->d_addr);
}

void common_dump_pkt(struct rte_mbuf *mbuf, const char *msg){
    printf("%s",msg);
    rte_pktmbuf_dump(stdout,mbuf,mbuf->pkt_len);
}

uint64_t common_mac_to_64(struct ether_addr *mac){

    return (((uint64_t) mac->addr_bytes[5])<<40) | 
           (((uint64_t) mac->addr_bytes[4])<<32) |
           (((uint64_t) mac->addr_bytes[3])<<24) |
           (((uint64_t) mac->addr_bytes[2])<<16) |
           (((uint64_t) mac->addr_bytes[1])<<8)  |
           (((uint64_t) mac->addr_bytes[0]))     |
           (uint64_t) 0;
}

void common_64_to_mac(uint64_t val, struct ether_addr *mac){
    mac->addr_bytes[0] = (uint8_t) (val);// & 0xFF);
    mac->addr_bytes[1] = (uint8_t) (val>>8);// & 0xFF);
    mac->addr_bytes[2] = (uint8_t) (val>>16);// & 0xFF);
    mac->addr_bytes[3] = (uint8_t) (val>>24);// & 0xFF);
    mac->addr_bytes[4] = (uint8_t) (val>>32);// & 0xFF);
    mac->addr_bytes[5] = (uint8_t) (val>>40);// & 0xFF);
}

int common_parse_portmask(const char *portmask){
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

enum sfcapp_type common_parse_apptype(const char *type){
    if(strcmp(type,"proxy") == 0)
        return SFC_PROXY;
    
    if(strcmp(type,"classifier") == 0)
        return SFC_CLASSIFIER;
    
    if(strcmp(type,"forwarder") == 0)
        return SFC_FORWARDER;
    
    return NONE;
}


int common_parse_uint16(const char *str, uint16_t *res){
    char *end;

    errno = 0;
    intmax_t val = strtoimax(str, &end, 16);

    if (errno == ERANGE || val < 0 || val > UINT16_MAX || end == str || *end != '\0')
        return -1;

    *res = (uint16_t) val;
    return 0;
}

int common_parse_uint32(const char* str, uint32_t *res){
    char *end;

    errno = 0;
    uint32_t val = strtoul(str, &end, 16);

    if (errno == ERANGE || errno == EINVAL || end == str || *end != '\0')
        return -1;

    *res = val;
    
    return 0;
}

int common_parse_uint64(const char* str, uint64_t *res){
    char *end;

    errno = 0;
    uint64_t val = strtoull(str, &end, 16);

    if (errno == ERANGE || errno == EINVAL || end == str || *end != '\0')
        return -1;

    *res = val;

    return 0;
}

int common_parse_ether(const char *str, struct ether_addr *eth_addr){
    int i,cnt;
    uint8_t vals[6];

    printf("Parsing: %s\n",str);

    //if(str == NULL) printf("str is NULL\n");
    //if(eth_addr == NULL) printf("eth_addr is NULL\n");
    //if(strlen(str) < (ETHER_ADDR_FMT_SIZE-1)) printf("strlen(str) < (ETHER_ADDR_FMT_SIZE-1) : %ld < %d\n", strlen(str),(ETHER_ADDR_FMT_SIZE-1));
    
    if(str == NULL || eth_addr == NULL || strlen(str) < (ETHER_ADDR_FMT_SIZE-1))
        return -1;

    cnt = sscanf(str,"%" SCNx8 ":%" SCNx8 ":%" SCNx8 ":%" SCNx8 ":%" SCNx8 ":%" SCNx8,
        &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]);

    if(cnt == 6){
        for(i = 0 ; i < 6 ; i++)
            eth_addr->addr_bytes[i] = vals[i];
    
        return 0;
    }

    //printf("Read %d bytes instead of 6\n",cnt);
    return -1;
    
}