#include <stdlib.h>

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cfgfile.h>
#include <rte_ethdev.h>
#include <rte_cfgfile.h>
#include <rte_ether.h>

#include "sfc_proxy.h"
#include "nsh.h"
#include "common.h"

#define VXLAN_NSH_INNER_OFFSET 58

extern struct sfcapp_config sfcapp_cfg;

static struct rte_hash *proxy_flow_lkp_table;
/* key = ipv4_5tuple ; value = NSH base hdr + SPI + SI (4B) */

static struct rte_hash* proxy_sf_id_lkp_table;
/* key = <spi,si> ; value = sfid (16b) */

static struct rte_hash *proxy_sf_address_lkp_table;
/* key = sfid (16b) ; value = ethernet (48b in 64b) */

static int proxy_init_flow_table(void){

    const struct rte_hash_parameters hash_params = {
        .name = "proxy_flow",
        .entries = PROXY_MAX_FLOWS,
        .reserved = 0,
        .key_len = sizeof(struct ipv4_5tuple),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id()
    };

    proxy_flow_lkp_table = rte_hash_create(&hash_params);

    if(proxy_flow_lkp_table == NULL)
        return -1;
    
    return 0;
}

static int proxy_init_sf_addr_table(void){
    
    const struct rte_hash_parameters hash_params = {
        .name = "proxy_sf_addr",
        .entries = PROXY_MAX_FUNCTIONS,
        .reserved = 0,
        .key_len = sizeof(uint16_t), /* SFID */
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id()
    };

    proxy_sf_address_lkp_table = rte_hash_create(&hash_params);

    if(proxy_sf_address_lkp_table == NULL)
        return -1;

    return 0;
}

static int proxy_init_sf_id_lkp_table(void){
    const struct rte_hash_parameters hash_params = {
        .name = "proxy_next_func",
        .entries = PROXY_MAX_FUNCTIONS,
        .reserved = 0,
        .key_len = sizeof(uint32_t),  /* <SPI,SI> */
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id()
    };

    proxy_sf_id_lkp_table = rte_hash_create(&hash_params);

    if(proxy_sf_id_lkp_table == NULL)
        return -1;

    return 0;
}

void proxy_add_sph_entry(uint32_t sph, uint16_t sfid){
    int ret;

    ret = rte_hash_add_key_data(proxy_sf_id_lkp_table,&sph, 
        (void *) ((uint64_t) sfid) );
    SFCAPP_CHECK_FAIL_LT(ret,0,"Failed to add stub entry 1.\n");

    printf("Added <sph=%" PRIx32 ",sfid=%" PRIx16 ">"
            " to proxy SF ID table.\n",sph,sfid);
}

void proxy_add_sf_address_entry(uint16_t sfid, struct ether_addr *eth_addr){
    int ret;

    ret = rte_hash_add_key_data(proxy_sf_address_lkp_table,&sfid, 
        (void *) common_mac_to_64(eth_addr));
    SFCAPP_CHECK_FAIL_LT(ret,0,"Failed to add SF entry to proxy table.\n");

    char buf[ETHER_ADDR_FMT_SIZE + 1];
    ether_format_addr(buf,ETHER_ADDR_FMT_SIZE,eth_addr);
    printf("Added <sfid=%" PRIx16 ",mac=%s> to proxy" 
        " SF Address table.\n",sfid,buf);
}

/* This function does all the processing on packets coming from 
 * the SFC network to the Legacy SFs. That includes: 
 * 
 * - Checking if flow info is already on table
 * - Decapsulating the packet
 * - Adding the corresponding SF MAC address
 * 
 * It handles packets in bulks. This can be further optimized by
 * using other DPDK bulk operations.
 */ 
static int proxy_handle_inbound_pkts(struct rte_mbuf **mbufs, uint16_t nb_pkts){

    struct nsh_hdr nsh_header;
    struct ipv4_5tuple tuple = { .proto = 0, .src_ip = 0, .dst_ip = 0, .src_port = 0, .dst_port = 0};
    uint16_t sfid;
    uint64_t data;
    struct ether_addr sf_mac;
    int i, lkp, drop, nb_tx;
    uint16_t offset;
    uint64_t sf_mac_64;
    uint64_t nsh_header_64;

    nb_tx = 0;

    for(i = 0; i < nb_pkts ; i++){
        drop = 0;
        
        nsh_get_header(mbufs[i],&nsh_header);

        offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
            sizeof(struct udp_hdr) + sizeof(struct vxlan_hdr) +
            sizeof(struct nsh_hdr);

        common_ipv4_get_5tuple(mbufs[i],&tuple,offset);        

        lkp = rte_hash_lookup(proxy_flow_lkp_table,&tuple);

        if(unlikely(lkp < 0)){
            if( (nsh_header.serv_path & 0x000000FF) != 0 ){
                nsh_header.serv_path--;
            }else{ /* Drop packet */
                drop = 1;
                continue;
            }

            nsh_header_64 = nsh_header_to_uint64(&nsh_header);
            lkp = rte_hash_add_key_data(proxy_flow_lkp_table,
                &tuple, (void *) nsh_header_64);

            nsh_header.serv_path++;
        }

        nsh_decap(mbufs[i]);
        
        lkp = rte_hash_lookup_data(proxy_sf_id_lkp_table, 
                (void *) &nsh_header.serv_path,
                (void **) &data);
        COND_MARK_DROP(lkp,drop);

        sfid = (uint16_t) data;

        lkp = rte_hash_lookup_data(proxy_sf_address_lkp_table,
                (void *) &sfid,
                (void **) &sf_mac_64);

        COND_MARK_DROP(lkp,drop);

        // Convert hash data back to MAC
        common_64_to_mac(sf_mac_64,&sf_mac);

        common_mac_update(mbufs[i],&sfcapp_cfg.ports[1].mac,&sf_mac);

        /* Enqueue packet for TX */
        nb_tx += rte_eth_tx_buffer(sfcapp_cfg.ports[1].id,0,sfcapp_cfg.ports[1].tx_buffer,mbufs[i]);

        if(unlikely(drop))
            rte_pktmbuf_free(mbufs[i]);
    }

    return nb_tx;
}

static int proxy_handle_outbound_pkts(struct rte_mbuf **mbufs, uint16_t nb_pkts){
    struct nsh_hdr nsh_header;
    uint64_t nsh_header_64;
    struct ipv4_5tuple tuple;
    uint16_t offset;
    int i,lkp,drop,nb_tx;

    nb_tx = 0;

    for(i = 0 ; i < nb_pkts ; i++){
        drop = 0;

        //common_dump_pkt(mbufs[i],"\n=== Received from SF ===\n");

        offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 
            sizeof(struct udp_hdr) + sizeof(struct vxlan_hdr);

        common_ipv4_get_5tuple(mbufs[i],&tuple,offset);

        /* Get packet header from hash table */
        lkp = rte_hash_lookup_data(proxy_flow_lkp_table,
                (void*) &tuple,(void**) &nsh_header_64);
        COND_MARK_DROP(lkp,drop);
        
        nsh_uint64_to_header(nsh_header_64,&nsh_header);
        
        /* Encapsulate packet */
        nsh_encap(mbufs[i],&nsh_header);

        /* Add SFF's MAC address */
        common_mac_update(mbufs[i],&sfcapp_cfg.ports[0].mac,&sfcapp_cfg.sff_addr);

        //printf("Sending to SFF...\n");
        //common_dump_pkt(mbufs[i],"\n=== Encapsulated packet ===\n");

        /* Enqueue packet for TX */
        nb_tx += rte_eth_tx_buffer(sfcapp_cfg.ports[0].id,0,sfcapp_cfg.ports[0].tx_buffer,mbufs[i]);

        if(unlikely(drop))
            rte_pktmbuf_free(mbufs[i]);
    }

    return nb_tx;
}

int proxy_setup(void){

    int ret = 0;

    ret = proxy_init_flow_table();
    SFCAPP_CHECK_FAIL_LT(ret,0,
        "Proxy: Failed to create flow lookup table.\n");
    ret = proxy_init_sf_addr_table();
    SFCAPP_CHECK_FAIL_LT(ret,0,
        "Proxy: Failed to create SF address lookup table.\n");
    ret = proxy_init_sf_id_lkp_table();
    SFCAPP_CHECK_FAIL_LT(ret,0,
        "Proxy: Failed to create SF id lookup table.\n");
    
    sfcapp_cfg.ports[0].handle_pkts = proxy_handle_inbound_pkts;
    sfcapp_cfg.ports[1].handle_pkts = proxy_handle_outbound_pkts;

    return 0;
}

