﻿#include <stdlib.h>

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cfgfile.h>
#include <rte_ethdev.h>

#include "sfc_proxy.h"
#include "common.h"

#define PROXY_MAX_FLOWS 1024
#define PROXY_MAX_FUNCTIONS 64
#define PROXY_CFG_SF_MAX_ENTRIES 2

extern struct sfcapp_config sfcapp_cfg;

static struct rte_hash *proxy_flow_header_lkp_table;
/* key = ipv4_5tuple ; value = NSH base hdr + SPI + SI (64B) */

static struct rte_hash *proxy_sf_address_lkp_table;
/* key = SPI + SI (4B) ; value = ether_addr */

/*static int proxy_parse_config_file(char* cfg_filename){

    struct rte_cfgfile *cfgfile;
    struct rte_cfgfile_entry entries[PROXY_CFG_SF_MAX_ENTRIES];
    char** sections;
    int nb_sections, nb_entries, i, j, ret;
    uint16_t sfid;
    struct ether_addr sf_mac;   
    

    cfgfile = rte_cfgfile_load_with_params(cfg_filename,0,
        sfcapp_cfgfile_params);
    if(cfgfile == NULL)
        rte_exit(EXIT_FAILURE,
            "Failed to load proxy config file\n");

    nb_sections = rte_cfgfile_num_sections(cfgfile,sections,
            PROXY_MAX_FUNCTIONS);
    if(nb_sections <= 0)
        rte_exit(EXIT_FAILURE,
            "Not enough sections in proxy config file\n");

    sections = (char**) malloc(nb_sections*sizeof(char*));
    if(sections == NULL)
        rte_exit(EXIT_FAILURE,
            "Failed to allocate memory when parsing proxy config file.\n");
    
    for(i = 0 ; i < nb_sections ; i++){
        sections[i] = (char*) malloc(CFG_NAME_LEN*sizeof(char));    
     
        if(sections[i] == NULL)
            rte_exit(EXIT_FAILURE,
                "Failed to allocate memory when parsing proxy config file.\n");
    }

    rte_cfgfile_sections(cfgfile,sections,PROXY_MAX_FUNCTIONS);
    
    //  Parse sections
    for(i = 0 ; i < nb_sections ; i++){
        nb_entries = rte_cfgfile_section_num_entries(cfgfile,
                        sections[i]);
        if(nb_entries != PROXY_CFG_SF_MAX_ENTRIES)
            rte_exit(EXIT_FAILURE,
                "Wrong number of entries for section %s, expecting %d.\n",
                section[i],
                PROXY_CFG_SF_MAX_ENTRIES);

        ret = rte_cfgfile_section_entries(cfgfile,sections[i],
            entries,PROXY_CFG_SF_MAX_ENTRIES);
        if(ret < 0)
            rte_exit("Failed to parse entries in section %s during proxy" 
                        "config file parsing.\n",sections[i]);
        
        sfid = 0;
        
        // Parse entries in each section
        for(j = 0 ; j < nb_entries ; j++){

            //sfid
            if(strcmp(entry->name,"sfid") == 0)
                sfid = sfcapp_parse_uint16t(entry->value);

            if(strcmp(entry->name,"mac") == 0)
                mac = sfcapp_parse_ether(entry->value);
        }
    }

}*/

static int proxy_init_flow_hdr_table(void){

    const struct rte_hash_parameters hash_params = {
        .name = "proxy_flow_hdr",
        .entries = PROXY_MAX_FLOWS,
        .reserved = 0,
        .key_len = sizeof(struct ipv4_5tuple),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id()
    };

    proxy_flow_header_lkp_table = rte_hash_create(&hash_params);

    if(proxy_flow_header_lkp_table == NULL)
        return -1;

    return 0;
}

static int proxy_init_sf_addr_table(void){
    
    const struct rte_hash_parameters hash_params = {
        .name = "proxy_sf_addr",
        .entries = PROXY_MAX_FUNCTIONS,
        .reserved = 0,
        .key_len = sizeof(uint16_t), 
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id()
    };

    proxy_sf_address_lkp_table = rte_hash_create(&hash_params);

    if(proxy_sf_address_lkp_table == NULL)
        return -1;

    return 0;
}

static int proxy_init_next_func_table(void){
    const struct rte_hash_parameters hash_params = {
        .name = "proxy_next_func",
        .entries = PROXY_MAX_FUNCTIONS,
        .reserved = 0,
        .key_len = sizeof(uint32_t),  /* SPI + SI*/
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id()
    };

    proxy_next_func_lkp_table = rte_hash_create(&hash_params);

    if(proxy_next_func_lkp_table == NULL)
        return -1;

    return 0;
}

int proxy_setup(char *cfg_filename){

    int ret = 0;
    uint16_t sfid_stub1 = 1;
    ether_addr mac_stub1 = {0xFF,0xEE,0xDD,0xCC,0xBB,0xAA};
    uint16_t sfid_stub2 = 2;
    ether_addr mac_stub2 = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};

    ret = proxy_init_flow_hdr_table();
    SFCAPP_CHECK_FAIL_LT(ret,0,
        "Proxy: Failed to create flow hash table.\n");
    ret = proxy_init_sf_addr_table();
    SFCAPP_CHECK_FAIL_LT(ret,0,
        "Proxy: Failed to create SF address hash table.\n");
    ret = proxy_init_next_func_table();
    SFCAPP_CHECK_FAIL_LT(ret,0,"Failed to create next func hash table.\n");

    printf("%s\n",cfg_filename);
    /*proxy_parse_config_file(cfg_filename);*/

    ret = rte_hash_add_key_data(proxy_sf_address_lkp_table,&sfid_stub1, (void*) mac_stub1);
    SFCAPP_CHECK_FAIL_LT(ret,0,"Failed to add stub entry 1.\n");
    ret = rte_hash_add_key_data(proxy_sf_address_lkp_table,&sfid_stub2, (void*) mac_stub2);
    SFCAPP_CHECK_FAIL_LT(ret,0,"Failed to add stub entry 2.\n");
    
    sfcapp_cfg.main_loop = proxy_main_loop;

    return 0;
}


void proxy_update_macs(struct rte_mbuf *mbuf, struct ether_addr *dst_mac){

    struct ether_addr aux;

    /* Swap src and dst */
    pkttools_mac_swap(mbuf);

    pkttools_mac_update(mbuf,*dst_mac);
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
void proxy_handle_inbound_pkts(struct rte_mbuf **mbufs, uint16_t nb_pkts, 
    uint64_t *drop_mask){

    uint64_t nsh_header;
    uint32_t nsh_path_info;
    struct ipv4_5tuple ip_5tuples[BURST_SIZE];
    uint32_t vals[BURST_SIZE];
    struct ether_addr sf_mac;
    int i, lkp;

    *drop_mask = 0;

    ipv4_get_5tuple_bulk(mbufs,nb_pkts,ip_5tuples);
    
    /* Check if flow info is already stored in table */
    rte_hash_lookup_bulk(&proxy_flow_header_lkp_table,ip_5tuples,
            nb_pkts,vals);
            
    for(i = 0; i < nb_pkts ; i++){

        nsh_get_header(mbufs,&nsh_header);

        /* Flow not mapped yet in table. Let's add it */
        if(unlikely(vals[i] < 0)){
             rte_hash_add_key_data(&proxy_flow_header_lkp_table,
                ip_5tuples[i],(void *) &nsh_header);
        }

        /* Decapsulate packet */
        nsh_decap(mbufs[i]);
    
        /* Get only low part of from 64B header*/
        nsh_path_info = (uint32_t) nsh_header;
        
        /* Get SF MAC address from table */
        lkp = rte_hash_lookup_data(&proxy_sf_address_lkp_table, (void *) &nsh_path_info,
                (void **) &sf_mac);

        // Currently not dropping packets
        /*if( unlikely(lkp < 0) ){
            *drop_mask |= 1<<i;
            continue;
        }*/

        /* Update src and dst MAC */ 
        proxy_update_macs(mbufs[i],&sf_mac);
    }
}

void proxy_handle_outbound_pkts(struct rte_mbuf **mbufs, uint16_t nb_pkts, 
    uint64_t *drop_mask){

}

void proxy_main_loop(void){

    struct rte_mbuf *rx_pkts[BURST_SIZE];
    uint16_t nb_rx, nb_tx;
    uint64_t drop_mask;

    /* Receive packet */

    /* If it came from network ...*/

    /* Else (came from legacy SF) */
        /* Get packet header from hash table */
        /* Encapsulate packet */
        /* Decrement SI (or save it already decremented?) */
        /* Add SFF's MAC address */
        /* Send it to network */  
    
    for(;;){
    
        /* Receive packets from network */

        rte_eth_rx_burst(sfcapp_cfg.port1,0,
            rx_pkts,BURST_SIZE);

        /* Process and decap received packets*/
        proxy_handle_inbound_pkts(rx_pkts,nb_rx,&drop_mask);

        /* TODO: Only send packets not marked for dropping */
        send_pkts(rx_pkts,sfcapp_cfg.port2,0,rx_pkts);

        /* Receive packets from SFs */
        rte_eth_rx_burst(sfcapp_cfg.port2,0,
            rx_pkts,BURST_SIZE);

        /* Process and encap packets from SFs */
        proxy_handle_outbound_pkts(rx_pkts,nb_rx,&drop_mask);

        /* TODO: Only send packets not marked for dropping  */
        send_pkts(rx_pkts,sfcapp_cfg.port1,0,rx_pkts);  
    }
}


