﻿#include <stdio.h>
#include <stdlib.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "sfc_forwarder.h"
#include "common.h"
#include "nsh.h"

extern struct sfcapp_config sfcapp_cfg;

static struct rte_hash *forwarder_next_sf_lkp_table;
/* key = spi-si ; value = next sf_id (uint16_t) */

static struct rte_hash *forwarder_next_sf_address_lkp_table;
/* key = sf_id (uint16_t) ; value = mac (48b in 64b) (uint64_t) */

static int forwarder_init_next_sf_table(void){

    const struct rte_hash_parameters hash_params = {
        .name = "forwarder_next_sf",
        .entries = FORWARDER_TABLE_SZ,
        .reserved = 0,
        .key_len = sizeof(uint32_t), /* <SPI,SI> */
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id()
    };

    forwarder_next_sf_lkp_table = rte_hash_create(&hash_params);

    if(forwarder_next_sf_lkp_table == NULL)
        return -1;
    
    return 0;
}

static int forwarder_init_sf_addr_table(void){

    const struct rte_hash_parameters hash_params = {
        .name = "forwarder_sf_addr",
        .entries = FORWARDER_TABLE_SZ,
        .reserved = 0,
        .key_len = sizeof(uint16_t), /* <SPI,SI> */
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id()
    };

    forwarder_next_sf_address_lkp_table = rte_hash_create(&hash_params);

    if(forwarder_next_sf_address_lkp_table == NULL)
        return -1;
    
    return 0;
}

void forwarder_add_sph_entry(uint32_t sph, uint16_t sfid){
    int ret;

    ret = rte_hash_add_key_data(forwarder_next_sf_lkp_table,&sph, 
        (void *) ((uint64_t) sfid) );
    SFCAPP_CHECK_FAIL_LT(ret,0,"Failed to add stub entry to Forwarder table.\n");

    printf("Successfully added <sph=%" PRIx32 ",sfid=%" PRIx16 ">"
            " to forwarder next sf table.\n",sph,sfid);
}

void forwarder_add_sf_address_entry(uint16_t sfid, struct ether_addr *sfmac){
    int ret;

    ret = rte_hash_add_key_data(forwarder_next_sf_address_lkp_table,&sfid, 
        (void *) common_mac_to_64(sfmac));
    SFCAPP_CHECK_FAIL_LT(ret,0,"Failed to add SF entry to forwarder table.\n");

    char buf[ETHER_ADDR_FMT_SIZE + 1];
    ether_format_addr(buf,ETHER_ADDR_FMT_SIZE,sfmac);
    printf("Successfully added <sfid=%" PRIx16 ",mac=%s> to forwarder" 
        " SF-address table.\n",sfid,buf);
}

int forwarder_setup(void){
    int ret;
    uint32_t serv_path;
    uint16_t sfid;
    uint64_t data;

    ret = forwarder_init_next_sf_table();
    SFCAPP_CHECK_FAIL_LT(ret,0,"Failed to initialize Forwarder Next-Func table.\n");

    ret = forwarder_init_sf_addr_table();
    SFCAPP_CHECK_FAIL_LT(ret,0,"Failed to initialize Forwarder SF Address table.\n");

    sfcapp_cfg.main_loop = forwarder_main_loop;

    /* Add table entries here!!! */
    serv_path = 0x1FF; data = 0x1;
    ret = rte_hash_add_key_data(forwarder_next_sf_lkp_table,&serv_path,(void *) data);
    if(ret < 0)
        rte_exit(EXIT_FAILURE,"Could not add entry");
    serv_path = 0x1FD; data = 0x3;
    ret = rte_hash_add_key_data(forwarder_next_sf_lkp_table,&serv_path,(void *) data);
    if(ret < 0)
        rte_exit(EXIT_FAILURE,"Could not add entry");
    serv_path = 0x2FF; data = 0x3;    
    ret = rte_hash_add_key_data(forwarder_next_sf_lkp_table,&serv_path,(void *) data);
    if(ret < 0)
        rte_exit(EXIT_FAILURE,"Could not add entry");
    serv_path = 0x2FE; data = 0x1;       
    ret = rte_hash_add_key_data(forwarder_next_sf_lkp_table,&serv_path,(void *) data);
    if(ret < 0)
        rte_exit(EXIT_FAILURE,"Could not add entry");

    sfid = 0x1; data = 0x0000A1B1C1D1E1F1;
    ret = rte_hash_add_key_data(forwarder_next_sf_address_lkp_table,&sfid,(void *) data);
    if(ret < 0)
        rte_exit(EXIT_FAILURE,"Could not add entry");
    sfid = 0x3; data = 0x0000A3B3C3D3E3F3;
    ret = rte_hash_add_key_data(forwarder_next_sf_address_lkp_table,&sfid,(void *) data);
    if(ret < 0)
        rte_exit(EXIT_FAILURE,"Could not add entry");

    return 0;
}

/* static forwarder_parse_config_file(char** sections, int nb_sections); */

static inline void forwarder_handle_pkts(struct rte_mbuf **mbufs, uint16_t nb_pkts,
uint64_t *drop_mask){
    int lkp;
    uint16_t i;
    uint64_t data;
    struct nsh_hdr nsh_header;
    uint16_t sfid;
    struct ether_addr sf_addr;

    for(i = 0 ; i < nb_pkts ; i++){
        
        common_dump_pkt(mbufs[i],"\n=== Input packet ===\n");

        nsh_get_header(mbufs[i],&nsh_header);

        /* Match SFP to SF in table */
        lkp = rte_hash_lookup_data(forwarder_next_sf_lkp_table,
                (void*) &nsh_header.serv_path,
                (void **) &data);
        
        if(unlikely(lkp < 0)){
            RTE_LOG(NOTICE,USER1,"Failed to find entry in SPH->SF table\n");
            *drop_mask |= 1<<i;
            continue;
        }
        sfid = (uint16_t) data;

        /* Match SFID to address in table */
        lkp = rte_hash_lookup_data(forwarder_next_sf_address_lkp_table,
                (void*) &sfid,
                (void**) &data);
        
        if(unlikely(lkp < 0)){
            RTE_LOG(NOTICE,USER1,"Failed to find MAC address for SF\n");
            *drop_mask |= 1<<i;
            continue;
        }
        
        /* Update MACs */
        common_64_to_mac(data,&sf_addr);
        common_mac_update(mbufs[i],&sfcapp_cfg.port1_mac,&sf_addr);

        common_dump_pkt(mbufs[i],"\n=== Output packet ===\n");
    }

}
__attribute__((noreturn)) void forwarder_main_loop(void){

    uint16_t nb_rx;
    struct rte_mbuf *rx_pkts[BURST_SIZE];
    uint64_t drop_mask;
    
    for(;;){
        drop_mask = 0;

        nb_rx = rte_eth_rx_burst(sfcapp_cfg.port1,0,rx_pkts,
                    BURST_SIZE);

        if(likely(nb_rx > 0))
            forwarder_handle_pkts(rx_pkts,nb_rx,&drop_mask);

        /* Forwarder uses the same port for rx and tx */
        send_pkts(rx_pkts,sfcapp_cfg.port1,0,nb_rx);  
    }
}