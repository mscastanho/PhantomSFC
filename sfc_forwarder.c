#include <stdio.h>
#include <stdlib.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_common.h>

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
        .key_len = sizeof(uint16_t), /* SFID */
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

    printf("Added <sph=%" PRIx32 ",sfid=%" PRIx16 ">"
            " to forwarder next sf table.\n",sph,sfid);
}

void forwarder_add_sf_address_entry(uint16_t sfid, struct ether_addr *sfmac){
    int ret;

    ret = rte_hash_add_key_data(forwarder_next_sf_address_lkp_table,&sfid, 
        (void *) common_mac_to_64(sfmac));
    SFCAPP_CHECK_FAIL_LT(ret,0,"Failed to add SF entry to forwarder table.\n");

    char buf[ETHER_ADDR_FMT_SIZE + 1];
    ether_format_addr(buf,ETHER_ADDR_FMT_SIZE,sfmac);
    printf("Added <sfid=%" PRIx16 ",mac=%s> to forwarder" 
        " SF-address table.\n",sfid,buf);
}

static int forwarder_handle_pkts(struct rte_mbuf **mbufs, uint16_t nb_pkts){
    int lkp, nb_tx, drop;
    uint16_t i;
    uint64_t data;
    struct nsh_hdr nsh_header;
    uint16_t sfid;
    struct ether_addr sf_addr;

    nb_tx = 0;
    
    for(i = 0, nb_tx = 0 ; i < nb_pkts ; i++){
        drop = 0;

        nsh_get_header(mbufs[i],&nsh_header);

        /* Match SFP to SF in table */
        lkp = rte_hash_lookup_data(forwarder_next_sf_lkp_table,
                (void*) &nsh_header.serv_path,
                (void **) &data);
        COND_MARK_DROP(lkp,drop);

        sfid = (uint16_t) data;
       
        if(sfid == 0){  /* End of chain */
            nsh_decap(mbufs[i]);

            /* Remove VXLAN encap! */
            rte_pktmbuf_adj(mbufs[i],
                sizeof(struct ether_hdr) +
                sizeof(struct ipv4_hdr) +
                sizeof(struct udp_hdr) +
                sizeof(struct vxlan_hdr));
        }else{
            /* Match SFID to address in table */
            lkp = rte_hash_lookup_data(forwarder_next_sf_address_lkp_table,
                    (void*) &sfid,
                    (void**) &data);
            COND_MARK_DROP(lkp,drop);
            /* Update MACs */
            common_64_to_mac(data,&sf_addr);
            common_mac_update(mbufs[i],&sfcapp_cfg.ports[1].mac,&sf_addr);
        }

        /* Enqueue packet for TX */
        nb_tx += rte_eth_tx_buffer(sfcapp_cfg.ports[1].id,0,sfcapp_cfg.ports[1].tx_buffer,mbufs[i]);
    
        if(unlikely(drop))
            rte_pktmbuf_free(mbufs[i]);
    }

    return nb_tx;

}

int forwarder_setup(void){
    int ret;

    ret = forwarder_init_next_sf_table();
    SFCAPP_CHECK_FAIL_LT(ret,0,"Failed to initialize Forwarder Next-Func table.\n");

    ret = forwarder_init_sf_addr_table();
    SFCAPP_CHECK_FAIL_LT(ret,0,"Failed to initialize Forwarder SF Address table.\n");

    sfcapp_cfg.ports[0].handle_pkts = forwarder_handle_pkts;
    
    return 0;
}