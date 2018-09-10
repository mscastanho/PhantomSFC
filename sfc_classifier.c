#include <stdio.h>
#include <stdlib.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "sfc_classifier.h"
#include "common.h"
#include "nsh.h"

#define BURST_TX_DRAIN_US 100

extern struct sfcapp_config sfcapp_cfg;
extern long int n_rx, n_tx;

static struct rte_hash* classifier_flow_path_lkp_table;

static int classifier_init_flow_path_table(void){

    const struct rte_hash_parameters hash_params = {
        .name = "classifier_flow_path",
        .entries = CLASSIFIER_MAX_FLOWS,
        .reserved = 0,
        .key_len = sizeof(struct ipv4_5tuple),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id()
    };

    classifier_flow_path_lkp_table = rte_hash_create(&hash_params);

    if(classifier_flow_path_lkp_table == NULL)
        return -1;
    
    return 0;
}

void classifier_add_flow_class_entry(struct ipv4_5tuple *tuple, uint32_t sfp){
    int ret;
    struct ipv4_5tuple local_tuple;
    memcpy(&local_tuple,tuple,sizeof(struct ipv4_5tuple));

    sfp = (sfp<<8) | 0xFF;

    ret = rte_hash_add_key_data(classifier_flow_path_lkp_table,&local_tuple, 
        (void *) ((uint64_t) sfp));
    SFCAPP_CHECK_FAIL_LT(ret,0,"Failed to add entry to classifier table.\n");

    printf("Added ");
    common_print_ipv4_5tuple(&local_tuple);
    printf(" -> %" PRIx32 " to classifier flow table\n",sfp);
}

static int classifier_handle_pkts(struct rte_mbuf **mbufs, uint16_t nb_pkts){
    uint16_t i;
    uint64_t path_info;
    struct ipv4_5tuple tuple;
    struct nsh_hdr *nsh_header;
    int lkp,ret,drop,nb_tx;

    nb_tx = 0;

    for(i = 0 ; i < nb_pkts ; i++){
        drop = 0;

        // common_dump_pkt(mbufs[i],"\n\n=== pkt before ===\n");
        /* Get 5-tuple */
        ret = common_ipv4_get_5tuple(mbufs[i],&tuple,0);
        COND_MARK_DROP(ret,drop);
    
        /* Get matching SPH from table */
        lkp = rte_hash_lookup_data(classifier_flow_path_lkp_table,&tuple,(void**) &path_info);

        if(lkp >= 0){ /* Has entry in table */

            /* Encapsulate with Ethernet + NSH */
            common_encap(mbufs[i]);
            
            nsh_header = rte_pktmbuf_mtod_offset(mbufs[i],struct nsh_hdr *,sizeof(struct ether_hdr));

            nsh_header->serv_path = rte_cpu_to_be_32((uint32_t) path_info);

            common_mac_update(mbufs[i],&sfcapp_cfg.ports[1].mac,&sfcapp_cfg.sff_addr);
            sfcapp_cfg.rx_pkts++;

            // common_dump_pkt(mbufs[i],"\n=== pkt after ===\n");
        }

        /* No matching SFP, then just give back to network
         * without modification. 
         */

        /* Enqueue packet for TX */
        nb_tx += rte_eth_tx_buffer(sfcapp_cfg.ports[1].id,0,sfcapp_cfg.ports[1].tx_buffer,mbufs[i]);
    }

    return nb_tx;
}

int classifier_setup(void){

    int ret;
    ret = classifier_init_flow_path_table();
    SFCAPP_CHECK_FAIL_LT(ret,0,"Failed to initialize Classifier table\n");

    sfcapp_cfg.ports[0].handle_pkts = classifier_handle_pkts;

    // Enable promiscuous mode for RX interface
    rte_eth_promiscuous_enable(sfcapp_cfg.ports[0].id);

    return 0;
}