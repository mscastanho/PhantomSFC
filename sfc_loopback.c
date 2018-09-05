#include <stdio.h>
#include <stdlib.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "common.h"
#include "sfc_loopback.h"

extern struct sfcapp_config sfcapp_cfg;

static int loopback_handle_pkts(struct rte_mbuf **mbufs, uint16_t nb_pkts){

    uint16_t nb_tx = 0;
    int i;
    
    for(i = 0 ; i < nb_pkts ; i++){
        if(likely(nb_pkts > 0)){
            nb_tx += rte_eth_tx_buffer(sfcapp_cfg.ports[1].id,0,sfcapp_cfg.ports[1].tx_buffer,mbufs[i]);
        }
    }

    return nb_tx;
}

int loopback_setup(void){

    sfcapp_cfg.ports[0].handle_pkts = loopback_handle_pkts;
    rte_eth_promiscuous_enable(sfcapp_cfg.ports[0].id);
    
    return 0;
}