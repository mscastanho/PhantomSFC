#include <stdio.h>
#include <stdlib.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "common.h"
#include "sfc_loopback.h"

extern struct sfcapp_config sfcapp_cfg;

int loopback_setup(void){

    sfcapp_cfg.main_loop = loopback_main_loop;
    rte_eth_promiscuous_enable(sfcapp_cfg.port1);
    
    return 0;
}

__attribute__((noreturn)) void loopback_main_loop(void){

    uint16_t nb_rx;
    struct rte_mbuf *rx_pkts[BURST_SIZE];
    uint64_t drop_mask;
    
    for(;;){
        drop_mask = 0;

        common_flush_tx_buffers();

        nb_rx = rte_eth_rx_burst(sfcapp_cfg.port1,0,rx_pkts,
                    BURST_SIZE);

        if(likely(nb_rx > 0)){
            /* Function will only forward packets to second interface without change */
            send_pkts(rx_pkts,sfcapp_cfg.port2,0,sfcapp_cfg.tx_buffer2,nb_rx,drop_mask);
        }
    }
}