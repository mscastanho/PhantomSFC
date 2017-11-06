﻿#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>

#include "common.h"
#include "sfc_classifier.h"
#include "sfc_proxy.h"
#include "sfc_forwarder.h"


/* Remove later */
int n_rx=0, n_tx=0;

static uint8_t nb_ports;
struct sfcapp_config sfcapp_cfg;

char cfg_filename[64];

static struct rte_mempool *sfcapp_pktmbuf_pool;

static const struct rte_eth_conf port_cfg = {
    .rxmode = {
        .header_split   = 0, /* Header Split disabled*/
        .split_hdr_size = 0,
        .hw_ip_checksum = 0, /* Disable IP Checksum */
        .hw_vlan_filter = 0, /* Disable VLAN filtering */
        .jumbo_frame    = 0, /* No jumbo frames */
        .hw_strip_crc   = 1, /* Enable HW CRC strip*/
    },

    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

static void sfcapp_assoc_ports(int portmask){
    uint8_t i;
    int count = 2; /* We'll only setup 2 ports */

    nb_ports = rte_eth_dev_count();
    if(nb_ports < 2)
        rte_exit(EXIT_FAILURE,"Not enough ports! 2 needed.\n");

    for(i = 0 ; i < nb_ports && count > 0 ; i++, count--){
        if((portmask & (1 << i)) == 0)
            continue;
    
        switch(count){
            case 2:
                sfcapp_cfg.port1 = i;
                break;
            case 1:
                sfcapp_cfg.port2 = i;
                break;
            default:
                break;
        }
    }
}

static int
parse_portmask(const char *portmask)
{
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

static const char sfcapp_options[] = {
    'p', /* Port mask */
    't', /* SFC entity type*/
    'f', /* Configuration file */
    'h', /* Print usage */
    'H' /* Hash table size*/
};

static void 
parse_args(int argc, char **argv){
    /* List of possible arguments
     * -t : Type (classifier, proxy, SFF)
     * -f : Configuration file (with rules, list of SFs, etc )
     * -H : Hash table size
     * -h : Print usage information
     */
    int sfcapp_opt;
    int pm;

    while( (sfcapp_opt = getopt(argc,argv,"p:t:hH:")) != -1){
        switch(sfcapp_opt){
            case 'p':
                pm = parse_portmask(optarg);
                if(pm < 0)
                    rte_exit(EXIT_FAILURE,"Failed to parse portmask\n");
                else
                    sfcapp_assoc_ports(pm);
                break;
            case 't':
                break;
            case 'f':
                break;
            case 'h':
                break;
            case 'H':
                break;
            case '?':
                break;
            default:
                rte_exit(EXIT_FAILURE,"Unrecognized option: %c\n",sfcapp_opt);
                break;
        }
    }
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\n%d packets received\n%d packets transmitted",
				n_rx,n_tx);
    }
    
    exit(0);
}

/* Function to allocate memory to be used by the application */ 
static void
alloc_mem(unsigned n_mbuf){

    unsigned lcore_id;
    const char* pool_name = "mbuf_pool";

    for(lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++){
        if(!rte_lcore_is_enabled(lcore_id))
            continue;
        
        if(sfcapp_pktmbuf_pool == NULL){
            sfcapp_pktmbuf_pool = rte_pktmbuf_pool_create(
                pool_name,
                n_mbuf,
                MEMPOOL_CACHE_SIZE,
                0,
                RTE_MBUF_DEFAULT_BUF_SIZE,
                rte_socket_id());
            
            if(sfcapp_pktmbuf_pool == NULL)
                rte_exit(EXIT_FAILURE,
                    "Failed to allocate mbuf pool\n");
            else
                printf("Successfully allocated mbuf pool\n");
        }

    }
}

static int
init_port(uint8_t port, struct rte_mempool *mbuf_pool){
    struct rte_eth_conf port_conf = port_cfg;
    int ret;
    uint16_t q;

    if(port >= rte_eth_dev_count())
        return -1;
    
    ret = rte_eth_dev_configure(port,NB_RX_QS,NB_TX_QS,&port_conf);
    if(ret != 0)
        return ret;
    
    /* Setup TX queues */
    for(q = 0 ; q < NB_TX_QS ; q++){
        ret = rte_eth_tx_queue_setup(port, q, NB_TX_DESC,
            rte_eth_dev_socket_id(port), NULL);

        if(ret < 0)
            return ret;
    }

    /* Setup RX queues */
    for(q = 0 ; q < NB_RX_QS ; q++){
        ret = rte_eth_rx_queue_setup(port, q, NB_RX_DESC,
            rte_eth_dev_socket_id(port), NULL, mbuf_pool);

        if(ret < 0)
            return ret;
    }

    ret = rte_eth_dev_start(port);

    if(ret > 0)
        return ret;

    struct ether_addr eth_addr;
    rte_eth_macaddr_get(port,&eth_addr);
    printf("MAC of port %u: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
            ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
            (unsigned) port,
            eth_addr.addr_bytes[0],eth_addr.addr_bytes[1],
            eth_addr.addr_bytes[2],eth_addr.addr_bytes[3],
            eth_addr.addr_bytes[4],eth_addr.addr_bytes[5]);

    /* Remove this later! */
    rte_eth_promiscuous_enable(port);

    return 0;

}

static int 
init_app(void) {
    int ret=0;

    /* Parse config file and init app*/
    switch(sfcapp_cfg.type){
        case SFC_CLASSIFIER:
            //ret = classifier_setup(cfg_filename);
            break;
        case SFC_FORWARDER:
            //ret = forwarder_setup(cfg_filename);
            break;
        case SFC_PROXY:
            ret = proxy_setup(cfg_filename);
            break;
    }

    return ret;
}

static __attribute__((noreturn)) void 
main_loop(void) {
    int rx_port = 0;
    int tx_port = 1;

    for(;;){
        struct rte_mbuf *rx_pkts[BURST_SIZE];
        uint16_t nb_rx = rte_eth_rx_burst(rx_port,0,
            rx_pkts,BURST_SIZE);
        
        if(unlikely(nb_rx == 0))
            continue;
        
        n_rx += nb_rx;
        
        uint16_t nb_tx = rte_eth_tx_burst(tx_port,0,
            rx_pkts,nb_rx);

        n_tx += nb_tx;

        if(unlikely(nb_tx < nb_rx)){
            uint16_t buf;
            for(buf = nb_tx ; buf < nb_rx ; buf++)
                rte_pktmbuf_free(rx_pkts[buf]);
        }
    
    }
}

int 
main(int argc, char **argv){

    int ret=0;
    int nb_lcores;

    ret = rte_eal_init(argc,argv);
    if(ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments.\n");

    argc -= ret;
    argv += ret;

    parse_args(argc,argv);

    alloc_mem(NB_MBUF);

    /* Remove later*/
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    ret = init_port(sfcapp_cfg.port1,sfcapp_pktmbuf_pool);
    SFCAPP_CHECK_FAIL_LT(ret,0,"Failed to setup RX port.\n");

    ret = init_port(sfcapp_cfg.port2,sfcapp_pktmbuf_pool);
    SFCAPP_CHECK_FAIL_LT(ret,0,"Failed to setup TX port.\n");

    /* Init TX buffer */
    /*ret = rte_eth_tx_buffer_init(&sfcapp_cfg.tx_buffer,BURST_SIZE);
    SFCAPP_CHECK_FAIL_LT(ret,0,"Failed to create TX buffer.\n");
    */

    nb_lcores = rte_lcore_count();
    SFCAPP_CHECK_FAIL_LT(nb_lcores,1,"Not enough lcores! At least 1 needed.\n");

    /* Read config files and setup app*/    
    ret = init_app();
    SFCAPP_CHECK_FAIL_LT(ret,0,"Failed to init app\n");
        
    /* Start app (single core) */
    (sfcapp_cfg.main_loop)();

    return 0;
}