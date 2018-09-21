#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_cfgfile.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_common.h>

#include "common.h"
#include "parser.h"
#include "sfc_classifier.h"
#include "sfc_proxy.h"
#include "sfc_forwarder.h"
#include "sfc_loopback.h"
#include "nsh.h"

struct sfcapp_config sfcapp_cfg;

char* cfg_filename = NULL;
char* elf_filename = NULL;

struct rte_mempool *sfcapp_pktmbuf_pool;

static const struct rte_eth_conf dev_cfg = {
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
    int count = 0; /* We'll only setup 2 ports */
    int nb_ports_avlb = rte_eth_dev_count();

    if(nb_ports_avlb < 2)
        rte_exit(EXIT_FAILURE,"Not enough ports! 2 needed.\n");

    for(i = 0 ; i < nb_ports_avlb && count < 2 ; i++){
        if((portmask & (1 << i)) == 0)
            continue;
    
        sfcapp_cfg.ports[count++].id = i;
    }

    /* Hardcoded since we are only using 1 port for RX and another 
     * for TX */
    sfcapp_cfg.nb_ports = 2;
}

const struct option sfcapp_options[] = {
    {"pmask"    , required_argument , 0 ,   'p' }, /* Port mask */
    {"type"     , required_argument , 0 ,   't' }, /* SFC entity type*/
    {"config"   , required_argument , 0 ,   'c' }, /* Configuration file */
    {"help"     , no_argument       , 0 ,   'h' }, /* Print usage */
    {"ebpf"     , required_argument , 0 ,   'e' }, /* Enable eBPF classification */
    {0          , 0                 , 0 ,   0   },
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
    enum sfcapp_type type;

    while( (sfcapp_opt = getopt_long(argc,argv,"p:t:c:he:",sfcapp_options,NULL)) != -1){
        switch(sfcapp_opt){
            case 'p':
                pm = parse_portmask(optarg);
                if(pm < 0)
                    rte_exit(EXIT_FAILURE,"Failed to parse portmask\n");
                else
                    sfcapp_assoc_ports(pm);
                break;
            case 't':
                type = parse_apptype(optarg);
                if(type == NONE)
                    rte_exit(EXIT_FAILURE,"Unrecognized type parameter.\n");
                else
                    sfcapp_cfg.type = type;
                break;
            case 'c':
                cfg_filename = optarg;
                break;
            case 'h':
                break;
            case 'e':
                elf_filename = optarg;
                break;
            case '?':
                break;
            default:
                rte_exit(EXIT_FAILURE,"Unrecognized option: %c\n",sfcapp_opt);
                break;
        }
    }
}

static void setup_app(void){

    switch(sfcapp_cfg.type){
        case SFC_CLASSIFIER:
            if(elf_filename == NULL){
                classifier_setup();
                parse_config_file(cfg_filename);
            }else{
                char* elf;
                long int len;
                elf = parse_ebpf_file(elf_filename,&len);
                classifier_ebpf_setup((void*) elf,len);
            }
            break;
        case SFC_FORWARDER:
            forwarder_setup();
            parse_config_file(cfg_filename);
            break;
        case SFC_PROXY:
            proxy_setup();
            parse_config_file(cfg_filename);
            break;
        case SFC_LOOPBACK:
            loopback_setup();
            break;
        case NONE:
            rte_exit(EXIT_FAILURE,"App type not detected, something is wrong!\n");
            break;
    };       
}

static void print_stats(void)
{    
    printf("\n\n%ld packets received\n%ld packets transmitted\n"
        "%ld packets dropped\n",
        sfcapp_cfg.rx_pkts,sfcapp_cfg.tx_pkts,sfcapp_cfg.dropped_pkts);
}

static void
signal_handler(int signum)
{
    switch(signum){
        case SIGUSR1: // Zero statistics
            sfcapp_cfg.tx_pkts = 0;
            sfcapp_cfg.rx_pkts = 0;
            sfcapp_cfg.dropped_pkts = 0;
            break;
        case SIGINT: // Print statistics
            print_stats();
            break;
        case SIGQUIT: // Print statistics and quit
            // print_stats();
            exit(0);
            break;
        default:
            print_stats();
    }
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

// static void
// drop_rtx_cnt_callback(struct rte_mbuf **pkts, uint16_t unsent, void *userdata){
//     // unsigned int _sent = 0;
//     // int cnt = unsent<<3; // 8 tries for each packet
//     // do {
//     //     /* Note: hard-coded TX queue */
//     //     _sent += rte_eth_tx_burst(sfcapp_cfg.port2, 0, &pkts[_sent],
//     //                                     unsent - _sent);
//     // } while (_sent != unsent && cnt-- > 0);

//     sfcapp_cfg.dropped_pkts += unsent;
//     // drop_rtx_cnt[0] += unsent;
//     // drop_rtx_cnt[1] += _sent;

// }

static int
init_port(uint8_t port, struct rte_mempool *mbuf_pool){
    struct rte_eth_conf port_conf = dev_cfg;
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

    rte_eth_promiscuous_disable(port);

    return 0;

}

static void sfcapp_main_loop(void){

    uint16_t nb_rx, nb_tx;
    struct rte_mbuf *rx_pkts[BURST_SIZE];
    uint64_t prev_tsc, cur_tsc;
    struct port_cfg *p_cfg;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
    int p;
    
    prev_tsc = 0;

    for(;;){
        cur_tsc = rte_rdtsc();

        /* Periodic buffer flush to reduce packet wait time 
         * in the TX buffer */
        if(unlikely(cur_tsc - prev_tsc > drain_tsc)){
            common_flush_tx_buffers();
            prev_tsc = cur_tsc;
        }

        for(p = 0 ; p < sfcapp_cfg.nb_ports ; p++){
            p_cfg = &sfcapp_cfg.ports[p];

            /* Receive pkts */
            nb_rx = rte_eth_rx_burst(p_cfg->id,0,rx_pkts,
                        BURST_SIZE);
            nb_tx = 0;

            /* Process pkts */
            if(likely(nb_rx > 0 && p_cfg->handle_pkts != NULL)){
                nb_tx = (uint16_t) p_cfg->handle_pkts(rx_pkts,nb_rx);

            }

            /* Update stats */
            sfcapp_cfg.rx_pkts += nb_rx;
            sfcapp_cfg.tx_pkts += nb_tx;
        }
    }
}

int main(int argc, char **argv){

    int i,ret=0;
    unsigned nb_lcores;
    
    ret = rte_eal_init(argc,argv);
    if(ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments.\n");

    rte_openlog_stream(stderr);

    argc -= ret;
    argv += ret;

    parse_args(argc,argv);

    nb_lcores = rte_lcore_count();
    SFCAPP_CHECK_FAIL_LT(nb_lcores,1,"Not enough lcores! At least 1 needed.\n");

    alloc_mem(RTE_MAX(2*NB_RX_DESC +
              2*nb_lcores*BURST_SIZE +
              2*NB_TX_DESC +
              nb_lcores*MEMPOOL_CACHE_SIZE,
              (unsigned) 8192));

    /* Set signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGUSR1, signal_handler);
    signal(SIGQUIT, signal_handler);

    /* Setup interfaces */
    for( i = 0 ; i < sfcapp_cfg.nb_ports ; i++ ){

        /* Initialize device */
        ret = init_port(sfcapp_cfg.ports[i].id,sfcapp_pktmbuf_pool);
        SFCAPP_CHECK_FAIL_LT(ret,0,"Failed to setup RX port.\n");
        
        /* Save MAC address */
        rte_eth_macaddr_get(sfcapp_cfg.ports[i].id,&sfcapp_cfg.ports[i].mac);

        /* Initialize TX buffers */
        sfcapp_cfg.ports[i].tx_buffer = rte_zmalloc(NULL, RTE_ETH_TX_BUFFER_SIZE(BURST_SIZE), 0);
        ret = rte_eth_tx_buffer_init(sfcapp_cfg.ports[i].tx_buffer,BURST_SIZE);
        SFCAPP_CHECK_FAIL_LT(ret,0,"Failed to create TX buffer1.\n");
        
        /* Set callbacks */
        rte_eth_tx_buffer_set_err_callback(sfcapp_cfg.ports[i].tx_buffer,
            rte_eth_tx_buffer_count_callback,&sfcapp_cfg.dropped_pkts);

        /* Set IP address*/
        sfcapp_cfg.ports[i].ip = 0; // TODO: changed later

        /* This value will be set by the corresponding element's
         * setup function. */
        sfcapp_cfg.ports[i].handle_pkts = NULL;
    }

    /* Initialize corresponding tables */
    setup_app();

    /* Print SFF's MAC read from config files */
    char mac[64];
    ether_format_addr(mac,64,&sfcapp_cfg.sff_addr);
    printf("SFF MAC: %s\n",mac);

    /* Reset stats */
    sfcapp_cfg.tx_pkts = 0;
    sfcapp_cfg.rx_pkts = 0;
    sfcapp_cfg.dropped_pkts = 0;
    
    /* Start application (single core) */
    printf("Running...\n");
    sfcapp_main_loop();

    return 0;
}