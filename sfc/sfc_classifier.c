#include <stdio.h>
#include <stdlib.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "sfc_classifier.h"
#include "common.h"
#include "nsh.h"
#include "ubpf.h"

#define BURST_TX_DRAIN_US 100

extern struct sfcapp_config sfcapp_cfg;
extern long int n_rx, n_tx;

static struct rte_hash* classifier_flow_path_lkp_table;

/* eBPF classification function */
static ubpf_jit_fn cls_fn = NULL;
struct ubpf_vm *vm;

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

static int classifier_proc_pkt(struct rte_mbuf *mbuf, int match, uint32_t path_info){
    struct nsh_hdr nsh_header;

    if(match >= 0){ /* Has entry in table */

        /* Encapsulate with VXLAN */
        common_vxlan_encap(mbuf);
        
        nsh_init_header(&nsh_header);
        nsh_header.serv_path = path_info;

        /* Encapsulate packet */
        nsh_encap(mbuf,&nsh_header);
        
        common_mac_update(mbuf,&sfcapp_cfg.ports[1].mac,&sfcapp_cfg.sff_addr);
        sfcapp_cfg.rx_pkts++;
    }

    /* No matching SFP, then just give back to network
    * without modification. 
    */

    /* Enqueue packet for TX */
    return rte_eth_tx_buffer(sfcapp_cfg.ports[1].id,0,sfcapp_cfg.ports[1].tx_buffer,mbuf);
}

static int classifier_handle_pkts(struct rte_mbuf **mbufs, uint16_t nb_pkts){
    uint16_t i;
    uint64_t path_info;
    struct ipv4_5tuple tuple;
    int lkp,ret,drop,nb_tx;

    nb_tx = 0;

    for(i = 0 ; i < nb_pkts ; i++){
        drop = 0;

        /* Get 5-tuple */
        ret = common_ipv4_get_5tuple(mbufs[i],&tuple,0);
        COND_MARK_DROP(ret,drop);
    
        /* Get matching SPH from table */
        lkp = rte_hash_lookup_data(classifier_flow_path_lkp_table,&tuple,(void**) &path_info);

        nb_tx += classifier_proc_pkt(mbufs[i],lkp,(uint32_t) path_info);
    }

    return nb_tx;
}

static int classifier_ebpf_handle_pkts(struct rte_mbuf **mbufs, uint16_t nb_pkts){
    uint16_t i;
    uint64_t path_info;
    int lkp,nb_tx;

    nb_tx = 0;
    lkp = 0;

    for(i = 0 ; i < nb_pkts ; i++){
    
        path_info = cls_fn(rte_pktmbuf_mtod(mbufs[i], struct ether_hdr *),mbufs[i]->pkt_len);

        /* If no chain configured, path_info should be 0 */
        if(path_info != 0)
            lkp = 1;
        
        nb_tx += classifier_proc_pkt(mbufs[i],lkp,(uint32_t) path_info);
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

int classifier_ebpf_setup(void *elf, int len){

    int ret = 0;
    int err;
    char *errmsg;

    /* Load and compile eBPF program */
    err = ubpf_load_elf(vm, elf, len, &errmsg);

    if (err != 0) {
        printf("Error message: %s\n", errmsg);
        free(errmsg);
        ret = 1;
    }

    // On x86-64 architectures use the JIT compiler, otherwise fallback to the interpreter
    #if __x86_64__
        ubpf_jit_fn ebpfprog = ubpf_compile(vm, &errmsg);
    #else
        ubpf_jit_fn ebpfprog = ebpf_exec;
    #endif

    if (ebpfprog == NULL) {
        printf("Error JIT %s\n", errmsg);
        free(errmsg);
        ret = 1;
    }

    cls_fn = ebpfprog;
    
    /* --- */

    sfcapp_cfg.ports[0].handle_pkts = classifier_ebpf_handle_pkts;

    // Enable promiscuous mode for RX interface
    rte_eth_promiscuous_enable(sfcapp_cfg.ports[0].id);

    return ret;
}