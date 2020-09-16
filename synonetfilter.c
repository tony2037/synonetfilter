/* Copyright (c) Synology Inc. All rights reserved.*/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "synonetfilter.h"
#define SMB2_PROTOCOL_ID 4266872130 // FE 53 4D 42
#define IP_HDR_SIZE 20
#define TCP_HDR_SIZE 20
#define NET_BIOS_SIZE 4
#define SMB2_HDR_SIZE 64
#define SMB2_WRITE_REQUEST_SIZE 48
#define SMB2_READ_RESPONSE_SIZE 16
#define TOTAL_HDR_SIZE (IP_HDR_SIZE +\
                        TCP_HDR_SIZE +\
                        NET_BIOS_SIZE +\
                        SMB2_HDR_SIZE +\
                        SMB2_WRITE_REQUEST_SIZE\
                        )

static struct nf_hook_ops *nfho = NULL;

static unsigned int filterSMB2Payload(unsigned char *data, unsigned int len)
{
    size_t i = 0;
    unsigned char distill = 0xff;
    for (i = 0; i < len; i++) {
        distill = distill & data[i];
    }
    
    if (distill == 0xff) {
        return 0;
    }
    else {
        return 1;
    }
}

static void printSignificantPayload(unsigned char *data, unsigned int len, unsigned int range)
{
    size_t i = 0;
    size_t j = 0;
    unsigned char distill = 0xff;
    for (i = 0; i < len; i++) {
        distill = distill & data[i];
        if (distill != 0xff) {
            if (i + 1 >= range) {
                for (j= i + 1 - range; j <= i; j++) {
                    printk(KERN_NOTICE "%x", data[j]);
                }
            }
            else if (len - i >= range) {
                for (j = i; j < i + range; j++) {
                    printk(KERN_NOTICE "%x", data[j]);
                }
            }
            else {
                printk(KERN_NOTICE "%x\n", data[i]);
            }
            break;
        }
    }
}

static unsigned int getSMB2Header(struct sk_buff *skb, struct SMB2_HEADER *smbhdr)
{    
    size_t offset = IP_HDR_SIZE + TCP_HDR_SIZE + NET_BIOS_SIZE;
    if (!skb || !smbhdr) {
        goto fail;
    }
    if (skb->len < (IP_HDR_SIZE + TCP_HDR_SIZE + NET_BIOS_SIZE + SMB2_HDR_SIZE)) {
        goto fail;
    }

    memcpy(smbhdr, &skb->data[offset], SMB2_HDR_SIZE);
    if (be32_to_cpu(smbhdr->protocolId) != SMB2_PROTOCOL_ID) {
        goto fail;
    }

    return 1;
fail:
    return 0;
}

static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph = NULL;
    struct tcphdr *tcph = NULL;
    struct SMB2_HEADER smbhdr = {0};
    char command[16] = {0};

    if (!skb) {
        return NF_ACCEPT;
    }

    iph = ip_hdr(skb);
    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        if (ntohs(tcph->dest) == 445) { // ntohs(x) __be16_to_cpu(x)
            printk(KERN_NOTICE "%u:%u -> %u:%u", ntohl(iph->saddr), ntohs(tcph->source), ntohl(iph->daddr), ntohs(tcph->dest));

            if (!getSMB2Header(skb, &smbhdr)) {
                goto forward;
            }
            if (be16_to_cpu(smbhdr.command) == SMB2_WRITE) {
                memcpy(command, "write", 5);
            }
            else if (be16_to_cpu(smbhdr.command) == SMB2_READ) {
                memcpy(command, "read", 4);
            }
            else {
                goto forward;
            }

            printk(KERN_NOTICE "%s request\n", command);

            if (filterSMB2Payload(&skb->data[TOTAL_HDR_SIZE], skb->len - TOTAL_HDR_SIZE)) {
                printSignificantPayload(&skb->data[TOTAL_HDR_SIZE], skb->len - TOTAL_HDR_SIZE, 4);
            }
        }
        goto forward;
    }
    else if (iph->protocol == IPPROTO_UDP) {
        goto forward;
    }

    return NF_DROP;
forward:
    return NF_ACCEPT;
}

static int __init SYNONETFILTER_init(void)
{
    nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    
    /* Initialize netfilter hook */
    nfho->hook = (nf_hookfn*)hfunc;     /* hook function */
    nfho->hooknum = NF_INET_LOCAL_IN;    /* received packets */
    nfho->pf = PF_INET;    /* IPv4 */
    nfho->priority = NF_IP_PRI_FIRST;    /* max hook priority */
    
    nf_register_net_hook(&init_net, nfho);

    return 0;
}

static void __exit SYNONETFILTER_exit(void)
{
    nf_unregister_net_hook(&init_net, nfho);
    kfree(nfho);
}

module_init(SYNONETFILTER_init);
module_exit(SYNONETFILTER_exit);
