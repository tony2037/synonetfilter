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

static struct nf_hook_ops *nfhoIN = NULL;
static struct nf_hook_ops *nfhoOUT = NULL;

static int printSignificantPayload(unsigned char *data, unsigned int len, unsigned int range)
{
    size_t i = 0;
    size_t j = 0;
    unsigned char distill = 0xff;
    int ret = 0;
    for (i = 0; i < len; i++) {
        distill = distill & data[i];
        if (distill != 0xff) {
            if (i + 1 >= range) {
                for (j= i + 1 - range; j <= i; j++) {
                    printk(KERN_NOTICE "=>%x", data[j]);
                }
            }
            else if (len - i >= range) {
                for (j = i; j < i + range; j++) {
                    printk(KERN_NOTICE "=>%x", data[j]);
                }
            }
            else {
                printk(KERN_NOTICE "=>%x\n", data[i]);
            }
            ret = 1;
            break;
        }
    }

    return ret;
}

static unsigned int getSMB2Header(struct sk_buff *skb, struct SMB2_HEADER *smbhdr)
{    
    size_t offset = IP_HDR_SIZE + TCP_HDR_SIZE + NET_BIOS_SIZE;
    unsigned int ret = 0;
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

    ret = 1;
fail:
    return ret;
}

static unsigned int hfuncIN(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph = NULL;
    struct tcphdr *tcph = NULL;
    struct SMB2_HEADER smbhdr = {0};
    unsigned char *iter = NULL;
    unsigned char *tail = NULL;
    int ret = 0;

    if (!skb) {
        return NF_ACCEPT;
    }
    ret = skb_linearize(skb);
    if (ret != 0) {
        printk(KERN_NOTICE "linearize failed..");
    }

    iph = ip_hdr(skb);
    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        if (ntohs(tcph->dest) == 445) { // ntohs(x) __be16_to_cpu(x)
            printTCPIP(iph, tcph);

            if (!getSMB2Header(skb, &smbhdr)) {
                goto forward;
            }

            if (IS_WRITE(be16_to_cpu(smbhdr.command)) && IS_REQUEST(be32_to_cpu(smbhdr.flags))) {
                printk(KERN_NOTICE "write request\n");

                if (printSignificantPayload(&skb->data[TOTAL_WRITE_REQUEST_HDR_SIZE], skb->len - TOTAL_WRITE_REQUEST_HDR_SIZE, 4)) {
                    tail = skb_tail_pointer(skb);
                    for (iter = skb->data; iter != tail; iter++) {
                        printk(KERN_NOTICE "%x", *iter);
                    }
                }
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

static unsigned int hfuncOUT(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph = NULL;
    struct tcphdr *tcph = NULL;
    struct SMB2_HEADER smbhdr = {0};
    unsigned char *iter = NULL;
    unsigned char *tail = NULL;
    int ret = 0;

    if (!skb) {
        return NF_ACCEPT;
    }
    ret = skb_linearize(skb);
    if (ret != 0) {
        printk(KERN_NOTICE "linearize failed..");
    }

    iph = ip_hdr(skb);
    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);

        if (ntohs(tcph->source) == 445) { // ntohs(x) __be16_to_cpu(x)
            printTCPIP(iph, tcph);

            if (!getSMB2Header(skb, &smbhdr)) {
                goto forward;
            }

            if (IS_READ(be16_to_cpu(smbhdr.command)) && IS_RESPONSE(be32_to_cpu(smbhdr.flags))) {
                printk(KERN_NOTICE "read response\n");

                if (printSignificantPayload(&skb->data[TOTAL_READ_RESPONSE_HDR_SIZE], skb->len - TOTAL_READ_RESPONSE_HDR_SIZE, 4)) {
                    tail = skb_tail_pointer(skb);
                    for (iter = skb->data; iter != tail; iter++) {
                        printk(KERN_NOTICE "%x", *iter);
                    }
                }
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
    nfhoIN = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (nfhoIN == NULL) {
        goto fail;
    }
    
    /* Initialize netfilter hook */
    nfhoIN->hook = (nf_hookfn*)hfuncIN;     /* hook function */
    nfhoIN->hooknum = NF_INET_LOCAL_IN;    /* received packets */
    nfhoIN->pf = PF_INET;    /* IPv4 */
    nfhoIN->priority = NF_IP_PRI_FIRST;    /* max hook priority */

    nfhoOUT = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (nfhoOUT == NULL) {
        goto fail;
    }
    
    nfhoOUT->hook = (nf_hookfn*)hfuncOUT;     /* hook function */
    nfhoOUT->hooknum = NF_INET_LOCAL_OUT;    /* received packets */
    nfhoOUT->pf = PF_INET;    /* IPv4 */
    nfhoOUT->priority = NF_IP_PRI_FIRST;    /* max hook priority */

    nf_register_net_hook(&init_net, nfhoIN);
    nf_register_net_hook(&init_net, nfhoOUT);

fail:
    return 0;
}

static void __exit SYNONETFILTER_exit(void)
{
    if (nfhoIN != NULL) {
        nf_unregister_net_hook(&init_net, nfhoIN);
        kfree(nfhoIN);
    }
    if (nfhoOUT != NULL) {
        nf_unregister_net_hook(&init_net, nfhoOUT);
        kfree(nfhoOUT);
    }
}

module_init(SYNONETFILTER_init);
module_exit(SYNONETFILTER_exit);
