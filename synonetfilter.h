/* Copyright (c) Synology Inc. All rights reserved.*/
#ifndef SYNONETFILTER_H
#define SYNONETFILTER_H

#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>

#define SMB2_PROTOCOL_ID 0xFE534D42

typedef enum __tag_SMB2_COMMAND {
    SMB2_WRITE = 0x900,
    SMB2_READ = 0x800,
} SMB2_COMMAND;
#define IS_WRITE(command) (command == SMB2_WRITE)
#define IS_READ(command) (command == SMB2_READ)

typedef enum __tag_SMB2_FLAGS {
    SMB2_FLAGS_SERVER_TO_REDIR =    0x01000000,
    SMB2_FLAGS_ASYNC_COMMAND =      0x02000000,
    SMB2_FLAGS_RELATED_OPERATIONS = 0x04000000,
    SMB2_FLAGS_SIGNED =             0x08000000,
    SMB2_FLAGS_DFS_OPERATIONS =     0x00000010,
    SMB2_FLAGS_REPLAY_OPERATION =   0x00000020,
} SMB2_FLAGS;
#define IS_RESPONSE(flags) (flags & SMB2_FLAGS_SERVER_TO_REDIR)
#define IS_REQUEST(flags) !IS_RESPONSE(flags)

struct SMB2_HEADER {
    __be32 protocolId;
    __be16 structureSize;
    __be16 creditCharge;
    __be32 reservedStatus;
    __be16 command;
    __be16 CreditReqRes;
    __be32 flags;
    __be32 nextCommand;
    __be64 messageId;
    __be32 reserved;
    __be32 treeId;
    __be64 sessionId;
    __be64 signatures[2];
};

static void printTCPIP(struct iphdr *iph, struct tcphdr *tcph)
{
    uint8_t *psaddr = NULL;
    uint8_t *pdaddr = NULL;
    uint32_t saddr = iph->saddr;
    uint32_t daddr = iph->daddr;
    if (iph == NULL || tcph == NULL) {
        goto fail;
    }
    psaddr = (uint8_t *)&saddr;
    pdaddr = (uint8_t *)&daddr;
    printk(KERN_NOTICE "%hu.%hu.%hu.%hu:%u -> %hu.%hu.%hu.%hu:%u",
                       psaddr[0], psaddr[1], psaddr[2], psaddr[3], ntohs(tcph->source),
                       pdaddr[0], pdaddr[1], pdaddr[2], pdaddr[3], ntohs(tcph->dest)
            );

fail:
    return;
};

#endif
