/* Copyright (c) Synology Inc. All rights reserved.*/
#ifndef SYNONETFILTER_H
#define SYNONETFILTER_H

#include <linux/types.h>

typedef enum __tag_SMB2_COMMAND {
    SMB2_WRITE = 0x900,
    SMB2_READ = 0x800,
} SMB2_COMMAND;

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

#endif
