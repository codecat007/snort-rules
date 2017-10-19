/*
 ** DHCP Option overflow
 ** 
 ** Copyright (C) 2006 Sourcefire, Inc. All Rights Reserved
 ** 
 ** Written by Lurene Grenier <lurene.grenier> & Brian Caswell <bmc@sourcefire.com>
 **
 ** This file may contain proprietary rules that were created, tested and
 ** certified by Sourcefire, Inc. (the "VRT Certified Rules") as well as
 ** rules that were created by Sourcefire and other third parties and
 ** distributed under the GNU General Public License (the "GPL Rules").  The
 ** VRT Certified Rules contained in this file are the property of
 ** Sourcefire, Inc. Copyright 2005 Sourcefire, Inc. All Rights Reserved.
 ** The GPL Rules created by Sourcefire, Inc. are the property of
 ** Sourcefire, Inc. Copyright 2002-2005 Sourcefire, Inc. All Rights
 ** Reserved.  All other GPL Rules are owned and copyrighted by their
 ** respective owners (please see www.snort.org/contributors for a list of
 ** owners and their respective copyrights).  In order to determine what
 ** rules are VRT Certified Rules or GPL Rules, please refer to the VRT
 ** Certified Rules License Agreement.
 **/

#include <string.h>
#include "sf_snort_plugin_api.h"
#include "sf_snort_packet.h"

int ruleDHCPCATeval(void *p);

/* content for sid 2257 */
static ContentInfo ruleDHCPCATcontent1 = 
{
    (uint8_t *)"|63 82 53 63|", /* pattern */
    4, /* depth */
    236, /* offset */
    CONTENT_FAST_PATTERN | CONTENT_BUF_NORMALIZED, 
    NULL, /* holder for boyer/moore PTR */
    NULL, /* more holder info - byteform */
    0 /* byteform length */
};

static RuleOption ruleDHCPCAToption1 = 
{
    OPTION_TYPE_CONTENT,
    {
        &ruleDHCPCATcontent1
    }
};

static RuleReference ruleDHCPCATref1 =
{
    "url", /* type */
    "technet.microsoft.com/en-us/security/bulletin/MS06-036" /* value XXX - update me */
};

static RuleReference ruleDHCPCATref2 =
{
    "cve", /* type */
    "2006-2372" /* value XXX - update me */
};

static RuleReference *ruleDHCPCATrefs[] =
{
    &ruleDHCPCATref1,
    &ruleDHCPCATref2,
    NULL
};

static RuleMetaData ruleDHCPCATpolicy1 = 
{
   "policy max-detect-ips drop"
};

static RuleMetaData *ruleDHCPCATmetadata[] =
{
   &ruleDHCPCATpolicy1,
   NULL
};

RuleOption *ruleDHCPCAToptions[] =
{
    &ruleDHCPCAToption1,
    NULL
};


Rule ruleDHCPCAT = {
   /* rule header, akin to => tcp any any -> any any               */{
       IPPROTO_UDP, /* proto */
       "any", /* SRCIP     */
       "any", /* SRCPORT   */
       0, /* DIRECTION */
       "any", /* DSTIP     */
       "68", /* DSTPORT   */
   },
   /* metadata */
   { 
       3,  /* genid (HARDCODED!!!) */
       7196, /* sigid b042351f-6f5e-43c6-aa84-f4040d0d6c83 */
       9, /* revision 82d5e41b-f883-44d4-ba85-4692e7d431e3 */
   
       "attempted-admin", /* classification XXX NOT PROVIDED BY GRAMMAR YET! */
       0,  /* hardcoded priority XXX NOT PROVIDED BY GRAMMAR YET! */
       "OS-WINDOWS Microsoft DHCP option overflow attempt",     /* message */
       ruleDHCPCATrefs, /* ptr to references */
       ruleDHCPCATmetadata
   },
   ruleDHCPCAToptions, /* ptr to rule options */
   ruleDHCPCATeval,                               /* Use internal eval func */
    0,                                  /* Not initialized */
    0,                                  /* Rule option count, used internally */
    0                                   /* Flag with no alert, used internally */
};

/* detection functions */
int ruleDHCPCATeval(void *p) {
    const uint8_t *end;
    const uint8_t *ptr;
    unsigned short type;
    unsigned short size;
    unsigned short sizes[256];
    SFSnortPacket *sp = (SFSnortPacket *) p;
    const uint8_t *cursor_normal = 0, *beg_of_payload;


    if (NULL == sp)
        return RULE_NOMATCH;

    if (NULL == sp->payload)
        return RULE_NOMATCH;

    if (contentMatch(p, ruleDHCPCAToptions[0]->option_u.content, &cursor_normal)) {
        if(getBuffer(sp, CONTENT_BUF_NORMALIZED, &beg_of_payload, &end) <= 0)
           return RULE_NOMATCH;

        /* offset for cookie + 2 options of size 500 */
        if (740 > (end - beg_of_payload))
        return RULE_NOMATCH;

        ptr = beg_of_payload + 240;
      
        memset(sizes, 0, sizeof(sizes));

        while (ptr + 2 < end)
        {
            type = (((uint8_t) *(ptr))&0xFF);
            size = (((uint8_t) *(ptr+1))&0xFF);
            if ((sizes[type] += size) > 500) {
                return RULE_MATCH;
            }
            ptr += 2 + size;
        }
    }

    return RULE_NOMATCH;
}
