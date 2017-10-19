/*
 * imail_imap version buffer overflow exploit attempt
 * 
 * Copyright (C) 2007 Sourcefire, Inc. All Rights Reserved
 * 
 * Writen by Patrick Mullen <pmullen@sourcefire.com>
 *
 * This file may contain proprietary rules that were created, tested and
 * certified by Sourcefire, Inc. (the "VRT Certified Rules") as well as
 * rules that were created by Sourcefire and other third parties and
 * distributed under the GNU General Public License (the "GPL Rules").  The
 * VRT Certified Rules contained in this file are the property of
 * Sourcefire, Inc. Copyright 2005 Sourcefire, Inc. All Rights Reserved.
 * The GPL Rules created by Sourcefire, Inc. are the property of
 * Sourcefire, Inc. Copyright 2002-2005 Sourcefire, Inc. All Rights
 * Reserved.  All other GPL Rules are owned and copyrighted by their
 * respective owners (please see www.snort.org/contributors for a list of
 * owners and their respective copyrights).  In order to determine what
 * rules are VRT Certified Rules or GPL Rules, please refer to the VRT
 * Certified Rules License Agreement.
 */


#include "sf_snort_plugin_api.h"
#include "sf_snort_packet.h"

#ifndef PM_EXP2
#define PM_EXP2(A) 1 << A
#endif

/* declare detection functions */
int ruleIMAIL_LDAPeval(void *p);

static RuleReference ruleIMAIL_LDAPref0 = 
{
    "url", /* type */
    "labs.idefense.com/intelligence/vulnerabilities/display.php?id=74" /* value */
};
static RuleReference ruleIMAIL_LDAPcve =
{
    "cve", /* type */
    "2004-0297"
};


static RuleReference *ruleIMAIL_LDAPrefs[] =
{
    &ruleIMAIL_LDAPref0,
    &ruleIMAIL_LDAPcve,
    NULL
};

static FlowFlags ruleIMAIL_LDAPflow =
{
    FLOW_ESTABLISHED|FLOW_TO_SERVER
};

static RuleOption ruleIMAIL_LDAPoption0 =
{
    OPTION_TYPE_FLOWFLAGS,
    {
        &ruleIMAIL_LDAPflow
    }
};

static ContentInfo ruleIMAIL_LDAPcontent =
{
    (uint8_t *)"|30|",                 /* pattern to search for */
    1,                      /* depth */
    0,                      /* offset */
    CONTENT_BUF_NORMALIZED,                      /* flags */
    NULL,                   /* holder for boyer/moore info */
    NULL,                   /* holder for byte representation of "NetBus" */
    0,                      /* holder for length of byte representation */
    0                       /* holder of increment length */
};

static RuleOption ruleIMAIL_LDAPoption1 =
{
    OPTION_TYPE_CONTENT,
    {
        &ruleIMAIL_LDAPcontent
    }
};


RuleOption *ruleIMAIL_LDAPoptions[] =
{
    &ruleIMAIL_LDAPoption0,
    &ruleIMAIL_LDAPoption1,
    NULL
};

Rule ruleIMAIL_LDAP = {
   /* rule header */
   {
       IPPROTO_TCP, /* proto */
       EXTERNAL_NET, /* SRCIP     */
       "any", /* SRCPORT   */
       0, /* DIRECTION */
       HOME_NET, /* DSTIP     */
       "389", /* DSTPORT   */
   },
   /* metadata */
   { 
       3,  /* genid (HARDCODED!!!) */
       10480, /* sigid d056361f-e644-4242-a918-92131e0b523d */
       4, /* revision 9ffa9a9e-3274-4df9-b54e-a1978f964bbd */
   
       "attempted-admin", /* classification, generic */
       0,  /* hardcoded priority XXX NOT PROVIDED BY GRAMMAR YET! */
       "SERVER-OTHER imail ldap buffer overflow exploit attempt",     /* message */
       ruleIMAIL_LDAPrefs /* ptr to references */
        ,NULL
   },
   ruleIMAIL_LDAPoptions, /* ptr to rule options */
   &ruleIMAIL_LDAPeval, /* ptr to rule detection function */
   0, /* am I initialized yet? */
   0, /* number of options */
   0  /* don't alert */
};


/* detection functions */

int process_val(const uint8_t *data, uint32_t data_len, uint32_t *retvalue) {
   uint32_t actual_data_len, i;      
   *retvalue = 0;

   /* Jump over NULLs */
   i = 0;
   while((i < data_len) && (data[i] == 0)) {
      i++;
   }
   actual_data_len = data_len - i; 
   if(actual_data_len > 4 || actual_data_len == 0) return(-1);
                                       /* We don't detect if the width can't
                                          be determined using a uint32_t */

   /* Now find the actual value */
   for(;i<data_len;i++) {
      *retvalue += data[i] * PM_EXP2(8*(data_len - i - 1));
   }

   return(0);
}


int ruleIMAIL_LDAPeval(void *p) {
   uint32_t current_byte = 0;
   uint32_t width, value, lengthwidth;
   int retval;

   uint32_t payload_len;

   const uint8_t *cursor_normal, *beg_of_payload, *end_of_payload;

   SFSnortPacket *sp = (SFSnortPacket *) p;

   if(sp == NULL)
      return RULE_NOMATCH;

   if(sp->payload == NULL)
      return RULE_NOMATCH;

   /* call flow match */
   if (checkFlow(sp, ruleIMAIL_LDAPoptions[0]->option_u.flowFlags) <= 0 )
      return RULE_NOMATCH;

   /* call content match */
   if (contentMatch(sp, ruleIMAIL_LDAPoptions[1]->option_u.content, &cursor_normal) <= 0) {
      return RULE_NOMATCH;
   }

   if(getBuffer(sp, CONTENT_BUF_NORMALIZED, &beg_of_payload, &end_of_payload) <= 0)
      return RULE_NOMATCH;

   payload_len = end_of_payload - beg_of_payload;

   if(payload_len < 10)   /* Minimum bind request length */
      return RULE_NOMATCH;

   /* our contentMatch already assures us the first byte is \x30, so just jump over it */
   current_byte++;

   /* Begin packet structure processing */
   /* Packet length (only care about width of the specifier) */
   if(beg_of_payload[current_byte] & 0x80) {
      current_byte += beg_of_payload[current_byte] & 0x0F;  /* Does imail do this properly? */
   }
   current_byte++;

   /* Message number (only care about width of the specifier) */
   if(payload_len < current_byte + 8) 
      return RULE_NOMATCH;

   if(beg_of_payload[current_byte] != 0x02) /* Int data type */
      return RULE_NOMATCH;
   current_byte++;

   /* int width specifier */
   if(beg_of_payload[current_byte] & 0x80) {
      width = beg_of_payload[current_byte] & 0x0F;
      current_byte++;

      if(payload_len < current_byte + width) 
         return RULE_NOMATCH;

      retval = process_val(&(beg_of_payload[current_byte]), width, &value);
      if(retval < 0) 
         return RULE_NOMATCH;  /* width is either 0 or > 4 */
      current_byte += width;   /* width of data width specifier */
      current_byte += value;   /* width of data itself */
   }  else {
      current_byte += beg_of_payload[current_byte] + 1;
   }

   /* Bind request */
   if(payload_len < current_byte + 5) 
      return RULE_NOMATCH;

   if(beg_of_payload[current_byte] != 0x60) 
      return RULE_NOMATCH;

   current_byte++;

   /* Message length  (only care about width of the specifier) */
   if(beg_of_payload[current_byte] & 0x80) {
      current_byte += beg_of_payload[current_byte] & 0x0F; 
   }
   current_byte++;

   /* ldap version */
   if(payload_len < current_byte + 3) 
      return RULE_NOMATCH;

   /* ldap version */
   if(beg_of_payload[current_byte] != 0x02) /* Int data type */
      return RULE_NOMATCH;
   current_byte++;

   /* Now check for funkiness with the version field */
   /* Get width of version number */
   if(beg_of_payload[current_byte] & 0x80) {

      /* Excess bits in the high nibble */
      if(beg_of_payload[current_byte] & 0x70)
         return RULE_MATCH;

      lengthwidth = beg_of_payload[current_byte] & 0x0F;
      current_byte++;
  
      if(payload_len < current_byte + lengthwidth) 
         return RULE_NOMATCH;

      retval = process_val(&(beg_of_payload[current_byte]), lengthwidth, &value);
      if(retval < 0)
          return RULE_MATCH; /* Something screwy's going on around here */
      width = value;
      current_byte += lengthwidth;
   }  else {
      width = beg_of_payload[current_byte];
      current_byte++;
   }

   if(payload_len < current_byte + width)
      return RULE_NOMATCH;

   /* In this case, if the version value is this fubar, trigger */
   retval = process_val(&(beg_of_payload[current_byte]), width, &value);
   if(retval < 0)
         return RULE_MATCH;

   /* LDAP version > 9 (currently, should be 1-3) */
   if(value > 9)
      return RULE_MATCH;

   return RULE_NOMATCH;
}
