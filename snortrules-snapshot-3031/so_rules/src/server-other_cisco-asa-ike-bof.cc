//--------------------------------------------------------------------------
// Copyright (C) 2019-2020 Cisco and/or its affiliates. All rights reserved.
//
// This file may contain proprietary rules that were created, tested and
// certified by Sourcefire, Inc. (the "VRT Certified Rules") as well as
// rules that were created by Sourcefire and other third parties and
// distributed under the GNU General Public License (the "GPL Rules").
// The VRT Certified Rules contained in this file are the property of
// Sourcefire, Inc. Copyright 2005 Sourcefire, Inc. All Rights Reserved.
// The GPL Rules created by Sourcefire, Inc. are the property of
// Sourcefire, Inc. Copyright 2002-2005 Sourcefire, Inc. All Rights
// Reserved. All other GPL Rules are owned and copyrighted by their
// respective owners (please see www.snort.org/contributors for a list
// of owners and their respective copyrights). In order to determine what
// rules are VRT Certified Rules or GPL Rules, please refer to the VRT
// Certified Rules License Agreement.
//--------------------------------------------------------------------------
// server-other_cisco-asa-ike-bof.cc author Brandon Stultz <brastult@cisco.com>

#include "main/snort_types.h"
#include "framework/so_rule.h"
#include "framework/cursor.h"
#include "protocols/packet.h"
#include "util_read.h"

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

using namespace snort;

static const char* rule_37675 = R"[Snort_SO_Rule](
alert udp $EXTERNAL_NET any -> $HOME_NET [500,4500] (
	msg:"SERVER-OTHER Cisco IOS invalid IKE fragment length memory corruption or exhaustion attempt";
	soid:37675;
	flow:to_server;
	content:"|84|",fast_pattern;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	reference:cve,2016-1287;
	reference:cve,2016-1344;
	reference:cve,2016-6381;
	reference:url,tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160210-asa-ike;
	reference:url,tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-ios-ikev2;
	reference:url,tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-ios-ikev1;
	classtype:attempted-admin;
	gid:3; sid:37675; rev:3;
)
)[Snort_SO_Rule]";

static const unsigned rule_37675_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.buffer(),
                 *end_of_buffer = c.endo();

   const uint8_t *next_payload_pos;
   uint8_t payload_type, next_payload_type;
   uint16_t payload_length;

   // skip non-ESP marker for nat-tunneled ISAKMP
   if(p->ptrs.dp == 4500)
      cursor_normal += 4;

   // check if we can read ISAKMP header and first payload
   if(cursor_normal + 32 > end_of_buffer)
      return IpsOption::NO_MATCH;

   // Check for IKEv1 (0x10) or IKEv2 (0x20)
   if((*(cursor_normal + 17) != 0x10) && (*(cursor_normal + 17) != 0x20))
      return IpsOption::NO_MATCH;

   DEBUG_SO(fprintf(stderr,"ISAKMP Request:\n");)

   // move cursor to first payload type
   cursor_normal += 16;

   // read first payload type
   payload_type = *cursor_normal;

   // move to first payload
   cursor_normal += 12;

   // check up to 20 ISAKMP payloads 
   for(int i = 0; i < 20; i++)
   {
      // We verify data availability above for first loop, below for subsequent loops
      next_payload_type = *cursor_normal;
      payload_length = read_big_16(cursor_normal + 2);

      DEBUG_SO(fprintf(stderr,"  payload: type 0x%02X len 0x%04X\n",payload_type,payload_length);)

      // Cisco-Fragmentation Payload (0x84)
      if(payload_type == 0x84)
      {
         // CVE-2016-1287:
         //  check for heap buffer overflow condition
         if(payload_length < 8)
            return IpsOption::MATCH;

         // CVE-2016-6381:
         //  check for memory exhaustion condition
         if(payload_length >= 36)
         {
            // verify we can read:
            //    Cisco Fragmentation Header  (8  bytes)
            //    ISAKMP Fragment             (28 bytes)
            if(cursor_normal + 36 > end_of_buffer)
               return IpsOption::NO_MATCH;

            // verify we have a valid ISAKMP fragment version
            // and if ISAKMP frag length > INT32_MAX, alert.
            if((cursor_normal[25] == 0x10) || (cursor_normal[25] == 0x20))
               if((cursor_normal[32] & 0x80) == 0x80)
                  return IpsOption::MATCH;
         }
      }

      // no next payload, bail
      if(next_payload_type == 0)
         return IpsOption::NO_MATCH;

      // calculate next payload position
      next_payload_pos = cursor_normal + payload_length;

      // integer overflow / zero-length payload check
      if(next_payload_pos <= cursor_normal)
         return IpsOption::NO_MATCH;

      // check next payload
      payload_type = next_payload_type;
      cursor_normal = next_payload_pos;

      // verify we can read:
      //    next payload type (1 byte)
      //    critical          (1 byte)
      //    payload length    (2 byte BE)
      if(cursor_normal + 4 > end_of_buffer)
         return IpsOption::NO_MATCH;
   }
   
   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_37675 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        3, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "37675", // name
        "SERVER-OTHER Cisco IOS invalid IKE fragment length memory corruption or exhaustion attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_37675,
    rule_37675_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_37675 = &so_37675.base;

