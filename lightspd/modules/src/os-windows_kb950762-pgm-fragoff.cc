//--------------------------------------------------------------------------
// Copyright (C) 2019-2021 Cisco and/or its affiliates. All rights reserved.
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
// os-windows_kb950762-pgm-fragoff.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_13825 = R"[Snort_SO_Rule](
alert ip $EXTERNAL_NET any -> 224.0.0.0/4 any (
	msg:"OS-WINDOWS Microsoft PGM fragment denial of service attempt";
	soid:13825;
	ip_proto:113;
	content:"|04 01|",offset 4,depth 2;
	so:eval;
	metadata:policy max-detect-ips drop;
	reference:cve,2008-1441;
	reference:url,technet.microsoft.com/en-us/security/bulletin/MS08-036;
	classtype:attempted-dos;
	gid:3; sid:13825; rev:9;
)
)[Snort_SO_Rule]";

static const unsigned rule_13825_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint8_t option_type, option_len;
   uint32_t frag_offset, total_len;

   // skip header
   cursor_normal += 18;

   // check up to 10 PGM options
   for(unsigned i = 0; i < 10; i++)
   {
      if(cursor_normal + 16 > end_of_buffer)
         return IpsOption::NO_MATCH;

      option_type = cursor_normal[0];
      option_len = cursor_normal[1];

      if(option_type == 0x01 || option_type == 0x81)
      {
         // IPT_FRAGMENT or OPT_FRAGMENT found, read values
         frag_offset = read_big_32(cursor_normal + 8);
         total_len = read_big_32(cursor_normal + 12);

         // check vulnerability condition
         if(frag_offset < 0x7F && total_len > 0x7FFF)
            return IpsOption::MATCH;

         // only check one fragment
         return IpsOption::NO_MATCH;
      }

      // check if this is the last option
      if(option_type & 0x80)
         return IpsOption::NO_MATCH;

      if(option_len == 0)
         return IpsOption::NO_MATCH;

      // check if we can skip option_len
      if(option_len > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // skip option_len
      cursor_normal += option_len;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_13825 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        9, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "13825", // name
        "OS-WINDOWS Microsoft PGM fragment denial of service attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_13825,
    rule_13825_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_13825 = &so_13825.base;

