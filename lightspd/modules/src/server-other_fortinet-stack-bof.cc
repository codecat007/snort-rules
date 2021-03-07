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
// server-other_fortinet-stack-bof.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_34967 = R"[Snort_SO_Rule](
alert tcp $EXTERNAL_NET any -> $HOME_NET 8000 (
	msg:"SERVER-OTHER Fortinet FSSO stack buffer overflow attempt";
	soid:34967;
	flow:to_server,established;
	content:"|80 06|",offset 4,depth 2;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	reference:bugtraq,73206;
	reference:cve,2015-2281;
	classtype:attempted-admin;
	gid:3; sid:34967; rev:2;
)
)[Snort_SO_Rule]";

static const unsigned rule_34967_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint32_t chunk_len;
   uint8_t chunk_type;

   // check first 10 chunks
   for(unsigned i = 0; i < 10; i++)
   {
      // read chunk_len (4 bytes) & chunk_type (1 byte)
      if(cursor_normal + 5 > end_of_buffer)
         return IpsOption::NO_MATCH;

      chunk_len = read_big_32(cursor_normal);
      chunk_type = *(cursor_normal + 4);

      // chunk_len must be at least 6
      // 4 byte chunk_size
      // 1 byte chunk_type
      // 1 byte chunk_data_type
      if(chunk_len < 6)
         return IpsOption::NO_MATCH;

      DEBUG_SO(fprintf(stderr,"FSSO type:0x%02X len:0x%08X\n",chunk_type,chunk_len);)

      switch(chunk_type)
      {
      case 0x11:
         if(chunk_len > 0x38)
            return IpsOption::MATCH;
         break;
      case 0x12:
         if(chunk_len > 0x6C)
            return IpsOption::MATCH;
         break;
      case 0x13:
         if(chunk_len > 0x60)
            return IpsOption::MATCH;
         break;
      default:
         break;
      }

      // check if we can skip chunk_len
      if(chunk_len > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // skip chunk_len
      cursor_normal += chunk_len;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_34967 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        2, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "34967", // name
        "SERVER-OTHER Fortinet FSSO stack buffer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_34967,
    rule_34967_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_34967 = &so_34967.base;

