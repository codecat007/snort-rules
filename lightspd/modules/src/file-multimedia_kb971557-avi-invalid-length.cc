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
// file-multimedia_kb971557-avi-invalid-length.cc author Brandon Stultz <brastult@cisco.com>

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

#define LIST 0x5453494C

using namespace snort;

static const char* rule_15857 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-MULTIMEDIA Microsoft Windows AVI file chunk length integer overflow attempt";
	soid:15857;
	file_data;
	content:"RIFF",depth 4;
	content:"AVI|20|",distance 4,within 4;
	so:eval;
	metadata:policy max-detect-ips drop;
	reference:cve,2009-1546;
	reference:url,technet.microsoft.com/en-us/security/bulletin/MS09-038;
	classtype:attempted-user;
	gid:3; sid:15857; rev:8;
)
)[Snort_SO_Rule]";

static const unsigned rule_15857_len = 0;

static bool check_list(const uint8_t* cursor, const uint8_t* end, unsigned depth)
{
   const uint8_t *end_of_chunk;

   uint32_t chunk_type, chunk_len;

   // limit LIST depth
   if(depth > 1)
      return false;

   // skip list_type (4 bytes)
   cursor += 4;

   // check up to 5 list chunks
   for(unsigned i = 0; i < 5; i++)
   {
      // check if we can:
      //  read chunk_type (4 bytes)
      //  read chunk_len  (4 bytes)
      if(cursor + 8 > end)
         return false;

      chunk_type = read_little_32_inc(cursor);
      chunk_len = read_little_32_inc(cursor);

      // check vulnerability condition
      if(chunk_len > 0x7FFFFFF6)
         return true;

      // add padding byte if needed
      chunk_len += chunk_len % 2;

      // check if we can read chunk_len
      if(chunk_len > end - cursor)
         return false;

      // calculate end_of_chunk position
      end_of_chunk = cursor + chunk_len;

      if(chunk_type == LIST)
         if(check_list(cursor, end_of_chunk, ++depth))
            return true;

      cursor = end_of_chunk;
   }

   return false;
}

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo(),
                 *end_of_block;

   uint32_t block_type, block_len;

   // check up to 5 blocks
   for(unsigned i = 0; i < 5; i++)
   {
      // check if we can:
      //  read block_type (4 bytes)
      //  read block_len  (4 bytes)
      if(cursor_normal + 8 > end_of_buffer)
         return IpsOption::NO_MATCH;

      block_type = read_little_32_inc(cursor_normal);
      block_len = read_little_32_inc(cursor_normal);

      // check vulnerability condition
      if(block_len > 0x7FFFFFF6)
         return IpsOption::MATCH;

      // check if we can read block_len
      if(block_len > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // calculate end_of_block position
      end_of_block = cursor_normal + block_len;

      if(block_type == LIST)
         if(check_list(cursor_normal, end_of_block, 0))
            return IpsOption::MATCH;

      // skip block
      cursor_normal = end_of_block;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_15857 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        8, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "15857", // name
        "FILE-MULTIMEDIA Microsoft Windows AVI file chunk length integer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_15857,
    rule_15857_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_15857 = &so_15857.base;

