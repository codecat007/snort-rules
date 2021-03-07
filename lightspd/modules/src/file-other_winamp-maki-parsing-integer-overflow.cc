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
// file-other_winamp-maki-parsing-integer-overflow.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_15433 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-OTHER Winamp MAKI parsing integer overflow attempt";
	soid:15433;
	file_data;
	content:"FG|03 04 17 00 00 00|",depth 8;
	byte_jump:4,0,relative,little,multiplier 16;
	so:eval;
	metadata:policy max-detect-ips drop;
	reference:bugtraq,35052;
	reference:cve,2009-1831;
	classtype:attempted-user;
	gid:3; sid:15433; rev:7;
)
)[Snort_SO_Rule]";

static const unsigned rule_15433_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint32_t str_count, data_block_len, check;
   uint16_t str_len;
   bool max_str = false;

   // check if we can read str_count
   if(cursor_normal + 4 > end_of_buffer)
     return IpsOption::NO_MATCH;

   str_count = read_little_32_inc(cursor_normal);

   DEBUG_SO(fprintf(stderr,"str_count=0x%08x\n",str_count);)

   // limit str_count
   if(str_count > 25)
   {
      str_count = 25;
      max_str = true;
   }

   for(unsigned i = 0; i < str_count; i++)
   {
      // skip to str_len
      cursor_normal += 4;

      // check if we can read str_len
      if(cursor_normal + 2 > end_of_buffer)
         return IpsOption::NO_MATCH;

      str_len = read_little_16_inc(cursor_normal);

      DEBUG_SO(fprintf(stderr,"str_len=0x%04x\n",str_len);)

      // check vulnerability condition
      if(str_len >= 0x8000)
         return IpsOption::MATCH;

      // check if we can skip str_len
      if(str_len > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // skip str_len
      cursor_normal += str_len;
   }

   if(max_str)
      return IpsOption::NO_MATCH;

   // check if we can read data_block_len
   if(cursor_normal + 4 > end_of_buffer)
      return IpsOption::NO_MATCH;

   data_block_len = read_little_32_inc(cursor_normal);

   check = data_block_len * 14; 

   // integer overflow check
   if(check < data_block_len)
      return IpsOption::NO_MATCH;

   data_block_len = check;

   // check if we can skip data_block_len
   if(data_block_len > end_of_buffer - cursor_normal)
      return IpsOption::NO_MATCH;

   // skip data_block_len
   cursor_normal += data_block_len;

   // check if we can read str_count
   if(cursor_normal + 4 > end_of_buffer)
     return IpsOption::NO_MATCH;

   str_count = read_little_32_inc(cursor_normal);

   DEBUG_SO(fprintf(stderr,"str_count=0x%08x\n",str_count);)

   // limit str_count
   if(str_count > 25)
      str_count = 25;

   for(unsigned i = 0; i < str_count; i++)
   {
      // skip to str_len
      cursor_normal += 4;

      // check if we can read str_len
      if(cursor_normal + 2 > end_of_buffer)
         return IpsOption::NO_MATCH;

      str_len = read_little_16_inc(cursor_normal);

      DEBUG_SO(fprintf(stderr,"str_len=0x%04x\n",str_len);)

      // check vulnerability condition
      if(str_len >= 0x8000)
         return IpsOption::MATCH;

      // check if we can skip str_len
      if(str_len > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // skip str_len
      cursor_normal += str_len;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_15433 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        7, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "15433", // name
        "FILE-OTHER Winamp MAKI parsing integer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_15433,
    rule_15433_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_15433 = &so_15433.base;

