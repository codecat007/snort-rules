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
// os-windows_kb2279986-opentype-font-heap-overflow.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_17765 = R"[Snort_SO_Rule](
alert file (
	msg:"OS-WINDOWS OpenType Font file parsing buffer overflow attempt";
	soid:17765;
	file_data;
	content:"name";
	content:"|00 03 00 01|",distance 0,fast_pattern;
	content:"OTTO",depth 4;
	so:eval;
	metadata:policy max-detect-ips drop;
	reference:cve,2010-2740;
	reference:url,technet.microsoft.com/en-us/security/bulletin/MS10-078;
	classtype:attempted-user;
	gid:3; sid:17765; rev:6;
)
)[Snort_SO_Rule]";

static const unsigned rule_17765_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *beg_of_buffer = c.buffer(),
                 *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint16_t num_tables, format, num_records,
            platform_id, encoding_id, length;

   uint32_t tag, name_offset;

   bool name_found = false;

   // check if we can:
   //  read num_tables     (2 bytes)
   //  skip search_range   (2 bytes)
   //  skip entry_selector (2 bytes)
   //  skip range_shift    (2 bytes)
   if(cursor_normal + 8 > end_of_buffer)
      return IpsOption::NO_MATCH;

   num_tables = read_big_16_inc(cursor_normal);
   cursor_normal += 6;

   // limit num_tables
   if(num_tables > 25)
      num_tables = 25;

   // locate the name table
   for(unsigned i = 0; i < num_tables; i++)
   {
      // check if we can:
      // read tag      (4 bytes)
      // skip checksum (4 bytes)
      // read offset   (4 bytes)
      // skip length   (4 bytes)
      if(cursor_normal + 16 > end_of_buffer)
         return IpsOption::NO_MATCH;

      tag = read_big_32(cursor_normal);

      // check for 'name' tag
      if(tag == 0x6E616D65)
      {
         name_offset = read_big_32(cursor_normal + 8);
         name_found = true;
         break;
      }

      cursor_normal += 16;
   }

   if(!name_found)
      return IpsOption::NO_MATCH;

   // check if we can jump name_offset
   if(name_offset > end_of_buffer - beg_of_buffer)
      return IpsOption::NO_MATCH;

   // jump name_offset
   cursor_normal = beg_of_buffer + name_offset;

   // check if we can:
   //  read format        (2 bytes)
   //  read num_records   (2 bytes)
   //  skip string_offset (2 bytes)
   if(cursor_normal + 6 > end_of_buffer)
      return IpsOption::NO_MATCH;

   format = read_big_16_inc(cursor_normal);

   if(format != 0)
      return IpsOption::NO_MATCH;

   num_records = read_big_16_inc(cursor_normal);
   cursor_normal += 2;

   // limit num_records
   if(num_records > 50)
      num_records = 50;

   for(unsigned i = 0; i < num_records; i++)
   {
      // check if we can:
      //  read platform_id (2 bytes)
      //  read encoding_id (2 bytes)
      //  skip language_id (2 bytes)
      //  skip name_id     (2 bytes)
      //  read length      (2 bytes)
      //  skip offset      (2 bytes)
      if(cursor_normal + 12 > end_of_buffer)
         return IpsOption::NO_MATCH;

      platform_id = read_big_16(cursor_normal);
      encoding_id = read_big_16(cursor_normal + 2);

      if(platform_id == 0x0003 && encoding_id == 0x0001)
      {
         length = read_big_16(cursor_normal + 8);

         // check if length is odd
         // (vulnerability condition)
         if(length & 0x01)
            return IpsOption::MATCH;
      }

      cursor_normal += 12;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_17765 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        6, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "17765", // name
        "OS-WINDOWS OpenType Font file parsing buffer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_17765,
    rule_17765_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_17765 = &so_17765.base;

