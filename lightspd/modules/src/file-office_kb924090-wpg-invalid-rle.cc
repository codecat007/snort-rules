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
// file-office_kb924090-wpg-invalid-rle.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_13958 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-OFFICE WordPerfect Graphics file invalid RLE buffer overflow attempt";
	soid:13958;
	file_data;
	content:"|FF|WPC|10 00 00 00 01 16 01 00 00 00|",depth 14;
	so:eval;
	metadata:policy max-detect-ips drop;
	reference:cve,2008-3460;
	reference:url,technet.microsoft.com/en-us/security/bulletin/ms08-044;
	classtype:attempted-user;
	gid:3; sid:13958; rev:10;
)
)[Snort_SO_Rule]";

static const unsigned rule_13958_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint8_t record_type;

   uint32_t record_size;

   // skip reserved (2 bytes)
   cursor_normal += 2;

   // check if we can read 1 byte
   if(cursor_normal + 1 > end_of_buffer)
      return IpsOption::NO_MATCH;

   if(*cursor_normal != 0x0F)
      return IpsOption::NO_MATCH;

   cursor_normal += 8;

   while(cursor_normal + 6 <= end_of_buffer)
   {
      record_type = *cursor_normal++;
      record_size = *cursor_normal++;

      if(record_size == 0xFF)
      {
         // multibyte size
         record_size = read_little_16_inc(cursor_normal);

         if(record_size & 0x8000)
         {
            // 4 byte size
            record_size &= 0x7FFF;
            record_size <<= 16;
            record_size |= read_little_16_inc(cursor_normal);
         }
      }

      DEBUG_SO(fprintf(stderr,"record_type=0x%02x\n",record_type);)
      DEBUG_SO(fprintf(stderr,"record_size=0x%08x\n",record_size);)

      // block WPG BitMap Type 1
      if(record_type == 0x0B)
         return IpsOption::MATCH;

      // check if we can skip record_size
      if(record_size > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // skip record_size
      cursor_normal += record_size;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_13958 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        10, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "13958", // name
        "FILE-OFFICE WordPerfect Graphics file invalid RLE buffer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_13958,
    rule_13958_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_13958 = &so_13958.base;

