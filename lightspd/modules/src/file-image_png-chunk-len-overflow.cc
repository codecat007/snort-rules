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
// file-image_png-chunk-len-overflow.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_29944 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-IMAGE Microsoft Office PNG parsing stack buffer overflow attempt";
	soid:29944;
	file_data;
	content:"|89|PNG|0D 0A 1A 0A|";
	so:eval,relative;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	reference:cve,2013-1331;
	reference:url,technet.microsoft.com/en-us/security/bulletin/ms13-051;
	classtype:attempted-admin;
	gid:3; sid:29944; rev:4;
)
)[Snort_SO_Rule]";

static const unsigned rule_29944_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint32_t chunk_size, chunk_type;

   // check up to 10 PNG chunks
   for(unsigned i = 0; i < 10; i++)
   {
      // check if we can read:
      //  chunk_size (4 bytes)
      //  chunk_type (4 bytes)
      if(cursor_normal + 8 > end_of_buffer)
         return IpsOption::NO_MATCH;

      chunk_size = read_big_32_inc(cursor_normal);
      chunk_type = read_big_32_inc(cursor_normal);

      switch(chunk_type)
      {
      case 0x74455874: // tEXt
         // CVE-2013-1331
         if(chunk_size > 0x7FFFFFFF)
            return IpsOption::MATCH;

         break;
      case 0x49454E44: // IEND
         return IpsOption::NO_MATCH;
      default:
         break;
      }

      // check if we can skip chunk_size
      if(chunk_size > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // skip chunk_size +4 byte CRC
      cursor_normal += chunk_size + 4;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_29944 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        4, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "29944", // name
        "FILE-IMAGE Microsoft Office PNG parsing stack buffer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_29944,
    rule_29944_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_29944 = &so_29944.base;

