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
// os-windows_kb954593-gdi-rce.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_14251 = R"[Snort_SO_Rule](
alert file (
	msg:"OS-WINDOWS Microsoft Windows GDI WMF parsing buffer overflow attempt";
	soid:14251;
	file_data;
	content:"|D7 CD C6 9A 00 00|";
	content:"|09 00|",distance 18,within 2;
	byte_jump:0,14,relative;
	so:eval;
	metadata:policy max-detect-ips drop;
	reference:cve,2008-3014;
	reference:url,technet.microsoft.com/en-us/security/bulletin/MS08-052;
	classtype:attempted-user;
	gid:3; sid:14251; rev:10;
)
)[Snort_SO_Rule]";

static const unsigned rule_14251_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo(),
                 *cursor_detect;

   uint16_t type, num_polygons;

   uint32_t size, check;

   // check up to 50 records
   for(unsigned i = 0; i < 50; i++)
   {
      cursor_detect = cursor_normal;

      // check if we can read:
      //  size (4 bytes)
      //  type (2 bytes)
      if(cursor_detect + 6 > end_of_buffer)
         return IpsOption::NO_MATCH;

      size = read_little_32_inc(cursor_detect);
      type = read_little_16_inc(cursor_detect);

      DEBUG_SO(fprintf(stderr,"size=0x%08x\n",size);)
      DEBUG_SO(fprintf(stderr,"type=0x%04x\n",type);)

      // PolyPolygon
      if(type == 0x0538)
      {
         // check if we can read:
         //  num_polygons (2 bytes)
         if(cursor_detect + 2 > end_of_buffer)
            return IpsOption::NO_MATCH;

         num_polygons = read_little_16_inc(cursor_detect);

         DEBUG_SO(fprintf(stderr,"num_polygons=0x%04x\n",num_polygons);)

         if(num_polygons > 0x0FFF)
            return IpsOption::MATCH;
      }

      // size is number of words
      // integer overflow check
      check = size * 2;
      if(check < size)
         return IpsOption::NO_MATCH;
      size = check;

      // check if we can skip size
      if(size > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // skip size
      cursor_normal += size;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_14251 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        10, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "14251", // name
        "OS-WINDOWS Microsoft Windows GDI WMF parsing buffer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_14251,
    rule_14251_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_14251 = &so_14251.base;

