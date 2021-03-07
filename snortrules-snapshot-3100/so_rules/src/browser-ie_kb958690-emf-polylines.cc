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
// browser-ie_kb958690-emf-polylines.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_15300 = R"[Snort_SO_Rule](
alert file (
	msg:"BROWSER-IE Microsoft Internet Explorer EMF polyline overflow attempt";
	soid:15300;
	file_data;
	content:"|20|EMF",offset 40,depth 4;
	content:"|01 00 00 00|",depth 4;
	byte_jump:4,0,relative,little,from_beginning;
	so:eval;
	metadata:policy max-detect-ips drop;
	reference:cve,2009-0081;
	reference:url,technet.microsoft.com/en-us/security/bulletin/ms09-006;
	classtype:attempted-admin;
	gid:3; sid:15300; rev:9;
)
)[Snort_SO_Rule]";

static const unsigned rule_15300_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo(),
                 *cursor_detect;

   uint32_t record_type, record_len,
            polyline_count, point_count,
            array_size, x, y;

   // check up to 100 EMF records
   for(unsigned i = 0; i < 100; i++)
   {
      // check if we can read:
      //  record_type (4 bytes)
      //  record_len  (4 bytes)
      if(cursor_normal + 8 > end_of_buffer)
         return IpsOption::NO_MATCH;

      record_type = read_little_32(cursor_normal);
      record_len = read_little_32(cursor_normal + 4);

      DEBUG_SO(fprintf(stderr,"record_type=0x%08x\n",record_type);)
      DEBUG_SO(fprintf(stderr,"record_len=0x%08x\n",record_len);)

      switch(record_type)
      {
      case 0x04: // POLYLINE
         // skip:
         //  record_type  (4 bytes)
         //  record_len   (4 bytes)
         //  RECTL bounds (16 bytes)
         cursor_detect = cursor_normal + 24;

         // check if we can read:
         //  point_count (4 bytes)
         if(cursor_detect + 4 > end_of_buffer)
            return IpsOption::NO_MATCH;

         point_count = read_little_32_inc(cursor_detect);

         // limit point_count
         if(point_count > 25)
            point_count = 25;

         for(unsigned j = 0; j < point_count; j++)
         {
            if(cursor_detect + 8 > end_of_buffer)
               return IpsOption::NO_MATCH;

            x = read_little_32_inc(cursor_detect);
            y = read_little_32_inc(cursor_detect);

            if(x >= 0x10000000 || y >= 0x10000000)
               return IpsOption::MATCH;
         }

         break;
      case 0x07: // POLYPOLYLINE
         // skip:
         //  record_type  (4 bytes)
         //  record_len   (4 bytes)
         //  RECTL bounds (16 bytes)
         cursor_detect = cursor_normal + 24;

         // check if we can read:
         //  polyline_count (4 bytes)
         //  point_count    (4 bytes)
         if(cursor_detect + 8 > end_of_buffer)
            return IpsOption::NO_MATCH;

         polyline_count = read_little_32_inc(cursor_detect);
         point_count = read_little_32_inc(cursor_detect);

         // calculate array_size
         array_size = polyline_count * 4;

         if(array_size < polyline_count)
            return IpsOption::NO_MATCH;

         // check if we can skip array_size
         if(array_size > end_of_buffer - cursor_detect)
            return IpsOption::NO_MATCH;

         // skip array_size
         cursor_detect += array_size;

         // limit point_count
         if(point_count > 25)
            point_count = 25;

         for(unsigned j = 0; j < point_count; j++)
         {
            if(cursor_detect + 8 > end_of_buffer)
               return IpsOption::NO_MATCH;

            x = read_little_32_inc(cursor_detect);
            y = read_little_32_inc(cursor_detect);

            if(x >= 0x10000000 || y >= 0x10000000)
               return IpsOption::MATCH;
         }

         break;
      case 0x0E: // EOF
         return IpsOption::NO_MATCH;
      default:
         break;
      }

      // check if we can skip record_len
      if(record_len > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // skip record_len
      cursor_normal += record_len;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_15300 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        9, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "15300", // name
        "BROWSER-IE Microsoft Internet Explorer EMF polyline overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_15300,
    rule_15300_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_15300 = &so_15300.base;

