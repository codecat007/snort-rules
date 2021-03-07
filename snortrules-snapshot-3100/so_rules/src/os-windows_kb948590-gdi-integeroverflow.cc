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
// os-windows_kb948590-gdi-integeroverflow.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_13666 = R"[Snort_SO_Rule](
alert file (
	msg:"OS-WINDOWS Microsoft Windows GDI integer overflow attempt";
	soid:13666;
	file_data;
	content:"|20|EMF",offset 40,depth 4;
	content:"|01 00 00 00|",depth 4;
	byte_jump:4,0,relative,little,from_beginning;
	so:eval;
	metadata:policy max-detect-ips drop;
	reference:cve,2008-1083;
	reference:url,technet.microsoft.com/en-us/security/bulletin/MS08-021;
	classtype:attempted-user;
	gid:3; sid:13666; rev:13;
)
)[Snort_SO_Rule]";

static const unsigned rule_13666_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo(),
                 *cursor_detect;

   uint16_t width, height, planes, bpp;

   uint32_t record_type, record_len,
            bitmap_offset, header_size;

   uint64_t check = 0;

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
      case 0x5E: // CREATEDIBPATTERNBRUSHPT
         // skip:
         //  type(4), len(4), ihbrush(4),
         //  usage(4) = (16 bytes)
         cursor_detect = cursor_normal + 16;

         // check if we can read:
         //  bitmap_offset (4 bytes)
         if(cursor_detect + 4 > end_of_buffer)
            return IpsOption::NO_MATCH;

         bitmap_offset = read_little_32(cursor_detect);
         break;
      case 0x51: // STRETCHDIBITS
         // skip:
         //  type(4), len(4), bounds(16), xdest(4),
         //  ydest(4), xsrc(4), ysrc(4), cxsrc(4),
         //  cysrc(4) = (48 bytes)
         cursor_detect = cursor_normal + 48;

         // check if we can read:
         //  bitmap_offset (4 bytes)
         if(cursor_detect + 4 > end_of_buffer)
            return IpsOption::NO_MATCH;

         bitmap_offset = read_little_32(cursor_detect);
         break;
      case 0x0E: // EOF
         return IpsOption::NO_MATCH;
      default:
         bitmap_offset = 0;
         break;
      }

      // check if we found a bitmap_offset
      if(bitmap_offset != 0)
      {
         DEBUG_SO(fprintf(stderr,"bitmap_offset=0x%08x\n",bitmap_offset);)

         // check if we can skip bitmap_offset
         if(bitmap_offset > end_of_buffer - cursor_normal)
            return IpsOption::NO_MATCH;

         // skip bitmap_offset
         cursor_detect = cursor_normal + bitmap_offset;

         // check if we can read:
         //  header_size (4 bytes)
         //  width       (2 bytes)
         //  height      (2 bytes)
         //  planes      (2 bytes)
         //  bpp         (2 bytes)
         if(cursor_detect + 12 > end_of_buffer)
            return IpsOption::NO_MATCH;

         header_size = read_little_32_inc(cursor_detect);

         DEBUG_SO(fprintf(stderr,"header_size=0x%08x\n",header_size);)

         if(header_size == 12)
         {
            // found BITMAPCOREHEADER
            width = read_little_16_inc(cursor_detect);
            height = read_little_16_inc(cursor_detect);
            planes = read_little_16_inc(cursor_detect);
            bpp = read_little_16_inc(cursor_detect);

            check = (width * planes) & 0xFFFFFFFF;

            if((check *= bpp) > 0xFFFFFFFF)
               return IpsOption::MATCH;

            if((check += 31) > 0xFFFFFFFF)
               return IpsOption::MATCH;

            // turn off lower 5 bits
            // (make divisible by 8)
            check &= ~31;
            check /= 8;

            if((check *= height) > 0xFFFFFFFF)
               return IpsOption::MATCH;

            if((check += 256 * 4) > 0xFFFFFFFF)
               return IpsOption::MATCH;

            if(record_type == 0x51)
               if(bpp == 1 || bpp == 4 || bpp == 8)
                  return IpsOption::MATCH;
         }
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

static const SoApi so_13666 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        13, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "13666", // name
        "OS-WINDOWS Microsoft Windows GDI integer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_13666,
    rule_13666_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_13666 = &so_13666.base;

