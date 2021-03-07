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
// os-windows_kb952954-image-color-mgmt.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_13954 = R"[Snort_SO_Rule](
alert file (
	msg:"OS-WINDOWS Microsoft Color Management System EMF file processing overflow attempt";
	soid:13954;
	file_data;
	content:"|20|EMF",offset 40,depth 4;
	content:"|01 00 00 00|",depth 4;
	byte_jump:4,0,relative,little,from_beginning;
	so:eval;
	metadata:policy max-detect-ips drop;
	reference:cve,2008-2245;
	reference:url,technet.microsoft.com/en-us/security/bulletin/ms08-046;
	classtype:attempted-user;
	gid:3; sid:13954; rev:10;
)
)[Snort_SO_Rule]";

static const unsigned rule_13954_len = 0;

static bool checkWideArray(const uint8_t* cursor, const uint8_t* end)
{
   while(cursor + 2 <= end)
   {
      // check for null termination
      if(cursor[0] == 0x00 && cursor[1] == 0x00)
         break;

      // check vulnerability condition
      if(cursor[0] == 0x3A && cursor[1] == 0x00)
      {
         if(cursor + 4 > end)
            return true;

         if(cursor[2] != 0x5C || cursor[3] != 0x00)
            return true;
      }

      cursor += 2;
   }

   return false;
}

static bool checkArray(const uint8_t* cursor, const uint8_t* end)
{
   while(cursor + 1 <= end)
   {
      // check for null termination
      if(cursor[0] == 0x00)
         break;

      // check vulnerability condition
      if(cursor[0] == 0x3A)
      {
         if(cursor + 2 > end)
            return true;

         if(cursor[1] != 0x5C)
            return true;
      }

      cursor += 1;
   }

   return false;
}

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo(),
                 *cursor_detect, *end_of_record;

   bool color_profile, wide_str;

   uint32_t record_type, record_len,
            name_len, data_len, array_len;

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
      case 0x70: // SETICMPROFILEA
         // skip:
         //  type(4), len(4), dwflags(4) = (12 bytes)
         cursor_detect = cursor_normal + 12;
         color_profile = true;
         wide_str = false;
         break;
      case 0x71: // SETICMPROFILEW
         // skip:
         //  type(4), len(4), dwflags(4) = (12 bytes)
         cursor_detect = cursor_normal + 12;
         color_profile = true;
         wide_str = true;
         break;
      case 0x79: // COLORMATCHTOTARGETW
         // skip:
         //  type(4), len(4), dwaction(4),
         //  dwflags(4) = (16 bytes)
         cursor_detect = cursor_normal + 16;
         color_profile = true;
         wide_str = true;
         break;
      case 0x0E: // EOF
         return IpsOption::NO_MATCH;
      default:
         color_profile = false;
         break;
      }

      // check if we found a color_profile
      if(color_profile)
      {
         // check if we can read:
         //  name_len (4 bytes)
         //  data_len (4 bytes)
         if(cursor_detect + 8 > end_of_buffer)
            return IpsOption::NO_MATCH;

         name_len = read_little_32_inc(cursor_detect);
         data_len = read_little_32_inc(cursor_detect);

         // calculate array_len
         array_len = name_len + data_len;

         // integer overflow check
         if(array_len < name_len)
            return IpsOption::NO_MATCH;

         DEBUG_SO(fprintf(stderr,"array_len=0x%08x\n",array_len);)

         // check if we can read array_len
         if(array_len > end_of_buffer - cursor_detect)
         {
            end_of_record = end_of_buffer;
         }
         else
         {
            end_of_record = cursor_detect + array_len;
         }

         if(wide_str)
         {
            if(checkWideArray(cursor_detect, end_of_record))
               return IpsOption::MATCH;
         }
         else
         {
            if(checkArray(cursor_detect, end_of_record))
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

static const SoApi so_13954 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        10, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "13954", // name
        "OS-WINDOWS Microsoft Color Management System EMF file processing overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_13954,
    rule_13954_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_13954 = &so_13954.base;

