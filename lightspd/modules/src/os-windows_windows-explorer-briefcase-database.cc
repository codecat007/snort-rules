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
// os-windows_windows-explorer-briefcase-database.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_24671 = R"[Snort_SO_Rule](
alert file (
	msg:"OS-WINDOWS Microsoft Windows Explorer briefcase database memory corruption attempt";
	soid:24671;
	file_data;
	content:"DDSH|02 05 01 14 14 00 00 00|",depth 12;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	reference:cve,2012-1527;
	reference:cve,2012-1528;
	reference:url,technet.microsoft.com/en-us/security/bulletin/MS12-072;
	classtype:attempted-user;
	gid:3; sid:24671; rev:3;
)
)[Snort_SO_Rule]";

static const unsigned rule_24671_len = 0;

/* 
   "Briefcase Directory" file structure

   Byte Header[14]

   struct VolumeHeader
   {
      UINT32 lcVolumes;
      UINT32 MaxVolumeLength;
   }

   // repeated: VolumeHeader.lcVolumes times
   struct VolumeDef
   {
      UINT32 hVol;
      UINT32 LinkInfoLen;
      BYTE bytes[VolumeDef.LinkInfoLen-4];
   } 

   struct StringHeaderTable
   {
      UINT32 MaxStringLen;
      UINT32 lcStrings; // count of strings
   }

   // repeated: StringHeaderTable.lcStrings times
   struct StringDef
   {
      UINT32 StringId;
      ASCII_SZ String[];
   }
*/

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint32_t lc_volumes, lc_strings,
            link_info_len;

   bool max_volumes = false;

   if(cursor_normal + 20 > end_of_buffer)
      return IpsOption::NO_MATCH;

   // VolumeHeader.lcVolumes (number of VolumeDef blocks)
   lc_volumes = read_little_32(cursor_normal + 8);

   cursor_normal += 20;

   // limit lc_volumes
   if(lc_volumes > 100)
   {
      lc_volumes = 100;
      max_volumes = true;
   }

   for(unsigned i = 0; i < lc_volumes; i++)
   {
      if(cursor_normal + 4 > end_of_buffer)
         return IpsOption::NO_MATCH;

      link_info_len = read_little_32_inc(cursor_normal);

      // CVE-2012-1527
      // VolumeDef.LinkInfoLen < 4
      if(link_info_len < 4)
         return IpsOption::MATCH;

      // check if we can jump link_info_len
      if(link_info_len > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // jump link_info_len
      cursor_normal += link_info_len;
   }

   if(max_volumes)
      return IpsOption::NO_MATCH;

   if(cursor_normal + 4 > end_of_buffer)
      return IpsOption::NO_MATCH;

   lc_strings = read_little_32(cursor_normal);

   // CVE-2012-1528
   if(lc_strings > 0x1FFFFFFF)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_24671 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        3, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "24671", // name
        "OS-WINDOWS Microsoft Windows Explorer briefcase database memory corruption attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_24671,
    rule_24671_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_24671 = &so_24671.base;

