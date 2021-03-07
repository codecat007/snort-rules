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
// file-office_kb2315011-outlook-rtf.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_17251 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-OFFICE Microsoft Outlook RTF remote code execution attempt";
	soid:17251;
	file_data;
	content:"|78 9F 3E 22 01 00|",depth 6;
	content:"|02 01 09 10|";
	so:eval,relative;
	metadata:policy max-detect-ips drop;
	reference:cve,2010-2728;
	reference:url,technet.microsoft.com/en-us/security/bulletin/MS10-064;
	classtype:attempted-admin;
	gid:3; sid:17251; rev:7;
)
)[Snort_SO_Rule]";

static const unsigned rule_17251_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint32_t num_props, prop_size,
            comp_size, comp_type,
            padding, check;

   // check if we can read:
   //  num_props (4 bytes)
   if(cursor_normal + 4 > end_of_buffer)
      return IpsOption::NO_MATCH;

   num_props = read_little_32_inc(cursor_normal);

   DEBUG_SO(fprintf(stderr,"num_props=0x%08x\n",num_props);)

   // limit num_props
   if(num_props > 10)
      num_props = 10;

   for(unsigned i = 0; i < num_props; i++)
   {
      // check if we can:
      //  read prop_size (4 bytes)
      //  read comp_size (4 bytes)
      //  skip raw_size  (4 bytes)
      //  read comp_type (4 bytes)
      if(cursor_normal + 16 > end_of_buffer)
         return IpsOption::NO_MATCH;

      prop_size = read_little_32_inc(cursor_normal);
      comp_size = read_little_32(cursor_normal);
      comp_type = read_little_32(cursor_normal+8);

      DEBUG_SO(fprintf(stderr,"prop_size=0x%08x\n",prop_size);)
      DEBUG_SO(fprintf(stderr,"comp_size=0x%08x\n",comp_size);)
      DEBUG_SO(fprintf(stderr,"comp_type=0x%08x\n",comp_type);)

      // match comp_type compressed
      if(comp_type != 0x75465A4C)
         return IpsOption::NO_MATCH;

      // check vulnerability condition
      if(comp_size < 12)
         return IpsOption::MATCH;

      // calculate padding
      padding = prop_size % 16;

      // integer overflow check
      check = prop_size + padding;
      if(check < prop_size)
         return IpsOption::NO_MATCH;
      prop_size = check;

      // check if we can skip prop_size
      if(prop_size > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // skip prop_size
      cursor_normal += prop_size;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_17251 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        7, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "17251", // name
        "FILE-OFFICE Microsoft Outlook RTF remote code execution attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_17251,
    rule_17251_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_17251 = &so_17251.base;

