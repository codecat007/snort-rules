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
// file-multimedia_adobe-shockwave-ffffff88.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_19350 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-MULTIMEDIA Adobe Shockwave Player director file integer overflow attempt";
	soid:19350;
	file_data;
	content:"|FF FF FF|";
	byte_jump:4,0,relative,little,align;
	content:"|88 FF FF FF|",within 4,fast_pattern;
	so:eval,relative;
	metadata:policy max-detect-ips drop;
	reference:cve,2010-2876;
	reference:url,www.adobe.com/support/security/bulletins/apsb10-20.html;
	classtype:attempted-user;
	gid:3; sid:19350; rev:7;
)
)[Snort_SO_Rule]";

static const unsigned rule_19350_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint16_t string_len;
   uint32_t size, count, check1, check2;

   // skip chunk size
   cursor_normal += 4;

   // check if we can read string_len
   if(cursor_normal + 2 > end_of_buffer)
      return IpsOption::NO_MATCH;

   string_len = read_little_16_inc(cursor_normal);

   // check if we can skip string_len
   if(string_len > end_of_buffer - cursor_normal)
      return IpsOption::NO_MATCH;

   // skip to size and count
   cursor_normal += string_len + 30;

   // check if we can read:
   //  size  (4 bytes)
   //  count (4 bytes)
   if(cursor_normal + 8 > end_of_buffer)
      return IpsOption::NO_MATCH;

   size = read_little_32_inc(cursor_normal);
   count = read_little_32_inc(cursor_normal);

   DEBUG_SO(fprintf(stderr,"string_len=0x%04x, ",string_len);)
   DEBUG_SO(fprintf(stderr,"size=0x%04x, ",size);)
   DEBUG_SO(fprintf(stderr,"count=0x%04x\n",count);)

   // vulnerability condition:
   //  count * size * 0x18 overflows 32 bits
   check1 = count * size;

   // if either size or count is 0, overflow not possible.
   if(check1 == 0)
      return IpsOption::NO_MATCH;

   if(check1 / size != count)
      return IpsOption::MATCH;

   check2 = check1 * 0x18;   

   if(check2 / 0x18 != check1)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_19350 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        7, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "19350", // name
        "FILE-MULTIMEDIA Adobe Shockwave Player director file integer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_19350,
    rule_19350_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_19350 = &so_19350.base;

