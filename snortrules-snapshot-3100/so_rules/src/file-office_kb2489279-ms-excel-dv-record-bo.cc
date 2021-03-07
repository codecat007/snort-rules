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
// file-office_kb2489279-ms-excel-dv-record-bo.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_18676 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-OFFICE Microsoft Office Excel DV record buffer overflow attempt";
	soid:18676;
	file_data;
	content:"|B2 01 12 00|";
	content:"|BE 01|",distance 18,within 2;
	so:eval,relative;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	reference:cve,2011-0105;
	reference:url,technet.microsoft.com/en-us/security/bulletin/MS11-021;
	classtype:attempted-user;
	gid:3; sid:18676; rev:11;
)
)[Snort_SO_Rule]";

static const unsigned rule_18676_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint8_t valType, fHighByte;
   uint16_t cch, cce;

   // skip length
   cursor_normal += 2;

   // check if we can read dwDvFlags
   if(cursor_normal + 4 > end_of_buffer)
      return IpsOption::NO_MATCH;

   valType = *cursor_normal & 0x0F;

   // valType must be: 1, 2, 4, 5, or 6
   if(valType == 0 || valType == 3 || valType > 6)
      return IpsOption::NO_MATCH;

   // typOperator must be 0
   if(cursor_normal[2] & 0xE0)
      return IpsOption::NO_MATCH;

   // skip dwDvFlags
   cursor_normal += 4;

   // skip:
   //  PromptTitle, ErrorTitle, Prompt, Error
   //  XLUnicodeString structures
   for(unsigned i = 0; i < 4; i++)
   {
      // check if we can read cch, fHighByte
      if(cursor_normal + 3 > end_of_buffer)
         return IpsOption::NO_MATCH;

      cch = read_little_16_inc(cursor_normal);

      fHighByte = *cursor_normal++;

      // if fHighByte bit is set
      // array size is cch * 2 (wide char)
      if(fHighByte & 1)
         cch *= 2;

      cursor_normal += cch;
   }

   // check if we can read formula1.cce
   if(cursor_normal + 2 > end_of_buffer)
      return IpsOption::NO_MATCH;

   cce = read_little_16_inc(cursor_normal);

   // skip cce, unused(2)
   cursor_normal += cce + 2;

   // check if we can read formula2.cce
   if(cursor_normal + 2 > end_of_buffer)
      return IpsOption::NO_MATCH;

   cce = read_little_16_inc(cursor_normal);

   // check vulnerability condition
   if(cce == 0)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_18676 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        11, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "18676", // name
        "FILE-OFFICE Microsoft Office Excel DV record buffer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_18676,
    rule_18676_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_18676 = &so_18676.base;

