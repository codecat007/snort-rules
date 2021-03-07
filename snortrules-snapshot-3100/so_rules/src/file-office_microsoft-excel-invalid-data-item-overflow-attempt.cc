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
// file-office_microsoft-excel-invalid-data-item-overflow-attempt.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_24666 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-OFFICE Microsoft Office Excel invalid data item buffer overflow attempt";
	soid:24666;
	file_type:MSOLE2;
	file_data;
	content:"|78 08|";
	content:"|78 08|",distance 2, within 2;
	content:"|00 00 00 00|",distance 12, within 4;
	byte_jump:2,1,relative,little,multiplier 8;
	content:"|00 00 00 00|",distance 14, within 4;
	so:eval,relative;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	reference:cve,2012-2543;
	reference:url,technet.microsoft.com/security/bulletin/MS12-076;
	classtype:attempted-user;
	gid:3; sid:24666; rev:6;
)
)[Snort_SO_Rule]";

static const unsigned rule_24666_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo(),
                 *cursor_tmp;

   uint16_t rgbNameL, cFieldData, entryIDL,
            strCaptionL, strFieldNameL;

   uint32_t cbdxfHdrDiskL, cbFmtInsertRowL;

   // jump to rgbName
   cursor_normal += 52;

   // make sure we can read rgbNameL
   if(cursor_normal + 2 > end_of_buffer)
      return IpsOption::NO_MATCH;

   // read rgbNameL
   rgbNameL = read_little_16(cursor_normal);

   // jump over rgbName
   cursor_normal += rgbNameL + 3;

   // make sure we can read cFieldData and entryID
   if(cursor_normal + 4 > end_of_buffer)
      return IpsOption::NO_MATCH;

   // read cfieldData
   cFieldData = read_little_16_inc(cursor_normal);

   // read entryIDL
   entryIDL = read_little_16(cursor_normal);

   // jump over entryID
   cursor_normal += entryIDL + 3;

   // max 10 iterations
   if(cFieldData > 10)
      cFieldData = 10;

   for(unsigned i = 0; i < cFieldData; i++)
   {
      // jump to cbFmtInsertRowL
      cursor_normal += 28;

      // make sure we can read length of cbFmtInsertRowL and strFieldNameL
      if(cursor_normal + 10 > end_of_buffer)
         return IpsOption::NO_MATCH;

      // read the cbFmtInsertRowL
      cbFmtInsertRowL = read_little_32_inc(cursor_normal);

      // move to strFieldName
      cursor_normal += 4;

      // read strFieldNameL
      strFieldNameL = read_little_16(cursor_normal);

      // jump strFieldName
      cursor_tmp = cursor_normal + strFieldNameL + 3;

      if(cursor_tmp < cursor_normal)
         return IpsOption::NO_MATCH;

      cursor_normal = cursor_tmp;

      // make sure we can read strCaptionL
      if(cursor_normal + 2 > end_of_buffer)
         return IpsOption::NO_MATCH;

      // read strCaptionL
      strCaptionL = read_little_16(cursor_normal);

      // jump over strCaptionL and dxFmtInsertRow
      cursor_tmp = cursor_normal + strCaptionL + cbFmtInsertRowL + 3;

      if(cursor_tmp < cursor_normal)
         return IpsOption::NO_MATCH;

      cursor_normal = cursor_tmp;

      // make sure we can read cbdxfHdrDiskL
      if(cursor_normal + 4 > end_of_buffer)
         return IpsOption::NO_MATCH;

      // read the cbdxfHdrDiskL
      cbdxfHdrDiskL = read_little_32(cursor_normal);

      // check vulnerability condition
      if(cbdxfHdrDiskL > 0x2020)
         return IpsOption::MATCH;

      cursor_tmp = cursor_normal + cbdxfHdrDiskL + 4;

      if(cursor_tmp < cursor_normal)
         return IpsOption::NO_MATCH;

      cursor_normal = cursor_tmp;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_24666 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        6, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "24666", // name
        "FILE-OFFICE Microsoft Office Excel invalid data item buffer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_24666,
    rule_24666_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_24666 = &so_24666.base;

