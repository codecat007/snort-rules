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
// os-windows_kb969947-win-kernel-fontparsing-rce.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_16232 = R"[Snort_SO_Rule](
alert file (
	msg:"OS-WINDOWS Microsoft Windows EOT font parsing integer overflow attempt";
	soid:16232;
	file_data;
	content:"|4C 50|",offset 34,depth 2;
	byte_extract:4,4,data_size,little;
	byte_math:bytes 4,offset 0,oper -,rvalue data_size,result header_size,endian little;
	byte_jump:0,0,post_offset header_size,from_beginning;
	content:"|00 01 00 00|",within 4;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	reference:cve,2009-2514;
	reference:url,technet.microsoft.com/en-us/security/bulletin/MS09-065;
	classtype:attempted-admin;
	gid:3; sid:16232; rev:9;
)
)[Snort_SO_Rule]";

static const unsigned rule_16232_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint16_t numTables;
   uint32_t offset, length, check;

   if(cursor_normal + 2 > end_of_buffer)
      return IpsOption::NO_MATCH;

   numTables = read_big_16_inc(cursor_normal);

   // limit how many tables we will check
   if(numTables > 25)
      numTables = 25;

   // skip:
   //  searchRange(2), entrySelector(2),
   //  rangeShift(2), Tag(4), checksum(4)
   cursor_normal += 14;

   for(unsigned i=0; i < numTables; i++)
   {
      if(cursor_normal + 8 > end_of_buffer)
         return IpsOption::NO_MATCH;

      offset = read_big_32_inc(cursor_normal);
      length = read_big_32_inc(cursor_normal);

      check = offset + length;

      // vulnerability condition
      if(check < offset)
         return IpsOption::MATCH;

      // skip Tag(4), checkSum(4)
      cursor_normal += 8;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_16232 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        9, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "16232", // name
        "OS-WINDOWS Microsoft Windows EOT font parsing integer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_16232,
    rule_16232_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_16232 = &so_16232.base;

