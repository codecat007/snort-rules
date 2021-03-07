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
// file-office_kb954066-excel-obj-record-invalid-ft.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_15117 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-OFFICE Microsoft Excel malformed OBJ record memory corruption attempt";
	soid:15117;
	file_data;
	content:"|5D 00|";
	content:"|15 00 12 00|",distance 2,within 4,fast_pattern;
	content:"|00 00 00 00|",distance 6,within 4;
	byte_jump:0,-16,relative;
	so:eval,relative;
	metadata:policy max-detect-ips drop;
	reference:cve,2008-4264;
	reference:url,technet.microsoft.com/en-us/security/bulletin/MS08-074;
	classtype:attempted-user;
	gid:3; sid:15117; rev:14;
)
)[Snort_SO_Rule]";

static const unsigned rule_15117_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo(),
                 *end_of_record;

   uint16_t obj_record_len, ft, cb;

   // check if we can:
   //  read obj_record_len (2 bytes)
   if(cursor_normal + 2 > end_of_buffer)
      return IpsOption::NO_MATCH;

   obj_record_len = read_little_16_inc(cursor_normal);

   DEBUG_SO(fprintf(stderr,"obj_record_len=0x%04x\n",obj_record_len);)

   if(obj_record_len == 0)
      return IpsOption::NO_MATCH;

   // check if we can read obj_record_len
   if(obj_record_len > end_of_buffer - cursor_normal)
      return IpsOption::NO_MATCH;

   // calculate end_of_record position
   end_of_record = cursor_normal + obj_record_len;

   // read each subrecord
   while(cursor_normal + 4 < end_of_record)
   {
      ft = read_little_16_inc(cursor_normal);
      cb = read_little_16_inc(cursor_normal);

      DEBUG_SO(fprintf(stderr,"ft=0x%02x\n",ft);)
      DEBUG_SO(fprintf(stderr,"cb=0x%02x\n",cb);)

      // check vulnerability condition
      if(ft > 0x15)
         return IpsOption::MATCH;

      // check if we can jump cb
      if(cb > end_of_record - cursor_normal)
         return IpsOption::NO_MATCH;

      // jump cb
      cursor_normal += cb;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_15117 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        14, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "15117", // name
        "FILE-OFFICE Microsoft Excel malformed OBJ record memory corruption attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_15117,
    rule_15117_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_15117 = &so_15117.base;

