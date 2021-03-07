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
// file-office_kb2027452-ms-excel-hfpicture-bo.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_16649 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-OFFICE Microsoft Excel HFPicture record stack buffer overflow attempt";
	soid:16649;
	file_data;
	content:"|66 08 00 00 00 00 00 00 00 00 00 00|";
	content:"|66 08|",distance -16, within 2;
	byte_test:2,>,21,0,relative,little;
	byte_test:2,<,0x2020,0,relative,little;
	byte_test:2,=,0x000F,16,relative,little;
	so:eval,relative;
	metadata:policy max-detect-ips drop;
	reference:cve,2010-1248;
	reference:url,technet.microsoft.com/en-us/security/bulletin/MS10-038;
	classtype:attempted-user;
	gid:3; sid:16649; rev:10;
)
)[Snort_SO_Rule]";

static const unsigned rule_16649_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint16_t record_size, subrecord_size, type;

   if(cursor_normal + 24 > end_of_buffer)
      return IpsOption::NO_MATCH;

   record_size = read_little_16_inc(cursor_normal);

   // skip:
   //  frtHeader(12), flags(1),
   //  reserved(1), instance(2)
   cursor_normal += 16;

   type = read_little_16_inc(cursor_normal); 

   // OfficeArtRecordHeader.type
   if(type != 0xF000 && type != 0xF002)
      return IpsOption::NO_MATCH;

   subrecord_size = read_little_32(cursor_normal);

   // vulnerability condition
   //  HFPicture.Length [record_size] !=
   //   sizeof(FrtHeader) [0x0C] +
   //   sizeof(DataItem_Uint16) [0x02] +
   //   sizeof(OfficeArtRecordHeader) [0x08] +
   //   rh.recLen [subrecord_size]
   if(record_size != subrecord_size + 22)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_16649 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        10, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "16649", // name
        "FILE-OFFICE Microsoft Excel HFPicture record stack buffer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_16649,
    rule_16649_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_16649 = &so_16649.base;

