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
// file-office_kb2293211-ms-excel-table-cleanup.cc author Brandon Stultz <brastult@cisco.com>
//                                                 author Nick Randolph <nrandolp@cisco.com>

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

static const char* rule_17762 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-OFFICE Microsoft Excel corrupted TABLE record clean up exploit attempt";
	soid:17762;
	file_data;
	content:"|06 00|";
	byte_jump:2,0,relative,little,post_offset -1;
	content:"|00 36 02 10 00|",within 5;
	so:eval,relative;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	reference:cve,2010-3232;
	reference:url,technet.microsoft.com/security/bulletin/MS10-080;
	classtype:attempted-user;
	gid:3; sid:17762; rev:12;
)
)[Snort_SO_Rule]";

static const unsigned rule_17762_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint16_t Ref_rwFirst, Ref_rwLast,
            rwInpRw, Ref_reserved2;

   if(cursor_normal + 10 > end_of_buffer)
      return IpsOption::NO_MATCH;

   Ref_rwFirst = read_little_16_inc(cursor_normal);
   Ref_rwLast = read_little_16_inc(cursor_normal);

   cursor_normal += 2;

   Ref_reserved2 = read_little_16_inc(cursor_normal);

   if(Ref_reserved2 & 0x03FF)
      return IpsOption::NO_MATCH;

   rwInpRw = read_little_16(cursor_normal);

   // check vulnerability condition
   if(rwInpRw < Ref_rwFirst || rwInpRw > Ref_rwLast)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_17762 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        12, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "17762", // name
        "FILE-OFFICE Microsoft Excel corrupted TABLE record clean up exploit attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_17762,
    rule_17762_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_17762 = &so_17762.base;

