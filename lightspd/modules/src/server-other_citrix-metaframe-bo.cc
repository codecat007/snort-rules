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
// server-other_citrix-metaframe-bo.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_13417 = R"[Snort_SO_Rule](
alert tcp $EXTERNAL_NET any -> $HOME_NET 2513 (
	msg:"SERVER-OTHER Citrix MetaFrame IMA authentication processing buffer overflow attempt";
	soid:13417;
	content:"|41 80 00 00 02|",offset 28,depth 5;
	byte_test:4,<,16,4,little;
	so:eval;
	metadata:policy max-detect-ips drop;
	reference:bugtraq,20986;
	reference:cve,2006-5821;
	classtype:attempted-admin;
	gid:3; sid:13417; rev:5;
)
)[Snort_SO_Rule]";

static const unsigned rule_13417_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.buffer(),
                 *end_of_buffer = c.endo();

   uint16_t description_length;
   uint32_t event_data_length, encr_data_length;

   // skip to event_data_length
   cursor_normal += 8;

   // check if we can:
   //  read event_data_length  (4 bytes)
   //  skip                    (22 bytes)
   //  read description_length (2 bytes)
   //  read encr_data_length   (4 bytes)
   if(cursor_normal + 32 > end_of_buffer)
      return IpsOption::NO_MATCH;

   event_data_length = read_little_32_inc(cursor_normal);

   // skip to description_length
   cursor_normal += 22;

   description_length = read_little_16_inc(cursor_normal);
   encr_data_length = read_little_32_inc(cursor_normal);

   // check vulnerability condition
   if(description_length + encr_data_length > event_data_length)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_13417 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        5, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "13417", // name
        "SERVER-OTHER Citrix MetaFrame IMA authentication processing buffer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_13417,
    rule_13417_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_13417 = &so_13417.base;

