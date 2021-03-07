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
// server-mail_ibm-domino-int-overflow.cc author Brandon Stultz <brastult@cisco.com>

#include "main/snort_types.h"
#include "framework/so_rule.h"
#include "framework/cursor.h"
#include "protocols/packet.h"
#include "util_read.h"

#include <cstdlib> // abs()

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

using namespace snort;

static const char* rule_42438 = R"[Snort_SO_Rule](
alert smtp (
	msg:"SERVER-MAIL IBM Domino BMP parsing integer overflow attempt";
	soid:42438;
	file_data;
	content:"BM",depth 2;
	content:"|00 00 00 00|",distance 4, within 4;
	content:"|28 00 00 00|",distance 4, within 4, fast_pattern;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	reference:bugtraq,74597;
	reference:cve,2015-1902;
	classtype:attempted-admin;
	gid:3; sid:42438; rev:2;
)
)[Snort_SO_Rule]";

static const unsigned rule_42438_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint32_t biWidth, biHeight;
   uint16_t biBitCount;
   uint64_t check;

   // check if we can read
   // biWidth (4 bytes)
   // biHeight (4 bytes)
   // skip biPlanes (2 bytes)
   // biBitCount (2 bytes)
   //
   if(cursor_normal + 12 > end_of_buffer)
      return IpsOption::NO_MATCH;

   biWidth = read_little_32_inc(cursor_normal);
   biHeight = read_little_32_inc(cursor_normal);

   // handle bitmap orientation 
   biWidth = (uint32_t)abs((int)biWidth);
   biHeight = (uint32_t)abs((int)biHeight);

   // skip biPlanes
   cursor_normal += 2;

   biBitCount = read_little_16(cursor_normal);

   // check for integer overflow condition
   check = (uint64_t)(biWidth & 0xFFFF) * (biBitCount >> 3) * biHeight;

   DEBUG_SO(fprintf(stderr,"check: %lu\n",check);)

   if(check > UINT32_MAX)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_42438 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        2, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "42438", // name
        "SERVER-MAIL IBM Domino BMP parsing integer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_42438,
    rule_42438_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_42438 = &so_42438.base;

