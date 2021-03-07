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
// server-other_landesk-qip-heal.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_15968 = R"[Snort_SO_Rule](
alert tcp $EXTERNAL_NET any -> $HOME_NET 12175 (
	msg:"SERVER-OTHER LANDesk Management Suite QIP service heal packet buffer overflow attempt";
	soid:15968;
	flow:to_server,established;
	content:"heal",offset 14,depth 4;
	content:"sdfx",depth 4;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	reference:bugtraq,31193;
	reference:cve,2008-2468;
	classtype:attempted-admin;
	gid:3; sid:15968; rev:4;
)
)[Snort_SO_Rule]";

static const unsigned rule_15968_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint32_t msg_len, string_offset;

   // check if we can read:
   //  msg_len       (4 bytes)
   //  skip          (26 bytes)
   //  string_offset (4 bytes)
   if(cursor_normal + 34 > end_of_buffer)
      return IpsOption::NO_MATCH;

   msg_len = read_big_32_inc(cursor_normal);

   // skip to stringOffset
   cursor_normal += 26;

   // QIP payload byte order is little endian
   string_offset = read_little_32_inc(cursor_normal);

   if(string_offset < 0x24 || string_offset > msg_len)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_15968 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        4, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "15968", // name
        "SERVER-OTHER Cisco IOS invalid IKE fragment length memory corruption or exhaustion attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_15968,
    rule_15968_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_15968 = &so_15968.base;

