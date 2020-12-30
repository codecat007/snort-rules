//--------------------------------------------------------------------------
// Copyright (C) 2019-2020 Cisco and/or its affiliates. All rights reserved.
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
// server-other_novell-edirectory-nullfilter.cc author Brandon Stultz <brastult@cisco.com>

#include "main/snort_types.h"
#include "framework/so_rule.h"
#include "framework/cursor.h"
#include "protocols/packet.h"
#include "utils/util_ber.h"

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

using namespace snort;

static const char* rule_15973 = R"[Snort_SO_Rule](
alert tcp $EXTERNAL_NET any -> $HOME_NET 389 (
	msg:"SERVER-OTHER Novell eDirectory LDAP null search parameter buffer overflow attempt";
	soid:15973;
	flow:to_server,established;
	content:"|A9|";
	content:"|30|";
	byte_jump:0,-1,relative;
	ber_data:0x30;
	ber_skip:0x02;
	ber_data:0x63;
	ber_skip:0x04;
	ber_skip:0x0A;
	ber_skip:0x0A;
	ber_skip:0x02;
	ber_skip:0x02;
	ber_skip:0x01;
	so:eval,relative;
	metadata:policy max-detect-ips drop;
	service:ldap;
	reference:bugtraq,30175;
	reference:cve,2008-1809;
	classtype:attempted-admin;
	gid:3; sid:15973; rev:5;
)
)[Snort_SO_Rule]";

static const unsigned rule_15973_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start();

   BerReader ber(c);

   BerElement filter;

   if(!ber.read(cursor_normal, filter))
      return IpsOption::NO_MATCH;

   if(filter.type != 0xA9)
      return IpsOption::NO_MATCH;

   if(filter.length == 0)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_15973 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        5, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "15973", // name
        "SERVER-OTHER Novell eDirectory LDAP null search parameter buffer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_15973,
    rule_15973_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_15973 = &so_15973.base;

