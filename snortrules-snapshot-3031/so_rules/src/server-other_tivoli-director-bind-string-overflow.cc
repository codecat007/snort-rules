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
// server-other_tivoli-director-bind-string-overflow.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_13418 = R"[Snort_SO_Rule](
alert tcp $EXTERNAL_NET any -> $HOME_NET 389 (
	msg:"SERVER-OTHER IBM Tivoli Director LDAP server invalid DN message buffer overflow attempt";
	soid:13418;
	flow:to_server,established;
	content:"|30|",depth 1;
	byte_jump:0,0,from_beginning;
	ber_data:0x30;
	ber_skip:0x02;
	ber_data:0x60;
	ber_skip:0x02;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	service:ldap;
	reference:bugtraq,16593;
	reference:cve,2006-0717;
	reference:cve,2011-0917;
	reference:url,www-1.ibm.com/support/docview.wss?uid=swq21230820;
	classtype:attempted-dos;
	gid:3; sid:13418; rev:9;
)
)[Snort_SO_Rule]";

static const unsigned rule_13418_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint32_t remaining;

   BerReader ber(c);

   BerElement name, eoc;

   if(!ber.read(cursor_normal, name))
      return IpsOption::NO_MATCH;

   // make sure name is a string
   if(name.type != 0x04)
      return IpsOption::NO_MATCH;

   if(name.length > 0xFFFF)
      return IpsOption::MATCH;

   remaining = end_of_buffer - cursor_normal;

   // check if we can skip name
   if(name.total_length > remaining)
      return IpsOption::NO_MATCH;

   // skip name
   cursor_normal += name.total_length;

   if(!ber.read(cursor_normal, eoc))
      return IpsOption::NO_MATCH;

   if(eoc.type == 0x80 && eoc.length > 0xFFFF)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_13418 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        9, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "13418", // name
        "SERVER-OTHER IBM Tivoli Director LDAP server invalid DN message buffer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_13418,
    rule_13418_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_13418 = &so_13418.base;

