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
// server-other_imail-ldap.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_10480 = R"[Snort_SO_Rule](
alert tcp $EXTERNAL_NET any -> $HOME_NET 389 (
	msg:"SERVER-OTHER imail ldap buffer overflow exploit attempt";
	soid:10480;
	flow:to_server,established;
	content:"|30|",depth 1;
	byte_jump:0,0,from_beginning;
	ber_data:0x30;
	so:eval;
	metadata:policy max-detect-ips drop;
	service:ldap;
	reference:cve,2004-0297;
	classtype:attempted-admin;
	gid:3; sid:10480; rev:6;
)
)[Snort_SO_Rule]";

static const unsigned rule_10480_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint32_t remaining;

   BerReader ber(c);

   BerElement msg_id, version;

   if(!ber.read(cursor_normal, msg_id))
      return IpsOption::NO_MATCH;

   // make sure msg_id is an integer
   if(msg_id.type != 0x02)
      return IpsOption::NO_MATCH;

   // check vulnerability condition
   if(msg_id.length > 4)
      return IpsOption::MATCH;

   remaining = end_of_buffer - cursor_normal;

   // check if we can skip msg_id
   if(msg_id.total_length > remaining)
      return IpsOption::NO_MATCH;

   // skip msg_id
   cursor_normal += msg_id.total_length;

   // bindRequest
   if(!ber.data(cursor_normal, 0x60))
      return IpsOption::NO_MATCH;

   // verify minimum for bindRequest.version
   if(cursor_normal + 3 > end_of_buffer)
      return IpsOption::NO_MATCH;

   // verify bindRequest.version is an integer
   if(*cursor_normal != 0x02)
      return IpsOption::NO_MATCH;

   // alert if the version element is invalid
   if(!ber.read(cursor_normal, version))
      return IpsOption::MATCH;

   // alert if version.length > 4
   if(version.length > 4)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_10480 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        6, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "10480", // name
        "SERVER-OTHER imail ldap buffer overflow exploit attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_10480,
    rule_10480_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_10480 = &so_10480.base;

