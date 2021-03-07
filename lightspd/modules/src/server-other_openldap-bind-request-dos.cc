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
// server-other_openldap-bind-request-dos.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_13425 = R"[Snort_SO_Rule](
alert tcp any any -> $HOME_NET 389 (
	msg:"SERVER-OTHER OpenLDAP BIND request denial of service attempt";
	soid:13425;
	flow:to_server,established;
	content:"|30|";
	byte_jump:0,-1,relative;
	ber_data:0x30;
	ber_skip:0x02;
	ber_data:0x60;
	ber_skip:0x02;
	ber_skip:0x04;
	ber_data:0xA3;
	ber_data:0x04;
	content:"CRAM-MD5",within 8;
	so:eval,relative;
	metadata:policy max-detect-ips drop;
	service:ldap;
	reference:bugtraq,20939;
	reference:cve,2006-5779;
	classtype:attempted-dos;
	gid:3; sid:13425; rev:6;
)
)[Snort_SO_Rule]";

static const unsigned rule_13425_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   BerReader ber(c);

   BerElement element;

   if(!ber.read(cursor_normal, element))
      return IpsOption::NO_MATCH;

   if(element.type != 0x04 || element.length < 255)
      return IpsOption::NO_MATCH;

   cursor_normal = element.data;

   if(cursor_normal + 255 > end_of_buffer)
      return IpsOption::NO_MATCH;

   // check vulnerability condition
   if(cursor_normal[254] == 0x20)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_13425 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        6, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "13425", // name
        "SERVER-OTHER OpenLDAP BIND request denial of service attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_13425,
    rule_13425_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_13425 = &so_13425.base;

