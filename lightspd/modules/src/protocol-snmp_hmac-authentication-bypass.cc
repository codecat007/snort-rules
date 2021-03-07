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
// protocol-snmp_hmac-authentication-bypass.cc author Brandon Stultz <brastult@cisco.com>

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

#define BER_DATA(t) if(!ber.data(cursor_normal,t)) return IpsOption::NO_MATCH;
#define BER_SKIP(t) if(!ber.skip(cursor_normal,t)) return IpsOption::NO_MATCH;

using namespace snort;

static const char* rule_17699 = R"[Snort_SO_Rule](
alert udp $EXTERNAL_NET any -> $HOME_NET 161 (
	msg:"PROTOCOL-SNMP Multiple Vendors SNMPv3 HMAC handling authentication bypass attempt";
	soid:17699;
	content:"|02 01 03|",depth 10;
	byte_jump:0,0,from_beginning;
	ber_data:0x30;
	ber_skip:0x02;
	ber_data:0x30;
	ber_skip:0x02;
	ber_skip:0x02;
	ber_skip:0x04;
	so:eval;
	metadata:policy max-detect-ips drop;
	service:snmp;
	reference:bugtraq,29623;
	reference:cve,2008-0960;
	classtype:attempted-admin;
	gid:3; sid:17699; rev:3;
)
)[Snort_SO_Rule]";

static const unsigned rule_17699_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet*)
{
   const uint8_t *cursor_normal = c.start();

   BerReader ber(c);

   BerElement auth_params;

   uint32_t security_model;

   if(!ber.extract(cursor_normal, security_model))
      return IpsOption::NO_MATCH;

   if(security_model != 3)
      return IpsOption::NO_MATCH;

   BER_DATA(0x04) // msgSecurityParameters
   BER_DATA(0x30) // UsmSecurityParameters
   BER_SKIP(0x04) // msgAuthoritativeEngineID
   BER_SKIP(0x02) // msgAuthoritativeEngineBoots
   BER_SKIP(0x02) // msgAuthoritativeEngineTime
   BER_SKIP(0x04) // msgUserName

   if(!ber.read(cursor_normal, auth_params))
      return IpsOption::NO_MATCH;

   if(auth_params.type == 0x04 && auth_params.length == 1)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_17699 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        3, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "17699", // name
        "PROTOCOL-SNMP Multiple Vendors SNMPv3 HMAC handling authentication bypass attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_17699,
    rule_17699_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_17699 = &so_17699.base;

