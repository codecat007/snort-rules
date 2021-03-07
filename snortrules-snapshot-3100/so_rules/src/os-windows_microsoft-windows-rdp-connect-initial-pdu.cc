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
// os-windows_microsoft-windows-rdp-connect-initial-pdu.cc author Brandon Stultz <brastult@cisco.com>
//                                                         author Patrick Mullen <pamullen@cisco.com>

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

static const char* rule_21619 = R"[Snort_SO_Rule](
alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (
	msg:"OS-WINDOWS Microsoft Windows RemoteDesktop connect-initial pdu remote code execution attempt";
	soid:21619;
	flow:to_server,established;
	content:"|03 00|",depth 2;
	content:"|F0 80 7F 65|";
	byte_jump:0,0,relative,post_offset -2;
	ber_data:0x65;
	ber_skip:0x04;
	ber_skip:0x04;
	ber_skip:0x01;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	service:rdp;
	reference:cve,2012-0002;
	reference:url,technet.microsoft.com/en-us/security/bulletin/ms12-020;
	classtype:attempted-admin;
	gid:3; sid:21619; rev:5;
)
)[Snort_SO_Rule]";

static const unsigned rule_21619_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *targetParameters;

   BerReader ber(c);

   uint32_t TpMaxChanIds, TpMaxUserIds,
            MpMaxChanIds;

   // save targetParameters position
   targetParameters = cursor_normal;

   BER_DATA(0x30) // Connect-Initial::targetParameters

   if(!ber.extract(cursor_normal, TpMaxChanIds))
      return IpsOption::NO_MATCH;

   // vulnerability condition 1
   if(TpMaxChanIds < 6)
      return IpsOption::MATCH;

   if(!ber.extract(cursor_normal, TpMaxUserIds))
      return IpsOption::NO_MATCH;

   // vulnerability condition 3
   if(TpMaxChanIds > 6 && TpMaxUserIds > 7)
      return IpsOption::MATCH;

   // move back to the targetParameters
   cursor_normal = targetParameters;

   BER_SKIP(0x30) // Connect-Initial::targetParameters
   BER_SKIP(0x30) // Connect-Initial::minimumParameters
   BER_DATA(0x30) // Connect-Initial::maximumParameters

   if(!ber.extract(cursor_normal, MpMaxChanIds))
      return IpsOption::NO_MATCH;

   // vulnerability conditition 2
   if(MpMaxChanIds < 6)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_21619 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        5, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "21619", // name
        "OS-WINDOWS Microsoft Windows RemoteDesktop connect-initial pdu remote code execution attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_21619,
    rule_21619_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_21619 = &so_21619.base;

