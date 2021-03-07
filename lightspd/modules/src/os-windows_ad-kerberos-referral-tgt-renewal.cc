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
// os-windows_ad-kerberos-referral-tgt-renewal.cc author Brandon Stultz <brastult@cisco.com>

#include "main/snort_types.h"
#include "framework/so_rule.h"
#include "framework/cursor.h"
#include "protocols/packet.h"
#include "utils/util_ber.h"
#include "util_read.h"

#include <cstring>

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

#define BER_DATA(t) if(!ber.data(cursor_normal,t)) return IpsOption::NO_MATCH;
#define BER_SKIP(t) if(!ber.skip(cursor_normal,t)) return IpsOption::NO_MATCH;

using namespace snort;

static const char* rule_16394 = R"[Snort_SO_Rule](
alert tcp $EXTERNAL_NET any -> $HOME_NET 88 (
	msg:"OS-WINDOWS Active Directory Kerberos referral TGT renewal DoS attempt";
	soid:16394;
	flow:to_server,established;
	content:"|A1 03 02 01 05 A2 03 02 01 0C|",depth 22;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	service:kerberos;
	reference:cve,2010-0035;
	reference:url,technet.microsoft.com/en-us/security/bulletin/MS10-014;
	classtype:attempted-dos;
	gid:3; sid:16394; rev:5;
)
)[Snort_SO_Rule]";

static const unsigned rule_16394_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo(),
                 *padata;

   BerReader ber(c);

   BerElement kdc_options, renew_realm, ticket_realm;

   // save padata position
   padata = cursor_normal;

   // skip to req-body
   BER_SKIP(0xA3)
   BER_DATA(0xA4)
   BER_DATA(0x30)
   BER_DATA(0xA0)

   // match kdc-options: renew
   if(!ber.read(cursor_normal, kdc_options))
      return IpsOption::NO_MATCH;

   if(kdc_options.type != 3 || kdc_options.length != 5)
      return IpsOption::NO_MATCH;

   cursor_normal = kdc_options.data;

   if(cursor_normal + 5 > end_of_buffer)
      return IpsOption::NO_MATCH;

   if(*cursor_normal++ != 0)
      return IpsOption::NO_MATCH;

   if(read_big_32_inc(cursor_normal) != 2)
      return IpsOption::NO_MATCH;

   BER_DATA(0xA2)

   // read renew_realm
   if(!ber.read(cursor_normal, renew_realm))
      return IpsOption::NO_MATCH;

   // make sure renew_realm is a string
   if(renew_realm.type != 0x1B)
      return IpsOption::NO_MATCH;

   // make sure we can read renew_realm.data
   if(renew_realm.data + renew_realm.length > end_of_buffer)
      return IpsOption::NO_MATCH;

   // go back to padata, get ticket_realm
   cursor_normal = padata;

   BER_DATA(0xA3);
   BER_DATA(0x30);
   BER_DATA(0x30); 
   BER_SKIP(0xA1);
   BER_DATA(0xA2);
   BER_DATA(0x04);
   BER_DATA(0x6E);
   BER_DATA(0x30);
   BER_SKIP(0xA0);
   BER_SKIP(0xA1);
   BER_SKIP(0xA2);
   BER_DATA(0xA3);
   BER_DATA(0x61);
   BER_DATA(0x30);
   BER_SKIP(0xA0);
   BER_DATA(0xA1);

   // read ticket_realm
   if(!ber.read(cursor_normal, ticket_realm))
      return IpsOption::NO_MATCH;

   // make sure ticket_realm is a string
   if(ticket_realm.type != 0x1B)
      return IpsOption::NO_MATCH;

   // make sure we can read ticket_realm
   if(ticket_realm.data + ticket_realm.length > end_of_buffer)
      return IpsOption::NO_MATCH;

   // check vulnerability condition
   if(ticket_realm.length != renew_realm.length)
      return IpsOption::MATCH;

   if(memcmp(ticket_realm.data, renew_realm.data, ticket_realm.length))
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_16394 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        5, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "16394", // name
        "OS-WINDOWS Active Directory Kerberos referral TGT renewal DoS attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_16394,
    rule_16394_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_16394 = &so_16394.base;

