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
// server-other_mit-kerberos-sname-null-ptr-deref.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_34971 = R"[Snort_SO_Rule](
alert udp $EXTERNAL_NET any -> $HOME_NET 88 (
	msg:"SERVER-OTHER MIT Kerberos KDC as-req sname null pointer dereference attempt";
	soid:34971;
	flow:to_server;
	content:"|A2 03 02 01 0A|";
	byte_jump:0,0,from_beginning;
	ber_data:0x6A;
	ber_data:0x30;
	ber_skip:0xA1;
	ber_data:0xA2;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	service:kerberos;
	reference:bugtraq,63555;
	reference:cve,2013-1418;
	classtype:attempted-dos;
	gid:3; sid:34971; rev:2;
)
)[Snort_SO_Rule]";

static const unsigned rule_34971_len = 0;

static const char* rule_34972 = R"[Snort_SO_Rule](
alert tcp $EXTERNAL_NET any -> $HOME_NET 88 (
	msg:"SERVER-OTHER MIT Kerberos KDC as-req sname null pointer dereference attempt";
	soid:34972;
	flow:to_server,established;
	content:"|A2 03 02 01 0A|";
	byte_jump:0,0,from_beginning,post_offset 4;
	ber_data:0x6A;
	ber_data:0x30;
	ber_skip:0xA1;
	ber_data:0xA2;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	service:kerberos;
	reference:bugtraq,63555;
	reference:cve,2013-1418;
	classtype:attempted-dos;
	gid:3; sid:34972; rev:2;
)
)[Snort_SO_Rule]";

static const unsigned rule_34972_len = 0;

static IpsOption::EvalStatus DetectKrbNullPtrDeref(Cursor& c)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   BerReader ber(c);
   uint32_t msg_type;

   // extract msg-type
   if(!ber.extract(cursor_normal, msg_type))
      return IpsOption::NO_MATCH;

   // make sure msg-type is krb-as-req (10)
   if(msg_type != 10)
      return IpsOption::NO_MATCH;

   // if optional PA-DATA exists, skip it
   if(cursor_normal + 1 > end_of_buffer)
      return IpsOption::NO_MATCH;

   if(*cursor_normal == 0xA3)
   {
      BER_SKIP(0xA3)
   }

   // KDC-REQ-BODY [4] ::= SEQUENCE [16]
   //    kdc-options [0]
   //    cname       [1] 
   //    realm       [2]
   //    sname       [3] 
   BER_DATA(0xA4)
   BER_DATA(0x30)
   BER_SKIP(0xA0)

   // if optional cname exists, skip it
   if(cursor_normal + 1 > end_of_buffer)
      return IpsOption::NO_MATCH;

   if(*cursor_normal == 0xA1)
   {
      BER_SKIP(0xA1)
   }

   // realm [2]
   BER_SKIP(0xA2)

   // check for sname
   if(cursor_normal + 1 > end_of_buffer)
      return IpsOption::NO_MATCH;

   // if the next BER element isn't sname [3],
   // null ptr deref triggered, alert
   if(*cursor_normal != 0xA3)
   {
      DEBUG_SO(fprintf(stderr,"expected sname [3], got BER type: 0x%02X\n", *cursor_normal);)
      return IpsOption::MATCH;
   }

   return IpsOption::NO_MATCH;
}

static IpsOption::EvalStatus rule_34971_eval(void*, Cursor& c, Packet* p)
{
   return DetectKrbNullPtrDeref(c);
}

static SoEvalFunc rule_34971_ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return rule_34971_eval;
}

static const SoApi so_34971 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        2, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "34971", // name
        "SERVER-OTHER MIT Kerberos KDC as-req sname null pointer dereference attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_34971,
    rule_34971_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    rule_34971_ctor, // ctor
    nullptr  // dtor
};

static IpsOption::EvalStatus rule_34972_eval(void*, Cursor& c, Packet* p)
{
   return DetectKrbNullPtrDeref(c);
}

static SoEvalFunc rule_34972_ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return rule_34972_eval;
}

static const SoApi so_34972 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        2, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "34972", // name
        "SERVER-OTHER MIT Kerberos KDC as-req sname null pointer dereference attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_34972,
    rule_34972_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    rule_34972_ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_34971 = &so_34971.base;
const BaseApi* pso_34972 = &so_34972.base;

