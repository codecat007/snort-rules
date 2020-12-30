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
// server-other_mit-kerberos-tgs-req-null-ptr-deref.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_27906 = R"[Snort_SO_Rule](
alert udp $EXTERNAL_NET any -> $HOME_NET 88 (
	msg:"SERVER-OTHER MIT Kerberos KDC prep_reprocess_req null pointer dereference attempt";
	soid:27906;
	flow:to_server;
	content:"|1B 00|";
	byte_jump:0,0,from_beginning;
	ber_data:0x6C;
	ber_data:0x30;
	ber_skip:0xA1;
	ber_skip:0xA2;
	ber_skip:0xA3,optional;
	ber_data:0xA4;
	ber_data:0x30;
	ber_skip:0xA0;
	ber_skip:0xA2;
	ber_data:0xA3;
	ber_data:0x30;
	ber_skip:0xA0;
	ber_data:0xA1;
	ber_data:0x30;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	service:kerberos;
	reference:cve,2013-1416;
	reference:url,web.mit.edu/kerberos/krb5-1.10/;
	classtype:attempted-admin;
	gid:3; sid:27906; rev:3;
)
)[Snort_SO_Rule]";

static const unsigned rule_27906_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start();

   BerReader ber(c);

   BerElement krb_str;

   // check up to 20 strings for the vulnerable condition
   for(unsigned i=0; i < 20; i++)
   {
      if(!ber.read(cursor_normal, krb_str))
         return IpsOption::NO_MATCH;

      DEBUG_SO(fprintf(stderr,"krb_str.length = 0x%02x\n",krb_str.length);)

      // vulnerable condition is krb_str.length == 0
      if(krb_str.length == 0)
         return IpsOption::MATCH;

      cursor_normal += krb_str.total_length;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_27906 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        3, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "27906", // name
        "SERVER-OTHER MIT Kerberos KDC prep_reprocess_req null pointer dereference attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_27906,
    rule_27906_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_27906 = &so_27906.base;

