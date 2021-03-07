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
// server-other_mit-kerberos-uninitialized-ptr.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_17741 = R"[Snort_SO_Rule](
alert udp $EXTERNAL_NET any -> $HOME_NET 88 (
	msg:"SERVER-OTHER MIT Kerberos asn1_decode_generaltime uninitialized pointer free attempt";
	soid:17741;
	flow:to_server;
	content:"|30|";
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	service:kerberos;
	reference:bugtraq,34409;
	reference:cve,2009-0846;
	classtype:attempted-admin;
	gid:3; sid:17741; rev:5;
)
)[Snort_SO_Rule]";

static const unsigned rule_17741_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.buffer(),
                 *end_of_buffer = c.endo();

   BerReader ber(c);

   BerElement req, req_body, sequence;

   if(!ber.read(cursor_normal, req))
      return IpsOption::NO_MATCH;

   if(req.type != 0x6A && req.type != 0x6C)
      return IpsOption::NO_MATCH;

   cursor_normal = req.data;

   BER_DATA(0x30) // SEQUENCE
   BER_SKIP(0xA1) // pvno [1]
   BER_SKIP(0xA2) // msg-type [2]

   // check if we can read the next element
   if(cursor_normal + 1 > end_of_buffer)
      return IpsOption::NO_MATCH;

   if(*cursor_normal == 0xA3)
   {
      // skip optional pa-data
      BER_SKIP(0xA3)
   }

   if(!ber.read(cursor_normal, req_body))
      return IpsOption::NO_MATCH;

   if(req_body.type != 0xA4)
      return IpsOption::NO_MATCH;

   cursor_normal = req_body.data;

   if(!ber.read(cursor_normal, sequence))
      return IpsOption::NO_MATCH;

   if(sequence.type != 0x30)
      return IpsOption::NO_MATCH;

   DEBUG_SO(fprintf(stderr,"req_body.length = 0x%08x\n",req_body.length);)
   DEBUG_SO(fprintf(stderr,"sequence.total_length = 0x%08x\n",sequence.total_length);)

   // check vulnerability condition
   if(req_body.length != sequence.total_length)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_17741 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        5, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "17741", // name
        "SERVER-OTHER MIT Kerberos asn1_decode_generaltime uninitialized pointer free attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_17741,
    rule_17741_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_17741 = &so_17741.base;

