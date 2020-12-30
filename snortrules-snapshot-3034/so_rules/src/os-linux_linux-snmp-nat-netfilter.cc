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
// os-linux_linux-snmp-nat-netfilter.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_13773 = R"[Snort_SO_Rule](
alert udp $EXTERNAL_NET any -> $HOME_NET [161:162] (
	msg:"OS-LINUX Linux Kernel snmp nat netfilter memory corruption attempt";
	soid:13773;
	flow:to_server;
	content:"|30|";
	byte_jump:0,0,from_beginning;
	ber_data:0x30;
	ber_data:0x02;
	content:"|01|",within 1;
	ber_skip:0x04;
	so:eval;
	metadata:policy max-detect-ips drop;
	service:snmp;
	reference:bugtraq,18081;
	reference:cve,2006-2444;
	reference:cve,2008-1673;
	classtype:attempted-dos;
	gid:3; sid:13773; rev:8;
)
)[Snort_SO_Rule]";

static const unsigned rule_13773_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   BerReader ber(c);

   BerElement trap, e;

   uint32_t remaining;

   if(!ber.read(cursor_normal, trap))
      return IpsOption::NO_MATCH;

   if(trap.type != 0xA4)
      return IpsOption::NO_MATCH;

   cursor_normal = trap.data;

   // verify snmp trap structure
   // if anything is invalid, alert

   // enterprise
   if(!ber.skip(cursor_normal, 0x06))
      return IpsOption::MATCH;

   // agent-addr
   if(!ber.skip(cursor_normal, 0x40))
      return IpsOption::MATCH;

   // generic-trap
   if(!ber.skip(cursor_normal, 0x02))
      return IpsOption::MATCH;

   // specific-trap
   if(!ber.skip(cursor_normal, 0x02))
      return IpsOption::MATCH;

   if(!ber.read(cursor_normal, e))
      return IpsOption::MATCH;

   // either Integer or Timestamp
   if(e.type != 0x02 && e.type != 0x43)
      return IpsOption::MATCH;

   remaining = end_of_buffer - cursor_normal;

   // check if we can jump e.total_length
   if(e.total_length > remaining)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_13773 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        8, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "13773", // name
        "OS-LINUX Linux Kernel snmp nat netfilter memory corruption attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_13773,
    rule_13773_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_13773 = &so_13773.base;

