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
// server-other_ldap-object-parameter-name-overflow.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_16375 = R"[Snort_SO_Rule](
alert tcp $EXTERNAL_NET any -> $HOME_NET 389 (
	msg:"SERVER-OTHER Oracle Internet Directory oidldapd buffer overflow attempt";
	soid:16375;
	flow:to_server,established;
	content:"|30|",depth 1;
	byte_jump:0,-1,relative;
	ber_data:0x30;
	ber_skip:0x02;
	ber_data:0x66;
	so:eval;
	metadata:policy max-detect-ips drop;
	service:ldap;
	classtype:attempted-admin;
	gid:3; sid:16375; rev:4;
)
)[Snort_SO_Rule]";

static const unsigned rule_16375_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   enum State { NAME, VALUE };
   State s = State::NAME;

   uint32_t namelen = 0;

   BerReader ber(c);
   BerElement element;

   if(!ber.read(cursor_normal, element))
      return IpsOption::NO_MATCH;

   if(element.type != 0x04)
      return IpsOption::NO_MATCH;

   cursor_normal = element.data;

   // check if we can read element.length
   if(element.length > end_of_buffer - cursor_normal)
      return IpsOption::NO_MATCH;

   // parse and check the parameter names
   for(unsigned i = 0; i < element.length; i++)
   {
      uint8_t b = *cursor_normal++;

      switch(s)
      {
      case State::NAME:
         if(b == '=')
         {
            // reset namelen
            namelen = 0;
            s = State::VALUE;
            continue;
         }

         namelen++;

         if(namelen > 100)
            return IpsOption::MATCH;

         break;
      default:
         if(b == ',')
         {
            s = State::NAME;
            continue;
         }
         break;
      }
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_16375 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        4, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "16375", // name
        "SERVER-OTHER Oracle Internet Directory oidldapd buffer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_16375,
    rule_16375_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_16375 = &so_16375.base;

