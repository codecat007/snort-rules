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
// server-iis_ms-aspdotnet-viewstate.cc author Brandon Stultz <brastult@cisco.com>

#include "main/snort_types.h"
#include "framework/so_rule.h"
#include "framework/cursor.h"
#include "protocols/packet.h"
#include "mime/decode_b64.h"

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

using namespace snort;

static const char* rule_15959 = R"[Snort_SO_Rule](
alert http (
	msg:"SERVER-IIS Microsoft ASP.NET viewstate denial of service attempt";
	soid:15959;
	flow:to_server,established;
	http_client_body;
	content:"__VIEWSTATE=";
	so:eval,relative;
	metadata:policy max-detect-ips drop;
	reference:cve,2005-1665;
	classtype:attempted-dos;
	gid:3; sid:15959; rev:5;
)
)[Snort_SO_Rule]";

static const unsigned rule_15959_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   uint8_t *cursor_normal = const_cast<uint8_t*>(c.start());

   uint8_t decoded_buf[1024];

   uint32_t num_decoded = 0,
            nest_level = 0;

   unsigned buffer_len = c.length();

   // limit buffer_len
   if(buffer_len > 1500)
      buffer_len = 1500;

   int result = sf_base64decode(
      cursor_normal, buffer_len,
      decoded_buf, sizeof(decoded_buf),
      &num_decoded
   );

   if(result < 0)
      return IpsOption::NO_MATCH;

   for(unsigned i = 0; i < num_decoded; i++)
   {
      if(decoded_buf[i] == '<')
         nest_level++;
      else if(decoded_buf[i] == '>' && nest_level > 0)
         nest_level--;

      if(nest_level > 500)
         return IpsOption::MATCH;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_15959 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        5, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "15959", // name
        "SERVER-IIS Microsoft ASP.NET viewstate denial of service attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_15959,
    rule_15959_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_15959 = &so_15959.base;

