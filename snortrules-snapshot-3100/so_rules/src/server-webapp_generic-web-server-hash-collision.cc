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
// server-webapp_generic-web-server-hash-collision.cc author Brandon Stultz <brastult@cisco.com>
//                                                    author Patrick Mullen <pamullen@cisco.com>

#include "main/snort_types.h"
#include "framework/so_rule.h"
#include "framework/cursor.h"
#include "protocols/packet.h"

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

#define MAX_POST_PARAMS 250
#define JUMP_DIST 3 // '&', 1 char name, '='

using namespace snort;

static const char* rule_20825 = R"[Snort_SO_Rule](
alert http $EXTERNAL_NET any -> $HOME_NET any (
	msg:"SERVER-WEBAPP generic web server hashing collision attack";
	soid:20825;
	flow:to_server,established;
	http_header;
	content:"Content-Length:",nocase;
	http_raw_body;
	so:eval;
	metadata:policy max-detect-ips drop;
	service:http;
	reference:url,technet.microsoft.com/en-us/security/bulletin/MS11-100;
	reference:url,technet.microsoft.com/en-us/security/advisory/2659883;
	reference:url,events.ccc.de/congress/2011/Fahrplan/events/4680.en.html;
	reference:cve,2010-1899;
	reference:cve,2011-3414;
	reference:cve,2011-5037;
	reference:cve,2012-0830;
	classtype:attempted-dos;
	gid:3; sid:20825; rev:11;
)
)[Snort_SO_Rule]";

static const unsigned rule_20825_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.buffer(),
                 *end_of_buffer = c.endo();

   unsigned paramcount = 0;

   if(c.size() < MAX_POST_PARAMS * JUMP_DIST)
      return IpsOption::NO_MATCH;

   while(cursor_normal < end_of_buffer)
   {
      if(*cursor_normal != '=')
      {
         cursor_normal++;
         continue;
      }

      // found '='
      paramcount++;

      // if there are too many parameters, alert
      if(paramcount >= MAX_POST_PARAMS)
         return IpsOption::MATCH;

      cursor_normal += JUMP_DIST;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_20825 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        11, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "20825", // name
        "SERVER-WEBAPP generic web server hashing collision attack", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_20825,
    rule_20825_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_20825 = &so_20825.base;

