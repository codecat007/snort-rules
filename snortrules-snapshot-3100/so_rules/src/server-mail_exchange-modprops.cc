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
// server-mail_exchange-modprops.cc author Brandon Stultz <brastult@cisco.com>

#include "main/snort_types.h"
#include "framework/so_rule.h"
#include "framework/cursor.h"
#include "protocols/packet.h"
#include "utils/boyer_moore.h"

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

using namespace snort;

static const char* pat = "MODPROPS";

static const unsigned pat_len = 8;

static const char* rule_15329 = R"[Snort_SO_Rule](
alert file (
	msg:"SERVER-MAIL Microsoft Exchange MODPROPS memory corruption attempt";
	soid:15329;
	file_data;
	content:"BEGIN:VEVENT",nocase;
	content:"MODPROPS",nocase;
	so:eval;
	metadata:policy max-detect-ips drop;
	reference:bugtraq,17908;
	reference:cve,2006-0027;
	reference:url,technet.microsoft.com/en-us/security/bulletin/ms06-019;
	classtype:attempted-admin;
	gid:3; sid:15329; rev:4;
)
)[Snort_SO_Rule]";

static const unsigned rule_15329_len = 0;

static IpsOption::EvalStatus eval(void* pv, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   BoyerMoore* boyer_moore = (BoyerMoore*)pv;

   unsigned count_one = 0, count_two = 0;

   while(true)
   {
      if(cursor_normal >= end_of_buffer)
         return IpsOption::NO_MATCH;

      if(*cursor_normal == 0x0D || *cursor_normal == 0x0A)
         break;

      if(*cursor_normal == ',')
         count_one++;

      cursor_normal++;
   }

   unsigned depth = end_of_buffer - cursor_normal;

   int pos = boyer_moore->search(cursor_normal, depth);

   if(pos < 0)
      return IpsOption::NO_MATCH;

   cursor_normal += pos + pat_len;

   while(true)
   {
      if(cursor_normal >= end_of_buffer)
         return IpsOption::NO_MATCH;

      if(*cursor_normal == 0x0D || *cursor_normal == 0x0A)
         break;

      if(*cursor_normal == ',')
         count_two++;

      cursor_normal++;
   }

   if(count_two > count_one)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = new BoyerMoore((const uint8_t*)pat, pat_len);
    return eval;
}

static void dtor(void* pv)
{
    delete (BoyerMoore*)pv;
}

static const SoApi so_15329 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        4, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "15329", // name
        "SERVER-MAIL Microsoft Exchange MODPROPS memory corruption attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_15329,
    rule_15329_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    dtor     // dtor
};

const BaseApi* pso_15329 = &so_15329.base;

