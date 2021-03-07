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
// file-office_rtf-nested-listoverridetables.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* pat = "{\\listoverride\\";

static const unsigned pat_len = 15;

static const char* rule_22089 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-OFFICE Microsoft RTF improper listoverride nesting attempt";
	soid:22089;
	file_data;
	content:"{|5C|listoverride|5C|";
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	reference:cve,2012-0183;
	reference:url,technet.microsoft.com/en-us/security/bulletin/ms12-029;
	classtype:attempted-user;
	gid:3; sid:22089; rev:6;
)
)[Snort_SO_Rule]";

static const unsigned rule_22089_len = 0;

static IpsOption::EvalStatus eval(void* pv, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   BoyerMoore* boyer_moore = (BoyerMoore*)pv;

   for(int i = 0; i < 5; i++)
   {
      unsigned nest_count = 1;

      unsigned depth = end_of_buffer - cursor_normal;

      int pos = boyer_moore->search(cursor_normal, depth);

      if(pos < 0)
         return IpsOption::NO_MATCH;

      for(int j = 0; j < pos; j++)
      {
         if(cursor_normal[j] == '{')
         {
            nest_count++;
         }
         else if(cursor_normal[j] == '}')
         {
            nest_count--;

            if(nest_count == 0)
               break;
         }
      }

      if(nest_count != 0)
         return IpsOption::MATCH;

      cursor_normal += pos + pat_len;
   }

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

static const SoApi so_22089 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        6, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "22089", // name
        "FILE-OFFICE Microsoft RTF improper listoverride nesting attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_22089,
    rule_22089_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    dtor     // dtor
};

const BaseApi* pso_22089 = &so_22089.base;

