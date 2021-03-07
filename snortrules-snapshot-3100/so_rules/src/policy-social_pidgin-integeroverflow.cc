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
// policy-social_pidgin-integeroverflow.cc author Brandon Stultz <brastult@cisco.com>

#include "main/snort_types.h"
#include "framework/so_rule.h"
#include "framework/cursor.h"
#include "protocols/packet.h"
#include "util_read.h"

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

using namespace snort;

static const char* rule_14263 = R"[Snort_SO_Rule](
alert http (
	msg:"POLICY-SOCIAL Pidgin MSNP2P message integer overflow attempt";
	soid:14263;
	file_data;
	content:"MSG",depth 3;
	content:"application/x-msnmsgrp2p",nocase;
	content:"P2P-Dest",nocase;
	pcre:"/^MSG((?![\r\n]{4}).)*?[\r\n]{4}/s";
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	reference:bugtraq,29956;
	reference:cve,2008-2927;
	reference:cve,2009-1376;
	reference:cve,2009-2694;
	classtype:attempted-user;
	gid:3; sid:14263; rev:8;
)
)[Snort_SO_Rule]";

static const unsigned rule_14263_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint32_t offset_32, length, flags, check;

   uint64_t offset_64, total_length;

   // skip:
   //  Channel SessionID (4 bytes)
   //  ID                (4 bytes)
   cursor_normal += 8;

   // check if we can read:
   //  offset       (8 bytes)
   //  total_length (8 bytes)
   //  length       (4 bytes)
   //  flags        (4 bytes)
   if(cursor_normal + 24 > end_of_buffer)
      return IpsOption::NO_MATCH;

   offset_64 = read_little_64_inc(cursor_normal);
   total_length = read_little_64_inc(cursor_normal);
   length = read_little_32_inc(cursor_normal);
   flags = read_little_32_inc(cursor_normal);

   DEBUG_SO(fprintf(stderr,"offset=0x%lx\n",offset_64);)
   DEBUG_SO(fprintf(stderr,"total_length=0x%lx\n",total_length);)
   DEBUG_SO(fprintf(stderr,"length=0x%x\n",length);)
   DEBUG_SO(fprintf(stderr,"flags=0x%x\n\n",flags);)

   offset_32 = (uint32_t)offset_64;

   // check vulnerability condition
   check = offset_32 + length;

   // CVE-2008-2927
   // CVE-2009-1376
   if(check > 0x7FFFFFFF || check < offset_32)
      return IpsOption::MATCH;

   if(offset_64 != 0 || length == 0 || length != total_length)
      return IpsOption::NO_MATCH;

   // CVE-2009-2694
   if(cursor_normal + 52 >= end_of_buffer) 
   {
      switch(flags)
      {
      case 0x00000000:
      case 0x01000000:
      case 0x00000020:
      case 0x01000020:
      case 0x01000030:
         return IpsOption::MATCH;
      default:
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

static const SoApi so_14263 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        8, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "14263", // name
        "POLICY-SOCIAL Pidgin MSNP2P message integer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_14263,
    rule_14263_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_14263 = &so_14263.base;

