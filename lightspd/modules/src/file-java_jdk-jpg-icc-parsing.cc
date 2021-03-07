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
// file-java_jdk-jpg-icc-parsing.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_15328 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-JAVA Sun JDK image parsing library ICC buffer overflow attempt";
	soid:15328;
	file_data;
	content:"|FF E2|";
	content:"ICC_PROFILE|00|",distance 2,within 12;
	content:"acsp",distance 38,within 4;
	byte_jump:0,88,relative;
	so:eval,relative;
	metadata:policy max-detect-ips drop;
	reference:bugtraq,24004;
	reference:cve,2007-2788;
	reference:url,scary.beasts.org/security/CESA-2006-004.html;
	classtype:attempted-user;
	gid:3; sid:15328; rev:6;
)
)[Snort_SO_Rule]";

static const unsigned rule_15328_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint32_t tag_count, tag_size;

   // check if we can read:
   //  tag_count (4 bytes)
   if(cursor_normal + 4 > end_of_buffer)
      return IpsOption::NO_MATCH;

   tag_count = read_big_32_inc(cursor_normal);

   DEBUG_SO(fprintf(stderr,"tag_count=0x%08x\n",tag_count);)

   // limit tag_count
   if(tag_count > 25)
      tag_count = 25;

   for(unsigned i = 0; i < tag_count; i++)
   {
      // check if we can:
      //  skip tag_name   (4 bytes)
      //  skip tag_offset (4 bytes)
      //  read tag_size   (4 bytes)
      if(cursor_normal + 12 > end_of_buffer)
         return IpsOption::NO_MATCH;

      tag_size = read_big_32(cursor_normal+8);

      DEBUG_SO(fprintf(stderr,"tag_size=0x%08x\n",tag_size);)

      if(tag_size > 0xFFFFFFF7)
         return IpsOption::MATCH;

      // skip tag
      cursor_normal += 12;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_15328 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        6, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "15328", // name
        "FILE-JAVA Sun JDK image parsing library ICC buffer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_15328,
    rule_15328_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_15328 = &so_15328.base;

