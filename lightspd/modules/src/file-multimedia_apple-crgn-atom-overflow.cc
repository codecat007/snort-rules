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
// file-multimedia_apple-crgn-atom-overflow.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_13897 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-MULTIMEDIA Apple QuickTime crgn atom parsing stack buffer overflow attempt";
	soid:13897;
	file_data;
	content:"clip";
	so:eval,relative;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	reference:bugtraq,28583;
	reference:cve,2008-1017;
	classtype:attempted-user;
	gid:3; sid:13897; rev:9;
)
)[Snort_SO_Rule]";

static const unsigned rule_13897_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint32_t atom_size, atom_id, check;
   uint16_t region_size;

   // check if we can read:
   //  atom_size   (4 bytes)
   //  atom_id     (4 bytes)
   //  region_size (2 bytes)
   if(cursor_normal + 10 > end_of_buffer)
      return IpsOption::NO_MATCH;

   atom_size = read_big_32_inc(cursor_normal);
   atom_id = read_big_32_inc(cursor_normal);

   // 'crgn' atom
   if(atom_id != 0x6372676E)
      return IpsOption::NO_MATCH;

   region_size = read_big_16_inc(cursor_normal);

   DEBUG_SO(fprintf(stderr,"region_size=0x%04x\n",region_size);)
   DEBUG_SO(fprintf(stderr,"atom_size=0x%08x\n",atom_size);)

   // check vulnerability condition
   check = region_size + 8;

   if(check > atom_size)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_13897 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        9, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "13897", // name
        "FILE-MULTIMEDIA Apple QuickTime crgn atom parsing stack buffer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_13897,
    rule_13897_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_13897 = &so_13897.base;

