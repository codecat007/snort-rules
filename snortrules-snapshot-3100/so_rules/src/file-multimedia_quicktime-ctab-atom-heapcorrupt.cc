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
// file-multimedia_quicktime-ctab-atom-heapcorrupt.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_17608 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-MULTIMEDIA Apple QuickTime color table atom heap corruption attempt";
	soid:17608;
	file_data;
	content:"moov",offset 4,depth 4;
	content:"ctab|00 00|",distance 0;
	byte_jump:0,-10,relative;
	so:eval,relative;
	metadata:policy max-detect-ips drop;
	reference:bugtraq,26338;
	reference:cve,2007-4677;
	classtype:attempted-user;
	gid:3; sid:17608; rev:7;
)
)[Snort_SO_Rule]";

static const unsigned rule_17608_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint32_t atom_size, buf_colors, num_colors;
   uint16_t ctab_size;

   // check if we can:
   //  read atom_size  (4 bytes)
   //  skip atom_type  (4 bytes)
   //  skip ctab_seed  (4 bytes)
   //  skip ctab_flags (2 bytes)
   //  read ctab_size  (2 bytes)
   if(cursor_normal + 16 > end_of_buffer)
      return IpsOption::NO_MATCH;

   atom_size = read_big_32(cursor_normal);
   ctab_size = read_big_16(cursor_normal + 14);

   DEBUG_SO(fprintf(stderr,"atom_size = 0x%08x\n",atom_size);)
   DEBUG_SO(fprintf(stderr,"ctab_size = 0x%08x\n",ctab_size);)

   if(atom_size < 16)
      return IpsOption::MATCH;

   // subtract header len
   atom_size -= 16;

   // Each color is four 16 bit
   // integers or 8 bytes.
   buf_colors = atom_size / 8;

   // ctab_size == 0 means that there
   // is one color in the array.
   num_colors = ctab_size + 1;

   // check vulnerability condition
   if(num_colors > buf_colors)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_17608 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        7, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "17608", // name
        "FILE-MULTIMEDIA Apple QuickTime color table atom heap corruption attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_17608,
    rule_17608_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_17608 = &so_17608.base;

