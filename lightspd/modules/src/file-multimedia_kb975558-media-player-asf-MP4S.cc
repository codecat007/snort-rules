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
// file-multimedia_kb975558-media-player-asf-MP4S.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_17242 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-MULTIMEDIA Windows Media Player ASF file arbitrary code execution attempt";
	soid:17242;
	file_data;
	content:"|C0 EF 19 BC 4D 5B CF 11 A8 FD 00 80 5F 5C 44 2B|";
	content:"|91 07 DC B7 B7 A9 CF 11 8E E6 00 C0 0C 20 53 65|",distance -40,within 16;
	byte_jump:0,77,relative;
	so:eval,relative;
	metadata:policy max-detect-ips drop;
	reference:cve,2010-0818;
	reference:url,technet.microsoft.com/en-us/security/bulletin/MS10-062;
	classtype:attempted-user;
	gid:3; sid:17242; rev:7;
)
)[Snort_SO_Rule]";

static const unsigned rule_17242_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint32_t image_width, compression_id,
            ifrmwidthsrc = 0;

   if(cursor_normal + 16 > end_of_buffer)
      return IpsOption::NO_MATCH;

   image_width = read_little_32_inc(cursor_normal);

   DEBUG_SO(fprintf(stderr,"image_width = %d\n",image_width);)

   cursor_normal += 8;

   compression_id = read_big_32_inc(cursor_normal);

   // "MP4S"
   if(compression_id != 0x4D503453)
      return IpsOption::NO_MATCH;

   // skip to ifrmwidthsrc
   cursor_normal += 32;

   // check if we can read ifrmwidthsrc
   if(cursor_normal + 3 > end_of_buffer)
      return IpsOption::NO_MATCH;

   // read ifrmwidthsrc
   ifrmwidthsrc = (*cursor_normal++ & 0x07) << 10;
   ifrmwidthsrc |= *cursor_normal++ << 2;
   ifrmwidthsrc |= *cursor_normal >> 6;

   DEBUG_SO(fprintf(stderr,"ifrmwidthsrc = %d\n",ifrmwidthsrc);)

   // vulnerability condition
   if(image_width < ifrmwidthsrc)
      return IpsOption::MATCH;

   // vulnerability condition
   if(image_width - ifrmwidthsrc > 0x10)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_17242 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        7, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "17242", // name
        "FILE-MULTIMEDIA Windows Media Player ASF file arbitrary code execution attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_17242,
    rule_17242_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_17242 = &so_17242.base;

