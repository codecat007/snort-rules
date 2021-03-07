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
// file-office_kb2545814-powerpoint-recolorinfoatom.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_18949 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-OFFICE Microsoft Office PowerPoint malformed RecolorInfoAtom out of bounds read attempt";
	soid:18949;
	file_type:MSOLE2;
	file_data;
	content:"|0F 00 11 F0|";
	content:"|00 00 E7 0F|",within 100;
	so:eval,relative;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	reference:cve,2011-1270;
	reference:url,technet.microsoft.com/en-us/security/bulletin/MS11-036;
	classtype:attempted-user;
	gid:3; sid:18949; rev:8;
)
)[Snort_SO_Rule]";

static const unsigned rule_18949_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint32_t header_len, check;
   uint16_t cColors, cFills;

   DEBUG_SO(fprintf(stderr,"SID 18949 eval\n");)

   if(cursor_normal + 10 > end_of_buffer)
      return IpsOption::NO_MATCH;

   header_len = read_little_32_inc(cursor_normal);

   // skip flags
   cursor_normal += 2;

   cColors = read_little_16_inc(cursor_normal);
   cFills  = read_little_16_inc(cursor_normal);

   DEBUG_SO(fprintf(stderr,"header_len = 0x%04x, cColors = 0x%02x, cFills = 0x%02x\n", header_len, cColors, cFills);)

   check = 0x0c + (cColors + cFills) * 0x2c;

   if(header_len < check)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_18949 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        8, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "18949", // name
        "FILE-OFFICE Microsoft Office PowerPoint malformed RecolorInfoAtom out of bounds read attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_18949,
    rule_18949_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_18949 = &so_18949.base;

