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
// file-office_openoffice-table-parsing-heap-bo.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_17665 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-OFFICE OpenOffice Word document table parsing heap buffer overflow attempt";
	soid:17665;
	file_data;
	content:"|00 00 00 FF 00 00 00 FF 00 00 00 FF 00 00 00 FF 22 56|";
	so:eval,relative;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	reference:bugtraq,36200;
	reference:cve,2009-0200;
	reference:cve,2009-0201;
	classtype:attempted-user;
	gid:3; sid:17665; rev:8;
)
)[Snort_SO_Rule]";

static const unsigned rule_17665_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint8_t itcFirst, itcLim;

   // check if we can read:
   //  itcFirst (1 byte)
   //  itcLim   (1 byte)
   if(cursor_normal + 2 > end_of_buffer)
      return IpsOption::NO_MATCH;

   itcFirst = *cursor_normal++;
   itcLim = *cursor_normal;

   // check vulnerability condition
   if(itcLim > 64 || itcFirst > itcLim)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_17665 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        8, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "17665", // name
        "FILE-OFFICE OpenOffice Word document table parsing heap buffer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_17665,
    rule_17665_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_17665 = &so_17665.base;

