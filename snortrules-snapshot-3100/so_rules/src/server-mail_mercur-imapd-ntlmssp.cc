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
// server-mail_mercur-imapd-ntlmssp.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_13921 = R"[Snort_SO_Rule](
alert imap (
	msg:"SERVER-MAIL Altrium Software MERCUR IMAPD NTLMSSP command handling memory corruption attempt";
	soid:13921;
	content:"TlRMTVNT";
	byte_jump:0,0,from_beginning;
	base64_decode:bytes 64,offset 0,relative;
	base64_data;
	content:"NTLMSSP|00 03 00 00 00|",depth 12;
	so:eval;
	metadata:policy max-detect-ips drop;
	reference:bugtraq,23058;
	reference:cve,2007-1578;
	classtype:attempted-admin;
	gid:3; sid:13921; rev:7;
)
)[Snort_SO_Rule]";

static const unsigned rule_13921_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   int16_t lm_x;

   // check if we can read:
   //  LmChallengeResponseLen (2 bytes)
   if(cursor_normal + 2 > end_of_buffer)
      return IpsOption::NO_MATCH;

   lm_x = read_little_16_inc(cursor_normal);

   DEBUG_SO(fprintf(stderr,"lm_x=0x%02x\n",lm_x);)
   DEBUG_SO(fprintf(stderr,"lm_x=%d\n",lm_x);)

   if(lm_x < 0 || lm_x > 56)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_13921 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        7, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "13921", // name
        "SERVER-MAIL Altrium Software MERCUR IMAPD NTLMSSP command handling memory corruption attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_13921,
    rule_13921_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_13921 = &so_13921.base;

