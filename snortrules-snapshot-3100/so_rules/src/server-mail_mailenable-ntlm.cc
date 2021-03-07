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
// server-mail_mailenable-ntlm.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_17693 = R"[Snort_SO_Rule](
alert smtp (
	msg:"SERVER-MAIL MailEnable NTLM Authentication buffer overflow attempt";
	soid:17693;
	content:"AUTH NTLM ";
	base64_decode:bytes 64,offset 0,relative;
	base64_data;
	content:"NTLMSSP|00 01 00 00 00|",depth 12;
	so:eval;
	metadata:policy max-detect-ips drop;
	reference:bugtraq,20290;
	reference:cve,2006-5176;
	reference:cve,2006-5177;
	classtype:attempted-admin;
	gid:3; sid:17693; rev:6;
)
)[Snort_SO_Rule]";

static const unsigned rule_17693_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint16_t domain_len, host_len;
   uint32_t domain_buf_offset, host_buf_offset;

   // skip:
   //  negotiate flags (4 bytes)
   cursor_normal += 4;

   // check if we can:
   //  read domain_len        (2 bytes)
   //  skip domain_max_len    (2 bytes)
   //  read domain_buf_offset (4 bytes)
   //  read host_len          (2 bytes)
   //  skip host_max_len      (2 bytes)
   //  read host_buf_offset   (4 bytes)
   if(cursor_normal + 16 > end_of_buffer)
      return IpsOption::NO_MATCH;

   domain_len = read_little_16_inc(cursor_normal);

   if(domain_len > 0x0400)
      return IpsOption::MATCH;

   // skip:
   //  domain_max_len (2 bytes)
   cursor_normal += 2;

   domain_buf_offset = read_little_32_inc(cursor_normal);

   if(domain_buf_offset > 0x00000800)
      return IpsOption::MATCH;

   host_len = read_little_16_inc(cursor_normal);

   if(host_len > 0x0400)
      return IpsOption::MATCH;

   // skip:
   //  host_max_len (2 bytes)
   cursor_normal += 2;

   host_buf_offset = read_little_32_inc(cursor_normal);

   if(host_buf_offset > 0x00000800)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_17693 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        6, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "17693", // name
        "SERVER-MAIL MailEnable NTLM Authentication buffer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_17693,
    rule_17693_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_17693 = &so_17693.base;

