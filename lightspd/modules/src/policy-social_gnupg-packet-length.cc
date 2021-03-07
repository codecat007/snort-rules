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
// policy-social_gnupg-packet-length.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_17697 = R"[Snort_SO_Rule](
alert smtp (
	msg:"POLICY-SOCIAL GnuPG Message Packet Length overflow attempt";
	soid:17697;
	content:"-----BEGIN PGP MESSAGE-----";
	content:"Version|3A|",distance 2,within 8;
	content:"|0D 0A 0D 0A|",distance 0;
	base64_decode:bytes 32,offset 0,relative;
	base64_data;
	so:eval;
	metadata:policy max-detect-ips drop;
	reference:cve,2006-3746;
	classtype:attempted-user;
	gid:3; sid:17697; rev:5;
)
)[Snort_SO_Rule]";

static const unsigned rule_17697_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint8_t packet_format;

   uint32_t packet_size;

   // check if we can read 6 bytes
   if(cursor_normal + 6 > end_of_buffer)
      return IpsOption::NO_MATCH;

   packet_format = *cursor_normal++;

   DEBUG_SO(fprintf(stderr,"packet_format=0x%02x\n",packet_format);)

   if(packet_format != 0xD0 && packet_format != 0xFD)
      return IpsOption::NO_MATCH;

   if(*cursor_normal++ != 0xFF)
      return IpsOption::NO_MATCH;

   packet_size = read_little_32_inc(cursor_normal);

   DEBUG_SO(fprintf(stderr,"packet_size=0x%08x\n",packet_size);)

   // check vulnerability condition
   if(packet_size >= 0xF9FFFFFF && packet_size <= 0xFEFFFFFF)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_17697 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        5, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "17697", // name
        "POLICY-SOCIAL GnuPG Message Packet Length overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_17697,
    rule_17697_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_17697 = &so_17697.base;

