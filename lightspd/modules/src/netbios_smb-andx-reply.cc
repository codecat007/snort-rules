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
// netbios_smb-andx-reply.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_16728 = R"[Snort_SO_Rule](
alert tcp $EXTERNAL_NET any -> $HOME_NET [139,445] (
	msg:"NETBIOS Samba SMB1 chain_reply function memory corruption attempt";
	soid:16728;
	flow:to_server,established;
	content:"|00|",depth 1;
	content:"|FF|SMBs",distance 3, within 5;
	isdataat:29,relative;
	content:!"|FF|",distance 28, within 1;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	service:netbios-ssn;
	reference:bugtraq,40884;
	reference:cve,2010-2063;
	classtype:attempted-admin;
	gid:3; sid:16728; rev:4;
)
)[Snort_SO_Rule]";

static const unsigned rule_16728_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *beg_of_buffer = c.buffer(),
                 *end_of_buffer = c.endo(),
                 *cursor_header;

   uint8_t word_count, command;
   uint16_t offset, previous_offset = 0;
   uint32_t netbios_length;

   cursor_header = beg_of_buffer + 1;

   // check if we can read the netbios_length
   if(cursor_header + 3 > end_of_buffer)
      return IpsOption::NO_MATCH;

   netbios_length = read_big_24(cursor_header);

   // pointer to the SMB header
   cursor_header += 3;

   // move to the first AndX command
   cursor_normal += 27;

   // check the first 5 AndX commands
   for(unsigned i=0; i<5; i++)
   {
      if(cursor_normal + 5 > end_of_buffer)
         return IpsOption::NO_MATCH;

      word_count = *cursor_normal++;
      command = *cursor_normal++;

      // if no further commands, bail
      if(command == 0xFF)
         return IpsOption::NO_MATCH;

      // jump reserved field
      cursor_normal++;

      // read offset
      offset = read_little_16(cursor_normal);

      // check vulnerability condition
      if(word_count > 0x0B && (offset < 32 || offset > (netbios_length + 36)))
         return IpsOption::MATCH;

      // offset must be > previous_offset
      if(offset <= previous_offset)
         return IpsOption::NO_MATCH;

      previous_offset = offset;
      cursor_normal = cursor_header + offset;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_16728 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        4, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "16728", // name
        "NETBIOS Samba SMB1 chain_reply function memory corruption attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_16728,
    rule_16728_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_16728 = &so_16728.base;

