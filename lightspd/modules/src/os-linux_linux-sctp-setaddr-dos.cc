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
// os-linux_linux-sctp-setaddr-dos.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_38346 = R"[Snort_SO_Rule](
alert ip $EXTERNAL_NET any -> $HOME_NET any (
	msg:"OS-LINUX Linux kernel SCTP INIT null pointer dereference attempt";
	soid:38346;
	ip_proto:132;
	content:"|C0 04|";
	content:"|01|",offset 12,depth 1;
	so:eval;
	metadata:policy max-detect-ips drop;
	reference:cve,2014-7841;
	classtype:attempted-dos;
	gid:3; sid:38346; rev:2;
)
)[Snort_SO_Rule]";

static const unsigned rule_38346_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint16_t ptype, plength, addr_type,
            padding, check;

   // RFC 4960 section 3.3.2
   // skip SCTP INIT header
   cursor_normal += 19;

   // parse up to 10 parameters (TLV 4 byte padded)
   for(unsigned i = 0; i < 10; i++)
   {
      // check if we can:
      //  read ptype          (2 bytes)
      //  read plength        (2 bytes)
      //  skip correlation_id (4 bytes)
      //  read addr_type      (2 bytes)
      if(cursor_normal + 10 > end_of_buffer)
         return IpsOption::NO_MATCH;

      ptype = read_big_16(cursor_normal); 

      DEBUG_SO(fprintf(stderr,"SCTP INIT parameter type:0x%04X\n", ptype);)

      // RFC 5061 section 4.2.4
      // check parameter (Set Primary Address)
      if(ptype == 0xC004)
      {
         // skip type(2), length(2), correlation_id(4)
         cursor_normal += 8;

         addr_type = read_big_16(cursor_normal);

         // if addr_type is invalid
         // e.g. NOT 0x0005 for ipv4 or 0x0006 for ipv6
         // then alert
         if(addr_type != 0x0005 && addr_type != 0x0006)
            return IpsOption::MATCH;

         // only check one Set Primary Address parameter
         return IpsOption::NO_MATCH;
      }

      plength = read_big_16(cursor_normal+2);

      // calculate padding
      padding = plength % 4;

      // integer overflow check
      check = plength + padding;
      if(check < plength)
         return IpsOption::NO_MATCH;
      plength = check;

      // check if we can jump plength
      if(plength > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // jump plength
      cursor_normal += plength;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_38346 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        2, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "38346", // name
        "OS-LINUX Linux kernel SCTP INIT null pointer dereference attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_38346,
    rule_38346_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_38346 = &so_38346.base;

