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
// server-other_ibm-domino-ldap-bof.cc author Brandon Stultz <brastult@cisco.com>

#include "main/snort_types.h"
#include "framework/so_rule.h"
#include "framework/cursor.h"
#include "protocols/packet.h"
#include "utils/util_ber.h"

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

#define BER_DATA(t) if(!ber.data(cursor_normal,t)) return IpsOption::NO_MATCH;
#define BER_SKIP(t) if(!ber.skip(cursor_normal,t)) return IpsOption::NO_MATCH;

using namespace snort;

static const char* rule_36153 = R"[Snort_SO_Rule](
alert tcp $EXTERNAL_NET any -> $HOME_NET 389 (
	msg:"SERVER-OTHER IBM Domino LDAP server ModifyRequest stack buffer overflow attempt";
	soid:36153;
	flow:to_server,established;
	content:"|3B|";
	so:eval;
	metadata:policy balanced-ips drop, policy max-detect-ips drop, policy security-ips drop;
	service:ldap;
	reference:bugtraq,73911;
	reference:cve,2015-0117;
	classtype:attempted-admin;
	gid:3; sid:36153; rev:3;
)
)[Snort_SO_Rule]";

static const unsigned rule_36153_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.buffer(),
                 *end_of_buffer = c.endo(),
                 *next_mod_item, *next_msg;

   int i, j, bytes_available, stop;
   uint32_t remaining;

   BerReader ber(c);

   BerElement msg, req, mod, attribute;

   // LDAPMessage ::= SEQUENCE [16]
   if(!ber.read(cursor_normal, msg))
      return IpsOption::NO_MATCH;

   if(msg.type != 0x30)
      return IpsOption::NO_MATCH;

   remaining = end_of_buffer - cursor_normal;

   // check if we can jump msg.total_length
   if(msg.total_length > remaining)
      return IpsOption::NO_MATCH;

   // calculate position of next msg
   next_msg = cursor_normal + msg.total_length;

   // move cursor to messageID
   cursor_normal = msg.data;

   // messageID [2]
   BER_SKIP(0x02)

   // Request ::= APPLICATION [6]
   if(!ber.read(cursor_normal, req))
      return IpsOption::NO_MATCH;

   // move cursor to LDAPDN
   cursor_normal = req.data; 

   if(req.type != 0x66)
   {
      // check second msg for modifyRequest
      cursor_normal = next_msg;

      BER_DATA(0x30) // LDAPMessage
      BER_SKIP(0x02) // messageID
      BER_DATA(0x66) // Request
   }

   // LDAPDN [4]
   BER_SKIP(0x04)

   // modification items ::= SEQUENCE [16]
   BER_DATA(0x30)

   // check up to 5 modification items 
   for(i=0; i<5; i++, cursor_normal = next_mod_item)
   {
      // modification item ::= SEQUENCE [16]
      if(!ber.read(cursor_normal, mod))
         return IpsOption::NO_MATCH;

      if(mod.type != 0x30)
         return IpsOption::NO_MATCH;

      DEBUG_SO(fprintf(stderr,"mod item [0x%04X]\n", mod.length);)

      remaining = end_of_buffer - cursor_normal;

      // check if we can jump mod.total_length
      if(mod.total_length > remaining)
         return IpsOption::NO_MATCH;

      // calculate position of next mod item
      next_mod_item = cursor_normal + mod.total_length;

      // if modification item data_len < 256 skip
      if(mod.length < 256)
         continue;

      // move cursor to operation 
      cursor_normal = mod.data;

      // operation [10]
      BER_SKIP(0x0A)

      // modification ::= SEQUENCE [16]
      BER_DATA(0x30)

      // attribute [4]
      if(!ber.read(cursor_normal, attribute))
         return IpsOption::NO_MATCH;

      if(attribute.type != 0x04)
         return IpsOption::NO_MATCH;

      DEBUG_SO(fprintf(stderr," attribute [0x%04X]\n", attribute.length);)

      // if the attribute len is < 256
      // it cannot possibly contain the vuln, skip
      if(attribute.length < 256)
         continue;

      // attribute.data position must be < end_of_buffer
      if(attribute.data >= end_of_buffer)
         return IpsOption::NO_MATCH;

      bytes_available = end_of_buffer - attribute.data;

      // calculate when we will stop checking bytes
      // we are guaranteed by the above that
      // attribute.length >= 256, thus stop
      // will at least be 0
      stop = attribute.length - 256;

      // move cursor to the attribute data
      cursor_normal = attribute.data;

      // limit stop to how much data we have available
      if(stop > bytes_available)
         stop = bytes_available;

      // Vuln is for there to be more than 256 bytes after the semicolon,
      // so if we find a semicolon before there are less than 256 bytes
      // left in the buffer, it's an exploit condition
      for(j=0; j < stop; j++)
      {
         if(cursor_normal[j] == ';')
            return IpsOption::MATCH;
      }
   }

   return IpsOption::NO_MATCH;
} 

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_36153 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        3, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "36153", // name
        "SERVER-OTHER IBM Domino LDAP server ModifyRequest stack buffer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_36153,
    rule_36153_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_36153 = &so_36153.base;

