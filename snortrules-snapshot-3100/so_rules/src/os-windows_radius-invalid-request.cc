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
// os-windows_radius-invalid-request.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_33053 = R"[Snort_SO_Rule](
alert udp any any -> $HOME_NET [1812,1645] (
	msg:"OS-WINDOWS Microsoft RADIUS Server invalid access-request username denial of service attempt";
	soid:33053;
	content:"|01|",depth 1;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	service:radius;
	reference:cve,2015-0015;
	reference:cve,2015-0050;
	reference:url,technet.microsoft.com/en-us/security/bulletin/MS15-007;
	reference:url,technet.microsoft.com/en-us/security/bulletin/MS16-021;
	classtype:attempted-dos;
	gid:3; sid:33053; rev:5;
)
)[Snort_SO_Rule]";

static const unsigned rule_33053_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.buffer(),
                 *end_of_buffer = c.endo();
 
   uint8_t atype, alength;
   uint16_t request_length;

   bool bad_char_seen = false;

   // RFC 2865 Page 17
   // code (1 byte), pkt identifier (1 byte)
   // length (2 bytes), authenticator (16 bytes)

   // check if we can read the request length
   if(cursor_normal + 4 > end_of_buffer)
      return IpsOption::NO_MATCH;

   // read the request length
   request_length = read_big_16(cursor_normal + 2);

   // jump the request length and check that we land on end_of_buffer
   if(cursor_normal + request_length != end_of_buffer)
      return IpsOption::NO_MATCH;

   // skip code (1 byte), pkt identifier (1 byte),
   // length (2 bytes), authenticator (16 bytes)
   cursor_normal += 20;

   // parse up to 10 attributes (TLV)
   for(unsigned i = 0; i < 10; i++)
   {
      // make sure we can read type and length (1 byte each)
      if(cursor_normal + 2 > end_of_buffer)
         return IpsOption::NO_MATCH;

      atype = cursor_normal[0];
      alength = cursor_normal[1];

      DEBUG_SO(fprintf(stderr,"radius attribute type:0x%02X len:0x%02X\n",atype,alength);)

      // make sure we can read value 
      if(alength > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      if(atype == 0x01)
      {
         // restrict how many bytes we will check
         // in the User-Name Attribute Value
         if(alength > 25)
            alength = 25;

         // User-Name Attribute, check for bad chars, if 2 are present, alert.
         // we start at index 2 because alength includes the Type and Length
         for(unsigned j = 2; j < alength; j++)
         {
            switch(cursor_normal[j]) {
            case 0:
               // CVE-2016-0050
               // null byte in the value, alert.
               return IpsOption::MATCH;
            case '(':
            case ')':
            case '*':
            case '/':
            case '\\':
               // CVE-2015-0015
               // if we have seen 2 bad chars, alert.
               if(bad_char_seen)
                  return IpsOption::MATCH;

               bad_char_seen = true;
               break;
            default:
               break;
            }
         }

         // only check one User-Name attribute
         return IpsOption::NO_MATCH;
      }

      cursor_normal += alength;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_33053 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        5, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "33053", // name
        "OS-WINDOWS Microsoft RADIUS Server invalid access-request username denial of service attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_33053,
    rule_33053_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_33053 = &so_33053.base;

