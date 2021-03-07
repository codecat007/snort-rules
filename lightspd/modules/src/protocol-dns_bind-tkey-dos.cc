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
// protocol-dns_bind-tkey-dos.cc author Brandon Stultz <brastult@cisco.com>

#include "main/snort_types.h"
#include "framework/so_rule.h"
#include "framework/cursor.h"
#include "protocols/packet.h"
#include "util_read.h"
#include "util_dns.h"

#include <cstring>

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

using namespace snort;

static const char* rule_35942 = R"[Snort_SO_Rule](
alert udp $EXTERNAL_NET any -> $HOME_NET 53 (
	msg:"PROTOCOL-DNS ISC BIND TKEY query processing denial of service attempt";
	soid:35942;
	flow:to_server;
	content:"|00 F9|",fast_pattern;
	content:"|00 01|",offset 4,depth 2;
	content:"|00 00 00|",distance 2,within 3;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	service:dns;
	reference:cve,2015-5477;
	reference:url,kb.isc.org/article/AA-01272;
	classtype:attempted-dos;
	gid:3; sid:35942; rev:3;
)
)[Snort_SO_Rule]";

static const unsigned rule_35942_len = 0;

static const char* rule_35943 = R"[Snort_SO_Rule](
alert tcp $EXTERNAL_NET any -> $HOME_NET 53 (
	msg:"PROTOCOL-DNS ISC BIND TKEY query processing denial of service attempt";
	soid:35943;
	flow:to_server,established;
	content:"|00 F9|",fast_pattern;
	content:"|00 01|",offset 6,depth 2;
	content:"|00 00 00|",distance 2,within 3;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	service:dns;
	reference:cve,2015-5477;
	reference:url,kb.isc.org/article/AA-01272;
	classtype:attempted-dos;
	gid:3; sid:35943; rev:3;
)
)[Snort_SO_Rule]";

static const unsigned rule_35943_len = 0;

static IpsOption::EvalStatus DetectBindTkeyDos(const uint8_t *cursor_normal, const uint8_t *end_of_buffer) {
   const uint8_t *query_name, *additional_name;
   uint16_t flags, num_of_answers, answer_data_len,
            num_of_additional, additional_rr_type,
            additional_data_len;
   unsigned int i, query_name_len, additional_name_len;

   // check if we can read flags (2 bytes)
   // skip question number (2 bytes)
   // read answer number (2 bytes)
   // skip authority RR number (2 bytes)
   // and read additional RR number (2 bytes)
   if(cursor_normal + 10 > end_of_buffer)
      return IpsOption::NO_MATCH;

   flags = read_big_16_inc(cursor_normal);

   // flags
   //
   // mask:
   // 0b1111101000001111 = 0xFA0F
   //   ^^   ^^^    ^   
   //   ||   |||    |   
   //   ||   |||    `- reply code (0000 = no error)
   //   ||   ||`- recursion and others
   //   ||   |`- truncated (0 = not truncated)
   //   ||   `- authoritative
   //   |`- opcode (0000 = standard query)
   //   `- response (0 = query)
   //
   if((flags & 0xFA0F) != 0)
      return IpsOption::NO_MATCH;

   // skip question number (we limit it to 1)
   cursor_normal += 2;

   // get the number of answers
   num_of_answers = read_big_16_inc(cursor_normal);

   // if num_of_answers > 5, bail
   if(num_of_answers > 5)
      return IpsOption::NO_MATCH;

   // skip authority RR number
   cursor_normal += 2;

   // get the number of additional RRs
   num_of_additional = read_big_16_inc(cursor_normal);

   // if num_of_additional > 5, bail
   if(num_of_additional > 5)
      return IpsOption::NO_MATCH;

   // store start of query name
   query_name = cursor_normal;

   // skip question Name (we limit to 1)
   if(!skip_dns_name(cursor_normal, end_of_buffer))
      return IpsOption::NO_MATCH;

   // store size of query name
   query_name_len = cursor_normal - query_name;

   // only compare up to 255 bytes 
   if(query_name_len > 255)
      return IpsOption::NO_MATCH;

   // check that we can read the query type 
   if(cursor_normal + 2 > end_of_buffer)
      return IpsOption::NO_MATCH;

   // verify that the query type is TKEY (0x00F9)
   // checked "backwards" to drop out faster since first byte is usually 0x00
   if((cursor_normal[1] != 0xF9) || (cursor_normal[0] != 0x00))
      return IpsOption::NO_MATCH;

   // skip type & class
   cursor_normal += 4;

   // go to the end of the answer section (up to 5)
   for(i=0; i < num_of_answers; i++)
   {
      // skip answer
      if(!skip_dns_name(cursor_normal, end_of_buffer))
         return IpsOption::NO_MATCH;

      // skip type, class, TTL
      cursor_normal += 8;

      // make sure we can read the answer data length
      if(cursor_normal + 2 > end_of_buffer)
         return IpsOption::NO_MATCH;

      // read the answer data length
      answer_data_len = read_big_16_inc(cursor_normal);

      // check if we can jump answer_data_len
      if(answer_data_len > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // jump the answer data length
      cursor_normal += answer_data_len;
   }

   // parse additional RRs (up to 5)
   for(i=0; i < num_of_additional; i++)
   {
      // store start of additional name
      additional_name = cursor_normal;

      // skip Additional RR Name
      if(!skip_dns_name(cursor_normal, end_of_buffer))
         return IpsOption::NO_MATCH;

      // calculate size of additional RR name
      additional_name_len = cursor_normal - additional_name;

      // verify we can read Type (2 bytes)
      // skip class & TTL (or EDNS data) (6 bytes)
      // and read data length (2 bytes)
      if(cursor_normal + 10 > end_of_buffer)
         return IpsOption::NO_MATCH;

      // read the additional RR type
      additional_rr_type = read_big_16_inc(cursor_normal);

      // skip class & TTL (or EDNS data)
      cursor_normal += 6;

      // read additional RR data length
      additional_data_len = read_big_16_inc(cursor_normal);

      // check if we can jump additional_data_len
      if(additional_data_len > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // jump the additional RR data length
      cursor_normal += additional_data_len;

      // skip RR if type is:
      //  TKEY (0x00F9) (expected normal)
      //   -- or --
      //  OPT  (0x0029) (not in vulnerable msg->section)
      //  TSIG (0x00FA) (not in vulnerable msg->section)
      // (1st condition of vuln)
      if(additional_rr_type == 0x00F9 ||
         additional_rr_type == 0x0029 ||
         additional_rr_type == 0x00FA)
         continue;

      // if we skipped a pointer to the Query, then the
      // Additional RR Name is equal to the Query Name
      // (2nd condition of the vuln), alert.
      if(additional_name_len == 2)
         if((additional_name[0] == 0xC0) && (additional_name[1] == 0x0C))
            return IpsOption::MATCH;   

      // verify skip_dns_name skipped an Additional RR Name
      // with the same size as the Query Name
      //
      // (if the sizes are different, they can't be the same)
      if(query_name_len != additional_name_len)
         continue;

      // finally, verify the Additional RR Name is
      // equal to the Query Name for uncompressed names
      // (2nd condition of vuln), alert.
      if(memcmp(query_name, additional_name, query_name_len) == 0)
         return IpsOption::MATCH;
   }

   return IpsOption::NO_MATCH;
}

static IpsOption::EvalStatus rule_35942_eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.buffer(),
                 *end_of_buffer = c.endo();

   // move cursor to flags
   cursor_normal += 2;

   return DetectBindTkeyDos(cursor_normal, end_of_buffer);
}

static SoEvalFunc rule_35942_ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return rule_35942_eval;
}

static const SoApi so_35942 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        3, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "35942", // name
        "PROTOCOL-DNS ISC BIND TKEY query processing denial of service attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_35942,
    rule_35942_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    rule_35942_ctor, // ctor
    nullptr  // dtor
};

static IpsOption::EvalStatus rule_35943_eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.buffer(),
                 *end_of_buffer = c.endo();

   // move cursor to flags
   // in the TCP case, flags are at offset 4
   cursor_normal += 4;

   return DetectBindTkeyDos(cursor_normal, end_of_buffer);
}

static SoEvalFunc rule_35943_ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return rule_35943_eval;
}

static const SoApi so_35943 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        3, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "35943", // name
        "PROTOCOL-DNS ISC BIND TKEY query processing denial of service attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_35943,
    rule_35943_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    rule_35943_ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_35942 = &so_35942.base;
const BaseApi* pso_35943 = &so_35943.base;

