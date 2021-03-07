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
// protocol-dns_dns-zero-len-rdata.cc author Brandon Stultz <brastult@cisco.com>

#include "main/snort_types.h"
#include "framework/so_rule.h"
#include "framework/cursor.h"
#include "protocols/packet.h"
#include "util_read.h"
#include "util_dns.h"

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

using namespace snort;

static const char* rule_23608 = R"[Snort_SO_Rule](
alert tcp $EXTERNAL_NET 53 -> $HOME_NET any (
	msg:"PROTOCOL-DNS dns zone transfer with zero-length rdata attempt";
	soid:23608;
	flow:to_client,established;
	content:"|00 FC 00 01|";
	content:"|00 06 00 01|";
	so:eval;
	metadata:policy max-detect-ips drop;
	service:dns;
	reference:cve,2012-1667;
	reference:url,www.isc.org/software/bind/advisories/cve-2012-1667;
	classtype:attempted-dos;
	gid:3; sid:23608; rev:3;
)
)[Snort_SO_Rule]";

static const unsigned rule_23608_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet*)
{
   const uint8_t *cursor_normal = c.buffer(),
                 *end_of_buffer = c.endo();

   uint16_t flags, num_questions, num_answers,
            query_type, query_class,
            answer_type, answer_class,
            data_len;

   // skip:
   //  size(2), txid(2)
   cursor_normal += 4;

   // check if we can read:
   //  flags(2), num_questions(2), num_answers(2)
   if(cursor_normal + 6 > end_of_buffer)
      return IpsOption::NO_MATCH;

   flags = read_big_16_inc(cursor_normal);

   // response, standard query, authoritative, no error
   if((flags & 0xF60F) != 0x8400)
      return IpsOption::NO_MATCH;

   num_questions = read_big_16_inc(cursor_normal);

   // verify there is only one query record
   if(num_questions != 1)
      return IpsOption::NO_MATCH;

   num_answers = read_big_16_inc(cursor_normal);

   // min answers is SOA + malicious record
   if(num_answers < 2)
      return IpsOption::NO_MATCH;

   // limit num_answers
   if(num_answers > 50)
      num_answers = 50;

   // skip:
   //  authority RR number (2 bytes)
   //  additional RR number (2 bytes)
   cursor_normal += 4;

   // skip the query
   if(!skip_dns_name(cursor_normal, end_of_buffer))
      return IpsOption::NO_MATCH;

   // check if we can read:
   //  query_type (2 bytes)
   //  query_class (2 bytes)
   if(cursor_normal + 4 > end_of_buffer)
      return IpsOption::NO_MATCH;

   query_type = read_big_16_inc(cursor_normal);
   query_class = read_big_16_inc(cursor_normal);

   // verify query is for a zone transfer
   //  0x00FC == AXFR, 0x0001 == IN
   if(query_type != 0x00FC || query_class != 0x0001)
      return IpsOption::NO_MATCH;

   // skip first answer name
   if(!skip_dns_name(cursor_normal, end_of_buffer))
      return IpsOption::NO_MATCH;

   // check if we can:
   //  read answer_type (2 bytes)
   //  read answer_class (2 bytes)
   //  skip TTL (4 bytes)
   //  read data_len (2 bytes)
   if(cursor_normal + 10 > end_of_buffer)
      return IpsOption::NO_MATCH;

   answer_type = read_big_16_inc(cursor_normal);
   answer_class = read_big_16_inc(cursor_normal);

   // verify first answer is a start of authority
   //  0x0006 == SOA, 0x0001 == IN
   if(answer_type != 0x0006 || answer_class != 0x0001)
      return IpsOption::NO_MATCH;

   // skip TTL
   cursor_normal += 4;

   data_len = read_big_16_inc(cursor_normal);

   // verify we can skip data_len
   if(data_len > end_of_buffer - cursor_normal)
      return IpsOption::NO_MATCH;

   // skip data_len
   cursor_normal += data_len;

   for(unsigned i = 1; i < num_answers; i++)
   {
      if(!skip_dns_name(cursor_normal, end_of_buffer))
         return IpsOption::NO_MATCH;

      // skip:
      //  type(2), class(2), TTL(4)
      cursor_normal += 8;

      // check if we can read:
      //  data_len (2 bytes)
      if(cursor_normal + 2 > end_of_buffer)
         return IpsOption::NO_MATCH;

      data_len = read_big_16_inc(cursor_normal);

      // check vulnerability condition
      if(data_len == 0)
         return IpsOption::MATCH;

      // verify we can skip data_len
      if(data_len > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // skip data_len
      cursor_normal += data_len;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_23608 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        3, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "23608", // name
        "PROTOCOL-DNS dns zone transfer with zero-length rdata attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_23608,
    rule_23608_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_23608 = &so_23608.base;

