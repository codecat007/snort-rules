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
// protocol-dns_libspf2-txt-record.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_15327 = R"[Snort_SO_Rule](
alert udp $EXTERNAL_NET 53 -> $HOME_NET any (
	msg:"PROTOCOL-DNS libspf2 DNS TXT record parsing buffer overflow attempt";
	soid:15327;
	flow:to_client;
	byte_test:2,&,0x8000,2;
	content:"|00 10 00 01|";
	so:eval;
	metadata:policy max-detect-ips drop;
	service:dns;
	reference:bugtraq,31881;
	reference:cve,2008-2469;
	classtype:attempted-user;
	gid:3; sid:15327; rev:8;
)
)[Snort_SO_Rule]";

static const unsigned rule_15327_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet*)
{
   const uint8_t *cursor_normal = c.buffer(),
                 *end_of_buffer = c.endo();

   uint16_t num_questions, num_answers,
            answer_type, answer_class,
            data_len;

   uint32_t txt_len, total_txt_len, check;

   // skip:
   //  txid(2), flags(2)
   cursor_normal += 4;

   // check if we can read:
   //  num_questions (2 bytes)
   //  num_answers   (2 bytes)
   if(cursor_normal + 4 > end_of_buffer)
      return IpsOption::NO_MATCH;

   num_questions = read_big_16_inc(cursor_normal);

   // verify there is only one question
   if(num_questions != 1)
      return IpsOption::NO_MATCH;

   num_answers = read_big_16_inc(cursor_normal);

   // require at least 1 answer
   if(num_answers == 0)
      return IpsOption::NO_MATCH;

   // limit num_answers
   if(num_answers > 10)
      num_answers = 10;

   // skip:
   //  authority RR number  (2 bytes)
   //  additional RR number (2 bytes)
   cursor_normal += 4;

   // skip question name (we limit to 1)
   if(!skip_dns_name(cursor_normal, end_of_buffer))
      return IpsOption::NO_MATCH;

   // skip:
   //  query_type  (2 bytes)
   //  query_class (2 bytes)
   cursor_normal += 4;

   for(unsigned i = 0; i < num_answers; i++)
   {
      // skip answer name
      if(!skip_dns_name(cursor_normal, end_of_buffer))
         return IpsOption::NO_MATCH;

      // check if we can:
      //  read answer_type  (2 bytes)
      //  read answer_class (2 bytes)
      //  skip ttl          (4 bytes)
      //  read data_len     (2 bytes)
      if(cursor_normal + 10 > end_of_buffer)
         return IpsOption::NO_MATCH;

      answer_type = read_big_16_inc(cursor_normal);
      answer_class = read_big_16_inc(cursor_normal);

      cursor_normal += 4;

      data_len = read_big_16_inc(cursor_normal);

      // RR type TXT (0x0010) class (0x0001) IN
      if(answer_type != 0x0010 || answer_class != 0x0001)
      {
         // check if we can skip data_len
         if(data_len > end_of_buffer - cursor_normal)
            return IpsOption::NO_MATCH;
   
         cursor_normal += data_len;

         // loop
         continue;
      }

      // found a TXT answer
      total_txt_len = 0;

      // loop through TXT sections
      // and sum the string lengths
      while(total_txt_len < data_len)
      {
         if(cursor_normal + 1 > end_of_buffer)
            return IpsOption::NO_MATCH;

         txt_len = *cursor_normal++;

         // integer overflow check
         check = total_txt_len + txt_len;
         if(check < total_txt_len)
            return IpsOption::NO_MATCH;
         total_txt_len = check;

         // integer overflow check
         check = total_txt_len + 1;
         if(check < total_txt_len)
            return IpsOption::NO_MATCH;
         total_txt_len = check;

         // check if we can skip txt_len
         if(txt_len > end_of_buffer - cursor_normal)
            return IpsOption::NO_MATCH;

         // skip txt_len
         cursor_normal += txt_len;
      }

      if(total_txt_len > data_len)
         return IpsOption::MATCH;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_15327 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        8, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "15327", // name
        "PROTOCOL-DNS libspf2 DNS TXT record parsing buffer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_15327,
    rule_15327_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_15327 = &so_15327.base;

