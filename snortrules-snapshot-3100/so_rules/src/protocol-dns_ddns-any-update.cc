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
// protocol-dns_ddns-any-update.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_15734 = R"[Snort_SO_Rule](
alert udp $EXTERNAL_NET any -> $HOME_NET 53 (
	msg:"PROTOCOL-DNS ISC BIND dynamic update message denial of service attempt";
	soid:15734;
	content:"|28 00 00 01 00 01|",offset 2,depth 6;
	so:eval;
	metadata:policy max-detect-ips drop;
	service:dns;
	reference:cve,2009-0696;
	reference:url,www.isc.org/software/bind/advisories/cve-2009-0696;
	classtype:attempted-dos;
	gid:3; sid:15734; rev:6;
)
)[Snort_SO_Rule]";

static const unsigned rule_15734_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet*)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint16_t num_updates, data_len,
            record_type, record_class;

   // check if we can read:
   //  num_updates (2 bytes)
   if(cursor_normal + 2 > end_of_buffer)
      return IpsOption::NO_MATCH;

   num_updates = read_big_16_inc(cursor_normal);

   if(num_updates == 0)
      return IpsOption::NO_MATCH;

   // skip:
   //  num additional (2 bytes)
   cursor_normal += 2;

   // skip the query
   // (content match enforces exactly 1)
   if(!skip_dns_name(cursor_normal, end_of_buffer))
      return IpsOption::NO_MATCH;

   // check if we can read
   //  record_type  (2 bytes)
   //  record_class (2 bytes)
   if(cursor_normal + 4 > end_of_buffer)
      return IpsOption::NO_MATCH;

   record_type = read_big_16_inc(cursor_normal);
   record_class = read_big_16_inc(cursor_normal);

   // verify record is SOA
   //  0x0006 == SOA, 0x0001 == IN
   if(record_type != 0x0006 || record_class != 0x0001)
      return IpsOption::NO_MATCH;

   // skip prerequisites
   // (content match enforces exactly 1)
   if(!skip_dns_name(cursor_normal, end_of_buffer))
      return IpsOption::NO_MATCH;

   // check if we can read
   //  record_type  (2 bytes)
   //  record_class (2 bytes)
   //  ttl          (4 bytes)
   //  data_len     (2 bytes)
   if(cursor_normal + 10 > end_of_buffer)
      return IpsOption::NO_MATCH;

   record_type = read_big_16_inc(cursor_normal);
   record_class = read_big_16_inc(cursor_normal);

   // verify record is ANY 
   //  0x00FF == ANY, 0x0001 == IN
   if(record_type != 0x00FF || record_class != 0x0001)
      return IpsOption::NO_MATCH;

   // skip TTL (4 bytes)
   cursor_normal += 4;

   // read data_len
   data_len = read_big_16_inc(cursor_normal);

   // check if we can skip data_len
   if(data_len > end_of_buffer - cursor_normal)
      return IpsOption::NO_MATCH;

   // skip data_len
   cursor_normal += data_len;

   for(unsigned i = 0; i < num_updates; i++)
   {
      if(!skip_dns_name(cursor_normal, end_of_buffer))
         return IpsOption::NO_MATCH;

      // check if we can read
      //  record_type  (2 bytes)
      //  record_class (2 bytes)
      //  ttl          (4 bytes)
      //  data_len     (2 bytes)
      if(cursor_normal + 10 > end_of_buffer)
         return IpsOption::NO_MATCH;

      record_type = read_big_16_inc(cursor_normal);

      DEBUG_SO(fprintf(stderr,"record_type=0x%04x\n",record_type);)

      // check vulnerability condition
      // (update of type ANY)
      if(record_type == 0x00FF)
         return IpsOption::MATCH;

      // skip:
      //  record_class (2 bytes)
      //  ttl          (4 bytes)
      cursor_normal += 6;

      // read data_len
      data_len = read_big_16_inc(cursor_normal);

      // check if we can skip data_len
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

static const SoApi so_15734 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        6, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "15734", // name
        "PROTOCOL-DNS ISC BIND dynamic update message denial of service attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_15734,
    rule_15734_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_15734 = &so_15734.base;

