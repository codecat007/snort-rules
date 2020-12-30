//--------------------------------------------------------------------------
// Copyright (C) 2019-2020 Cisco and/or its affiliates. All rights reserved.
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
// server-other_openssl-dtls-hs-fragment.cc author Brandon Stultz <brastult@cisco.com>

#include "main/snort_types.h"
#include "framework/so_rule.h"
#include "framework/cursor.h"
#include "protocols/packet.h"
#include "flow/flow.h"
#include "util_read.h"

#include <ctime>

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

// dtls client->server handshake types
#define HS_CLIENT_HELLO 1
#define HS_CLIENT_KEYX 16
#define HS_CHG_CIPHER_SPEC 20
#define DTLS_HS 22

#define FRAG_TABLE_LEN 5
#define TIME_WINDOW 2

using namespace snort;

static const char* rule_31361 = R"[Snort_SO_Rule](
alert udp $EXTERNAL_NET any -> $HOME_NET [4433,443] (
	msg:"SERVER-OTHER OpenSSL DTLSv1.0 handshake fragment buffer overrun attempt";
	soid:31361;
	flow:to_server;
	content:"|16 FE FF|",depth 3;
	so:eval;
	metadata:policy balanced-ips drop, policy max-detect-ips drop, policy security-ips drop;
	reference:bugtraq,67900;
	reference:cve,2014-0195;
	reference:url,www.openssl.org/news/secadv_20140605.txt;
	classtype:attempted-admin;
	gid:3; sid:31361; rev:4;
)
)[Snort_SO_Rule]";

static const unsigned rule_31361_len = 0;

#if(BASE_API_VERSION > 1)

// dtls handshake fragment datatype
struct dtls_hs_fragment {
   struct timeval ts;        // fragment timestamp
   uint8_t hs_type;          // handshake type
   uint16_t msg_seq;         // message sequence
   uint32_t reassembled_len; // reassembled msg length
   uint32_t len;             // fragment length
};

class FlowData_31361 : public RuleFlowData
{
public:
   FlowData_31361() : RuleFlowData(id) { }

   static void init()
   { id = FlowData::create_flow_data_id(); }

   size_t size_of() override
   { return sizeof(*this); }

public:
   static unsigned id;
   dtls_hs_fragment fragment_table[FRAG_TABLE_LEN] = {};
};

unsigned FlowData_31361::id = 0;

static IpsOption::EvalStatus check_msg_seq(dtls_hs_fragment& fragment, Packet* p)
{
   // check if fragment sequence is within range
   if(fragment.msg_seq >= FRAG_TABLE_LEN)
      return IpsOption::NO_MATCH;

   // get the FlowData for this flow
   FlowData_31361* fd =
      (FlowData_31361*)p->flow->get_flow_data(FlowData_31361::id);

   // initalize and set the FlowData if it does not exist
   if(!fd)
   {
      fd = new FlowData_31361();
      p->flow->set_flow_data(fd);
   }

   // lookup previous fragment
   dtls_hs_fragment& previous_fragment = fd->fragment_table[fragment.msg_seq];

   // check if we have seen a fragment of this sequence before
   if(previous_fragment.reassembled_len != 0)
   {
      // We have seen a fragment of this sequence in this
      // stream. Check for the vulnerabile condition, if
      // the fragment type differs or if it was encountered
      // outside the time window, replace the entry in the
      // table with this fragment.
      if((fragment.hs_type == previous_fragment.hs_type) &&
         (p->pkth->ts.tv_sec <= (previous_fragment.ts.tv_sec + TIME_WINDOW)) &&
         (fragment.reassembled_len != previous_fragment.reassembled_len))
         return IpsOption::MATCH;
   }

   // Add fragment's information to the table for future checks
   previous_fragment.ts = p->pkth->ts;
   previous_fragment.hs_type = fragment.hs_type;
   previous_fragment.msg_seq = fragment.msg_seq;
   previous_fragment.reassembled_len = fragment.reassembled_len;

   return IpsOption::NO_MATCH;
} 

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.buffer(),
                 *end_of_buffer = c.endo(),
                 *end_of_rec_pos;

   uint16_t dtls_record_len;
   uint8_t dtls_record_type;
   int i,j;

   dtls_hs_fragment fragment = {};

   if ( !p->flow )
      return IpsOption::NO_MATCH;

   // check up to 2 DTLS records
   for(i=0; i<2; i++)
   {
      // make sure we can read the DTLS record type and length
      if(cursor_normal + 13 > end_of_buffer)
         return IpsOption::NO_MATCH;

      // read the dtls record type
      dtls_record_type = *cursor_normal;

      // skip version, epoch, sequence number
      cursor_normal += 11;

      // read the DTLS record length (2 byte big-endian)
      dtls_record_len = read_big_16_inc(cursor_normal);

      // check if we can jump dtls_record_len
      if(dtls_record_len > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // calculate the end of record position
      end_of_rec_pos = cursor_normal + dtls_record_len;

      // if the DTLS record is not a handshake, skip it.
      if(dtls_record_type != DTLS_HS)
      {
         cursor_normal = end_of_rec_pos;
         continue;
      }

      // check up to 3 dtls handshake fragments per DTLS record
      for(j=0; j<3; j++)
      {
         // make sure we can read the dtls fragment header
         if(cursor_normal + 12 > end_of_buffer)
            return IpsOption::NO_MATCH;

         // read handshake type
         fragment.hs_type = *cursor_normal++;

         // make sure we are inspecting a client hs_type 
         if(fragment.hs_type != HS_CLIENT_HELLO &&
            fragment.hs_type != HS_CLIENT_KEYX &&
            fragment.hs_type != HS_CHG_CIPHER_SPEC)
            return IpsOption::NO_MATCH;

         // read reassembled_len (3 byte big-endian)
         fragment.reassembled_len = read_big_24_inc(cursor_normal);

         // read message sequence (2 byte big-endian)
         fragment.msg_seq = read_big_16_inc(cursor_normal);

         // skip fragment offset (3 byte big-endian)
         cursor_normal += 3;

         // read fragment len (3 byte big-endian)
         fragment.len = read_big_24_inc(cursor_normal);

         // while this is invalid, it is handled properly by OpenSSL
         if(fragment.len > fragment.reassembled_len)
            return IpsOption::NO_MATCH;

         // check if message is fragmented
         if(fragment.len < fragment.reassembled_len)
            if(check_msg_seq(fragment, p) == IpsOption::MATCH)
               return IpsOption::MATCH;

         // check if we can skip fragment.len
         if(fragment.len > end_of_buffer - cursor_normal)
            return IpsOption::NO_MATCH;

         // skip fragment.len
         cursor_normal += fragment.len;

         // check if we went past the end_of_rec_pos
         if(cursor_normal > end_of_rec_pos)
            return IpsOption::NO_MATCH;

         // if we landed on the end of the dtls
         // record then break the inner loop
         if(cursor_normal == end_of_rec_pos)
            break;
      }
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    FlowData_31361::init();
    *pv = nullptr;
    return eval;
}

#else

static IpsOption::EvalStatus eval(void*, Cursor&, Packet*)
{
    return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

#endif

static const SoApi so_31361 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        4, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "31361", // name
        "SERVER-OTHER OpenSSL DTLSv1.0 handshake fragment buffer overrun attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_31361,
    rule_31361_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_31361 = &so_31361.base;

