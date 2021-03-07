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
// server-other_cups-ipp-memory-corruption.cc author Brandon Stultz <brastult@cisco.com>

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

#define IPPERROR -1 

using namespace snort;

struct IPPTAG {
   uint8_t tag;
   uint16_t name_len;
   uint16_t value_len;
};

static const char* rule_26972 = R"[Snort_SO_Rule](
alert http (
	msg:"SERVER-OTHER CUPS IPP multi-valued attribute memory corruption attempt";
	soid:26972;
	flow:to_server,established;
	http_client_body;
	content:"|01 01 00 0B|",depth 4;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	service:ipp;
	reference:cve,2010-2941;
	reference:bugtraq,44530;
	reference:url,lists.apple.com/archives/security-announce/2010/Nov/msg00000.html;
	classtype:attempted-admin;
	gid:3; sid:26972; rev:4;
)
)[Snort_SO_Rule]";

static const unsigned rule_26972_len = 0;

static int parseipptag(const uint8_t*& cursor, const uint8_t* end_of_buffer, IPPTAG& tuple)
{
   const uint8_t* cursor_tmp; 

   // check if we can read: tag (1 byte) + name_len (2 bytes)
   if(cursor + 3 > end_of_buffer)
      return IPPERROR;

   // store the tag
   tuple.tag = *cursor++;

   // if the tag is another attribute-group (0x01)
   // or end-of-attributes (0x03), return error
   if((tuple.tag == 0x01) || (tuple.tag == 0x03))
      return IPPERROR;

   // store the name_len (2 bytes, BE)
   tuple.name_len  = read_big_16_inc(cursor);

   if(tuple.name_len > 0) {
      // jump the name_len, check for overflow
      cursor_tmp = cursor + tuple.name_len;
      if(cursor_tmp < cursor)
         return IPPERROR;
      cursor = cursor_tmp;
   }

   // check if we can read: value_len (2 bytes)
   if(cursor + 2 > end_of_buffer)
      return IPPERROR;

   // store the value_len (2 bytes, BE)
   tuple.value_len  = read_big_16_inc(cursor);

   // jump the value_len, check for overflow
   cursor_tmp = cursor + tuple.value_len;
   if(cursor_tmp < cursor)
      return IPPERROR;
   cursor = cursor_tmp;

   // no error
   return 1;
}

//
// Set 1:
// 0x35, 0x36, 0x41, 0x42, 0x44..0x49
//
// Set 2:
// 0x37..0x40, 0x43
//

static int classifytag(uint8_t tag)
{
   if(((tag >= 0x37) && (tag <= 0x40)) || (tag == 0x43)) // 37-40, 43
      return 2;
   else if ((tag >= 0x35) && (tag <= 0x49)) // 35, 36, 41, 42, 44-49
      return 1;
   else
      return IPPERROR;
}

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   IPPTAG tuple;
   int base_class_type, additional_class_type;

   // skip request id (4 bytes)
   cursor_normal += 4;

   // attribute-group (1 byte)
   // extra bytes for minimum size req'd to exploit
   if(cursor_normal + 10 > end_of_buffer)
      return IpsOption::NO_MATCH;

   // verify we have an attribute-group (0x01)
   if(*cursor_normal++ != 0x01)
      return IpsOption::NO_MATCH;

   // Now we want to parse through the following structure:
   //
   //          Tag: 1 byte   |XX|
   //  Name Length: 2 bytes  |XX XX| = A
   //         Name: A bytes
   // Value Length: 2 bytes  |XX XX| = B
   //        Value: B bytes
   //         **optional**
   //          Tag: 1 byte   |XX|
   //  Name Length: 2 bytes  |XX XX| = C
   //  (if C == 0, same name as above, aka "additional-value")
   //               [...]
   //  0x03 (end of attributes) || 0x01 (attribute-group)
   if(parseipptag(cursor_normal, end_of_buffer, tuple) == IPPERROR)
      return IpsOption::NO_MATCH;

   // the first name_length in a tag-name structure must not be 0
   // subsequent name_lengths may be 0, indicating additional values
   // for the attribute in the nearest preceding name see: RFC 2910
   if(tuple.name_len == 0)
      return IpsOption::NO_MATCH;

   // classify the tag type, if we don't know the type, NOMATCH
   if((base_class_type = classifytag(tuple.tag)) == IPPERROR)
      return IpsOption::NO_MATCH;
   DEBUG_SO(fprintf(stderr,"ipptag [0x%02x] (base class %d)\n",tuple.tag,base_class_type);)

   // check up to 25 tag-name structures
   for(int i = 0; i < 25; i++)
   {
      if(parseipptag(cursor_normal, end_of_buffer, tuple) == IPPERROR)
         return IpsOption::NO_MATCH;

      // if the name_length is not 0, we just parsed
      // a new 'base' structure, classify this and continue
      if(tuple.name_len != 0)
      {
         if((base_class_type = classifytag(tuple.tag)) == IPPERROR)
            return IpsOption::NO_MATCH;
         DEBUG_SO(fprintf(stderr,"ipptag [0x%02x] (base class %d)\n",tuple.tag,base_class_type);)
         continue;
      }

      // classify the additional tag type
      if((additional_class_type = classifytag(tuple.tag)) == IPPERROR)
         return IpsOption::NO_MATCH;
      DEBUG_SO(fprintf(stderr,"   ipptag [0x%02x] (class %d)\n",tuple.tag,additional_class_type);)

      // if the tuple class types differ
      // then the vulnerability condition
      // has been met, alert.
      if(base_class_type != additional_class_type)
         return IpsOption::MATCH;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_26972 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        4, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "26972", // name
        "SERVER-OTHER CUPS IPP multi-valued attribute memory corruption attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_26972,
    rule_26972_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_26972 = &so_26972.base;

