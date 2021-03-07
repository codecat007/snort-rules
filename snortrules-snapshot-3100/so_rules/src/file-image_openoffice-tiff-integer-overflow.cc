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
// file-image_openoffice-tiff-integer-overflow.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_15975 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-IMAGE OpenOffice TIFF parsing integer overflow attempt";
	soid:15975;
	file_data;
	content:"II|2A 00|",depth 4;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	reference:bugtraq,25690;
	reference:cve,2007-2834;
	classtype:attempted-user;
	gid:3; sid:15975; rev:6;
)
)[Snort_SO_Rule]";

static const unsigned rule_15975_len = 0;

static const char* rule_15976 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-IMAGE OpenOffice TIFF parsing integer overflow attempt";
	soid:15976;
	file_data;
	content:"MM|00 2A|",depth 4;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	reference:bugtraq,25690;
	reference:cve,2007-2834;
	classtype:attempted-user;
	gid:3; sid:15976; rev:6;
)
)[Snort_SO_Rule]";

static const unsigned rule_15976_len = 0;

enum Endian { BIG, LITTLE };

static inline uint32_t read_32(const uint8_t* p, Endian e)
{
   if(e == Endian::BIG)
      return read_big_32(p);

   return read_little_32(p);
}

static inline uint16_t read_16(const uint8_t* p, Endian e)
{
   if(e == Endian::BIG)
      return read_big_16(p);

   return read_little_16(p);
}

static IpsOption::EvalStatus DetectIntOverflow(Cursor& c, Endian e)
{
   const uint8_t *beg_of_buffer = c.buffer(),
                 *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint32_t ifd_offset, count;
   uint16_t ifd_entry_count, tag_id;

   // check if we can read the IFD offset
   if(cursor_normal + 4 > end_of_buffer)
      return IpsOption::NO_MATCH;

   // read the IFD offset
   ifd_offset = read_32(cursor_normal, e);

   // check if we can jump to the IFD
   if(ifd_offset > c.size())
      return IpsOption::NO_MATCH;

   // jump to the IFD
   cursor_normal = beg_of_buffer + ifd_offset;

   // check if we can read ifd_entry_count
   if(cursor_normal + 2 > end_of_buffer)
      return IpsOption::NO_MATCH;

   ifd_entry_count = read_16(cursor_normal, e);
   cursor_normal += 2;

   DEBUG_SO(fprintf(stderr,"ifd_entry_count = 0x%04x\n",ifd_entry_count);)

   // limit ifd_entry_count
   if(ifd_entry_count > 15)
      ifd_entry_count = 15;

   // check up to 15 IFD entries
   for(unsigned i = 0; i < ifd_entry_count; i++)
   {
      // check if we can read the IFD
      if(cursor_normal + 12 > end_of_buffer)
         return IpsOption::NO_MATCH;

      tag_id = read_16(cursor_normal, e);

      DEBUG_SO(fprintf(stderr,"tag_id = 0x%04x\n",tag_id);)

      // check:
      //  StripOffsets (0x0111) or StripByteCounts (0x0117)
      if(tag_id == 0x0111 || tag_id == 0x0117)
      {
         count = read_32(cursor_normal + 4, e);

         DEBUG_SO(fprintf(stderr,"count = 0x%08x\n",count);)

         // check vulnerability condition
         if(count >= 0x40000000)
            return IpsOption::MATCH;
      }

      // skip IFD entry
      cursor_normal += 12;
   }

   return IpsOption::NO_MATCH;
}

static IpsOption::EvalStatus rule_15975_eval(void*, Cursor& c, Packet*)
{
   return DetectIntOverflow(c, Endian::LITTLE);
}

static SoEvalFunc rule_15975_ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return rule_15975_eval;
}

static const SoApi so_15975 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        6, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "15975", // name
        "FILE-IMAGE OpenOffice TIFF parsing integer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_15975,
    rule_15975_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    rule_15975_ctor, // ctor
    nullptr  // dtor
};

static IpsOption::EvalStatus rule_15976_eval(void*, Cursor& c, Packet*)
{
   return DetectIntOverflow(c, Endian::BIG);
}

static SoEvalFunc rule_15976_ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return rule_15976_eval;
}

static const SoApi so_15976 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        6, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "15976", // name
        "FILE-IMAGE OpenOffice TIFF parsing integer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_15976,
    rule_15976_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    rule_15976_ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_15975 = &so_15975.base;
const BaseApi* pso_15976 = &so_15976.base;

