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
// file-executable_norton-av-aspack-heap-corruption.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_39379 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-EXECUTABLE Norton Antivirus ASPack heap corruption attempt";
	soid:39379;
	file_data;
	byte_jump:4,60,little,from_beginning;
	content:"PE|00 00|",within 4;
	so:eval;
	metadata:policy balanced-ips drop, policy max-detect-ips drop, policy security-ips drop;
	reference:cve,2016-2208;
	reference:url,googleprojectzero.blogspot.com/2016/06/how-to-compromise-enterprise-endpoint.html;
	classtype:attempted-admin;
	gid:3; sid:39379; rev:2;
)
)[Snort_SO_Rule]";

static const unsigned rule_39379_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo(),
                 *cursor_detect;

   uint16_t num_sections, optional_len;

   uint32_t image_len, raw_data_len;

   uint64_t name;

   // check if we can:
   //  skip machine         (2 bytes)
   //  read num_sections    (2 bytes)
   //  skip timestamp       (4 bytes)
   //  skip symbol_tbl_ptr  (4 bytes)
   //  skip num_symbol_tbl  (4 bytes)
   //  read optional_len    (2 bytes)
   //  skip characteristics (2 bytes)
   if(cursor_normal + 20 > end_of_buffer)
      return IpsOption::NO_MATCH;

   num_sections = read_little_16(cursor_normal + 2);

   if(num_sections == 0)
      return IpsOption::NO_MATCH;

   if(num_sections > 25)
      num_sections = 25;

   optional_len = read_little_16(cursor_normal + 16);

   // skip COFF header
   cursor_normal += 20;

   cursor_detect = cursor_normal;

   // skip:
   //  magic(2), linker_ver(2), code_len(4),
   //  init_len(4), uninit_len(4), entry_addr(4),
   //  code_base(4), data_base(4), image_base(4),
   //  section_align(4), file_align(4),
   //  os_ver(4), img_ver(4), subsys_ver(4),
   //  win32_ver(4) = (56 bytes)
   cursor_detect += 56;

   // check if we can read:
   //  image_len (4 bytes)
   if(cursor_detect + 4 > end_of_buffer)
      return IpsOption::NO_MATCH;

   image_len = read_little_32(cursor_detect);

   // check if we can jump optional_len
   if(optional_len > end_of_buffer - cursor_normal)
      return IpsOption::NO_MATCH;

   // jump optional_len
   cursor_normal += optional_len;

   // check up to 25 sections
   for(unsigned i = 0; i < num_sections; i++)
   {
      // check if we can read the section
      if(cursor_normal + 40 > end_of_buffer)
         return IpsOption::NO_MATCH;

      name = read_little_64(cursor_normal);

      if(name != 0x637273722E)
      {
         // not ".rsrc"
         raw_data_len = read_little_32(cursor_normal + 16);

         // check vulnerability condition
         if(raw_data_len > image_len)
            return IpsOption::MATCH;
      }

      // skip section
      cursor_normal += 40;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_39379 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        2, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "39379", // name
        "FILE-EXECUTABLE Norton Antivirus ASPack heap corruption attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_39379,
    rule_39379_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_39379 = &so_39379.base;

