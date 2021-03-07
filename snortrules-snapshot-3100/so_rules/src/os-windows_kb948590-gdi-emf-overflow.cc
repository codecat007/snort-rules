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
// os-windows_kb948590-gdi-emf-overflow.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_13676 = R"[Snort_SO_Rule](
alert file (
	msg:"OS-WINDOWS Microsoft Windows GDI emf filename buffer overflow attempt";
	soid:13676;
	file_data;
	content:"|20|EMF",offset 40,depth 4;
	content:"|01 00 00 00|",depth 4;
	byte_jump:4,0,relative,little,from_beginning;
	so:eval;
	metadata:policy max-detect-ips drop;
	reference:cve,2008-1087;
	reference:url,technet.microsoft.com/en-us/security/bulletin/ms08-021;
	classtype:attempted-user;
	gid:3; sid:13676; rev:10;
)
)[Snort_SO_Rule]";

static const unsigned rule_13676_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint32_t record_type, record_len;

   uint16_t wide_char;

   // check up to 100 EMF records
   for(unsigned i = 0; i < 100; i++)
   {
      // check if we can read:
      //  record_type (4 bytes)
      //  record_len  (4 bytes)
      if(cursor_normal + 8 > end_of_buffer)
         return IpsOption::NO_MATCH;

      record_type = read_little_32(cursor_normal);
      record_len = read_little_32(cursor_normal + 4);

      DEBUG_SO(fprintf(stderr,"record_type=0x%08x\n",record_type);)
      DEBUG_SO(fprintf(stderr,"record_len=0x%08x\n",record_len);)

      // EOF
      if(record_type == 0x0E)
         return IpsOption::NO_MATCH;

      if(record_type != 0x79)
      {
         // check if we can skip record_len
         if(record_len > end_of_buffer - cursor_normal)
            return IpsOption::NO_MATCH;

         // skip record_len
         cursor_normal += record_len;

         // loop
         continue;
      }

      // found COLORMATCHTOTARGETW
      // skip:
      //  type(4), len(4),
      //  dwaction(4), dwflags(4),
      //  cbname(4), cbdata(4) = (24 bytes)
      cursor_normal += 24;

      // check up to 260 wide characters
      for(unsigned j = 0; j < 260; j++)
      {
          if(cursor_normal + 2 > end_of_buffer)
             return IpsOption::NO_MATCH;

          wide_char = read_little_16(cursor_normal);

          if(wide_char == 0)
             return IpsOption::NO_MATCH;
      }

      // no null within 260 wide characters, alert
      return IpsOption::MATCH;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_13676 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        10, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "13676", // name
        "OS-WINDOWS Microsoft Windows GDI emf filename buffer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_13676,
    rule_13676_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_13676 = &so_13676.base;

