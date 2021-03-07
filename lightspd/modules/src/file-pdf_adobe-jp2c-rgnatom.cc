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
// file-pdf_adobe-jp2c-rgnatom.cc author Brandon Stultz <brastult@cisco.com>
//                                author Patrick Mullen <pamullen@cisco.com>

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

static const char* rule_16370 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-PDF Adobe Reader JP2C Region Atom CompNum memory corruption attempt";
	soid:16370;
	file_type:PDF;
	file_data;
	content:"jP|20 20|";
	content:"|FF 4F FF 51 00 2F|";
	so:eval,relative;
	metadata:policy max-detect-ips drop;
	reference:cve,2009-3955;
	classtype:attempted-user;
	gid:3; sid:16370; rev:7;
)
)[Snort_SO_Rule]";

static const unsigned rule_16370_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint16_t csiz, crgn, atom_type, atom_len;

   // skip to csiz
   cursor_normal += 34;

   // check if we can read csiz
   if(cursor_normal + 2 > end_of_buffer)
      return IpsOption::NO_MATCH;

   csiz = read_big_16_inc(cursor_normal);

   DEBUG_SO(fprintf(stderr,"csiz=0x%04x\n",csiz);)

   // skip to the next atom
   cursor_normal += 9;

   // check up to 25 atoms
   for(unsigned i = 0; i < 25; i++)
   {
      // check if we can read:
      //  atom_type (2 bytes)
      //  atom_len  (2 bytes)
      if(cursor_normal + 4 > end_of_buffer)
         return IpsOption::NO_MATCH;

      atom_type = read_big_16_inc(cursor_normal);
      atom_len = read_big_16(cursor_normal);

      if((atom_type & 0xFF00) != 0xFF00)
         return IpsOption::NO_MATCH;

      DEBUG_SO(fprintf(stderr,"atom_type=0x%04x\n",atom_type);)
      DEBUG_SO(fprintf(stderr,"atom_len=0x%04x\n",atom_len);)

      if(atom_type == 0xFF5E)
      {
         // found region of interest atom
         // check if we can read crgn
         if(cursor_normal + 4 > end_of_buffer)
            return IpsOption::NO_MATCH;

         switch(atom_len)
         {
         case 5:
            crgn = *(cursor_normal + 2);
            break;
         case 6:
            crgn = read_big_16(cursor_normal + 2);
            break;
         default:
            return IpsOption::NO_MATCH;
         }

         DEBUG_SO(fprintf(stderr,"crgn=0x%04x\n",crgn);)

         // check vulnerability condition
         if(crgn >= csiz)
            return IpsOption::MATCH;
      }

      // check if we can jump atom_len
      if(atom_len > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // jump atom_len
      cursor_normal += atom_len;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_16370 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        7, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "16370", // name
        "FILE-PDF Adobe Reader JP2C Region Atom CompNum memory corruption attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_16370,
    rule_16370_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_16370 = &so_16370.base;

