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
// file-image_oracle-oit-memory-corruption.cc author Brandon Stultz <brastult@cisco.com>

#include "main/snort_types.h"
#include "framework/so_rule.h"
#include "framework/cursor.h"
#include "protocols/packet.h"

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

using namespace snort;

static const char* rule_41372 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-IMAGE Oracle Outside In libvs_gif out of bounds write attempt";
	soid:41372;
	file_data;
	content:"GIF8",depth 4;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	reference:url,www.talosintelligence.com/reports/;
	classtype:attempted-admin;
	gid:3; sid:41372; rev:2;
)
)[Snort_SO_Rule]";

static const unsigned rule_41372_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.buffer(),
                 *end_of_buffer = c.endo();

   uint8_t fields, block_type, block_size;
   uint32_t gct_size;
   uint16_t image_width, image_height;
   int i, j;

   DEBUG_SO(fprintf(stderr,"[GIF]\n");)

   // skip GIF header
   cursor_normal += 10;

   // make sure we can read the screen descriptor
   if(cursor_normal + 3 > end_of_buffer)
      return IpsOption::NO_MATCH;

   // read packed fields
   fields = *cursor_normal;

   // skip the rest of the screen descriptor
   cursor_normal += 3;

   // if we have a GCT, skip it.
   if(fields & 0x80)
   {
      // calculate the size of the GCT
      gct_size = 3 * (1 << ((fields & 0x07) + 1));

      DEBUG_SO(fprintf(stderr," GCT size: %d\n",gct_size);)

      // check if we can skip the GCT
      if(gct_size > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // skip the GCT
      cursor_normal += gct_size;
   }

   // skip up to 5 data blocks
   // looking for the ImageDescriptor
   for(i=0; i<5; i++)
   {
      // make sure we can read data block
      // type, size, ImageWidth, and ImageHeight
      if(cursor_normal + 9 > end_of_buffer)
         return IpsOption::NO_MATCH;

      block_type = *cursor_normal;

      // found the ImageDescriptor
      if(block_type == 0x2C)
      {
         // order doesn't matter
         image_width = *(uint16_t*)(cursor_normal + 5);
         image_height = *(uint16_t*)(cursor_normal + 7);

         // check vuln condition
         if((image_width == 0xFFFF) && (image_height != 0xFFFF))
            return IpsOption::MATCH;

         // only one ImageDescriptor
         return IpsOption::NO_MATCH;
      }

      // block type is not an extension, bail.
      if(block_type != 0x21)
         return IpsOption::NO_MATCH;

      // read block_size (verified we can above)
      block_size = *(cursor_normal + 2);

      DEBUG_SO(fprintf(stderr," block 0x%02X size: %d\n",block_type,block_size);)

      // check if we can skip block_size
      if(block_size > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // skip the block
      cursor_normal += block_size + 3;

      // process up to 5 data sub-blocks
      for(j=0; j<5; j++)
      {
         // make sure we can read data sub-block size
         if(cursor_normal + 1 > end_of_buffer)
            return IpsOption::NO_MATCH;

         block_size = *cursor_normal++;

         DEBUG_SO(fprintf(stderr,"  sub-block size: %d\n",block_size);) 

         // if sub block_size is 0, end of block 
         if(block_size == 0)
            break;

         // check if we can skip block_size
         if(block_size > end_of_buffer - cursor_normal)
            return IpsOption::NO_MATCH;

         // skip the sub-block
         cursor_normal += block_size;
      }
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_41372 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        2, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "41372", // name
        "FILE-IMAGE Oracle Outside In libvs_gif out of bounds write attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_41372,
    rule_41372_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_41372 = &so_41372.base;

