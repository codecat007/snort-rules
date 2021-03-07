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
// os-windows_kb924090-bmp-filter.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_13879 = R"[Snort_SO_Rule](
alert file (
	msg:"OS-WINDOWS Windows BMP image conversion arbitrary code execution attempt";
	soid:13879;
	file_data;
	content:"BM",depth 2;
	content:"|28 00 00 00|",distance 12, within 4, fast_pattern;
	so:eval;
	metadata:policy max-detect-ips drop;
	reference:cve,2008-3020;
	reference:cve,2009-2518;
	reference:url,technet.microsoft.com/en-us/security/bulletin/ms08-044;
	reference:url,technet.microsoft.com/en-us/security/bulletin/ms09-062;
	classtype:attempted-user;
	gid:3; sid:13879; rev:13;
)
)[Snort_SO_Rule]";

static const unsigned rule_13879_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint16_t bpp;

   uint32_t clrused, maxclr;

   // skip:
   //  width(4), height(4), planes(2)
   cursor_normal += 10;

   // check if we can:
   //  read bpp         (2 bytes)
   //  skip compression (4 bytes)
   //  skip image_size  (4 bytes)
   //  skip xres        (4 bytes)
   //  skip yres        (4 bytes)
   //  read clrused     (4 bytes) 
   if(cursor_normal + 22 > end_of_buffer)
      return IpsOption::NO_MATCH;

   bpp = read_little_16_inc(cursor_normal);

   cursor_normal += 16;

   clrused = read_little_32_inc(cursor_normal);

   DEBUG_SO(fprintf(stderr,"bpp=0x%04x\n",bpp);)
   DEBUG_SO(fprintf(stderr,"clrused=0x%08x\n",clrused);)

   if(bpp == 0 || bpp >= 32)
      return IpsOption::NO_MATCH;

   maxclr = 1 << bpp;

   if(clrused > maxclr)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_13879 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        13, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "13879", // name
        "OS-WINDOWS Windows BMP image conversion arbitrary code execution attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_13879,
    rule_13879_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_13879 = &so_13879.base;

