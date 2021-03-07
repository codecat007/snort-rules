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
// file-office_kb956416-excel-rept-underflow.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_14655 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-OFFICE Microsoft Office Excel REPT integer underflow attempt";
	soid:14655;
	file_data;
	content:"|41 1E|",fast_pattern;
	content:"|06 00|",distance -100,within 200;
	content:"|17|",distance 24,within 1;
	byte_jump:0,-4,relative;
	so:eval,relative;
	metadata:policy max-detect-ips drop;
	reference:bugtraq,31706;
	reference:cve,2008-4019;
	reference:url,technet.microsoft.com/en-us/security/bulletin/ms08-057;
	classtype:attempted-user;
	gid:3; sid:14655; rev:14;
)
)[Snort_SO_Rule]";

static const unsigned rule_14655_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo(),
                 *function_type_pos;

   uint16_t structure_len, argument_len,
            function_type;

   // +-----+--------------------+--------------+-----+
   // | len | ptgstr(0x17)"AAAA" |0x44(cellref) |REPT |
   // |-----+--------------------|--------------+-----+
   // |0F 00|17|04 00|41 41 41 41|44 XX XX XX XX|41 1E|
   // |     |  | len |           |              |     |
   // +-----+--------------------+--------------+-----+

   // check if we can:
   //  skip reserved      (1 byte)
   //  read structure_len (2 bytes)
   //  skip argument_type (1 byte)
   //  read argument_len  (2 bytes)
   if(cursor_normal + 6 > end_of_buffer)
      return IpsOption::NO_MATCH;

   structure_len = read_little_16(cursor_normal+1);
   argument_len = read_little_16(cursor_normal+4);

   // check if we can skip structure_len
   if(structure_len > end_of_buffer - cursor_normal)
      return IpsOption::NO_MATCH;

   // skip structure_len
   function_type_pos = cursor_normal + structure_len;

   // check if we can read:
   //  function_type (2 bytes)
   if(function_type_pos + 2 > end_of_buffer)
      return IpsOption::NO_MATCH;

   function_type = read_little_16(function_type_pos);

   // match REPT (0x1E41)
   if(function_type != 0x1E41)
      return IpsOption::NO_MATCH;

   cursor_normal += 6;

   // check if we can skip argument_len
   if(argument_len > end_of_buffer - cursor_normal)
      return IpsOption::NO_MATCH;

   // skip argument_len
   cursor_normal += argument_len;

   // check if we can read:
   //  argument (1 byte)
   if(cursor_normal + 1 > end_of_buffer)
      return IpsOption::NO_MATCH;

   // match cellref (0x44) 
   if(*cursor_normal++ != 0x44)
      return IpsOption::NO_MATCH; 

   // skip cellref_len
   cursor_normal += 4;

   // make sure we are not out of bounds
   if(cursor_normal >= end_of_buffer)
      return IpsOption::NO_MATCH;

   // if function_type_pos equals the sum of
   // walking the entire structure, then alert.
   if(cursor_normal == function_type_pos)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_14655 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        14, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "14655", // name
        "FILE-OFFICE Microsoft Office Excel REPT integer underflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_14655,
    rule_14655_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_14655 = &so_14655.base;

