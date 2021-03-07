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
// netbios_smb-filename-len-overflow.cc author Brandon Stultz <brastult@cisco.com>

#include "main/snort_types.h"
#include "framework/so_rule.h"
#include "framework/cursor.h"
#include "protocols/packet.h"
#include "flow/flow.h"
#include "util_read.h"

#include <algorithm>
#include <vector>

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

using namespace snort;

static const char* rule_24973 = R"[Snort_SO_Rule](
alert tcp (
	msg:"NETBIOS SMB Trans2 FIND_FIRST2 response file name length overflow attempt";
	soid:24973;
	flow:established;
	content:"|FF|SMB2|00 00 00 00|",offset 4,depth 9;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	service:netbios-ssn;
	reference:cve,2012-4774;
	reference:url,technet.microsoft.com/en-us/security/bulletin/MS12-081;
	classtype:attempted-admin;
	gid:3; sid:24973; rev:9;
)
)[Snort_SO_Rule]";

static const unsigned rule_24973_len = 0;

#if(BASE_API_VERSION > 1)

class FlowData_24973 : public RuleFlowData
{
public:
   FlowData_24973() : RuleFlowData(id)
   { pids.reserve(10); }

   static void init()
   { id = FlowData::create_flow_data_id(); }

   size_t size_of() override
   { return sizeof(*this); }

public:
   static unsigned id;
   std::vector<uint16_t> pids;
};

unsigned FlowData_24973::id = 0;

static void storePid(uint16_t pid, Packet* p)
{
   // get the FlowData for this flow
   FlowData_24973* fd =
      (FlowData_24973*)p->flow->get_flow_data(FlowData_24973::id);

   // initalize and set the FlowData if it does not exist
   if(!fd)
   {
      fd = new FlowData_24973();
      p->flow->set_flow_data(fd);
   }

   std::vector<uint16_t>& pids = fd->pids;

   // only store up to 10 SMB pids
   if(pids.size() >= 10)
      return;

   // if pid doesn't exist in FlowData, store pid for future checks
   if(std::find(pids.begin(), pids.end(), pid) == pids.end())
      pids.push_back(pid); 
}

static bool checkPid(uint16_t pid, Packet* p)
{
   // get the FlowData for this flow
   FlowData_24973* fd =
      (FlowData_24973*)p->flow->get_flow_data(FlowData_24973::id);

   // no pids on flow
   if(!fd)
      return false;

   std::vector<uint16_t>& pids = fd->pids;

   // check if pid exists on flow
   for(auto it = pids.begin(); it != pids.end(); it++)
   {
      if(*it == pid)
      {
         // pid found, remove it from vector
         pids.erase(it);

         return true;
      }
   }

   return false;
}

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *beg_of_buffer = c.buffer(),
                 *cursor_normal = c.start(),
                 *end_of_buffer = c.endo(),
                 *cursor_detect;

   uint8_t flags;

   uint16_t flags2, pid, interest_offset,
            check, subcommand, interest,
            count_offset, data_offset,
            search_count, error_offset,
            last_entry_offset;

   uint32_t end_of_entries, next_entry_offset,
            filename_length, max_filename_length;

   if ( !p->flow )
      return IpsOption::NO_MATCH;

   // check if we can:
   //  read flags     (1 byte)
   //  read flags2    (2 bytes)
   //  skip pid high  (2 bytes)
   //  skip signature (8 bytes)
   //  skip reserved  (2 bytes)
   //  skip tree id   (2 bytes)
   //  read pid       (2 bytes)
   if(cursor_normal + 19 > end_of_buffer)
      return IpsOption::NO_MATCH;

   flags = *cursor_normal++;
   flags2 = read_little_16_inc(cursor_normal);

   cursor_normal += 14;

   pid = read_little_16_inc(cursor_normal);

   // skip:
   //  uid (2 bytes)
   //  mid (2 bytes)
   cursor_normal += 4;

   if((flags & 0x80) == 0)
   {
      // SMB Trans2 Request
      // skip:
      //  wct(1), total_param_count(2),
      //  total_data_count(2), max_param_count(2),
      //  max_data_count(2), max_setup_count(1),
      //  reserved(1), flags(2),
      //  timeout(4), reserved(2),
      //  parameter_count(2) = (21 bytes)
      cursor_normal += 21;

      // check if we can:
      //  read param_offset (2 bytes)
      //  skip data_count   (2 bytes)
      //  skip data_offset  (2 bytes)
      //  skip setup_count  (1 byte)
      //  skip reserved     (1 byte)
      //  read subcommand   (2 bytes)
      if(cursor_normal + 10 > end_of_buffer)
         return IpsOption::NO_MATCH;

      interest_offset = read_little_16_inc(cursor_normal);

      // integer overflow check
      check = interest_offset + 10;
      if(check < interest_offset)
         return IpsOption::NO_MATCH;
      interest_offset = check;

      cursor_normal += 6;

      subcommand = read_little_16_inc(cursor_normal);

      // match FIND_FIRST2 subcommand
      if(subcommand != 0x0001)
         return IpsOption::NO_MATCH;

      // check if we can skip interest_offset 
      if(interest_offset > end_of_buffer - beg_of_buffer)
         return IpsOption::NO_MATCH;

      // skip interest_offset
      cursor_normal = beg_of_buffer + interest_offset;

      // check if we can read:
      //  interest (2 bytes)
      if(cursor_normal + 2 > end_of_buffer)
         return IpsOption::NO_MATCH;

      interest = read_little_16_inc(cursor_normal);

      // match: Find File Both Dir Info (0x0104)
      if(interest != 0x0104)
         return IpsOption::NO_MATCH;

      // store pid on the flow
      storePid(pid, p);

      return IpsOption::NO_MATCH;
   }

   // SMB Trans2 Response

   // check if we have seen pid before
   if(!checkPid(pid, p))
      return IpsOption::NO_MATCH;

   // Find File Response 
   // skip:
   //  wct(1), total_param_count(2),
   //  total_data_count(2), reserved(2),
   //  parameter_count(2) = (9 bytes)
   cursor_normal += 9;

   // check if we can:
   //  read param_offset       (2 bytes)
   //  skip param_displacement (2 bytes)
   //  skip data_count         (2 bytes)
   //  read data_offset        (2 bytes)
   if(cursor_normal + 8 > end_of_buffer)
      return IpsOption::NO_MATCH;

   count_offset = read_little_16_inc(cursor_normal);

   // integer overflow check
   check = count_offset + 6;
   if(check < count_offset)
      return IpsOption::NO_MATCH;
   count_offset = check;

   cursor_normal += 4;

   data_offset = read_little_16_inc(cursor_normal);

   // integer overflow check
   check = data_offset + 4;
   if(check < data_offset)
      return IpsOption::NO_MATCH;
   data_offset = check;

   // check if we can skip count_offset
   if(count_offset > end_of_buffer - beg_of_buffer)
      return IpsOption::NO_MATCH;

   // skip count_offset
   cursor_normal = beg_of_buffer + count_offset;

   // check if we can:
   //  read search_count      (2 bytes)
   //  skip end_of_search     (2 bytes)
   //  read error_offset      (2 bytes)
   //  read last_entry_offset (2 bytes)
   if(cursor_normal + 8 > end_of_buffer)
      return IpsOption::NO_MATCH;

   search_count = read_little_16_inc(cursor_normal);

   DEBUG_SO(fprintf(stderr,"search_count=0x%04x\n",search_count);)

   // if no entries to check, bail
   if(search_count == 0)
      return IpsOption::NO_MATCH;

   // limit search_count
   if(search_count > 10)
      search_count = 10;

   cursor_normal += 2;

   error_offset = read_little_16_inc(cursor_normal);

   // if error, bail
   if(error_offset != 0)
      return IpsOption::NO_MATCH;

   last_entry_offset = read_little_16_inc(cursor_normal);

   // check if we can skip data_offset
   if(data_offset > end_of_buffer - beg_of_buffer)
      return IpsOption::NO_MATCH;

   // skip data_offset
   cursor_normal = beg_of_buffer + data_offset;

   // check if we can skip last_entry_offset
   if(last_entry_offset > end_of_buffer - cursor_normal)
      return IpsOption::NO_MATCH;

   // skip last_entry_offset
   cursor_detect = cursor_normal + last_entry_offset;

   // check if we can read:
   //  end_of_entries (4 bytes)
   if(cursor_detect + 4 > end_of_buffer)
      return IpsOption::NO_MATCH;

   end_of_entries = read_little_32(cursor_detect);

   // verify end_of_entries
   if(end_of_entries != 0)
      return IpsOption::NO_MATCH;

   // set max_filename_length based
   // on the unicode flag, vulnerability
   // is > 259 characters
   if((flags2 & 0x8000) == 0x8000)
      max_filename_length = 518;
   else
      max_filename_length = 259;

   for(unsigned i = 0; i < search_count; i++)
   {
      cursor_detect = cursor_normal;

      // check if we can:
      //  read next_entry_offset (4 bytes)
      //  skip (56 bytes)
      //  read filename_length   (4 bytes)
      if(cursor_detect + 64 > end_of_buffer)
         return IpsOption::NO_MATCH;

      next_entry_offset = read_little_32_inc(cursor_detect);

      DEBUG_SO(fprintf(stderr,"next_entry_offset=0x%08x\n",next_entry_offset);)

      cursor_detect += 56;

      filename_length = read_little_32_inc(cursor_detect);

      DEBUG_SO(fprintf(stderr,"filename_length=0x%08x\n",filename_length);)

      // check vulnerability condition
      if(filename_length > max_filename_length)
         return IpsOption::MATCH;

      // check if we can skip next_entry_offset
      if(next_entry_offset > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // skip next_entry_offset
      cursor_normal += next_entry_offset;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    FlowData_24973::init();
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

static const SoApi so_24973 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        9, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "24973", // name
        "NETBIOS SMB Trans2 FIND_FIRST2 response file name length overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_24973,
    rule_24973_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_24973 = &so_24973.base;

