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
// netbios_smb-rap-read-access-violation.cc author Brandon Stultz <brastult@cisco.com>

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

static const char* rule_23847 = R"[Snort_SO_Rule](
alert tcp $EXTERNAL_NET [139,445] -> $HOME_NET any (
	msg:"NETBIOS MS-RAP NetServerEnum2 read access violation attempt";
	soid:23847;
	flow:to_client,established;
	content:"|FF|SMB|25 00 00 00 00|",offset 4,depth 9;
	content:"|EA 00|",distance 47,within 2;
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	service:netbios-ssn;
	reference:cve,2012-1850;
	reference:url,technet.microsoft.com/en-us/security/bulletin/MS12-054;
	classtype:attempted-admin;
	gid:3; sid:23847; rev:3;
)
)[Snort_SO_Rule]";

static const unsigned rule_23847_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *beg_of_buffer = c.buffer(),
                 *end_of_buffer = c.endo(),
                 *start_of_smb, *beg_of_servers;

   int16_t converter, server_comment,
           server_comment_position;

   uint32_t entries, netbios_message_length;

   // Beginning of 9-byte content match
   start_of_smb = beg_of_buffer + 4;

   netbios_message_length = read_big_16(beg_of_buffer + 2);

   // Verify we have data to read for mutiplier and start of servers field.
   // remember, we are after the |EA 00| match above for LANMAN protocol
   if((cursor_normal + 29) > end_of_buffer)
     return IpsOption::NO_MATCH;

   // Read in the mutiplier (called "Convert" in the protocol) we will use
   // this value later to calculate the indicated server comment position.
   converter = read_little_16_inc(cursor_normal);
   DEBUG_SO(fprintf(stderr,"converter: %d\n",converter);)

   // Account for default converter offset
   // observed in live MS-RAP traffic
   if(converter == 0)
      converter = 0x45;

   // Read in the server entry count.
   entries = read_little_16(cursor_normal);
   DEBUG_SO(fprintf(stderr,"number of entries: %d\n",entries);)

   // Store the position of the servers entry array. We will use
   // this later to calculate the indicated server comment position.
   // Note we do not increment cursor_normal because it turns out we are
   // perfectly lined up for reading what we need already.
   beg_of_servers = cursor_normal + 4;

   // Now we need to loop through each entry in the server entry array to check
   // for the vulnerability condition i.e. if the indicated server comment position
   // is beyond the SMB message length.

   // Limit the number of checks we'll do
   if(entries > 20)
      entries = 20;

   for(unsigned i = 0; i < entries; i++) {
     // Verify we have a server comment position (2 byte field) to read.
     if((cursor_normal + 27) > end_of_buffer)
        return IpsOption::NO_MATCH;

     DEBUG_SO(fprintf(stderr,"Entry: %d\n", i+1);)

     // Set the cursor to the server comment field.
     cursor_normal += 26; // each record is 26 bytes long.

     // Read the server comment base position.
     server_comment = read_little_16(cursor_normal);
     DEBUG_SO(fprintf(stderr, "server_comment: %d\n", server_comment);)

     // Calculate the server comment position relative
     // to the beginning of the server entry array.
     server_comment_position = server_comment - converter;

     // If the absolute server comment position
     // (beginning of servers array + relative server comment position)
     // is beyond the smb message length the
     // vulnerability condition has been met.
     if((beg_of_servers + server_comment_position) > (start_of_smb + netbios_message_length))
        return IpsOption::MATCH;
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_23847 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        3, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "23847", // name
        "NETBIOS MS-RAP NetServerEnum2 read access violation attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_23847,
    rule_23847_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_23847 = &so_23847.base;

