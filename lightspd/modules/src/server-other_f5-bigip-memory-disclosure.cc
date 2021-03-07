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
// server-other_f5-bigip-memory-disclosure.cc author Brandon Stultz <brastult@cisco.com>

#include "main/snort_types.h"
#include "framework/so_rule.h"
#include "framework/cursor.h"
#include "protocols/packet.h"
#include "flow/flow.h"
#include "util_read.h"

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

// tls handshake types
#define HS_CLIENT_HELLO 1 // client hello
#define HS_SERVER_HELLO 2 // server hello

using namespace snort;

static const char* rule_41548 = R"[Snort_SO_Rule](
alert ssl (
	msg:"SERVER-OTHER F5 BIG-IP TLS session ticket implementation uninitialized memory disclosure attempt";
	soid:41548;
	flow:established;
	ssl_state:client_hello,server_hello;
	content:"|16 03|",depth 2;
	so:eval;
	metadata:policy balanced-ips drop, policy max-detect-ips drop, policy security-ips drop;
	service:ssl;
	reference:cve,2016-9244;
	reference:url,support.f5.com/csp/article/K05121675;
	classtype:attempted-recon;
	gid:3; sid:41548; rev:3;
)
)[Snort_SO_Rule]";

static const unsigned rule_41548_len = 0;

#if(BASE_API_VERSION > 1)

struct tls_record {
   uint16_t version;        // tls record version
   uint8_t  hs_type;        // tls handshake type
   uint16_t hs_version;     // tls handshake version
   uint8_t  session_id_len; // tls session id length
   uint8_t  session_id_msb; // tls session id msb
};

struct tls_session_data {
   uint8_t id_len; // session id length
   uint8_t id_msb; // session id msb 
};

class FlowData_41548 : public RuleFlowData
{
public:
   FlowData_41548() : RuleFlowData(id) { }

   static void init()
   { id = FlowData::create_flow_data_id(); }

   size_t size_of() override
   { return sizeof(*this); }

public:
   static unsigned id;
   tls_session_data ssn_data = {};
};

unsigned FlowData_41548::id = 0;

static bool isTlsVersion(uint16_t version)
{
   switch(version) {
   case 0x0300: // SSLv3
   case 0x0301: // TLSv1.0
   case 0x0302: // TLSv1.1
   case 0x0303: // TLSv1.2
      return true;
   }

   // unknown tls version
   return false;
}

static IpsOption::EvalStatus checkClientHello(tls_record& record, Packet* p) {
   // get the FlowData for this flow
   FlowData_41548* fd =
      (FlowData_41548*)p->flow->get_flow_data(FlowData_41548::id);

   // initalize and set the FlowData if it does not exist
   if(!fd)
   {
      fd = new FlowData_41548();
      p->flow->set_flow_data(fd);
   }

   // store session id_len and id_msb in FlowData for future checks
   fd->ssn_data.id_len = record.session_id_len;
   fd->ssn_data.id_msb = record.session_id_msb;

   return IpsOption::NO_MATCH;
}

static IpsOption::EvalStatus checkServerHello(tls_record& record, Packet* p) {
   // F5 BIG-IP always sets session_id_len to 32
   if(record.session_id_len != 32)
      return IpsOption::NO_MATCH;

   // get the FlowData for this flow
   FlowData_41548* fd =
      (FlowData_41548*)p->flow->get_flow_data(FlowData_41548::id);

   // if no FlowData, server is defining a new session, bail.
   if(!fd)
   {
      DEBUG_SO(fprintf(stderr,"no FlowData, server defining new session, bailing.\n");)
      return IpsOption::NO_MATCH;
   }

   DEBUG_SO(fprintf(stderr,"fd->ssn_data.id_len   = %d\n",fd->ssn_data.id_len);)
   DEBUG_SO(fprintf(stderr,"record.session_id_len = %d\n",record.session_id_len);)
   DEBUG_SO(fprintf(stderr,"fd->ssn_data.id_msb   = %02X\n",fd->ssn_data.id_msb);)
   DEBUG_SO(fprintf(stderr,"record.session_id_msb = %02X\n\n",record.session_id_msb);)

   // server is resuming a previous session, check vuln condition.
   if(fd->ssn_data.id_len < record.session_id_len)
      if(fd->ssn_data.id_msb == record.session_id_msb)
         return IpsOption::MATCH;
 
   return IpsOption::NO_MATCH;
}

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.buffer(),
                 *end_of_buffer = c.endo();

   tls_record record = {};

   if ( !p->flow )
      return IpsOption::NO_MATCH;

   // TLS record:
   //   type    (1 byte)
   //   version (2 bytes)
   //   length  (2 bytes)
   //   Handshake Protocol record:
   //     handshake type    (1 byte)
   //     length            (3 bytes)
   //     version           (2 bytes)
   //     random            (32 bytes)
   //     session id_len    (1 byte)
   //     session id_msb    (1 byte)
   if(cursor_normal + 45 > end_of_buffer)
      return IpsOption::NO_MATCH;

   record.session_id_len = *(cursor_normal+43);

   // if it is an initial session (id_len == 0) (true in most cases)
   // or vuln impossible (id_len > 32), bail.
   if(record.session_id_len == 0 || record.session_id_len > 32)
      return IpsOption::NO_MATCH;

   record.version    = read_big_16(cursor_normal+1); 
   record.hs_type    = *(cursor_normal+5);
   record.hs_version = read_big_16(cursor_normal+9);
   record.session_id_msb = *(cursor_normal+44);

   // check tls version fields
   if(!isTlsVersion(record.version))
      return IpsOption::NO_MATCH;

   if(!isTlsVersion(record.hs_version))
      return IpsOption::NO_MATCH;

   switch(record.hs_type) {
   case HS_CLIENT_HELLO:
      return checkClientHello(record, p);
   case HS_SERVER_HELLO:
      return checkServerHello(record, p);
   }

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    FlowData_41548::init();
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

static const SoApi so_41548 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        3, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "41548", // name
        "SERVER-OTHER F5 BIG-IP TLS session ticket implementation uninitialized memory disclosure attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_41548,
    rule_41548_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_41548 = &so_41548.base;

