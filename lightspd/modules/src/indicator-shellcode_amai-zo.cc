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
// indicator-shellcode_amai-zo.cc author Brandon Stultz <brastult@cisco.com>
//                                author Lurene Grenier <lurene.grenier@sourcefire.com>

#include "main/snort_types.h"
#include "framework/so_rule.h"
#include "framework/cursor.h"
#include "protocols/packet.h"
#include "util_read.h"

#include <cstring>

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

using namespace snort;

static const char* rule_17775 = R"[Snort_SO_Rule](
alert ip (
	msg:"INDICATOR-SHELLCODE Shikata Ga Nai x86 polymorphic shellcode decoder detected";
	soid:17775;
	content:"|D9 74 24 F4|";
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	service:dcerpc, ftp, imap, netbios-ssn, pop3;
	classtype:shellcode-detect;
	gid:3; sid:17775; rev:6;
)
)[Snort_SO_Rule]";

static const unsigned rule_17775_len = 0;

static const char* rule_40130 = R"[Snort_SO_Rule](
alert file (
	msg:"INDICATOR-SHELLCODE Shikata Ga Nai x86 polymorphic shellcode decoder detected";
	soid:40130;
	file_data;
	content:"|D9 74 24 F4|";
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	classtype:shellcode-detect;
	gid:3; sid:40130; rev:3;
)
)[Snort_SO_Rule]";

static const unsigned rule_40130_len = 0;

static const char* rule_33587 = R"[Snort_SO_Rule](
alert http (
	msg:"INDICATOR-SHELLCODE Shikata Ga Nai x86 polymorphic shellcode decoder detected";
	soid:33587;
	http_header;
	content:"|D9 74 24 F4|";
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	classtype:shellcode-detect;
	gid:3; sid:33587; rev:6;
)
)[Snort_SO_Rule]";

static const unsigned rule_33587_len = 0;

static const char* rule_49939 = R"[Snort_SO_Rule](
alert http (
	msg:"INDICATOR-SHELLCODE Shikata Ga Nai x86 polymorphic shellcode decoder detected";
	soid:49939;
	http_uri;
	content:"|D9 74 24 F4|";
	so:eval;
	metadata:policy max-detect-ips drop, policy security-ips drop;
	classtype:shellcode-detect;
	gid:3; sid:49939; rev:2;
)
)[Snort_SO_Rule]";

static const unsigned rule_49939_len = 0;

enum Status : uint8_t
{
   NONE           = 0x00,
   FPU            = 0x01,
   CLEAR_REGISTER = 0x02,
   INIT_KEY       = 0x04,
   FNSTENV        = 0x08,
   INIT_COUNTER   = 0x10,
   POP_EIP        = 0x20,
   LOOPBLOCK      = 0x40,
   LOOP_INST      = 0x80,
   COMPLETE       = 0xFF
};

enum Register : uint8_t
{
   EAX, EBX, ECX, EDX,
   ESI, EDI, EBP, ESP
};

class ShellcodeDetector
{
public:
   ShellcodeDetector(const Cursor& c)
   {
      reset();
      beg = c.buffer();
      cursor = c.start();
      end = c.endo();
   }

   bool found(const uint8_t* c);

private:
   void reset()
   {
      status = NONE;
      base = nullptr;
      end_offset = 27;
   }

   bool fpu();
   bool clear_register();
   bool init_key();
   bool fnstenv();
   bool init_counter();
   bool pop_eip();
   bool loopblock();
   bool loop_inst();

   // state machine
   uint8_t status;
   const uint8_t* base;
   unsigned end_offset;

   uint32_t xor_key;

   uint8_t key_register;
   uint8_t addr_register;
   unsigned fpu_offset;

   // cursor
   const uint8_t* beg;
   const uint8_t* cursor;
   const uint8_t* end;

   uint8_t buffer[48];
};

static inline bool check_fpu(uint8_t op0, uint8_t op1)
{
   if(op0 < 0xD9 || op0 > 0xDD || op0 == 0xDC)
      return false;

   if(op0 == 0xDA && op1 >= 0xC0 && op1 <= 0xDF)
      return true;

   if(op0 == 0xDB && op1 >= 0xC0 && op1 <= 0xDF)
      return true;

   if(op0 == 0xDD && op1 >= 0xC0 && op1 <= 0xC7)
      return true;

   if(op0 == 0xD9)
   {
      if(op1 >= 0xE8 && op1 <= 0xEE)
         return true;

      if(op1 >= 0xC0 && op1 <= 0xCF)
         return true;

      if(op1 == 0xD0 || op1 == 0xE1 ||
         op1 == 0xF6 || op1 == 0xF7 ||
         op1 == 0xE5)
         return true;
   }

   return false;
}

bool ShellcodeDetector::fpu()
{
   if(cursor + 2 > end)
      return false;

   uint8_t op0 = cursor[0],
           op1 = cursor[1];

   if(!check_fpu(op0, op1))
      return false;

   if(!base)
      base = cursor;

   fpu_offset = cursor - base;

   status |= FPU;

   // skip instruction
   cursor += 2;

   return true;
}

bool ShellcodeDetector::clear_register()
{
   if(cursor + 2 > end)
      return false;

   uint8_t op0 = cursor[0],
           op1 = cursor[1];

   if(op1 != 0xC9)
      return false;

   if(op0 == 0x31 || op0 == 0x29 ||
      op0 == 0x33 || op0 == 0x2B)
   {
      if(!base)
         base = cursor;

      status |= CLEAR_REGISTER;

      // skip instruction
      cursor += 2;

      return true;
   }

   return false;
}

bool ShellcodeDetector::init_key()
{
   if(cursor + 5 > end)
      return false;

   uint8_t op0 = cursor[0];

   if(op0 - 0xA1 == EAX)
   {
      key_register = EAX;
   }
   else
   {
      key_register = op0 - 0xB8;

      if(key_register > ESP)
         return false;
   }

   xor_key = read_little_32(cursor + 1);

   if(!base)
      base = cursor;

   status |= INIT_KEY;

   // skip instruction
   cursor += 5;

   return true;
}

bool ShellcodeDetector::fnstenv()
{
   if(cursor + 4 > end)
      return false;

   if(!(status & FPU))
      return false;

   if(read_little_32(cursor) != 0xF42474D9)
      return false;

   status |= FNSTENV;

   // skip instruction
   cursor += 4;

   return true;
}

bool ShellcodeDetector::init_counter()
{
   if(cursor + 2 > end)
      return false;

   if(!(status & CLEAR_REGISTER))
      return false;

   uint8_t op0 = cursor[0],
           op1 = cursor[1];

   if(op0 == 0xB1)
   {
      // skip instruction
      cursor += 2;
   }
   else if(op0 == 0x66 && op1 == 0xB9)
   {
      if(cursor + 4 > end)
         return false;

      // adjust end_offset
      end_offset += 2;

      // skip instruction
      cursor += 4;
   }
   else
   {
      return false;
   }

   status |= INIT_COUNTER;

   return true;
}

bool ShellcodeDetector::pop_eip()
{
   if(cursor + 1 > end)
      return false;

   if(!(status & FNSTENV))
      return false;

   addr_register = cursor[0] - 0x58;

   if(addr_register > ESP)
      return false;

   status |= POP_EIP;

   // skip instruction
   cursor += 1;

   return true;
}

bool ShellcodeDetector::loopblock()
{
   const uint8_t flags = (FPU | INIT_KEY | INIT_COUNTER | POP_EIP);

   uint8_t cutoff;
   uint16_t XOR, opcode16;
   uint32_t SUB, ADD, opcode32,
            encrypted, decrypted;

   uint8_t* decode_pos;

   if(cursor + 6 > end)
      return false;

   if((status & flags) != flags)
      return false;

   XOR  = 0x0031;
   XOR |= (0x40 + addr_register + (8 * key_register)) << 8;

   SUB  = 0x31FC0083;
   SUB |= (0xE8 + addr_register) << 8;

   ADD  = 0x31040083;
   ADD |= (0xC0 + addr_register) << 8;

   opcode16 = read_little_16(cursor);
   opcode32 = read_little_32(cursor);

   if(opcode16 == XOR)
   {
      cutoff = end_offset - fpu_offset - cursor[2];
   }
   else if(opcode32 == SUB || opcode32 == ADD)
   {
      cutoff = end_offset - fpu_offset - 4 - cursor[5];
   }
   else
   {
      return false;
   }

   // calculate decode_pos
   decode_pos = const_cast<uint8_t*>(base + end_offset - cutoff);

   // decode_pos must be valid
   if(decode_pos < beg || decode_pos + 4 > end)
      return false;

   encrypted = read_little_32(decode_pos);

   decrypted = encrypted ^ xor_key;

   decode_pos[0] = (decrypted & 0x000000FF);
   decode_pos[1] = (decrypted & 0x0000FF00) >> 8;
   decode_pos[2] = (decrypted & 0x00FF0000) >> 16;
   decode_pos[3] = (decrypted & 0xFF000000) >> 24;

   status |= LOOPBLOCK;

   // skip instruction
   cursor += 9;

   return true;
}

bool ShellcodeDetector::loop_inst()
{
   if(cursor + 2 > end)
      return false;

   if(!(status & LOOPBLOCK))
      return false;

   if(read_little_16(cursor) != 0xF5E2)
      return false;

   status |= LOOP_INST;

   // skip instruction
   cursor += 2;

   return true;
}

bool ShellcodeDetector::found(const uint8_t* c)
{
   cursor = c;

   // cursor must be valid
   if(cursor < beg || cursor + 48 > end)
      return false;

   memcpy(buffer, cursor, 48);

   beg = buffer;
   cursor = buffer;
   end = cursor + 48;

   while(cursor < end && status != COMPLETE)
   {
      if(!(status & FPU))
         if(fpu())
            continue;

      if(!(status & CLEAR_REGISTER))
         if(clear_register())
            continue;

      if(!(status & INIT_KEY))
         if(init_key())
            continue;

      if(!(status & FNSTENV))
         if(fnstenv())
            continue;

      if(!(status & INIT_COUNTER))
         if(init_counter())
            continue;

      if(!(status & POP_EIP))
         if(pop_eip())
            continue;

      if(!(status & LOOPBLOCK))
         if(loopblock())
            continue;

      if(!(status & LOOP_INST))
         if(loop_inst())
            continue;

      if(status == NONE || status == INIT_KEY)
      {
         reset();
         cursor += 1;
         continue;
      }

      return false;
   }

   if(status == COMPLETE)
      return true;

   return false;
}

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *beg_of_buffer = c.buffer(),
                 *cursor_normal = c.start();

   ShellcodeDetector sd(c);

   // start the ShikataGaNai detector
   // up to 21 bytes before FNSTENV
   if(cursor_normal >= beg_of_buffer + 21)
      cursor_normal -= 21;
   else
      cursor_normal = beg_of_buffer;

   // run the ShikataGaNai detector
   if(sd.found(cursor_normal))
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_17775 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        6, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "17775", // name
        "INDICATOR-SHELLCODE Shikata Ga Nai x86 polymorphic shellcode decoder detected", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_17775,
    rule_17775_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

static const SoApi so_40130 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        3, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "40130", // name
        "INDICATOR-SHELLCODE Shikata Ga Nai x86 polymorphic shellcode decoder detected", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_40130,
    rule_40130_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

static const SoApi so_33587 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        6, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "33587", // name
        "INDICATOR-SHELLCODE Shikata Ga Nai x86 polymorphic shellcode decoder detected", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_33587,
    rule_33587_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

static const SoApi so_49939 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        2, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "49939", // name
        "INDICATOR-SHELLCODE Shikata Ga Nai x86 polymorphic shellcode decoder detected", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_49939,
    rule_49939_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_17775 = &so_17775.base;
const BaseApi* pso_40130 = &so_40130.base;
const BaseApi* pso_33587 = &so_33587.base;
const BaseApi* pso_49939 = &so_49939.base;

