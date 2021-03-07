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
// file-pdf_obfuscated-pdf-header.cc author Brandon Stultz <brastult@cisco.com>
//                                   author Patrick Mullen <pamullen@cisco.com>

#include "main/snort_types.h"
#include "framework/so_rule.h"
#include "framework/cursor.h"
#include "protocols/packet.h"

#include <cctype>  // isalnum()
#include <cstdlib> // strtoul()

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

using namespace snort;

static const char* rule_16343 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-PDF PDF header obfuscation attempt";
	soid:16343;
	file_type:PDF;
	file_data;
	content:"%PDF-",fast_pattern;
	content:"obj",nocase;
	content:"<<",within 4;
	content:!"/Type /Font",nocase,within 500;
	so:eval,relative;
	metadata:policy balanced-ips drop, policy max-detect-ips drop, policy security-ips drop;
	reference:url,www.adobe.com/devnet/acrobat/pdfs/PDF32000_2008.pdf;
	classtype:misc-activity;
	gid:3; sid:16343; rev:14;
)
)[Snort_SO_Rule]";

static const unsigned rule_16343_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
    const uint8_t *cursor_normal = c.start(),
                  *end_of_buffer = c.endo();

    bool hex_flag = false, ascii_flag = false;
    char escape_buf[3] = {};
    unsigned long escape_char;

    for(;cursor_normal < end_of_buffer; cursor_normal++)
    {
        // make sure we can read 3 bytes
        if(cursor_normal + 3 > end_of_buffer)
            return IpsOption::NO_MATCH;

        // check for end of object header
        // if found, search for new "obj <<" tag
        if((cursor_normal[0] == '>') && (cursor_normal[1] == '>'))
            break;

        if(cursor_normal[0] == '#')
        {
            // check for hex encoding
            escape_buf[0] = cursor_normal[1];
            escape_buf[1] = cursor_normal[2];
            cursor_normal += 2;
            escape_char = strtoul(escape_buf, NULL, 16);

            if(!isalnum(escape_char))
                continue;

            // if mixed with ascii encoding, alert
            if(ascii_flag)
                return IpsOption::MATCH;

            hex_flag = true;
        }
        else if(cursor_normal[0] == '(')
        {
            // skip binary data in obj tag
            cursor_normal++;
            for(;cursor_normal < end_of_buffer; cursor_normal++)
            {
                // if we find a close paren, check if it is escaped.
                // if not, we are at the end of the binary data.
                if(*cursor_normal == ')')
                    if(*(cursor_normal - 1) != '\\')
                        break;
            }
        }
        else
        {
            // check for ascii encoding
            if(isalnum(cursor_normal[0]))
            {
                // if mixed with hex encoding, alert
                if(hex_flag)
                    return IpsOption::MATCH;

                ascii_flag = true;
            }
        }
    }

    return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_16343 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        14, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "16343", // name
        "FILE-PDF PDF header obfuscation attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_16343,
    rule_16343_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_16343 = &so_16343.base;

