//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// util_dns.h author Brandon Stultz <brastult@cisco.com>

#ifndef UTIL_DNS_H
#define UTIL_DNS_H

#include <cstdint>

inline bool skip_dns_name(const uint8_t*& cursor, const uint8_t* end)
{
    while ( true )
    {
        if ( cursor + 1 > end )
            return false;

        uint8_t b = *cursor++;

        if ( b == 0 )
            break;

        if ( (b & 0xC0) == 0xC0 )
        {
            cursor++;
            break;
        }

        cursor += b;
    }

    return true;
}

#endif

