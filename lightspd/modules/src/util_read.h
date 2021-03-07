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
// util_read.h author Brandon Stultz <brastult@cisco.com>

#ifndef UTIL_READ_H
#define UTIL_READ_H

#include <cstdint>

//--------------------------------------------------------------------------
// big-endian
//--------------------------------------------------------------------------

inline uint64_t read_big_64(const uint8_t* p)
{
    uint64_t v = 0;

    v  = ((uint64_t)*p++) << 56;
    v |= ((uint64_t)*p++) << 48;
    v |= ((uint64_t)*p++) << 40;
    v |= ((uint64_t)*p++) << 32;
    v |= ((uint64_t)*p++) << 24;
    v |= ((uint64_t)*p++) << 16;
    v |= ((uint64_t)*p++) << 8;
    v |= ((uint64_t)*p);

    return v;
}

inline uint32_t read_big_32(const uint8_t* p)
{
    uint32_t v = 0;

    v  = *p++ << 24;
    v |= *p++ << 16;
    v |= *p++ << 8;
    v |= *p;

    return v;
}

inline uint32_t read_big_24(const uint8_t* p)
{
    uint32_t v = 0;

    v  = *p++ << 16;
    v |= *p++ << 8;
    v |= *p;

    return v;
}

inline uint16_t read_big_16(const uint8_t* p)
{
    return (*p << 8) | *(p+1);
}

//--------------------------------------------------------------------------
// big-endian incrementing
//--------------------------------------------------------------------------

inline uint64_t read_big_64_inc(const uint8_t*& p)
{
    uint64_t v = read_big_64(p);
    p += 8;
    return v;
}

inline uint32_t read_big_32_inc(const uint8_t*& p)
{
    uint32_t v = read_big_32(p);
    p += 4;
    return v;
}

inline uint32_t read_big_24_inc(const uint8_t*& p)
{
    uint32_t v = read_big_24(p);
    p += 3;
    return v;
}

inline uint16_t read_big_16_inc(const uint8_t*& p)
{
    uint16_t v = read_big_16(p);
    p += 2;
    return v;
}

//--------------------------------------------------------------------------
// little-endian
//--------------------------------------------------------------------------

inline uint64_t read_little_64(const uint8_t* p)
{
    uint64_t v = 0;

    v  = ((uint64_t)*p++);
    v |= ((uint64_t)*p++) << 8;
    v |= ((uint64_t)*p++) << 16;
    v |= ((uint64_t)*p++) << 24;
    v |= ((uint64_t)*p++) << 32;
    v |= ((uint64_t)*p++) << 40;
    v |= ((uint64_t)*p++) << 48;
    v |= ((uint64_t)*p)   << 56;

    return v;
}

inline uint32_t read_little_32(const uint8_t* p)
{
    uint32_t v = 0;

    v  = *p++;
    v |= *p++ << 8;
    v |= *p++ << 16;
    v |= *p   << 24;

    return v;
}

inline uint32_t read_little_24(const uint8_t* p)
{
    uint32_t v = 0;

    v  = *p++;
    v |= *p++ << 8;
    v |= *p   << 16;

    return v;
}

inline uint16_t read_little_16(const uint8_t* p)
{
    return (*(p+1) << 8) | *p;
}

//--------------------------------------------------------------------------
// little-endian incrementing
//--------------------------------------------------------------------------

inline uint64_t read_little_64_inc(const uint8_t*& p)
{
    uint64_t v = read_little_64(p);
    p += 8;
    return v;
}

inline uint32_t read_little_32_inc(const uint8_t*& p)
{
    uint32_t v = read_little_32(p);
    p += 4;
    return v;
}

inline uint32_t read_little_24_inc(const uint8_t*& p)
{
    uint32_t v = read_little_24(p);
    p += 3;
    return v;
}

inline uint16_t read_little_16_inc(const uint8_t*& p)
{
    uint16_t v = read_little_16(p);
    p += 2;
    return v;
}

#endif

