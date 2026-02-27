// Copyright (c) 2014-2024, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "int-util.h"
#include "crypto/hash.h"
#include "cryptonote_config.h"
#include "difficulty.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "difficulty"

namespace cryptonote {

  using std::size_t;
  using std::uint64_t;
  using std::vector;

  const difficulty_type max64bit(std::numeric_limits<std::uint64_t>::max());
  const boost::multiprecision::uint256_t max128bit(std::numeric_limits<boost::multiprecision::uint128_t>::max());
  const boost::multiprecision::uint512_t max256bit(std::numeric_limits<boost::multiprecision::uint256_t>::max());

#define FORCE_FULL_128_BITS

  bool check_hash_128(const crypto::hash &hash, difficulty_type difficulty)
  {
#ifndef FORCE_FULL_128_BITS
    if (difficulty >= max64bit && ((const uint64_t *)&hash)[3] > 0)
      return false;
#endif

    boost::multiprecision::uint512_t hashVal = 0;

#ifdef FORCE_FULL_128_BITS
    for (int i = 0; i < 4; i++)
#else
    for (int i = 1; i < 4; i++)
#endif
    {
      hashVal <<= 64;
      hashVal |= swap64le(((const uint64_t *)&hash)[3 - i]);
    }

    return hashVal * difficulty <= max256bit;
  }

  bool check_hash(const crypto::hash &hash, difficulty_type difficulty)
  {
    if (difficulty <= max64bit)
      return check_hash_64(hash, difficulty.convert_to<std::uint64_t>());
    else
      return check_hash_128(hash, difficulty);
  }

  difficulty_type next_difficulty(std::vector<uint64_t> timestamps,
                                   std::vector<difficulty_type> cumulative_difficulties,
                                   size_t target_seconds)
  {
    size_t window = DIFFICULTY_WINDOW;
    size_t cut = DIFFICULTY_CUT;

    if (target_seconds == DIFFICULTY_TARGET_V2)
    {
      window = 45;
      cut = 4;
    }

    if (timestamps.size() > window)
    {
      timestamps.resize(window);
      cumulative_difficulties.resize(window);
    }

    size_t length = timestamps.size();
    if (length <= 1)
      return 1;

    std::sort(timestamps.begin(), timestamps.end());

    size_t cut_begin, cut_end;

    if (length <= window - 2 * cut)
    {
      cut_begin = 0;
      cut_end = length;
    }
    else
    {
      cut_begin = (length - (window - 2 * cut) + 1) / 2;
      cut_end = cut_begin + (window - 2 * cut);
    }

    uint64_t time_span = timestamps[cut_end - 1] - timestamps[cut_begin];
    if (time_span == 0)
      time_span = 1;

    difficulty_type total_work =
        cumulative_difficulties[cut_end - 1] -
        cumulative_difficulties[cut_begin];

    boost::multiprecision::uint256_t res =
        (boost::multiprecision::uint256_t(total_work) *
         target_seconds + time_span - 1) /
        time_span;

    return res.convert_to<difficulty_type>();
  }

  std::string hex(difficulty_type v)
  {
    static const char chars[] = "0123456789abcdef";
    std::string s;

    while (v > 0)
    {
      s.push_back(chars[(v & 0xf).convert_to<unsigned>()]);
      v >>= 4;
    }

    if (s.empty())
      s += "0";

    std::reverse(s.begin(), s.end());
    return "0x" + s;
  }

} // namespace cryptonote
