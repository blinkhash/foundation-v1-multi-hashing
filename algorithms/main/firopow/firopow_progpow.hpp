// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

/// @file
///
/// ProgPoW API
///
/// This file provides the public API for ProgPoW as the Ethash API extension.

#include "firopow.hpp"

namespace firopow_progpow
{
using namespace firopow_main;  // Include firopow_main namespace.

/// The ProgPoW algorithm revision implemented as specified in the spec
/// https://github.com/ifdefelse/ProgPOW.
constexpr auto revision = "0.9.4";

constexpr int period_length = 1;
constexpr uint32_t num_regs = 32;
constexpr size_t num_lanes = 16;
constexpr uint32_t num_rounds = 64;
constexpr int num_cache_accesses = 11;
constexpr int num_math_operations = 18;
constexpr size_t l1_cache_size = 16 * 1024;
constexpr size_t l1_cache_num_items = l1_cache_size / sizeof(uint32_t);

void hash_one(const epoch_context& context, int block_number, const ethash::hash256 *header_hash,
    uint64_t nonce, ethash::hash256 *mix_out_ptr, ethash::hash256 *hash_out_ptr) noexcept;

bool verify(const epoch_context& context, int block_number, const ethash::hash256 *header_hash,
    const ethash::hash256 &mix_hash, uint64_t nonce, ethash::hash256 *hash_out) noexcept;

}  // namespace firopow_progpow
