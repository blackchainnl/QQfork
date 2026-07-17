// Copyright (c) 2026 The Quantum Quasar developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <crypto/argon2_selftest.h>

#include <crypto/argon2/argon2.h>

#include <algorithm>
#include <array>
#include <cstdint>

bool Argon2idSelfTest()
{
    // RFC 9106, section 5.3: Argon2id v=19, t=3, m=32 KiB, p=4,
    // password=32*0x01, salt=16*0x02, secret=8*0x03, ad=12*0x04.
    std::array<uint8_t, 32> output{};
    std::array<uint8_t, 32> password{};
    std::array<uint8_t, 16> salt{};
    std::array<uint8_t, 8> secret{};
    std::array<uint8_t, 12> associated_data{};
    password.fill(0x01);
    salt.fill(0x02);
    secret.fill(0x03);
    associated_data.fill(0x04);

    argon2_context context{};
    context.out = output.data();
    context.outlen = output.size();
    context.pwd = password.data();
    context.pwdlen = password.size();
    context.salt = salt.data();
    context.saltlen = salt.size();
    context.secret = secret.data();
    context.secretlen = secret.size();
    context.ad = associated_data.data();
    context.adlen = associated_data.size();
    context.t_cost = 3;
    context.m_cost = 32;
    context.lanes = 4;
    context.threads = 4;
    context.version = ARGON2_VERSION_13;
    context.flags = ARGON2_DEFAULT_FLAGS;

    static constexpr std::array<uint8_t, 32> EXPECTED{
        0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c,
        0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
        0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e,
        0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59,
    };

    return argon2_ctx(&context, Argon2_id) == ARGON2_OK && output == EXPECTED;
}
