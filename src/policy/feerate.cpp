// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2009-2022 Blackcoin Core Developers
// Copyright (c) 2009-2022 Blackcoin More Developers
// Copyright (c) 2009-2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <policy/feerate.h>
#include <tinyformat.h>

#include <limits>

CFeeRate::CFeeRate(const CAmount& nFeePaid, uint32_t num_bytes)
{
    const int64_t nSize{num_bytes};

    if (nSize > 0) {
        // Split the calculation so a representable fee rate does not overflow
        // while scaling the fee. Saturate only when the mathematical result
        // itself cannot be represented by CAmount.
        constexpr CAmount SCALE{1000};
        const CAmount quotient{nFeePaid / nSize};
        const CAmount remainder{nFeePaid % nSize};
        const CAmount max{std::numeric_limits<CAmount>::max()};
        const CAmount min{std::numeric_limits<CAmount>::min()};

        if (quotient > max / SCALE) {
            nSatoshisPerK = max;
        } else if (quotient < min / SCALE) {
            nSatoshisPerK = min;
        } else {
            const CAmount whole{quotient * SCALE};
            const CAmount fractional{remainder * SCALE / nSize};
            if (fractional > 0 && whole > max - fractional) {
                nSatoshisPerK = max;
            } else if (fractional < 0 && whole < min - fractional) {
                nSatoshisPerK = min;
            } else {
                nSatoshisPerK = whole + fractional;
            }
        }
    } else {
        nSatoshisPerK = 0;
    }
}

CAmount CFeeRate::GetFee(uint32_t num_bytes) const
{
    const int64_t nSize{num_bytes};

    if (nSize == 0 || nSatoshisPerK == 0) return 0;

    // Split before multiplying so the intermediate product cannot overflow
    // when the final fee is representable. Preserve the historical rounding:
    // positive fractional satoshis round up, while negative values truncate
    // toward zero. Saturate only if the mathematical fee itself is outside
    // the range representable by CAmount.
    constexpr CAmount SCALE{1000};
    const CAmount quotient{nSatoshisPerK / SCALE};
    const CAmount remainder{nSatoshisPerK % SCALE};
    const CAmount max{std::numeric_limits<CAmount>::max()};
    const CAmount min{std::numeric_limits<CAmount>::min()};

    if (quotient > max / nSize) return max;
    if (quotient < min / nSize) return min;

    const CAmount whole{quotient * nSize};
    const CAmount remainder_product{remainder * nSize};
    CAmount fractional{remainder_product / SCALE};
    if (remainder_product > 0 && remainder_product % SCALE != 0) {
        ++fractional;
    }

    if (fractional > 0 && whole > max - fractional) return max;
    if (fractional < 0 && whole < min - fractional) return min;

    CAmount nFee{whole + fractional};

    if (nFee == 0 && nSize != 0) {
        if (nSatoshisPerK > 0) nFee = CAmount(1);
        if (nSatoshisPerK < 0) nFee = CAmount(-1);
    }

    return nFee;
}

std::string CFeeRate::ToString(const FeeEstimateMode& fee_estimate_mode) const
{
    switch (fee_estimate_mode) {
    case FeeEstimateMode::SAT_VB: return strprintf("%d.%03d %s/vB", nSatoshisPerK / 1000, nSatoshisPerK % 1000, CURRENCY_ATOM);
    default:                      return strprintf("%d.%08d %s/kvB", nSatoshisPerK / COIN, nSatoshisPerK % COIN, CURRENCY_UNIT);
    }
}
