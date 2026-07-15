// Copyright (c) 2026 The Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERFACES_POW_MINING_H
#define BITCOIN_INTERFACES_POW_MINING_H

#include <cstdint>
#include <string_view>

namespace interfaces {

/** Bounded runtime state reported by the in-process Gold Rush PoW miner. */
enum class WalletPowMiningState : uint8_t {
    DISABLED,
    STARTING,
    CHAIN_UNAVAILABLE,
    WALLET_LOCKED_OR_STAKING_ONLY,
    NO_SPENDABLE_LEGACY_FEE_UTXO,
    EPOCH_INACTIVE,
    CLAIM_IN_FLIGHT,
    CLAIM_QUARANTINED,
    READY,
    HASHING,
    RUNTIME_ERROR,
};

constexpr std::string_view WalletPowMiningStateName(WalletPowMiningState state) noexcept
{
    switch (state) {
    case WalletPowMiningState::DISABLED: return "disabled";
    case WalletPowMiningState::STARTING: return "starting";
    case WalletPowMiningState::CHAIN_UNAVAILABLE: return "chain_unavailable";
    case WalletPowMiningState::WALLET_LOCKED_OR_STAKING_ONLY: return "wallet_locked_or_staking_only";
    case WalletPowMiningState::NO_SPENDABLE_LEGACY_FEE_UTXO: return "no_spendable_legacy_fee_utxo";
    case WalletPowMiningState::EPOCH_INACTIVE: return "epoch_inactive";
    case WalletPowMiningState::CLAIM_IN_FLIGHT: return "claim_in_flight";
    case WalletPowMiningState::CLAIM_QUARANTINED: return "claim_quarantined";
    case WalletPowMiningState::READY: return "ready";
    case WalletPowMiningState::HASHING: return "hashing";
    case WalletPowMiningState::RUNTIME_ERROR: return "error";
    }
    return "error";
}

} // namespace interfaces

#endif // BITCOIN_INTERFACES_POW_MINING_H
