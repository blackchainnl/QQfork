// Copyright (c) 2021-2022 The Bitcoin Core developers
// Copyright (c) 2021-2022 Blackcoin Core Developers
// Copyright (c) 2021-2022 Blackcoin More Developers
// Copyright (c) 2021-2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/util.h>

#include <chain.h>
#include <key.h>
#include <key_io.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <validationinterface.h>
#include <wallet/context.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <memory>

namespace wallet {
std::unique_ptr<CWallet> CreateSyncedWallet(interfaces::Chain& chain, CChain& cchain, const CKey& key)
{
    auto wallet = std::make_unique<CWallet>(&chain, "", CreateMockableWalletDatabase());
    {
        LOCK2(::cs_main, wallet->cs_wallet);
        wallet->SetLastBlockProcessed(cchain.Height(), cchain.Tip()->GetBlockHash());
    }
    wallet->LoadWallet();
    {
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet->SetupDescriptorScriptPubKeyMans();

        FlatSigningProvider provider;
        std::string error;
        std::unique_ptr<Descriptor> desc = Parse("combo(" + EncodeSecret(key) + ")", provider, error, /* require_checksum=*/ false);
        assert(desc);
        WalletDescriptor w_desc(std::move(desc), 0, 0, 1, 1);
        if (!wallet->AddWalletDescriptor(w_desc, provider, "", false)) assert(false);
    }
    WalletRescanReserver reserver(*wallet);
    reserver.reserve();
    CWallet::ScanResult result = wallet->ScanForWalletTransactions(cchain.Genesis()->GetBlockHash(), /*start_height=*/0, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
    assert(result.status == CWallet::ScanResult::SUCCESS);
    assert(result.last_scanned_block == cchain.Tip()->GetBlockHash());
    assert(*result.last_scanned_height == cchain.Height());
    assert(result.last_failed_block.IsNull());
    return wallet;
}

std::shared_ptr<CWallet> TestLoadWallet(std::unique_ptr<WalletDatabase> database, WalletContext& context, uint64_t create_flags)
{
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto wallet = CWallet::Create(context, "", std::move(database), create_flags, error, warnings);
    NotifyWalletLoaded(context, wallet);
    if (context.chain) {
        wallet->postInitProcess();
    }
    return wallet;
}

std::shared_ptr<CWallet> TestLoadWallet(WalletContext& context)
{
    DatabaseOptions options;
    options.create_flags = WALLET_FLAG_DESCRIPTORS;
    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto database = MakeWalletDatabase("", options, status, error);
    return TestLoadWallet(std::move(database), context, options.create_flags);
}

void TestUnloadWallet(std::shared_ptr<CWallet>&& wallet)
{
    SyncWithValidationInterfaceQueue();
    wallet->m_chain_notifications_handler.reset();
    UnloadWallet(std::move(wallet));
}

std::unique_ptr<WalletDatabase> DuplicateMockDatabase(WalletDatabase& database)
{
    return std::make_unique<MockableDatabase>(dynamic_cast<MockableDatabase&>(database).m_records);
}

std::string getnewaddress(CWallet& w)
{
    constexpr auto output_type = OutputType::BECH32;
    return EncodeDestination(getNewDestination(w, output_type));
}

CTxDestination getNewDestination(CWallet& w, OutputType output_type)
{
    return *Assert(w.GetNewDestination(output_type, ""));
}

// BytePrefix compares equality with other byte spans that begin with the same prefix.
struct BytePrefix { Span<const std::byte> prefix; };
bool operator<(BytePrefix a, Span<const std::byte> b) { return a.prefix < b.subspan(0, std::min(a.prefix.size(), b.size())); }
bool operator<(Span<const std::byte> a, BytePrefix b) { return a.subspan(0, std::min(a.size(), b.prefix.size())) < b.prefix; }

MockableCursor::MockableCursor(const MockableData& records, bool pass, Span<const std::byte> prefix)
{
    m_pass = pass;
    std::tie(m_cursor, m_cursor_end) = records.equal_range(BytePrefix{prefix});
}

DatabaseCursor::Status MockableCursor::Next(DataStream& key, DataStream& value)
{
    if (!m_pass) {
        return Status::FAIL;
    }
    if (m_cursor == m_cursor_end) {
        return Status::DONE;
    }
    key.clear();
    value.clear();
    const auto& [key_data, value_data] = *m_cursor;
    key.write(key_data);
    value.write(value_data);
    m_cursor++;
    return Status::MORE;
}

bool MockableBatch::ReadKey(DataStream&& key, DataStream& value)
{
    if (!m_database.m_pass) {
        return false;
    }
    SerializeData key_data{key.begin(), key.end()};
    const auto& records = Records();
    const auto& it = records.find(key_data);
    if (it == records.end()) {
        return false;
    }
    value.clear();
    value.write(it->second);
    return true;
}

bool MockableBatch::WriteKey(DataStream&& key, DataStream&& value, bool overwrite)
{
    if (ShouldFailWrite()) {
        return false;
    }
    SerializeData key_data{key.begin(), key.end()};
    SerializeData value_data{value.begin(), value.end()};
    auto& records = Records();
    auto [it, inserted] = records.emplace(key_data, value_data);
    if (!inserted && overwrite) { // Overwrite if requested
        it->second = value_data;
        inserted = true;
    }
    return inserted;
}

bool MockableBatch::EraseKey(DataStream&& key)
{
    if (ShouldFailWrite()) {
        return false;
    }
    SerializeData key_data{key.begin(), key.end()};
    Records().erase(key_data);
    return true;
}

bool MockableBatch::HasKey(DataStream&& key)
{
    if (!m_database.m_pass) {
        return false;
    }
    SerializeData key_data{key.begin(), key.end()};
    return Records().count(key_data) > 0;
}

bool MockableBatch::ErasePrefix(Span<const std::byte> prefix)
{
    if (ShouldFailWrite()) {
        return false;
    }
    auto& records = Records();
    auto it = records.begin();
    while (it != records.end()) {
        auto& key = it->first;
        if (key.size() < prefix.size() || std::search(key.begin(), key.end(), prefix.begin(), prefix.end()) != key.begin()) {
            it++;
            continue;
        }
        it = records.erase(it);
    }
    return true;
}

MockableData& MockableBatch::Records()
{
    return m_transaction_records ? *m_transaction_records : m_database.m_records;
}

const MockableData& MockableBatch::Records() const
{
    return m_transaction_records ? *m_transaction_records : m_database.m_records;
}

bool MockableBatch::ShouldFailWrite()
{
    if (!m_database.m_pass) return true;
    const size_t write_index = m_database.m_write_calls++;
    return m_database.m_fail_write_at && write_index == *m_database.m_fail_write_at;
}

std::unique_ptr<DatabaseCursor> MockableBatch::GetNewCursor()
{
    return std::make_unique<MockableCursor>(Records(), m_database.m_pass);
}

std::unique_ptr<DatabaseCursor> MockableBatch::GetNewPrefixCursor(Span<const std::byte> prefix)
{
    return std::make_unique<MockableCursor>(Records(), m_database.m_pass, prefix);
}

bool MockableBatch::TxnBegin(bool durable)
{
    if (!m_database.m_pass || m_database.m_fail_begin || m_transaction_records) return false;
    m_database.m_write_calls = 0;
    m_database.m_last_txn_durable = durable;
    m_transaction_records = m_database.m_records;
    return true;
}

bool MockableBatch::TxnCommit()
{
    if (!m_database.m_pass || !m_transaction_records || m_database.m_fail_commit) return false;
    m_database.m_records = std::move(*m_transaction_records);
    m_transaction_records.reset();
    return true;
}

bool MockableBatch::TxnAbort()
{
    if (!m_transaction_records) return false;
    m_transaction_records.reset();
    return m_database.m_pass;
}

std::unique_ptr<WalletDatabase> CreateMockableWalletDatabase(MockableData records)
{
    return std::make_unique<MockableDatabase>(records);
}

MockableDatabase& GetMockableDatabase(CWallet& wallet)
{
    return dynamic_cast<MockableDatabase&>(wallet.GetDatabase());
}
} // namespace wallet
