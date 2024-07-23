// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <crypto/muhash.h>
#include <index/coinstatsindex.h>
#include <kernel/coinstats.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <serialize.h>
#include <txdb.h>
#include <undo.h>
#include <validation.h>

using kernel::ApplyCoinHash;
using kernel::CCoinsStats;
using kernel::GetBogoSize;
using kernel::RemoveCoinHash;

static constexpr uint8_t DB_BLOCK_HASH{'s'};
static constexpr uint8_t DB_BLOCK_HEIGHT{'t'};
static constexpr uint8_t DB_MUHASH{'M'};
static constexpr uint8_t DB_VERSION{'V'};

namespace {

struct DBVal {
    uint256 muhash;
    uint64_t transaction_output_count;
    uint64_t bogo_size;
    CAmount total_amount;
    CAmount block_subsidy;
    CAmount total_unspendable_amount;
    CAmount block_prevout_spent_amount;
    CAmount block_new_outputs_ex_coinbase_amount;
    CAmount block_coinbase_amount;

    CAmount block_unspendables_genesis_block;
    CAmount block_unspendables_bip30;
    CAmount block_unspendables_scripts;
    CAmount block_unspendables_unclaimed_rewards;

    SERIALIZE_METHODS(DBVal, obj)
    {
        READWRITE(obj.muhash);
        READWRITE(obj.transaction_output_count);
        READWRITE(obj.bogo_size);
        READWRITE(obj.total_amount);
        READWRITE(obj.block_subsidy);
        READWRITE(obj.total_unspendable_amount);
        READWRITE(obj.block_prevout_spent_amount);
        READWRITE(obj.block_new_outputs_ex_coinbase_amount);
        READWRITE(obj.block_coinbase_amount);
        READWRITE(obj.block_unspendables_genesis_block);
        READWRITE(obj.block_unspendables_bip30);
        READWRITE(obj.block_unspendables_scripts);
        READWRITE(obj.block_unspendables_unclaimed_rewards);
    }
};

struct DBHeightKey {
    int height;

    explicit DBHeightKey(int height_in) : height(height_in) {}

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_BLOCK_HEIGHT);
        ser_writedata32be(s, height);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const uint8_t prefix{ser_readdata8(s)};
        if (prefix != DB_BLOCK_HEIGHT) {
            throw std::ios_base::failure("Invalid format for coinstatsindex DB height key");
        }
        height = ser_readdata32be(s);
    }
};

struct DBHashKey {
    uint256 block_hash;

    explicit DBHashKey(const uint256& hash_in) : block_hash(hash_in) {}

    SERIALIZE_METHODS(DBHashKey, obj)
    {
        uint8_t prefix{DB_BLOCK_HASH};
        READWRITE(prefix);
        if (prefix != DB_BLOCK_HASH) {
            throw std::ios_base::failure("Invalid format for coinstatsindex DB hash key");
        }

        READWRITE(obj.block_hash);
    }
};

}; // namespace

std::unique_ptr<CoinStatsIndex> g_coin_stats_index;

CoinStatsIndex::CoinStatsIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory, bool f_wipe)
    : BaseIndex(std::move(chain), "coinstatsindex")
{
    fs::path path{gArgs.GetDataDirNet() / "indexes" / "coinstats"};
    fs::create_directories(path);

    m_db = std::make_unique<CoinStatsIndex::DB>(path / "db", n_cache_size, f_memory, f_wipe);
}

bool CoinStatsIndex::CustomAppend(const interfaces::BlockInfo& block)
{
    CAmount block_unspendable{0};
    CBlockUndo block_undo{};

    m_block_prevout_spent_amount = 0;
    m_block_new_outputs_ex_coinbase_amount = 0;
    m_block_coinbase_amount = 0;
    m_block_subsidy = GetBlockSubsidy(block.height, Params().GetConsensus());

    m_block_unspendables_genesis_block = 0;
    m_block_unspendables_bip30 = 0;
    m_block_unspendables_scripts = 0;
    m_block_unspendables_unclaimed_rewards = 0;

    // Ignore genesis block
    if (block.height > 0) {
        // pindex variable gives indexing code access to node internals. It
        // will be removed in upcoming commit
        const CBlockIndex* pindex = WITH_LOCK(cs_main, return m_chainstate->m_blockman.LookupBlockIndex(block.hash));
        if (!m_chainstate->m_blockman.UndoReadFromDisk(block_undo, *pindex)) {
            return false;
        }

        std::pair<uint256, DBVal> read_out;
        if (!m_db->Read(DBHeightKey(block.height - 1), read_out)) {
            return false;
        }

        uint256 expected_block_hash{*Assert(block.prev_hash)};
        if (read_out.first != expected_block_hash) {
            LogPrintf("WARNING: previous block header belongs to unexpected block %s; expected %s\n",
                      read_out.first.ToString(), expected_block_hash.ToString());

            if (!m_db->Read(DBHashKey(expected_block_hash), read_out)) {
                LogError("%s: previous block header not found; expected %s\n",
                             __func__, expected_block_hash.ToString());
                return false;
            }
        }

        // Add the new utxos created from the block
        assert(block.data);
        for (size_t i = 0; i < block.data->vtx.size(); ++i) {
            const auto& tx{block.data->vtx.at(i)};

            // Skip duplicate txid coinbase transactions (BIP30).
            if (IsBIP30Unspendable(*pindex) && tx->IsCoinBase()) {
                block_unspendable += m_block_subsidy;
                m_block_unspendables_bip30 += m_block_subsidy;
                continue;
            }

            for (uint32_t j = 0; j < tx->vout.size(); ++j) {
                const CTxOut& out{tx->vout[j]};
                Coin coin{out, block.height, tx->IsCoinBase()};
                COutPoint outpoint{tx->GetHash(), j};

                // Skip unspendable coins
                if (coin.out.scriptPubKey.IsUnspendable()) {
                    block_unspendable += coin.out.nValue;
                    m_block_unspendables_scripts += coin.out.nValue;
                    continue;
                }

                ApplyCoinHash(m_muhash, outpoint, coin);

                if (tx->IsCoinBase()) {
                    m_block_coinbase_amount += coin.out.nValue;
                } else {
                    m_block_new_outputs_ex_coinbase_amount += coin.out.nValue;
                }

                ++m_transaction_output_count;
                m_total_amount += coin.out.nValue;
                m_bogo_size += GetBogoSize(coin.out.scriptPubKey);
            }

            // The coinbase tx has no undo data since no former output is spent
            if (!tx->IsCoinBase()) {
                const auto& tx_undo{block_undo.vtxundo.at(i - 1)};

                for (size_t j = 0; j < tx_undo.vprevout.size(); ++j) {
                    Coin coin{tx_undo.vprevout[j]};
                    COutPoint outpoint{tx->vin[j].prevout.hash, tx->vin[j].prevout.n};

                    RemoveCoinHash(m_muhash, outpoint, coin);

                    m_block_prevout_spent_amount += coin.out.nValue;

                    --m_transaction_output_count;
                    m_total_amount -= coin.out.nValue;
                    m_bogo_size -= GetBogoSize(coin.out.scriptPubKey);
                }
            }
        }
    } else {
        // genesis block
        block_unspendable += m_block_subsidy;
        m_block_unspendables_genesis_block += m_block_subsidy;
    }

    // If spent prevouts + block subsidy are still a higher amount than
    // new outputs + coinbase + current unspendable amount this means
    // the miner did not claim the full block reward. Unclaimed block
    // rewards are also unspendable.
    m_block_unspendables_unclaimed_rewards = (m_block_prevout_spent_amount + m_block_subsidy) - (m_block_new_outputs_ex_coinbase_amount + m_block_coinbase_amount + block_unspendable);
    m_total_unspendable_amount += (m_block_unspendables_unclaimed_rewards + block_unspendable);

    std::pair<uint256, DBVal> value;
    value.first = block.hash;
    value.second.transaction_output_count = m_transaction_output_count;
    value.second.bogo_size = m_bogo_size;
    value.second.total_amount = m_total_amount;
    value.second.total_unspendable_amount = m_total_unspendable_amount;

    value.second.block_subsidy = m_block_subsidy;
    value.second.block_prevout_spent_amount = m_block_prevout_spent_amount;
    value.second.block_new_outputs_ex_coinbase_amount = m_block_new_outputs_ex_coinbase_amount;
    value.second.block_coinbase_amount = m_block_coinbase_amount;

    value.second.block_unspendables_genesis_block = m_block_unspendables_genesis_block;
    value.second.block_unspendables_bip30 = m_block_unspendables_bip30;
    value.second.block_unspendables_scripts = m_block_unspendables_scripts;
    value.second.block_unspendables_unclaimed_rewards = m_block_unspendables_unclaimed_rewards;

    uint256 out;
    m_muhash.Finalize(out);
    value.second.muhash = out;

    // Intentionally do not update DB_MUHASH here so it stays in sync with
    // DB_BEST_BLOCK, and the index is not corrupted if there is an unclean shutdown.
    return m_db->Write(DBHeightKey(block.height), value);
}

[[nodiscard]] static bool CopyHeightIndexToHashIndex(CDBIterator& db_it, CDBBatch& batch,
                                       const std::string& index_name,
                                       int start_height, int stop_height)
{
    DBHeightKey key{start_height};
    db_it.Seek(key);

    for (int height = start_height; height <= stop_height; ++height) {
        if (!db_it.GetKey(key) || key.height != height) {
            LogError("%s: unexpected key in %s: expected (%c, %d)\n",
                         __func__, index_name, DB_BLOCK_HEIGHT, height);
            return false;
        }

        std::pair<uint256, DBVal> value;
        if (!db_it.GetValue(value)) {
            LogError("%s: unable to read value in %s at key (%c, %d)\n",
                         __func__, index_name, DB_BLOCK_HEIGHT, height);
            return false;
        }

        batch.Write(DBHashKey(value.first), std::move(value.second));

        db_it.Next();
    }
    return true;
}

bool CoinStatsIndex::CustomRewind(const interfaces::BlockKey& current_tip, const interfaces::BlockKey& new_tip)
{
    CDBBatch batch(*m_db);
    std::unique_ptr<CDBIterator> db_it(m_db->NewIterator());

    // During a reorg, we need to copy all hash digests for blocks that are
    // getting disconnected from the height index to the hash index so we can
    // still find them when the height index entries are overwritten.
    if (!CopyHeightIndexToHashIndex(*db_it, batch, m_name, new_tip.height, current_tip.height)) {
        return false;
    }

    if (!m_db->WriteBatch(batch)) return false;

    {
        LOCK(cs_main);
        const CBlockIndex* iter_tip{m_chainstate->m_blockman.LookupBlockIndex(current_tip.hash)};
        const CBlockIndex* new_tip_index{m_chainstate->m_blockman.LookupBlockIndex(new_tip.hash)};

        do {
            CBlock block;

            if (!m_chainstate->m_blockman.ReadBlockFromDisk(block, *iter_tip)) {
                LogError("%s: Failed to read block %s from disk\n",
                             __func__, iter_tip->GetBlockHash().ToString());
                return false;
            }

            if (!ReverseBlock(block, iter_tip)) {
                return false; // failure cause logged internally
            }

            iter_tip = iter_tip->GetAncestor(iter_tip->nHeight - 1);
        } while (new_tip_index != iter_tip);
    }

    return true;
}

static bool LookUpOne(const CDBWrapper& db, const interfaces::BlockKey& block, DBVal& result)
{
    // First check if the result is stored under the height index and the value
    // there matches the block hash. This should be the case if the block is on
    // the active chain.
    std::pair<uint256, DBVal> read_out;
    if (!db.Read(DBHeightKey(block.height), read_out)) {
        return false;
    }
    if (read_out.first == block.hash) {
        result = std::move(read_out.second);
        return true;
    }

    // If value at the height index corresponds to an different block, the
    // result will be stored in the hash index.
    return db.Read(DBHashKey(block.hash), result);
}

std::optional<CCoinsStats> CoinStatsIndex::LookUpStats(const CBlockIndex& block_index) const
{
    CCoinsStats stats{block_index.nHeight, block_index.GetBlockHash()};
    stats.index_used = true;

    DBVal entry;
    if (!LookUpOne(*m_db, {block_index.GetBlockHash(), block_index.nHeight}, entry)) {
        return std::nullopt;
    }

    stats.hashSerialized = entry.muhash;
    stats.nTransactionOutputs = entry.transaction_output_count;
    stats.nBogoSize = entry.bogo_size;
    stats.total_amount = entry.total_amount;
    stats.total_unspendable_amount = entry.total_unspendable_amount;

    stats.block_subsidy = entry.block_subsidy;
    stats.block_prevout_spent_amount = entry.block_prevout_spent_amount;
    stats.block_new_outputs_ex_coinbase_amount = entry.block_new_outputs_ex_coinbase_amount;
    stats.block_coinbase_amount = entry.block_coinbase_amount;

    stats.block_unspendables_genesis_block = entry.block_unspendables_genesis_block;
    stats.block_unspendables_bip30 = entry.block_unspendables_bip30;
    stats.block_unspendables_scripts = entry.block_unspendables_scripts;
    stats.block_unspendables_unclaimed_rewards = entry.block_unspendables_unclaimed_rewards;

    return stats;
}

bool CoinStatsIndex::CustomInit(const std::optional<interfaces::BlockKey>& block)
{
    uint32_t code_version{GetVersion()};
    uint32_t db_version{0};
    // We are starting the index for the first time and write version first so
    // we don't run into the version check later.
    if (!block.has_value() && !m_db->Exists(DB_VERSION)) {
        m_db->Write(DB_VERSION, code_version);
        db_version = code_version;
    }

    // If we can't read a version this means the index has never been updated
    // and needs to be reset now. Otherwise request a reset if we have a
    // version mismatch.
    if (m_db->Exists(DB_VERSION)) {
        m_db->Read(DB_VERSION, db_version);
    }
    if (db_version == 0 && code_version == 1) {
        // Attempt to migrate coinstatsindex without the need to reindex
        if (!MigrateToV1()) {
            LogError("Error while migrating coinstatsindex to v1. In order to rebuild the index, remove the indexes/coinstats directory in your datadir\n");
            return false;
        };
    } else if (db_version != code_version) {
        LogError("%s version mismatch: expected %s but %s was found. In order to rebuild the index, remove the indexes/coinstats directory in your datadir\n",
                     GetName(), code_version, db_version);
        return false;
    }

    if (!m_db->Read(DB_MUHASH, m_muhash)) {
        // Check that the cause of the read failure is that the key does not
        // exist. Any other errors indicate database corruption or a disk
        // failure, and starting the index would cause further corruption.
        if (m_db->Exists(DB_MUHASH)) {
            LogError("%s: Cannot read current %s state; index may be corrupted\n",
                         __func__, GetName());
            return false;
        }
    }

    if (block) {
        DBVal entry;
        if (!LookUpOne(*m_db, *block, entry)) {
            LogError("%s: Cannot read current %s state; index may be corrupted\n",
                         __func__, GetName());
            return false;
        }

        uint256 out;
        m_muhash.Finalize(out);
        if (entry.muhash != out) {
            LogError("%s: Cannot read current %s state; index may be corrupted\n",
                         __func__, GetName());
            return false;
        }

        m_transaction_output_count = entry.transaction_output_count;
        m_bogo_size = entry.bogo_size;
        m_total_amount = entry.total_amount;
        m_total_unspendable_amount = entry.total_unspendable_amount;

        m_block_subsidy = entry.block_subsidy;
        m_block_prevout_spent_amount = entry.block_prevout_spent_amount;
        m_block_new_outputs_ex_coinbase_amount = entry.block_new_outputs_ex_coinbase_amount;
        m_block_coinbase_amount = entry.block_coinbase_amount;

        m_block_unspendables_genesis_block = entry.block_unspendables_genesis_block;
        m_block_unspendables_bip30 = entry.block_unspendables_bip30;
        m_block_unspendables_scripts = entry.block_unspendables_scripts;
        m_block_unspendables_unclaimed_rewards = entry.block_unspendables_unclaimed_rewards;
    }

    return true;
}

bool CoinStatsIndex::CustomCommit(CDBBatch& batch)
{
    // DB_MUHASH should always be committed in a batch together with DB_BEST_BLOCK
    // to prevent an inconsistent state of the DB.
    batch.Write(DB_MUHASH, m_muhash);
    return true;
}

// Reverse a single block as part of a reorg
bool CoinStatsIndex::ReverseBlock(const CBlock& block, const CBlockIndex* pindex)
{
    CBlockUndo block_undo;
    std::pair<uint256, DBVal> read_out;

    // Ignore genesis block
    if (pindex->nHeight > 0) {
        if (!m_chainstate->m_blockman.UndoReadFromDisk(block_undo, *pindex)) {
            return false;
        }

        if (!m_db->Read(DBHeightKey(pindex->nHeight - 1), read_out)) {
            return false;
        }

        uint256 expected_block_hash{pindex->pprev->GetBlockHash()};
        if (read_out.first != expected_block_hash) {
            LogPrintf("WARNING: previous block header belongs to unexpected block %s; expected %s\n",
                      read_out.first.ToString(), expected_block_hash.ToString());

            if (!m_db->Read(DBHashKey(expected_block_hash), read_out)) {
                LogError("%s: previous block header not found; expected %s\n",
                             __func__, expected_block_hash.ToString());
                return false;
            }
        }
    }

    // Remove the new UTXOs that were created from the block
    for (size_t i = 0; i < block.vtx.size(); ++i) {
        const auto& tx{block.vtx.at(i)};

        for (uint32_t j = 0; j < tx->vout.size(); ++j) {
            const CTxOut& out{tx->vout[j]};
            COutPoint outpoint{tx->GetHash(), j};
            Coin coin{out, pindex->nHeight, tx->IsCoinBase()};

            // Skip unspendable coins
            if (coin.out.scriptPubKey.IsUnspendable()) {
                m_total_unspendable_amount -= coin.out.nValue;
                continue;
            }

            RemoveCoinHash(m_muhash, outpoint, coin);

            --m_transaction_output_count;
            m_total_amount -= coin.out.nValue;
            m_bogo_size -= GetBogoSize(coin.out.scriptPubKey);
        }

        // The coinbase tx has no undo data since no former output is spent
        if (!tx->IsCoinBase()) {
            const auto& tx_undo{block_undo.vtxundo.at(i - 1)};

            for (size_t j = 0; j < tx_undo.vprevout.size(); ++j) {
                Coin coin{tx_undo.vprevout[j]};
                COutPoint outpoint{tx->vin[j].prevout.hash, tx->vin[j].prevout.n};

                ApplyCoinHash(m_muhash, outpoint, coin);

                m_transaction_output_count++;
                m_total_amount += coin.out.nValue;
                m_bogo_size += GetBogoSize(coin.out.scriptPubKey);
            }
        }
    }

    // Check that the rolled back internal values are consistent with the DB
    // read out where possible, i.e. when total historical values are tracked.
    // Otherwise just read the values from the index entry.
    uint256 out;
    m_muhash.Finalize(out);
    Assert(read_out.second.muhash == out);

    Assert(m_total_amount == read_out.second.total_amount);
    m_total_unspendable_amount -= m_block_unspendables_unclaimed_rewards;
    Assert(m_total_unspendable_amount == read_out.second.total_unspendable_amount);
    Assert(m_transaction_output_count == read_out.second.transaction_output_count);
    Assert(m_bogo_size == read_out.second.bogo_size);

    m_block_subsidy = read_out.second.block_subsidy;
    m_block_prevout_spent_amount = read_out.second.block_prevout_spent_amount;
    m_block_new_outputs_ex_coinbase_amount = read_out.second.block_new_outputs_ex_coinbase_amount;
    m_block_coinbase_amount = read_out.second.block_coinbase_amount;

    m_block_unspendables_genesis_block = read_out.second.block_unspendables_genesis_block;
    m_block_unspendables_bip30 = read_out.second.block_unspendables_bip30;
    m_block_unspendables_scripts = read_out.second.block_unspendables_scripts;
    m_block_unspendables_unclaimed_rewards = read_out.second.block_unspendables_unclaimed_rewards;

    return true;
}

bool CoinStatsIndex::MigrateToV1() {
    LogPrintf("Migrating coinstatsindex to new format. This might take a few minutes.\n");
    CDBBatch batch(*m_db);
    DBVal entry;
    const CBlockIndex *pindex{m_best_block_index};
    if (!LookUpOne(*m_db, {pindex->GetBlockHash(), pindex->nHeight}, entry)) {
        return false;
    }

    while (true) {
        if (pindex->nHeight % 10000 == 0) LogPrintf("Migrating block at height %i\n", pindex->nHeight);
        if (!pindex->pprev) break; //finished, the entry for the genesis block doesn't need to be updated
        //Load Previous entry
        DBVal entry_prev;
        if (!LookUpOne(*m_db, {pindex->pprev->GetBlockHash(), pindex->pprev->nHeight}, entry_prev)) {
            return false;
        }
        //Combine entries
        if (entry.block_subsidy < entry_prev.block_subsidy
            || entry.block_prevout_spent_amount < entry_prev.block_prevout_spent_amount
            || entry.block_prevout_spent_amount < entry_prev.block_prevout_spent_amount
            || entry.block_new_outputs_ex_coinbase_amount < entry_prev.block_new_outputs_ex_coinbase_amount
            || entry.block_coinbase_amount < entry_prev.block_coinbase_amount
            || entry.block_unspendables_genesis_block < entry_prev.block_unspendables_genesis_block
            || entry.block_unspendables_bip30 < entry_prev.block_unspendables_bip30
            || entry.block_unspendables_scripts < entry_prev.block_unspendables_scripts
            || entry.block_unspendables_unclaimed_rewards < entry_prev.block_unspendables_unclaimed_rewards
        ) {
            LogError("Coinstatsindex is corrupted at height %i\n", pindex->nHeight);
            return false;
        }
        entry.block_subsidy = entry.block_subsidy - entry_prev.block_subsidy;
        entry.block_prevout_spent_amount = entry.block_prevout_spent_amount - entry_prev.block_prevout_spent_amount;
        entry.block_new_outputs_ex_coinbase_amount = entry.block_new_outputs_ex_coinbase_amount - entry_prev.block_new_outputs_ex_coinbase_amount;
        entry.block_coinbase_amount = entry.block_coinbase_amount - entry_prev.block_coinbase_amount;
        entry.block_unspendables_genesis_block = entry.block_unspendables_genesis_block - entry_prev.block_unspendables_genesis_block;
        entry.block_unspendables_bip30 = entry.block_unspendables_bip30 - entry_prev.block_unspendables_bip30;
        entry.block_unspendables_scripts = entry.block_unspendables_scripts - entry_prev.block_unspendables_scripts;
        entry.block_unspendables_unclaimed_rewards = entry.block_unspendables_unclaimed_rewards - entry_prev.block_unspendables_unclaimed_rewards;
        std::pair<uint256, DBVal> result;
        result.first = pindex->GetBlockHash();
        result.second = entry;
        batch.Write(DBHeightKey(pindex->nHeight), result);
        pindex = pindex->pprev;
        entry = entry_prev;
    }
    batch.Write(DB_VERSION, 1);
    if (!m_db->WriteBatch(batch)) return false;
    LogPrintf("Migration of coinstatsindex successful\n");
    return true;
}
