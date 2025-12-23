// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <chain.h>
#include <chainparams.h>
#include <flatfile.h>
#include <kernel/disconnected_transactions.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <validation.h>

#include <ranges>
#include <vector>

namespace {

/** Test chainstate that mocks ConnectTip/DisconnectTip for fuzz testing. */
struct TestChainstate : public Chainstate {
    using Chainstate::Chainstate;

    FuzzedDataProvider* m_fuzzed_data_provider{nullptr};

    //! Expose protected method for test use
    void CallInvalidBlockFound(CBlockIndex* pindex, const BlockValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        InvalidBlockFound(pindex, state);
    }

    bool ConnectTip(
        BlockValidationState& state,
        CBlockIndex* pindexNew,
        std::shared_ptr<const CBlock> block_to_connect,
        ConnectTrace& connectTrace,
        DisconnectedBlockTransactions& disconnectpool) override EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_mempool->cs)
    {
        // Mock validation: randomly decide if block is invalid
        if (!pindexNew->IsValid(BLOCK_VALID_SCRIPTS)) {
            if (m_fuzzed_data_provider && m_fuzzed_data_provider->ConsumeBool()) {
                // Block is invalid
                state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "fuzz-invalid");
                InvalidBlockFound(pindexNew, state);
                return false;
            }
            // Block is valid - mark it as such
            pindexNew->RaiseValidity(BLOCK_VALID_SCRIPTS);
            pindexNew->nStatus |= BLOCK_HAVE_UNDO;
        }

        // Update chain tip
        m_chain.SetTip(*pindexNew);
        PruneBlockIndexCandidates();

        return true;
    }

    bool DisconnectTip(BlockValidationState& state, DisconnectedBlockTransactions* disconnectpool) override EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_mempool->cs)
    {
        CBlockIndex* pindexDelete = m_chain.Tip();
        assert(pindexDelete);
        assert(pindexDelete->pprev);

        // Check if we have undo data (simulating pruning check)
        if (!(pindexDelete->nStatus & BLOCK_HAVE_UNDO)) {
            // Can't disconnect - undo data was pruned
            state.Invalid(BlockValidationResult::BLOCK_MISSING_PREV, "fuzz-missing-undo");
            return false;
        }

        // Simply update chain tip without UTXO operations
        m_chain.SetTip(*pindexDelete->pprev);

        return true;
    }
};

/** Factory function for creating TestChainstate. */
std::unique_ptr<Chainstate> MakeTestChainstate(
    CTxMemPool* mempool,
    node::BlockManager& blockman,
    ChainstateManager& chainman,
    std::optional<uint256> from_snapshot_blockhash)
{
    return std::make_unique<TestChainstate>(mempool, blockman, chainman, from_snapshot_blockhash);
}

/** Custom setup that uses TestChainstate with mocked ConnectTip. */
struct BlockIndexTreeSetup : public ChainTestingSetup {
    explicit BlockIndexTreeSetup(const ChainType chain_type = ChainType::REGTEST, TestOpts opts = {})
        : ChainTestingSetup{chain_type, [&opts] {
              opts.setup_net = false;
              opts.chainman_factory = MakeTestChainstateManager;
              return opts;
          }()}
    {
        // Set the chainstate factory before loading
        auto& test_chainman = static_cast<TestChainstateManager&>(*m_node.chainman);
        test_chainman.m_chainstate_factory = MakeTestChainstate;

        // Now load the chainstate (which will use our factory)
        LoadVerifyActivateChainstate();
    }
};

const BlockIndexTreeSetup* g_setup;
} // namespace

CBlockHeader ConsumeBlockHeader(FuzzedDataProvider& provider, uint256 prev_hash, int& nonce_counter)
{
    CBlockHeader header;
    header.nVersion = provider.ConsumeIntegral<decltype(header.nVersion)>();
    header.hashPrevBlock = prev_hash;
    header.hashMerkleRoot = uint256{}; // never used
    header.nTime = provider.ConsumeIntegral<decltype(header.nTime)>();
    header.nBits = Params().GenesisBlock().nBits; // not fuzzed because not used (validation is mocked).
    header.nNonce = nonce_counter++;              // prevent creating multiple block headers with the same hash
    return header;
}

void initialize_block_index_tree()
{
    static const auto testing_setup = MakeNoLogFileContext<BlockIndexTreeSetup>();
    g_setup = testing_setup.get();
}

FUZZ_TARGET(block_index_tree, .init = initialize_block_index_tree)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    SetMockTime(ConsumeTime(fuzzed_data_provider));
    auto& chainman = static_cast<TestChainstateManager&>(*g_setup->m_node.chainman);
    auto& blockman = static_cast<TestBlockManager&>(chainman.m_blockman);
    CBlockIndex* genesis = chainman.ActiveChainstate().m_chain[0];
    int nonce_counter = 0;
    std::vector<CBlockIndex*> blocks;
    blocks.push_back(genesis);
    bool abort_run{false};

    std::vector<CBlockIndex*> pruned_blocks;

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 1000)
    {
        if (abort_run) break;
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                // Receive a header building on an existing valid one. This assumes headers are valid, so PoW is not relevant here.
                LOCK(cs_main);
                CBlockIndex* prev_block = PickValue(fuzzed_data_provider, blocks);
                if (!(prev_block->nStatus & BLOCK_FAILED_MASK)) {
                    CBlockHeader header = ConsumeBlockHeader(fuzzed_data_provider, prev_block->GetBlockHash(), nonce_counter);
                    CBlockIndex* index = blockman.AddToBlockIndex(header, chainman.m_best_header);
                    assert(index->nStatus & BLOCK_VALID_TREE);
                    assert(index->pprev == prev_block);
                    blocks.push_back(index);
                }
            },
            [&] {
                // Receive a full block (valid or invalid) for an existing header, but don't attempt to connect it yet
                LOCK(cs_main);
                CBlockIndex* index = PickValue(fuzzed_data_provider, blocks);
                // Must be new to us and not known to be invalid (e.g. because of an invalid ancestor).
                if (index->nTx == 0 && !(index->nStatus & BLOCK_FAILED_MASK)) {
                    if (fuzzed_data_provider.ConsumeBool()) { // Invalid
                        BlockValidationState state;
                        state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "consensus-invalid");
                        static_cast<TestChainstate&>(chainman.ActiveChainstate()).CallInvalidBlockFound(index, state);
                    } else {
                        size_t nTx = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 1000);
                        CBlock block; // Dummy block, so that ReceivedBlockTransactions can infer a nTx value.
                        block.vtx = std::vector<CTransactionRef>(nTx);
                        FlatFilePos pos(0, fuzzed_data_provider.ConsumeIntegralInRange<int>(1, 1000));
                        chainman.ReceivedBlockTransactions(block, index, pos);
                        assert(index->nStatus & BLOCK_VALID_TRANSACTIONS);
                        assert(index->nStatus & BLOCK_HAVE_DATA);
                    }
                }
            },
            [&] {
                // Call real ActivateBestChain with mocked ConnectTip/DisconnectTip
                auto& test_chainstate = static_cast<TestChainstate&>(chainman.ActiveChainstate());
                test_chainstate.m_fuzzed_data_provider = &fuzzed_data_provider;

                BlockValidationState state;
                if (!test_chainstate.ActivateBestChain(state)) {
                    // Activation failed (e.g., due to pruned undo data during reorg)
                    // This mirrors the abort_run behavior of the old manual implementation
                    if (state.GetResult() == BlockValidationResult::BLOCK_MISSING_PREV) {
                        abort_run = true;
                    }
                }

                test_chainstate.m_fuzzed_data_provider = nullptr;
            },
            [&] {
                // Prune chain - dealing with block files is beyond the scope of this test, so just prune random blocks, making no assumptions
                // about what blocks are pruned together because they are in the same block file.
                // Also don't prune blocks outside of the chain for now - this would make the fuzzer crash because of the problem described in
                // https://github.com/bitcoin/bitcoin/issues/31512
                LOCK(cs_main);
                auto& chain = chainman.ActiveChain();
                int prune_height = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, chain.Height());
                CBlockIndex* prune_block{chain[prune_height]};
                if (prune_block != chain.Tip() && (prune_block->nStatus & BLOCK_HAVE_DATA)) {
                    blockman.m_have_pruned = true;
                    prune_block->nStatus &= ~BLOCK_HAVE_DATA;
                    prune_block->nStatus &= ~BLOCK_HAVE_UNDO;
                    prune_block->nFile = 0;
                    prune_block->nDataPos = 0;
                    prune_block->nUndoPos = 0;
                    auto range = blockman.m_blocks_unlinked.equal_range(prune_block->pprev);
                    while (range.first != range.second) {
                        std::multimap<CBlockIndex*, CBlockIndex*>::iterator _it = range.first;
                        range.first++;
                        if (_it->second == prune_block) {
                            blockman.m_blocks_unlinked.erase(_it);
                        }
                    }
                    pruned_blocks.push_back(prune_block);
                }
            },
            [&] {
                // Download a previously pruned block
                LOCK(cs_main);
                size_t num_pruned = pruned_blocks.size();
                if (num_pruned == 0) return;
                size_t i = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, num_pruned - 1);
                CBlockIndex* index = pruned_blocks[i];
                assert(!(index->nStatus & BLOCK_HAVE_DATA));
                CBlock block;
                block.vtx = std::vector<CTransactionRef>(index->nTx); // Set the number of tx to the prior value.
                FlatFilePos pos(0, fuzzed_data_provider.ConsumeIntegralInRange<int>(1, 1000));
                chainman.ReceivedBlockTransactions(block, index, pos);
                assert(index->nStatus & BLOCK_VALID_TRANSACTIONS);
                assert(index->nStatus & BLOCK_HAVE_DATA);
                pruned_blocks.erase(pruned_blocks.begin() + i);
            });
    }
    if (!abort_run) {
        chainman.CheckBlockIndex();
    }

    // clean up global state changed by last iteration and prepare for next iteration
    {
        LOCK(cs_main);
        genesis->nStatus |= BLOCK_HAVE_DATA;
        genesis->nStatus |= BLOCK_HAVE_UNDO;
        chainman.m_best_header = genesis;
        chainman.ResetBestInvalid();
        chainman.nBlockSequenceId = 2;
        chainman.ActiveChain().SetTip(*genesis);
        chainman.ActiveChainstate().setBlockIndexCandidates.clear();
        chainman.m_cached_finished_ibd = false;
        blockman.m_blocks_unlinked.clear();
        blockman.m_have_pruned = false;
        blockman.CleanupForFuzzing();
        // Delete all blocks but Genesis from block index
        uint256 genesis_hash = genesis->GetBlockHash();
        for (auto it = blockman.m_block_index.begin(); it != blockman.m_block_index.end();) {
            if (it->first != genesis_hash) {
                it = blockman.m_block_index.erase(it);
            } else {
                ++it;
            }
        }
        chainman.ActiveChainstate().TryAddBlockIndexCandidate(genesis);
        assert(blockman.m_block_index.size() == 1);
        assert(chainman.ActiveChainstate().setBlockIndexCandidates.size() == 1);
        assert(chainman.ActiveChain().Height() == 0);
    }
}
