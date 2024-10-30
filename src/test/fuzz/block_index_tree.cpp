// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <cstdint>
#include <flatfile.h>
#include <optional>
#include <ranges>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <vector>

const TestingSetup* g_setup;


static uint32_t nonce_count{0};
CBlockHeader ConsumeBlockHeader(FuzzedDataProvider& provider, uint256 prev_hash)
{
    CBlockHeader header;
    header.nVersion = provider.ConsumeIntegral<decltype(header.nVersion)>();
    header.hashPrevBlock = prev_hash;
    header.hashMerkleRoot = prev_hash; // dummy value, it's never used
    header.nTime = provider.ConsumeIntegral<decltype(header.nTime)>();
    header.nBits = Params().GenesisBlock().nBits;
    header.nNonce = nonce_count++; // prevent creating multiple block headers with the same hash
    return header;
}

void initialize_block_index_tree()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    g_setup = testing_setup.get();
}

FUZZ_TARGET(block_index_tree, .init = initialize_block_index_tree)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    ChainstateManager& chainman = *g_setup->m_node.chainman;
    auto& blockman = chainman.m_blockman;
    CBlockIndex* genesis = chainman.ActiveChainstate().m_chain[0];
    uint256 genesis_hash = genesis->GetBlockHash();
    bool debug_log{false};
    {
        LOCK(cs_main);
        assert(chainman.ActiveChain().Height() == 0);
    }

    // TODO: maybe simulate snapshot load
    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 1000)
    {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                // Receive a header building on an existing one
                LOCK(cs_main);
                CBlockIndex* prev_block = &(PickValue(fuzzed_data_provider, blockman.m_block_index).second);
                if (!(prev_block->nStatus & BLOCK_FAILED_MASK)) {
                    CBlockHeader header = ConsumeBlockHeader(fuzzed_data_provider, prev_block->GetBlockHash());
                    CBlockIndex* pindex = blockman.AddToBlockIndex(header, chainman.m_best_header);
                    if (debug_log) std::cout << "MZ inserted:" << pindex->GetBlockHash() << "|height" << pindex->nHeight << "| size: " << blockman.m_block_index.size() << "|prev: " << pindex->pprev->GetBlockHash() << std::endl;
                }
            },
            [&] {
                // Receive transactions for a block
                LOCK(cs_main);
                CBlockIndex* index = &(PickValue(fuzzed_data_provider, blockman.m_block_index).second);
                if (index->nTx == 0 && !(index->nStatus & BLOCK_FAILED_MASK)) {
                    // Dummy block, just so that ReceivedBlockTransaction can infer a nTx value.
                    size_t nTx = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 1000);
                    CBlock block;
                    block.vtx = std::vector<CTransactionRef>(nTx);
                    FlatFilePos pos(0, fuzzed_data_provider.ConsumeIntegralInRange<int>(1, 1000));
                    chainman.ReceivedBlockTransactions(block, index, pos);
                    if (debug_log) std::cout << "MZ Rec Tx after:" << index->GetBlockHash() << "|" << index->nHeight << "|nTx:" << index->nTx << "| nChainTx:" << index->m_chain_tx_count << std::endl;
                }
            },
            [&] {
                // Attempt to connect a single block to the chain (may be valid or invalid)
                LOCK(cs_main);
                auto& chain = chainman.ActiveChain();
                CBlockIndex* block = &(PickValue(fuzzed_data_provider, blockman.m_block_index).second);
                if (block->pprev == chain.Tip() && block->m_chain_tx_count > 0 && !(block->nStatus & BLOCK_FAILED_MASK)) { // block is eligible to be connected
                    if (fuzzed_data_provider.ConsumeBool()) {                                                              // block is valid
                        block->RaiseValidity(BLOCK_VALID_SCRIPTS);
                        chain.SetTip(*block);
                        chainman.ActiveChainstate().PruneBlockIndexCandidates();
                        if (debug_log) std::cout << "MZ connected: " << block->GetBlockHash() << "|height:" << block->nHeight << std::endl;
                    } else { // block found to be invalid during connection
                        BlockValidationState state;
                        state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "consensus-invalid");
                        chainman.ActiveChainstate().InvalidBlockFound(block, state);
                        if (debug_log) std::cout << "MZ marked invalid: " << block->GetBlockHash() << "|height:" << block->nHeight << std::endl;
                    }
                }
            },
            [&] {
                // Simplified ActivateBestChain(): Reorg to a chain with more work - for now, assume that all newly connected blocks are valid
                if (debug_log) std::cout << "MZ reorg start" << std::endl;
                LOCK(cs_main);
                auto& chain = chainman.ActiveChain();
                CBlockIndex* old_tip = chain.Tip();
                CBlockIndex* best_tip = chainman.ActiveChainstate().FindMostWorkChain();
                if (best_tip != old_tip) {
                    // Reset chain to forking point
                    const CBlockIndex* fork = chain.FindFork(best_tip);
                    chain.SetTip(*chain[fork->nHeight]);
                    std::vector<CBlockIndex*> to_connect;
                    CBlockIndex* iter = best_tip;
                    while (iter && iter->nHeight != fork->nHeight) {
                        to_connect.push_back(iter);
                        iter = iter->pprev;
                    }
                    for (CBlockIndex* block : to_connect | std::views::reverse) {
                        block->RaiseValidity(BLOCK_VALID_SCRIPTS);
                        chain.SetTip(*block);
                        // ABC may release cs_main / not connect all blocks in one go - but only if we have at least much chain work as we had at the start.
                        if (block->nChainWork > old_tip->nChainWork && fuzzed_data_provider.ConsumeBool()) {
                            break;
                        }
                    }
                    chainman.ActiveChainstate().PruneBlockIndexCandidates();
                    if (debug_log) std::cout << "MZ reorg from: " << old_tip->GetBlockHash() << "|height:" << old_tip->nHeight << " To:" << chain.Tip()->GetBlockHash() << "|height:" << chain.Tip()->nHeight << std::endl;
                }
            },
            [&] { // Prune chain - dealing with block files is beyond the scope of this test, so just prune all blocks below a given height.
                LOCK(cs_main);
                auto& chain = chainman.ActiveChain();
                int prune_height = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, chain.Height());
                CBlockIndex* prune_block{chain[prune_height]};
                if (prune_block != chain.Tip()) {
                    CBlockIndex* iter = prune_block;
                    blockman.m_have_pruned = true;
                    while (iter) {
                        iter->nStatus &= ~BLOCK_HAVE_DATA;
                        iter->nStatus &= ~BLOCK_HAVE_UNDO;
                        iter->nFile = 0;
                        iter->nDataPos = 0;
                        iter->nUndoPos = 0;
                        auto range = blockman.m_blocks_unlinked.equal_range(iter->pprev);
                        while (range.first != range.second) {
                            std::multimap<CBlockIndex*, CBlockIndex*>::iterator _it = range.first;
                            range.first++;
                            if (_it->second == iter) {
                                blockman.m_blocks_unlinked.erase(_it);
                            }
                        }
                        iter = iter->pprev;
                    }
                }
            });
    }
    chainman.CheckBlockIndex();


    // clean up global state for next iteration
    {
        if (debug_log) std::cout << "MZ Cleanup" << std::endl;
        LOCK(cs_main);
        genesis->nStatus |= BLOCK_HAVE_DATA;
        genesis->nStatus |= BLOCK_HAVE_UNDO;
        chainman.m_best_header = genesis;
        chainman.m_best_invalid = nullptr;
        chainman.m_failed_blocks.clear();
        chainman.ActiveChain().SetTip(*genesis);
        chainman.ActiveChainstate().setBlockIndexCandidates.clear();
        blockman.m_blocks_unlinked.clear();
        blockman.CleanupForFuzzing();
        blockman.m_have_pruned = false;

        // Reset m_block_index by deleting all blocks but Genesis
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
    }
}
