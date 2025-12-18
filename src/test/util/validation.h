// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_VALIDATION_H
#define BITCOIN_TEST_UTIL_VALIDATION_H

#include <kernel/blockmanager_opts.h>
#include <kernel/chainstatemanager_opts.h>
#include <validation.h>

#include <functional>
#include <memory>
#include <optional>

class CTxMemPool;
namespace node {
class BlockManager;
} // namespace node
namespace util {
class SignalInterrupt;
} // namespace util
class CValidationInterface;

struct TestBlockManager : public node::BlockManager {
    /** Test-only method to clear internal state for fuzzing */
    void CleanupForFuzzing();
};

/** Factory function type for creating custom Chainstate instances in tests. */
using ChainstateFactory = std::function<std::unique_ptr<Chainstate>(
    CTxMemPool* mempool,
    node::BlockManager& blockman,
    ChainstateManager& chainman,
    std::optional<uint256> from_snapshot_blockhash)>;

struct TestChainstateManager : public ChainstateManager {
    /** Inherit ChainstateManager's constructor */
    using ChainstateManager::ChainstateManager;

    /** Optional factory for creating custom Chainstate types (e.g., TestChainstate). */
    std::optional<ChainstateFactory> m_chainstate_factory{};

    /** Override to use m_chainstate_factory if set. */
    Chainstate& InitializeChainstate(CTxMemPool* mempool) override EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Disable the next write of all chainstates */
    void DisableNextWrite();
    /** Reset the ibd cache to its initial state */
    void ResetIbd();
    /** Toggle IsInitialBlockDownload from true to false */
    void JumpOutOfIbd();
    /** Wrappers that avoid making chainstatemanager internals public for tests */
    void InvalidBlockFound(CBlockIndex* pindex, const BlockValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void InvalidChainFound(CBlockIndex* pindexNew) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    CBlockIndex* FindMostWorkChain() EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void ResetBestInvalid() EXCLUSIVE_LOCKS_REQUIRED(cs_main);
};

/** Factory function for creating TestChainstateManager.
 * Use this with TestOpts::chainman_factory to properly instantiate
 * TestChainstateManager instead of using UB static_cast.
 */
inline std::unique_ptr<ChainstateManager> MakeTestChainstateManager(
    const util::SignalInterrupt& interrupt,
    kernel::ChainstateManagerOpts chainman_opts,
    kernel::BlockManagerOpts blockman_opts)
{
    return std::make_unique<TestChainstateManager>(interrupt, std::move(chainman_opts), std::move(blockman_opts));
}

class ValidationInterfaceTest
{
public:
    static void BlockConnected(
        const kernel::ChainstateRole& role,
        CValidationInterface& obj,
        const std::shared_ptr<const CBlock>& block,
        const CBlockIndex* pindex);
};

#endif // BITCOIN_TEST_UTIL_VALIDATION_H
