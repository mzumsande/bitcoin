// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_BLOCKTIMES_H
#define BITCOIN_NODE_BLOCKTIMES_H

#include <sync.h>

#include <chrono>
#include <cstddef>
#include <deque>

class BlockTimes
{

private:
    //! Maximum number of samples stored per peer.
    static constexpr size_t MAX_SIZE{10};
    mutable Mutex m_mutex;
    /** Last 10 block download rates. */
    std::deque<int64_t> m_offsets GUARDED_BY(m_mutex){};

public:

    void Add(int64_t entry) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
        LOCK(m_mutex);
        if (m_offsets.size() >= MAX_SIZE) {
            m_offsets.pop_front();
        }
        m_offsets.push_back(entry);
    };

    int64_t Median() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
        auto sorted_copy = m_offsets;
        std::sort(sorted_copy.begin(), sorted_copy.end());
        return sorted_copy[sorted_copy.size() / 2];
    };
};

#endif // BITCOIN_NODE_BLOCKTIMES_H
