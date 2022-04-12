// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ADDRMAN_MULTI_IMPL_H
#define BITCOIN_ADDRMAN_MULTI_IMPL_H

#include <logging.h>
#include <logging/timer.h>
#include <netaddress.h>
#include <protocol.h>
#include <serialize.h>
#include <sync.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>

/**
 * Extended statistics about an address
 */
class AddrInfoMultiIndex : public CService
{
public:
    //! where knowledge about this address first came from
    CNetAddr source;

    //! in tried set?
    bool fInTried{false};

    //! position in addr_statistics
    mutable int m_pos_addrstats{-1};

    //! Which bucket this entry is in (tried bucket for fInTried, new bucket otherwise).
    int m_bucket;

    //! Which position in that bucket this entry occupies.
    int m_bucketpos;

    //! Update bucket info
    void Rebucket(const uint256& key, const std::vector<bool>& asmap)
    {
        m_bucket = fInTried ? GetTriedBucket(key, asmap) : GetNewBucket(key, asmap);
        m_bucketpos = GetBucketPosition(key, !fInTried, m_bucket);
    }

    AddrInfoMultiIndex(const CService &addrIn, const CNetAddr &addrSource) : CService(addrIn), source(addrSource)
    {
    }

    AddrInfoMultiIndex() : CService(), source()
    {
    }

    //! Calculate in which "tried" bucket this entry belongs
    int GetTriedBucket(const uint256 &nKey, const std::vector<bool> &asmap) const;

    //! Calculate in which "new" bucket this entry belongs, given a certain source
    int GetNewBucket(const uint256 &nKey, const CNetAddr& src, const std::vector<bool> &asmap) const;

    //! Calculate in which "new" bucket this entry belongs, using its default source
    int GetNewBucket(const uint256 &nKey, const std::vector<bool> &asmap) const
    {
        return GetNewBucket(nKey, source, asmap);
    }

    //! Calculate in which position of a bucket to store this entry.
    int GetBucketPosition(const uint256 &nKey, bool fNew, int nBucket) const;
};

class AddrManImplMultiIndex
{
public:
    AddrManImplMultiIndex(std::vector<bool>&& asmap, bool deterministic, int32_t consistency_check_ratio);

    ~AddrManImplMultiIndex();

    template <typename Stream>
    void Serialize(Stream& s_) const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    template <typename Stream>
    void Unserialize(Stream& s_) EXCLUSIVE_LOCKS_REQUIRED(!cs);

    size_t size() const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    bool Add(const std::vector<CAddress>& vAddr, const CNetAddr& source, int64_t nTimePenalty)
        EXCLUSIVE_LOCKS_REQUIRED(!cs);

    bool Good(const CService& addr, int64_t nTime)
        EXCLUSIVE_LOCKS_REQUIRED(!cs);

    void Attempt(const CService& addr, bool fCountFailure, int64_t nTime)
        EXCLUSIVE_LOCKS_REQUIRED(!cs);

    void ResolveCollisions() EXCLUSIVE_LOCKS_REQUIRED(!cs);

    std::pair<CAddress, int64_t> SelectTriedCollision() EXCLUSIVE_LOCKS_REQUIRED(!cs);

    std::pair<CAddress, int64_t> Select(bool newOnly) const
        EXCLUSIVE_LOCKS_REQUIRED(!cs);

    std::vector<CAddress> GetAddr(size_t max_addresses, size_t max_pct, std::optional<Network> network) const
        EXCLUSIVE_LOCKS_REQUIRED(!cs);

    void Connected(const CService& addr, int64_t nTime)
        EXCLUSIVE_LOCKS_REQUIRED(!cs);

    void SetServices(const CService& addr, ServiceFlags nServices)
        EXCLUSIVE_LOCKS_REQUIRED(!cs);

    std::optional<AddressPositionMultiIndex> FindAddressEntry(const CAddress& addr)
        EXCLUSIVE_LOCKS_REQUIRED(!cs);

    const std::vector<bool>& GetAsmap() const;

    friend class AddrManDeterministicMultiIndex;

private:
    //! A mutex to protect the inner data structures.
    mutable Mutex cs;

    //! Source of random numbers for randomization in inner loops
    mutable FastRandomContext insecure_rand GUARDED_BY(cs);

    //! secret key to randomize bucket select with
    uint256 nKey;

    //! Serialization versions.
    enum Format : uint8_t {
        V0_HISTORICAL = 0,    //!< historic format, before commit e6b343d88
        V1_DETERMINISTIC = 1, //!< for pre-asmap files
        V2_ASMAP = 2,         //!< for files including asmap version
        V3_BIP155 = 3,        //!< same as V2_ASMAP plus addresses are in BIP155 format
        V4_MULTIPORT = 4,     //!< adds support for multiple ports per IP
        V5_MULTIINDEX = 5     //!< Redesign, multi-index based
    };

    //! The maximum format this software knows it can unserialize. Also, we always serialize
    //! in this format.
    //! The format (first byte in the serialized stream) can be higher than this and
    //! still this software may be able to unserialize the file - if the second byte
    //! (see `lowest_compatible` in `Unserialize()`) is less or equal to this.
    static constexpr Format FILE_FORMAT = Format::V5_MULTIINDEX;

    //! The initial value of a field that is incremented every time an incompatible format
    //! change is made (such that old software versions would not be able to parse and
    //! understand the new file format). This is 32 because we overtook the "key size"
    //! field which was 32 historically.
    //! @note Don't increment this. Increment `lowest_compatible` in `Serialize()` instead.
    static constexpr uint8_t INCOMPATIBILITY_BASE = 32;

    struct ByAddress {
    };
    struct ByBucket {
    };

    //! Extract by address, separately for aliases or non-aliases
    struct ByAddressExtractor {
        using result_type = std::pair<const CService&, bool>;
        result_type operator()(const AddrInfoMultiIndex& info) const { return {info, info.m_pos_addrstats == -1}; }
    };

    using ByBucketView = std::tuple<bool, int, int>;

    //! Extract by bucket
    struct ByBucketExtractor {
        using result_type = ByBucketView;
        result_type operator()(const AddrInfoMultiIndex& info) const { return {info.fInTried, info.m_bucket, info.m_bucketpos}; }
    };

    using AddrManIndex = boost::multi_index_container<
        AddrInfoMultiIndex,
        boost::multi_index::indexed_by<
            boost::multi_index::ordered_non_unique<boost::multi_index::tag<ByAddress>, ByAddressExtractor>,
            boost::multi_index::ordered_non_unique<boost::multi_index::tag<ByBucket>, ByBucketExtractor>>>;

    /**
    *  Unique statistics about an address in addrman.
    *  If there are multiple aliases in New, there is only one AddrStatistics for them.
    */
    struct AddrStatistics {
        AddrManIndex::index<ByAddress>::type::iterator addr{nullptr};

        //! last try whatsoever by us
        int64_t nLastTry{0};

        //! last counted attempt
        int64_t nLastCountAttempt{0};

        //! last successful connection by us
        int64_t nLastSuccess{0};

        //! connection attempts since last successful attempt
        int nAttempts{0};

        //! network-propagated timestamp
        uint32_t nTime{0};

        //! Service flags
        ServiceFlags nServices{NODE_NONE};

        AddrStatistics(){};
        AddrStatistics(AddrManIndex::index<ByAddress>::type::iterator addr_in) : addr(addr_in){};
    };

    // The actual data table
    AddrManIndex m_index GUARDED_BY(cs);

    //! randomly-ordered vector of all (non-alias) entries
    mutable std::vector<AddrStatistics> addr_statistics GUARDED_BY(cs);

    // number of "tried" entries
    int nTried GUARDED_BY(cs){0};

    //! number of (unique) "new" entries
    int nNew GUARDED_BY(cs){0};

    //! last time Good was called (memory only). Initially set to 1 so that "never" is strictly worse.
    int64_t nLastGood GUARDED_BY(cs){1};

    //! Holds addrs inserted into tried table that collide with existing entries. Test-before-evict discipline used to resolve these collisions.
    std::set<const AddrInfoMultiIndex*> m_tried_collisions;

    /** Perform consistency checks every m_consistency_check_ratio operations (if non-zero). */
    const int32_t m_consistency_check_ratio;

    // Compressed IP->ASN mapping, loaded from a file when a node starts.
    // Should be always empty if no file was provided.
    // This mapping is then used for bucketing nodes in Addrman.
    //
    // If asmap is provided, nodes will be bucketed by
    // AS they belong to, in order to make impossible for a node
    // to connect to several nodes hosted in a single AS.
    // This is done in response to Erebus attack, but also to generally
    // diversify the connections every node creates,
    // especially useful when a large fraction of nodes
    // operate under a couple of cloud providers.
    //
    // If a new asmap was provided, the existing records
    // would be re-bucketed accordingly.
    const std::vector<bool> m_asmap;

    //! Count the number of occurrences of entries with this address (including aliases).
    int CountAddr(const CService& addr) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    //! Update the nNew or nTried counters, respectively
    void UpdateStat(const AddrInfoMultiIndex& info, int inc) EXCLUSIVE_LOCKS_REQUIRED(cs);

    void EraseInner(AddrManIndex::index<ByAddress>::type::iterator it) EXCLUSIVE_LOCKS_REQUIRED(cs);

    //! Determine whether the statistics about an entry are bad enough so that it can just be deleted
    bool IsTerrible(const AddrStatistics& stat, int64_t nNow = GetAdjustedTime()) const;

    //! Calculate the relative chance this entry should be given when selecting nodes to connect to
    double GetChance(const AddrStatistics& stat, int64_t nNow = GetAdjustedTime()) const;

    //! Creates a CAddress from AddrInfoMultiIndex and its AddrStatistics
    CAddress MakeAddress(const AddrInfoMultiIndex& addrInfo) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    template <typename Iter>
    void Erase(Iter it) EXCLUSIVE_LOCKS_REQUIRED(cs)
    {
        EraseInner(m_index.project<ByAddress>(it));
    }

    //! Modify an entry. This will also recalculate the bucket it's in.
    template <typename Iter, typename Fun>
    void Modify(Iter it, Fun fun) EXCLUSIVE_LOCKS_REQUIRED(cs)
    {
        UpdateStat(*it, -1);
        m_index.modify(m_index.project<ByAddress>(it), [&](AddrInfoMultiIndex& info) {
            fun(info);
            info.Rebucket(nKey, m_asmap);
        });
        UpdateStat(*it, 1);
    }

    AddrManIndex::index<ByAddress>::type::iterator Insert(AddrInfoMultiIndex info, AddrStatistics stats, bool alias) EXCLUSIVE_LOCKS_REQUIRED(cs)
    {
        info.Rebucket(nKey, m_asmap);

        if (alias) {
            info.m_pos_addrstats = -1;
        } else {
            info.m_pos_addrstats = addr_statistics.size();
        }
        UpdateStat(info, 1);
        auto it = m_index.insert(std::move(info)).first;
        stats.addr = it;
        if (!alias) {
            addr_statistics.push_back(stats);
        }
        return it;
    }

    //! Swap two elements in addr_statistics.
    void SwapRandom(unsigned int m_pos_addrstats1, unsigned int m_pos_addrstats2) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    //! Move an entry from the "new" table(s) to the "tried" table
    void MakeTried(AddrManIndex::index<ByAddress>::type::iterator it) EXCLUSIVE_LOCKS_REQUIRED(cs);

    /** Attempt to add a single address to addrman's new table.
     *  @see AddrManMultiIndex::Add() for parameters. */
    bool AddSingle(const CAddress& addr, const CNetAddr& source, int64_t nTimePenalty) EXCLUSIVE_LOCKS_REQUIRED(cs);

    bool Good_(const CService& addr, bool test_before_evict, int64_t time) EXCLUSIVE_LOCKS_REQUIRED(cs);

    bool Add_(const std::vector<CAddress> &vAddr, const CNetAddr& source, int64_t nTimePenalty) EXCLUSIVE_LOCKS_REQUIRED(cs);

    void Attempt_(const CService& addr, bool fCountFailure, int64_t nTime) EXCLUSIVE_LOCKS_REQUIRED(cs);

    std::pair<CAddress, int64_t> Select_(bool newOnly) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    std::vector<CAddress> GetAddr_(size_t max_addresses, size_t max_pct, std::optional<Network> network) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    void Connected_(const CService& addr, int64_t nTime) EXCLUSIVE_LOCKS_REQUIRED(cs);

    void SetServices_(const CService& addr, ServiceFlags nServices) EXCLUSIVE_LOCKS_REQUIRED(cs);

    void ResolveCollisions_() EXCLUSIVE_LOCKS_REQUIRED(cs);

    std::pair<CAddress, int64_t> SelectTriedCollision_() EXCLUSIVE_LOCKS_REQUIRED(cs);

    std::optional<AddressPositionMultiIndex> FindAddressEntry_(const CAddress& addr) EXCLUSIVE_LOCKS_REQUIRED(cs);

    //! Consistency check, taking into account m_consistency_check_ratio.
    //! Will std::abort if an inconsistency is detected.
    void Check() const EXCLUSIVE_LOCKS_REQUIRED(cs);

    //! Perform consistency check, regardless of m_consistency_check_ratio.
    //! @returns an error code or zero.
    int CheckAddrman() const EXCLUSIVE_LOCKS_REQUIRED(cs);
};

#endif // BITCOIN_ADDRMAN_MULTI_IMPL_H
