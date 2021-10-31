// Copyright (c) 2012 Pieter Wuille
// Copyright (c) 2012-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrman_multi.h>
#include <addrman_multi_impl.h>

#include <hash.h>
#include <logging.h>
#include <logging/timer.h>
#include <netaddress.h>
#include <protocol.h>
#include <random.h>
#include <serialize.h>
#include <streams.h>
#include <timedata.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/check.h>

#include <cmath>
#include <optional>

/** Over how many buckets entries with tried addresses from a single group (/16 for IPv4) are spread */
static constexpr uint32_t ADDRMAN_TRIED_BUCKETS_PER_GROUP{8};
/** Over how many buckets entries with new addresses originating from a single group are spread */
static constexpr uint32_t ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP{64};
/** Maximum number of times an address can occur in the new table */
static constexpr int32_t ADDRMAN_NEW_BUCKETS_PER_ADDRESS{8};
/** How old addresses can maximally be */
static constexpr int64_t ADDRMAN_HORIZON_DAYS{30};
/** After how many failed attempts we give up on a new node */
static constexpr int32_t ADDRMAN_RETRIES{3};
/** How many successive failures are allowed ... */
static constexpr int32_t ADDRMAN_MAX_FAILURES{10};
/** ... in at least this many days */
static constexpr int64_t ADDRMAN_MIN_FAIL_DAYS{7};
/** How recent a successful connection should be before we allow an address to be evicted from tried */
static constexpr int64_t ADDRMAN_REPLACEMENT_HOURS{4};
/** The maximum number of tried addr collisions to store */
static constexpr size_t ADDRMAN_SET_TRIED_COLLISION_SIZE{10};
/** The maximum time we'll spend trying to resolve a tried table collision, in seconds */
static constexpr int64_t ADDRMAN_TEST_WINDOW{40*60}; // 40 minutes

int AddrInfo::GetTriedBucket(const uint256& nKey, const std::vector<bool>& asmap) const
{
    uint64_t hash1 = (CHashWriter(SER_GETHASH, 0) << nKey << GetKey()).GetCheapHash();
    uint64_t hash2 = (CHashWriter(SER_GETHASH, 0) << nKey << GetGroup(asmap) << (hash1 % ADDRMAN_TRIED_BUCKETS_PER_GROUP)).GetCheapHash();
    return hash2 % ADDRMAN_TRIED_BUCKET_COUNT;
}

int AddrInfo::GetNewBucket(const uint256& nKey, const CNetAddr& src, const std::vector<bool>& asmap) const
{
    std::vector<unsigned char> vchSourceGroupKey = src.GetGroup(asmap);
    uint64_t hash1 = (CHashWriter(SER_GETHASH, 0) << nKey << GetGroup(asmap) << vchSourceGroupKey).GetCheapHash();
    uint64_t hash2 = (CHashWriter(SER_GETHASH, 0) << nKey << vchSourceGroupKey << (hash1 % ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP)).GetCheapHash();
    return hash2 % ADDRMAN_NEW_BUCKET_COUNT;
}

int AddrInfo::GetBucketPosition(const uint256& nKey, bool fNew, int nBucket) const
{
    uint64_t hash1 = (CHashWriter(SER_GETHASH, 0) << nKey << (fNew ? uint8_t{'N'} : uint8_t{'K'}) << nBucket << GetKey()).GetCheapHash();
    return hash1 % ADDRMAN_BUCKET_SIZE;
}

bool AddrInfo::IsTerrible(int64_t nNow) const
{
    if (nLastTry && nLastTry >= nNow - 60) // never remove things tried in the last minute
        return false;

    if (nTime > nNow + 10 * 60) // came in a flying DeLorean
        return true;

    if (nTime == 0 || nNow - nTime > ADDRMAN_HORIZON_DAYS * 24 * 60 * 60) // not seen in recent history
        return true;

    if (nLastSuccess == 0 && nAttempts >= ADDRMAN_RETRIES) // tried N times and never a success
        return true;

    if (nNow - nLastSuccess > ADDRMAN_MIN_FAIL_DAYS * 24 * 60 * 60 && nAttempts >= ADDRMAN_MAX_FAILURES) // N successive failures in the last week
        return true;

    return false;
}

double AddrInfo::GetChance(int64_t nNow) const
{
    double fChance = 1.0;
    int64_t nSinceLastTry = std::max<int64_t>(nNow - nLastTry, 0);

    // deprioritize very recent attempts away
    if (nSinceLastTry < 60 * 10)
        fChance *= 0.01;

    // deprioritize 66% after each failed attempt, but at most 1/28th to avoid the search taking forever or overly penalizing outages.
    fChance *= pow(0.66, std::min(nAttempts, 8));

    return fChance;
}

AddrManMultiImpl::AddrManMultiImpl(std::vector<bool>&& asmap, bool deterministic, int32_t consistency_check_ratio)
    : insecure_rand{deterministic}
    , nKey{deterministic ? uint256{1} : insecure_rand.rand256()}
    , m_consistency_check_ratio{consistency_check_ratio}
    , m_asmap{std::move(asmap)}
{}

AddrManMultiImpl::~AddrManMultiImpl()
{
    nKey.SetNull();
}

template <typename Stream>
void AddrManMultiImpl::Serialize(Stream& s_) const
{
    LOCK(cs);

    /**
     * Serialized format.
     * * format version byte (@see `Format`)
     * * lowest compatible format version byte. This is used to help old software decide
     *   whether to parse the file. For example:
     *   * Bitcoin Core version N knows how to parse up to format=3. If a new format=4 is
     *     introduced in version N+1 that is compatible with format=3 and it is known that
     *     version N will be able to parse it, then version N+1 will write
     *     (format=4, lowest_compatible=3) in the first two bytes of the file, and so
     *     version N will still try to parse it.
     *   * Bitcoin Core version N+2 introduces a new incompatible format=5. It will write
     *     (format=5, lowest_compatible=5) and so any versions that do not know how to parse
     *     format=5 will not try to read the file.
     * * nKey
     * * nNew
     * * nTried
     * * number of "new" buckets XOR 2**30
     * * all new addresses (total count: nNew)
     * * all tried addresses (total count: nTried)
     * * for each new bucket:
     *   * number of elements
     *   * for each element: index in the serialized "all new addresses"
     * * asmap checksum
     *
     * 2**30 is xorred with the number of buckets to make addrman deserializer v0 detect it
     * as incompatible. This is necessary because it did not check the version number on
     * deserialization.
     *
     * vvNew, vvTried, mapInfo, mapAddr and vRandom are never encoded explicitly;
     * they are instead reconstructed from the other information.
     *
     * This format is more complex, but significantly smaller (at most 1.5 MiB), and supports
     * changes to the ADDRMAN_ parameters without breaking the on-disk structure.
     *
     * We don't use SERIALIZE_METHODS since the serialization and deserialization code has
     * very little in common.
     */

    // Always serialize in the latest version (FILE_FORMAT).

    OverrideStream<Stream> s(&s_, s_.GetType(), s_.GetVersion() | ADDRV2_FORMAT);

    s << static_cast<uint8_t>(FILE_FORMAT);

    // Increment `lowest_compatible` iff a newly introduced format is incompatible with
    // the previous one.
    static constexpr uint8_t lowest_compatible = Format::V5_MULTIINDEX;
    s << static_cast<uint8_t>(INCOMPATIBILITY_BASE + lowest_compatible);

    s << nKey;
    s << nNew;
    s << nTried;

    int n_left = nNew;
    bool in_tried = false;
    int nser = 0;
    for (auto it = m_index.get<ByBucket>().begin(); it != m_index.get<ByBucket>().end();) {
        // Aliases are handled together with the main one
        if(it->nRandomPos == -1 ) {
            ++it;
            continue;
        }
        if (n_left == 0) {
            assert(!in_tried);
            in_tried = true;
            n_left = nTried;
        }
        unsigned alias_count = CountAddr(*it);
        s << static_cast<const CAddress&>(*it);
        s << it->nLastTry;
        s << it->nLastCountAttempt;
        s << it->nLastSuccess;
        s << it->nAttempts;
        if (!in_tried) {
            s << alias_count;
        } else {
            assert(alias_count == 1);
        }
        AddrManIndex::index<ByAddress>::type::iterator addrit = m_index.project<ByAddress>(it);
        for (unsigned int i = 0; i < alias_count; ++i) {
            assert(addrit->fInTried == in_tried);
            s << addrit->source;
            ++addrit;
            ++nser;
        }
        ++it;
        n_left--;
    }
}

template <typename Stream>
void AddrManMultiImpl::Unserialize(Stream& s_)
{
    LOCK(cs);

    assert(m_index.empty());

    Format format;
    s_ >> Using<CustomUintFormatter<1>>(format);

    int stream_version = s_.GetVersion();
    if (format >= Format::V3_BIP155) {
        // Add ADDRV2_FORMAT to the version so that the CNetAddr and CAddress
        // unserialize methods know that an address in addrv2 format is coming.
        stream_version |= ADDRV2_FORMAT;
    }

    OverrideStream<Stream> s(&s_, s_.GetType(), stream_version);

    uint8_t compat;
    s >> compat;
    const uint8_t lowest_compatible = compat - INCOMPATIBILITY_BASE;
    if (lowest_compatible > FILE_FORMAT) {
        throw std::ios_base::failure(strprintf(
            "Unsupported format of addrman database: %u. It is compatible with formats >=%u, "
            "but the maximum supported by this version of %s is %u.",
            uint8_t{format}, uint8_t{lowest_compatible}, PACKAGE_NAME, uint8_t{FILE_FORMAT}));
    }

    s >> nKey;

    int read_new, read_tried;
    s >> read_new;
    s >> read_tried;

    int nUBuckets = 0;
    if (format < Format::V5_MULTIINDEX) {
        s >> nUBuckets;
        if (format >= Format::V1_DETERMINISTIC) {
            nUBuckets ^= (1 << 30);
        }
    }

    // Read entries.
    for (int i = 0; i < read_new + read_tried; ++i) {
        AddrInfo info;
        unsigned sources = 1;
        if (format >= Format::V5_MULTIINDEX) {
            s >> static_cast<CAddress&>(info);
            s >> info.nLastTry;
            s >> info.nLastCountAttempt;
            s >> info.nLastSuccess;
            s >> info.nAttempts;
            if (i < read_new) {
                s >> sources;
            }
            if (sources) s >> info.source;
        } else {
            s >> info;
        }
        info.fInTried = i >= read_new;
        for (unsigned int i = 0; i < sources; ++i) {
            if (i) s >> info.source;
            info.Rebucket(nKey, m_asmap);
            // If another entry in the same bucket/position already exists, delete it.
            auto it_bucket = m_index.get<ByBucket>().find(ByBucketExtractor()(info));
            if (it_bucket != m_index.get<ByBucket>().end()) {
                Erase(it_bucket);
            }
            // If we're adding an entry with the same address as one that exists:
            // - If it's a new entry, mark it as an alias.
            // - If it's a tried entry, delete all existing ones (there can be at most
            //   one tried entry for a given address, and there can't be both tried and
            //   new ones simultaneously).
            bool alias = false;
            auto it_addr = m_index.get<ByAddress>().lower_bound(std::pair<const CService&, bool>(info, false));
            if (it_addr != m_index.get<ByAddress>().end() && static_cast<const CService&>(*it_addr) == info) {
                if (info.fInTried) {
                    do {
                        Erase(it_addr);
                        it_addr = m_index.get<ByAddress>().lower_bound(std::pair<const CService&, bool>(info, false));
                    } while (it_addr != m_index.get<ByAddress>().end() && static_cast<const CService&>(*it_addr) == info);
                } else {
                    alias = true;
                }
            }
            // Insert the read entry into the table.
            Insert(info, alias);
        }
    }

    // Bucket information and asmap checksum are ignored as of V4.
    if (format < Format::V5_MULTIINDEX) {
        for (int bucket = 0; bucket < nUBuckets; ++bucket) {
            int num_entries{0};
            s >> num_entries;
            for (int n = 0; n < num_entries; ++n) {
                int entry_index{0};
                s >> entry_index;
            }
        }
        uint256 serialized_asmap_checksum;
        if (format >= Format::V2_ASMAP) {
            s >> serialized_asmap_checksum;
        }
    }

    const int check_code{CheckAddrman()};
    if (check_code != 0) {
        throw std::ios_base::failure(strprintf(
            "Corrupt data. Consistency check failed with code %s",
            check_code));
    }
}

int AddrManMultiImpl::CountAddr(const CService& addr) const
{
    AssertLockHeld(cs);
    auto it = m_index.get<ByAddress>().lower_bound(std::pair<const CService&, bool>(addr, false));
    if (it == m_index.get<ByAddress>().end()) return 0;
    auto it_end = m_index.get<ByAddress>().upper_bound(std::pair<const CService&, bool>(addr, true));
    return std::distance(it, it_end);
}

void AddrManMultiImpl::UpdateStat(const AddrInfo& info, int inc)
{
    if (info.nRandomPos != -1) {
        if (info.fInTried) {
            nTried += inc;
        } else {
            nNew += inc;
        }
    }
}

void AddrManMultiImpl::EraseInner(AddrManIndex::index<ByAddress>::type::iterator it)
{
    AssertLockHeld(cs);
    if (it->nRandomPos != -1) {
        // In case the entry being deleted has an alias, we don't delete the requested one, but
        // the alias instead. The alias' source IP is moved to the actual entry however, so
        // it is preserved.
        auto it_alias = m_index.get<ByAddress>().find(std::make_pair<const CService&, bool>(*it, true));
        if (it_alias != m_index.get<ByAddress>().end()) {
            if (m_tried_collisions.count(&*it_alias)) m_tried_collisions.insert(&*it);
            Modify(it, [&](AddrInfo& info) { info.source = it_alias->source; });
            it = it_alias;
        } else {
            // Actually deleting a non-alias entry; remove it from vRandom.
            SwapRandom(it->nRandomPos, vRandom.size() - 1);
            vRandom.pop_back();
        }
    }

    LogPrint(BCLog::ADDRMAN, "Removed %s from new[%i][%i]\n", it->ToString(), it->m_bucket, it->m_bucketpos);
    m_tried_collisions.erase(&*it);
    UpdateStat(*it, -1);
    m_index.erase(it);
}

void AddrManMultiImpl::SwapRandom(unsigned int nRndPos1, unsigned int nRndPos2) const
{
    AssertLockHeld(cs);

    if (nRndPos1 == nRndPos2)
        return;

    assert(nRndPos1 < vRandom.size() && nRndPos2 < vRandom.size());

    auto it1 = vRandom[nRndPos1];
    auto it2 = vRandom[nRndPos2];

    it1->nRandomPos = nRndPos2;
    it2->nRandomPos = nRndPos1;

    vRandom[nRndPos1] = it2;
    vRandom[nRndPos2] = it1;
}

void AddrManMultiImpl::MakeTried(AddrManIndex::index<ByAddress>::type::iterator it)
{
    AssertLockHeld(cs);

    // Extract the entry.
    AddrInfo info = *it;
    assert(!it->fInTried);
    Erase(it);
    // remove the entry from all new buckets
    while (true) {
        auto it_existing = m_index.get<ByAddress>().lower_bound(std::pair<const CService&, bool>(info, false));
        if (it_existing == m_index.get<ByAddress>().end() || *it_existing != static_cast<const CService&>(info)) break;
        Erase(it_existing);
    }

    // first make space to add it (the existing tried entry there is moved to new, deleting whatever is there).
    info.fInTried = true;
    info.Rebucket(nKey, m_asmap);
    auto it_existing = m_index.get<ByBucket>().find(ByBucketExtractor()(info));
    if (it_existing != m_index.get<ByBucket>().end()) {
        // find an item to evict
        AddrInfo info_evict = *it_existing;

        // Remove the to-be-evicted item from the tried set.
        Erase(it_existing);

        // find which new bucket it belongs to
        info_evict.fInTried = false;
        info_evict.Rebucket(nKey, m_asmap);
        auto it_new_existing = m_index.get<ByBucket>().find(ByBucketExtractor()(info_evict));
        if (it_new_existing != m_index.get<ByBucket>().end()) {
            Erase(it_new_existing);
        }

        // Enter it into the new set again.
        bool alias = m_index.get<ByAddress>().count(std::pair<const CService&, bool>(info_evict, false));
        LogPrint(BCLog::ADDRMAN, "Moved %s from tried[%i][%i] to new[%i][%i] to make space\n",
                  info_evict.ToString(), info.m_bucket, info.m_bucketpos, info_evict.m_bucket, info_evict.m_bucketpos);
        Insert(std::move(info_evict), alias);
    }

    Insert(std::move(info), false);
}

bool AddrManMultiImpl::AddSingle(const CAddress& addr, const CNetAddr& source, int64_t nTimePenalty)
{
    AssertLockHeld(cs);

    if (!addr.IsRoutable())
        return false;

    auto it = m_index.get<ByAddress>().find(std::pair<const CService&, bool>(addr, false));

    // Do not set a penalty for a source's self-announcement
    if (addr == source) {
        nTimePenalty = 0;
    }

    AddrInfo info(addr, source);
    info.fInTried = false;

    bool alias;

    if (it != m_index.get<ByAddress>().end()) {
        // periodically update nTime
        bool fCurrentlyOnline = (GetAdjustedTime() - addr.nTime < 24 * 60 * 60);
        int64_t nUpdateInterval = (fCurrentlyOnline ? 60 * 60 : 24 * 60 * 60);
        if (addr.nTime && (!it->nTime || it->nTime < addr.nTime - nUpdateInterval - nTimePenalty)) {
            Modify(it, [&](AddrInfo& info) { info.nTime = std::max((int64_t)0, addr.nTime - nTimePenalty); });
        }

        // add services
        Modify(it, [&](AddrInfo& info) { info.nServices = ServiceFlags(info.nServices | addr.nServices);});

        // do not update if no new information is present
        if (!addr.nTime || (it->nTime && addr.nTime <= it->nTime))
            return false;

        // do not update if the entry was already in the "tried" table
        if (it->fInTried)
            return false;

        // do not update if the max reference count is reached
        int aliases = CountAddr(addr);
        if (aliases == ADDRMAN_NEW_BUCKETS_PER_ADDRESS)
            return false;

        // stochastic test: previous number of aliases == N: 2^N times harder to increase it
        int nFactor = 1;
        for (int n = 0; n < aliases; n++)
            nFactor *= 2;
        if (nFactor > 1 && (insecure_rand.randrange(nFactor) != 0))
            return false;

        alias = true;
    } else {
        info.nTime = std::max((int64_t)0, (int64_t)addr.nTime - nTimePenalty);
        alias = false;
    }

    info.Rebucket(nKey, m_asmap);
    auto it_existing = m_index.get<ByBucket>().find(ByBucketExtractor()(info));
    bool fInsert = it_existing == m_index.get<ByBucket>().end();
    if (it_existing == m_index.get<ByBucket>().end() || static_cast<const CService&>(*it_existing) != addr) {
        if (!fInsert) {
            const AddrInfo& infoExisting = *it_existing;
            if (infoExisting.IsTerrible() || (!alias && CountAddr(infoExisting) > 1)) {
                // Overwriting the existing new table entry.
                fInsert = true;
            }
        }
        if (fInsert) {
            if (it_existing != m_index.get<ByBucket>().end()) Erase(it_existing);
            LogPrint(BCLog::ADDRMAN, "Added %s mapped to AS%i to new[%i][%i]\n",
                     info.ToString(), addr.GetMappedAS(m_asmap), info.m_bucket, info.m_bucketpos);
            Insert(std::move(info), alias);
        }
    }
    return fInsert;
}

bool AddrManMultiImpl::Good_(const CService& addr, bool test_before_evict, int64_t nTime)
{
    AssertLockHeld(cs);

    nLastGood = nTime;

    auto it = m_index.get<ByAddress>().find(std::pair<const CService&, bool>(addr, false));

    // if not found, bail out
    if (it == m_index.get<ByAddress>().end()) return false;

    const AddrInfo& info = *it;

    // update info
    Modify(it, [&](AddrInfo& info) {
        info.nLastSuccess = nTime;
        info.nLastTry = nTime;
        info.nAttempts = 0;
    });
    // nTime is not updated here, to avoid leaking information about
    // currently-connected peers.

    // if it is already in the tried set, don't do anything else
    if (info.fInTried) return false;

    // which tried bucket to move the entry to
    int tried_bucket = info.GetTriedBucket(nKey, m_asmap);
    int tried_bucket_pos = info.GetBucketPosition(nKey, false, tried_bucket);

    // Will moving this address into tried evict another entry?
    auto it_collision = m_index.get<ByBucket>().find(ByBucketView{true, tried_bucket, tried_bucket_pos});
    if (test_before_evict && it_collision != m_index.get<ByBucket>().end()) {
        if (m_tried_collisions.size() < ADDRMAN_SET_TRIED_COLLISION_SIZE) {
            m_tried_collisions.insert(&*it);
        }
        // Output the entry we'd be colliding with, for debugging purposes
        LogPrint(BCLog::ADDRMAN, "Collision with %s while attempting to move %s to tried table. Collisions=%d\n",
                 it_collision->ToString(),
                 addr.ToString(),
                 m_tried_collisions.size());
        return false;
    } else {
        MakeTried(it);
        LogPrint(BCLog::ADDRMAN, "Moved %s mapped to AS%i to tried[%i][%i]\n",
                 addr.ToString(), addr.GetMappedAS(m_asmap), tried_bucket, tried_bucket_pos);
        return true;
    }
}

bool AddrManMultiImpl::Add_(const std::vector<CAddress> &vAddr, const CNetAddr& source, int64_t nTimePenalty)
{
    int added{0};
    for (std::vector<CAddress>::const_iterator it = vAddr.begin(); it != vAddr.end(); it++) {
        added += AddSingle(*it, source, nTimePenalty) ? 1 : 0;
    }
    if (added > 0) {
        LogPrint(BCLog::ADDRMAN, "Added %i addresses (of %i) from %s: %i tried, %i new\n", added, vAddr.size(), source.ToString(), nTried, nNew);
    }
    return added > 0;
}

void AddrManMultiImpl::Attempt_(const CService& addr, bool fCountFailure, int64_t nTime)
{
    AssertLockHeld(cs);

    auto it = m_index.get<ByAddress>().find(std::pair<const CService&, bool>(addr, false));

    // if not found, bail out
    if (it == m_index.get<ByAddress>().end()) return;

    // update info
    auto last_good = nLastGood; // avoid the lambda needing cs LOCKed
    Modify(it, [&](AddrInfo& info) {
        info.nLastTry = nTime;
        if (fCountFailure && info.nLastCountAttempt < last_good) {
            info.nLastCountAttempt = nTime;
            info.nAttempts++;
        }
    });
}

std::pair<CAddress, int64_t> AddrManMultiImpl::Select_(bool newOnly) const
{
    AssertLockHeld(cs);

    if (m_index.empty()) return {};

    if (newOnly && nNew == 0) return {};

    // Use a 50% chance for choosing between tried and new table entries.
    if (!newOnly &&
       (nTried > 0 && (nNew == 0 || insecure_rand.randbool() == 0))) {
        // use a tried node
        double fChanceFactor = 1.0;
        while (1) {
            AddrManIndex::index<ByBucket>::type::iterator it;
            // Pick a tried bucket, and an initial position in that bucket.
            int nKBucket = insecure_rand.randrange(ADDRMAN_TRIED_BUCKET_COUNT);
            int nKBucketPos = insecure_rand.randrange(ADDRMAN_BUCKET_SIZE);
            // Iterate over the positions of that bucket, starting at the initial one,
            // and looping around.
            int i;
            for (i = 0; i < ADDRMAN_BUCKET_SIZE; ++i) {
                it = m_index.get<ByBucket>().find(ByBucketView{true, nKBucket, (nKBucketPos + i) % ADDRMAN_BUCKET_SIZE});
                if (it != m_index.get<ByBucket>().end()) break;
            }
            // If the bucket is entirely empty, start over with a (likely) different one.
            if (i == ADDRMAN_BUCKET_SIZE) continue;
            // With probability GetChance() * fChanceFactor, return the entry.
            if (insecure_rand.randbits(30) < fChanceFactor * it->GetChance() * (1 << 30)) {
                LogPrint(BCLog::ADDRMAN, "Selected %s from tried\n", it->ToString());
                return {*it, it->nLastTry};
            }
            // Otherwise start over with a (likely) different bucket, and increased chance factor.
            fChanceFactor *= 1.2;
        }
    } else {
        // use a new node
        double fChanceFactor = 1.0;
        while (1) {
            AddrManIndex::index<ByBucket>::type::iterator it;
            // Pick a new bucket, and an initial position in that bucket.
            int nUBucket = insecure_rand.randrange(ADDRMAN_NEW_BUCKET_COUNT);
            int nUBucketPos = insecure_rand.randrange(ADDRMAN_BUCKET_SIZE);
            // Iterate over the positions of that bucket, starting at the initial one,
            // and looping around.
            int i;
            for (i = 0; i < ADDRMAN_BUCKET_SIZE; ++i) {
                it = m_index.get<ByBucket>().find(ByBucketView{false, nUBucket, (nUBucketPos + i) % ADDRMAN_BUCKET_SIZE});
                if (it != m_index.get<ByBucket>().end()) break;
            }
            // If the bucket is entirely empty, start over with a (likely) different one.
            if (i == ADDRMAN_BUCKET_SIZE) continue;
            // With probability GetChance() * fChanceFactor, return the entry.
            if (insecure_rand.randbits(30) < fChanceFactor * it->GetChance() * (1 << 30)) {
                LogPrint(BCLog::ADDRMAN, "Selected %s from new\n", it->ToString());
                return {*it, it->nLastTry};
            }
            // Otherwise start over with a (likely) different bucket, and increased chance factor.
            fChanceFactor *= 1.2;
        }
    }
}

std::vector<CAddress> AddrManMultiImpl::GetAddr_(size_t max_addresses, size_t max_pct, std::optional<Network> network) const
{
    AssertLockHeld(cs);

    size_t nNodes = vRandom.size();
    if (max_pct != 0) {
        nNodes = max_pct * nNodes / 100;
    }
    if (max_addresses != 0) {
        nNodes = std::min(nNodes, max_addresses);
    }

    // gather a list of random nodes, skipping those of low quality
    const int64_t now{GetAdjustedTime()};
    std::vector<CAddress> addresses;
    for (unsigned int n = 0; n < vRandom.size(); n++) {
        if (addresses.size() >= nNodes)
            break;

        int nRndPos = insecure_rand.randrange(vRandom.size() - n) + n;
        SwapRandom(n, nRndPos);

        const AddrInfo& ai = *vRandom[n];

        // Filter by network (optional)
        if (network != std::nullopt && ai.GetNetClass() != network) continue;

        // Filter for quality
        if (ai.IsTerrible(now)) continue;

        addresses.push_back(ai);
    }
    LogPrint(BCLog::ADDRMAN, "GetAddr returned %d random addresses\n", addresses.size());
    return addresses;
}

void AddrManMultiImpl::Connected_(const CService& addr, int64_t nTime)
{
    AssertLockHeld(cs);

    auto it = m_index.get<ByAddress>().find(std::pair<const CService&, bool>(addr, false));

    // if not found, bail out
    if (it == m_index.get<ByAddress>().end()) return;

    const AddrInfo& info = *it;

    // update info
    int64_t nUpdateInterval = 20 * 60;
    if (nTime - info.nTime > nUpdateInterval) {
        Modify(it, [&](AddrInfo& info){ info.nTime = nTime; });
    }
}

void AddrManMultiImpl::SetServices_(const CService& addr, ServiceFlags nServices)
{
    AssertLockHeld(cs);

    auto it = m_index.get<ByAddress>().find(std::pair<const CService&, bool>(addr, false));

    // if not found, bail out
    if (it == m_index.get<ByAddress>().end()) return;

    // update info
    Modify(it, [&](AddrInfo& info){ info.nServices = nServices; });
}

void AddrManMultiImpl::ResolveCollisions_()
{
    AssertLockHeld(cs);

    for (auto it = m_tried_collisions.begin(); it != m_tried_collisions.end();) {
        auto it_old = *it;
        auto next_it = std::next(it); // Needs to be precomputed, as it may be deleted by the Good_() calls.

        bool erase_collision = false;

        {
            const AddrInfo& info_new = **it;

            // Which tried bucket to move the entry to.
            int tried_bucket = info_new.GetTriedBucket(nKey, m_asmap);
            int tried_bucket_pos = info_new.GetBucketPosition(nKey, false, tried_bucket);
            auto it_old = m_index.get<ByBucket>().find(ByBucketView{true, tried_bucket, tried_bucket_pos});
            if (it_old != m_index.get<ByBucket>().end()) { // The position in the tried bucket is not empty

                // Get the to-be-evicted address that is being tested
                const AddrInfo& info_old = *it_old;

                // Has successfully connected in last X hours
                if (GetAdjustedTime() - info_old.nLastSuccess < ADDRMAN_REPLACEMENT_HOURS*(60*60)) {
                    erase_collision = true;
                } else if (GetAdjustedTime() - info_old.nLastTry < ADDRMAN_REPLACEMENT_HOURS*(60*60)) { // attempted to connect and failed in last X hours

                    // Give address at least 60 seconds to successfully connect
                    if (GetAdjustedTime() - info_old.nLastTry > 60) {
                        LogPrint(BCLog::ADDRMAN, "Replacing %s with %s in tried table\n", info_old.ToString(), info_new.ToString());

                        // Replaces an existing address already in the tried table with the new address
                        Good_(info_new, false, GetAdjustedTime());
                        erase_collision = true;
                    }
                } else if (GetAdjustedTime() - info_new.nLastSuccess > ADDRMAN_TEST_WINDOW) {
                    // If the collision hasn't resolved in some reasonable amount of time,
                    // just evict the old entry -- we must not be able to
                    // connect to it for some reason.
                    LogPrint(BCLog::ADDRMAN, "Unable to test; replacing %s with %s in tried table anyway\n", info_old.ToString(), info_new.ToString());
                    Good_(info_new, false, GetAdjustedTime());
                    erase_collision = true;
                }
            } else { // Collision is not actually a collision anymore
                Good_(info_new, false, GetAdjustedTime());
                erase_collision = true;
            }
        }

        if (erase_collision) {
            m_tried_collisions.erase(it_old);
        }
        it = next_it;
    }
}

std::pair<CAddress, int64_t> AddrManMultiImpl::SelectTriedCollision_()
{
    AssertLockHeld(cs);

    if (m_tried_collisions.size() == 0) return {};
    auto it = m_tried_collisions.begin();

    // Selects a random element from m_tried_collisions
    std::advance(it, insecure_rand.randrange(m_tried_collisions.size()));
    auto it_new = *it;

    const AddrInfo& newInfo = *it_new;

    // which tried bucket to move the entry to
    int tried_bucket = newInfo.GetTriedBucket(nKey, m_asmap);
    int tried_bucket_pos = newInfo.GetBucketPosition(nKey, false, tried_bucket);

    auto it_old = m_index.get<ByBucket>().find(ByBucketView{true, tried_bucket, tried_bucket_pos});

    if (it_old != m_index.get<ByBucket>().end()) return {*it_old, it_old->nLastTry};
    return {};
}

std::optional<AddressPosition> AddrManMultiImpl::FindAddressEntry_(const CAddress& addr)
{
    AssertLockHeld(cs);

    auto it = m_index.get<ByAddress>().find(std::pair<const CService&, bool>(addr, false));
    if (it == m_index.get<ByAddress>().end()) return std::nullopt;

    const AddrInfo& addr_info = *it;

    if(addr_info.fInTried) {
        int bucket{addr_info.GetTriedBucket(nKey, m_asmap)};
        return AddressPosition(/*tried=*/true,
                               /*multiplicity=*/1,
                               /*bucket=*/bucket,
                               /*position=*/addr_info.GetBucketPosition(nKey, false, bucket));
    } else {
        int bucket{addr_info.GetNewBucket(nKey, m_asmap)};
        return AddressPosition(/*tried=*/false,
                               /*multiplicity=*/CountAddr(addr_info),
                               /*bucket=*/bucket,
                               /*position=*/addr_info.GetBucketPosition(nKey, true, bucket));
    }
}

void AddrManMultiImpl::Check() const
{
    AssertLockHeld(cs);

    // Run consistency checks 1 in m_consistency_check_ratio times if enabled
    if (m_consistency_check_ratio == 0) return;
    if (insecure_rand.randrange(m_consistency_check_ratio) >= 1) return;

    const int err{CheckAddrman()};
    if (err) {
        LogPrintf("ADDRMAN CONSISTENCY CHECK FAILED!!! err=%i\n", err);
        assert(false);
    }
}

//TODO: better return values?
int AddrManMultiImpl::CheckAddrman() const
{
    AssertLockHeld(cs);

    LOG_TIME_MILLIS_WITH_CATEGORY_MSG_ONCE(
        strprintf("new %i, tried %i, total %u", nNew, nTried, vRandom.size()), BCLog::ADDRMAN);

    int counted_new = 0;
    int counted_tried = 0;

    for (auto it = m_index.get<ByAddress>().begin(); it != m_index.get<ByAddress>().end(); ++it) {
        const AddrInfo& info = *it;
        if (info.nRandomPos == -1) {
            // Tried entries cannot have aliases.
            if (info.fInTried) return -1;
            // Aliases must have the same address as their precessor in this iteration order.
            if (it == m_index.get<ByAddress>().begin() || static_cast<const CService&>(info) != *std::prev(it)) return -2;
        } else {
            if ((size_t) info.nRandomPos >= vRandom.size()) return -22;
            if (vRandom[info.nRandomPos] != it) return -23;
            if (info.fInTried) {
                counted_tried++;
            } else {
                counted_new++;
            }
            // Non-alias entries must have a different address as their predecessor in this iteration order.
            if (it != m_index.get<ByAddress>().begin() && static_cast<const CService&>(info) == *std::prev(it)) return -3;
        }

        AddrInfo copy = info;
        copy.Rebucket(nKey, m_asmap);
        if (copy.m_bucket != info.m_bucket || copy.m_bucketpos != info.m_bucketpos) return -5;
    }

    if (counted_new != nNew) return -6;
    if (counted_tried != nTried) return -7;
    if ((size_t) (counted_new + counted_tried) != vRandom.size()) return -8;

    for (auto it = m_index.get<ByBucket>().begin(); it != m_index.get<ByBucket>().end(); ++it) {
        if (it != m_index.get<ByBucket>().begin()) {
            if (it->fInTried == std::prev(it)->fInTried &&
                it->m_bucket == std::prev(it)->m_bucket &&
                it->m_bucketpos == std::prev(it)->m_bucketpos) {
                return -10;
            }
        }
    }

    return 0;
}

size_t AddrManMultiImpl::size() const
{
    LOCK(cs); // TODO: Cache this in an atomic to avoid this overhead
    return vRandom.size();
}

bool AddrManMultiImpl::Add(const std::vector<CAddress>& vAddr, const CNetAddr& source, int64_t nTimePenalty)
{
    LOCK(cs);
    Check();
    auto ret = Add_(vAddr, source, nTimePenalty);
    Check();
    return ret;
}

bool AddrManMultiImpl::Good(const CService& addr, int64_t nTime)
{
    LOCK(cs);
    Check();
    auto ret = Good_(addr, /* test_before_evict */ true, nTime);
    Check();
    return ret;
}

void AddrManMultiImpl::Attempt(const CService& addr, bool fCountFailure, int64_t nTime)
{
    LOCK(cs);
    Check();
    Attempt_(addr, fCountFailure, nTime);
    Check();
}

void AddrManMultiImpl::ResolveCollisions()
{
    LOCK(cs);
    Check();
    ResolveCollisions_();
    Check();
}

std::pair<CAddress, int64_t> AddrManMultiImpl::SelectTriedCollision()
{
    LOCK(cs);
    Check();
    const auto ret = SelectTriedCollision_();
    Check();
    return ret;
}

std::pair<CAddress, int64_t> AddrManMultiImpl::Select(bool newOnly) const
{
    LOCK(cs);
    Check();
    const auto addrRet = Select_(newOnly);
    Check();
    return addrRet;
}

std::vector<CAddress> AddrManMultiImpl::GetAddr(size_t max_addresses, size_t max_pct, std::optional<Network> network) const
{
    LOCK(cs);
    Check();
    const auto addresses = GetAddr_(max_addresses, max_pct, network);
    Check();
    return addresses;
}

void AddrManMultiImpl::Connected(const CService& addr, int64_t nTime)
{
    LOCK(cs);
    Check();
    Connected_(addr, nTime);
    Check();
}

void AddrManMultiImpl::SetServices(const CService& addr, ServiceFlags nServices)
{
    LOCK(cs);
    Check();
    SetServices_(addr, nServices);
    Check();
}

std::optional<AddressPosition> AddrManMultiImpl::FindAddressEntry(const CAddress& addr)
{
    LOCK(cs);
    Check();
    auto entry = FindAddressEntry_(addr);
    Check();
    return entry;
}

const std::vector<bool>& AddrManMultiImpl::GetAsmap() const
{
    return m_asmap;
}

AddrMan::AddrMan(std::vector<bool> asmap, bool deterministic, int32_t consistency_check_ratio)
    : m_impl(std::make_unique<AddrManMultiImpl>(std::move(asmap), deterministic, consistency_check_ratio)) {}

AddrMan::~AddrMan() = default;

template <typename Stream>
void AddrMan::Serialize(Stream& s_) const
{
    m_impl->Serialize<Stream>(s_);
}

template <typename Stream>
void AddrMan::Unserialize(Stream& s_)
{
    m_impl->Unserialize<Stream>(s_);
}

// explicit instantiation
template void AddrMan::Serialize(CHashWriter& s) const;
template void AddrMan::Serialize(CAutoFile& s) const;
template void AddrMan::Serialize(CDataStream& s) const;
template void AddrMan::Unserialize(CAutoFile& s);
template void AddrMan::Unserialize(CHashVerifier<CAutoFile>& s);
template void AddrMan::Unserialize(CDataStream& s);
template void AddrMan::Unserialize(CHashVerifier<CDataStream>& s);

size_t AddrMan::size() const
{
    return m_impl->size();
}

bool AddrMan::Add(const std::vector<CAddress>& vAddr, const CNetAddr& source, int64_t nTimePenalty)
{
    return m_impl->Add(vAddr, source, nTimePenalty);
}

bool AddrMan::Good(const CService& addr, int64_t nTime)
{
    return m_impl->Good(addr, nTime);
}

void AddrMan::Attempt(const CService& addr, bool fCountFailure, int64_t nTime)
{
    m_impl->Attempt(addr, fCountFailure, nTime);
}

void AddrMan::ResolveCollisions()
{
    m_impl->ResolveCollisions();
}

std::pair<CAddress, int64_t> AddrMan::SelectTriedCollision()
{
    return m_impl->SelectTriedCollision();
}

std::pair<CAddress, int64_t> AddrMan::Select(bool newOnly) const
{
    return m_impl->Select(newOnly);
}

std::vector<CAddress> AddrMan::GetAddr(size_t max_addresses, size_t max_pct, std::optional<Network> network) const
{
    return m_impl->GetAddr(max_addresses, max_pct, network);
}

void AddrMan::Connected(const CService& addr, int64_t nTime)
{
    m_impl->Connected(addr, nTime);
}

void AddrMan::SetServices(const CService& addr, ServiceFlags nServices)
{
    m_impl->SetServices(addr, nServices);
}

std::optional<AddressPosition> AddrMan::FindAddressEntry(const CAddress& addr)
{
    return m_impl->FindAddressEntry(addr);
}

const std::vector<bool>& AddrMan::GetAsmap() const
{
    return m_impl->GetAsmap();
}
