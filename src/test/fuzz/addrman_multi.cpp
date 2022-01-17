// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrdb.h>
#include <addrman.h>
#include <addrman_impl.h>
#include <addrman_multi.h>
#include <addrman_multi_impl.h>
#include <chainparams.h>
#include <merkleblock.h>
#include <random.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <time.h>
#include <util/asmap.h>

#include <cassert>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

void initialize_multi_addrman()
{
    SelectParams(CBaseChainParams::REGTEST);
}


class AddrManDeterministicMultiIndex : public AddrManMultiIndex
{
public:
    explicit AddrManDeterministicMultiIndex(std::vector<bool> asmap, uint256 seed)
        : AddrManMultiIndex(std::move(asmap), /* deterministic */ true, /* consistency_check_ratio */ 0)
    {
        WITH_LOCK(m_impl->cs, m_impl->insecure_rand = FastRandomContext{seed});
    }
};

class AddrManDeterministic : public AddrMan
{
public:
    explicit AddrManDeterministic(std::vector<bool> asmap, uint256 seed)
        : AddrMan(std::move(asmap), /* deterministic */ true, /* consistency_check_ratio */ 0)
    {
        WITH_LOCK(m_impl->cs, m_impl->insecure_rand = FastRandomContext{seed});
    }

    bool IsNewAddressInBucket(CAddress &addr, int bucket, int bucketpos) {
        LOCK(m_impl->cs);
        int nId{0};
        m_impl->Find(addr, &nId);
        return (m_impl->vvNew[bucket][bucketpos] == nId);
    }
};

[[nodiscard]] inline std::vector<bool> ConsumeAsmap(FuzzedDataProvider& fuzzed_data_provider) noexcept
{
    std::vector<bool> asmap = ConsumeRandomLengthBitVector(fuzzed_data_provider);
    if (!SanityCheckASMap(asmap, 128)) asmap.clear();
    return asmap;
}

void CompareAddrManImpls(AddrManDeterministic& addrman, AddrManDeterministicMultiIndex& addrman_multi, std::vector<CAddress>& addresses)
{
    assert(addrman.size() == addrman_multi.size());
    for(auto addr: addresses) {
        auto addr_position = addrman.FindAddressEntry(addr);
        auto addr_position_multi = addrman_multi.FindAddressEntry(addr);
        assert(addr_position.has_value() == addr_position_multi.has_value());
        if(addr_position.has_value()){
            assert(addr_position.value().tried == addr_position_multi.value().tried);
            assert(addr_position.value().multiplicity == addr_position_multi.value().multiplicity);
            // FindAddressEntry() calculates the bucket where an address belongs to (using its source)
            // The existing addrman only tracks the source of the first seen occurrence. If this entry
            // gets evicted, but there is an alias, it will not report the bucket it is currently in.
            // The Multi-Index implemenation does not have this limitation, so we'll check instead for
            // the actual bucket it is in.
            if(addr_position.value().bucket != addr_position_multi.value().bucket){
                assert(!addr_position.value().tried);
                assert(addrman.IsNewAddressInBucket(addr, addr_position_multi.value().bucket, addr_position_multi.value().position));
            }
            else {
                assert(addr_position.value().position == addr_position_multi.value().position);
            };
        }
    }
}

FUZZ_TARGET_INIT(addrman_compare, initialize_multi_addrman)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    SetMockTime(ConsumeTime(fuzzed_data_provider));
    std::vector<bool> asmap = ConsumeAsmap(fuzzed_data_provider);
    uint256 seed = ConsumeUInt256(fuzzed_data_provider);
    auto addr_man_multi_ptr = std::make_unique<AddrManDeterministic>(asmap, seed);
    auto addr_man_ptr = std::make_unique<AddrManDeterministicMultiIndex>(asmap, seed);
    AddrManDeterministic& addr_man = *addr_man_multi_ptr;
    AddrManDeterministicMultiIndex& addr_man_multi = *addr_man_ptr;
    std::vector<CAddress> inserted_addresses;
    while (fuzzed_data_provider.ConsumeBool()) {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                addr_man.ResolveCollisions();
                addr_man_multi.ResolveCollisions();
            },
            [&] {
                auto collision_old = addr_man.SelectTriedCollision();
                auto collision_new = addr_man_multi.SelectTriedCollision();
                assert(collision_old == collision_new);
            },
            [&] {
                std::vector<CAddress> addresses;
                while (fuzzed_data_provider.ConsumeBool()) {
                    const std::optional<CAddress> opt_address = ConsumeDeserializable<CAddress>(fuzzed_data_provider);
                    if (!opt_address) {
                        break;
                    }
                    addresses.push_back(*opt_address);
                }
                const std::optional<CNetAddr> opt_net_addr = ConsumeDeserializable<CNetAddr>(fuzzed_data_provider);
                if (opt_net_addr) {
                    int64_t penalty = fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(0, 100000000);
                    bool result_old = addr_man.Add(addresses, *opt_net_addr, penalty);
                    bool result_new = addr_man_multi.Add(addresses, *opt_net_addr, penalty);
                    assert(result_old == result_new);
                    // Keep track of inserted addresses
                    if(result_old) {
                        inserted_addresses.insert(inserted_addresses.end(), addresses.begin(), addresses.end());
                    }
                }
            },
            [&] {
                const std::optional<CService> opt_service = ConsumeDeserializable<CService>(fuzzed_data_provider);
                if (opt_service) {
                    int64_t time = ConsumeTime(fuzzed_data_provider);
                    bool result_old = addr_man.Good(*opt_service, time);
                    bool result_new = addr_man_multi.Good(*opt_service, time);
                    assert(result_old == result_new);
                }
            },
            [&] {
                const std::optional<CService> opt_service = ConsumeDeserializable<CService>(fuzzed_data_provider);
                if (opt_service) {
                    int64_t time = ConsumeTime(fuzzed_data_provider);
                    bool fCountFailure = fuzzed_data_provider.ConsumeBool();
                    addr_man.Attempt(*opt_service, fCountFailure, time);
                    addr_man_multi.Attempt(*opt_service, fCountFailure, time);
                }
            },
            [&] {
                const std::optional<CService> opt_service = ConsumeDeserializable<CService>(fuzzed_data_provider);
                if (opt_service) {
                    int64_t time = ConsumeTime(fuzzed_data_provider);
                    addr_man.Connected(*opt_service, time);
                    addr_man_multi.Connected(*opt_service, time);
                }
            },
            [&] {
                const std::optional<CService> opt_service = ConsumeDeserializable<CService>(fuzzed_data_provider);
                if (opt_service) {
                    auto services = ConsumeWeakEnum(fuzzed_data_provider, ALL_SERVICE_FLAGS);
                    addr_man.SetServices(*opt_service, services);
                    addr_man_multi.SetServices(*opt_service, services);
                }
            });
    }
    CompareAddrManImpls(addr_man, addr_man_multi, inserted_addresses);

    // Test constant functions Select and GetAddr
    const AddrMan& const_addr_man{addr_man};
    const AddrManMultiIndex& const_addr_man_multi{addr_man_multi};

    bool newOnly{fuzzed_data_provider.ConsumeBool()};
    auto select_old = const_addr_man.Select(newOnly);
    auto select_new = const_addr_man_multi.Select(newOnly);

    size_t max_addresses{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096)};
    size_t max_pct{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096)};
    auto addr_old = const_addr_man.GetAddr( max_addresses, max_pct, /* network */ std::nullopt);
    auto addr_new = const_addr_man_multi.GetAddr( max_addresses, max_pct, /* network */ std::nullopt);
    // GetAddr can yield slightly different results, because the order in vRandom is not exactly the same
    // This is due to a small difference in AddSingle: The old addrman first adds to vRandom, and then
    // checks for collisions. The multiindex first checks for collisions and adds in the end
    // assert(std::equal(addr_old.begin(), addr_old.end(), addr_new.begin()));
    assert(select_old == select_new);
}
