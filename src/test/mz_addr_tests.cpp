// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrdb.h>
#include <addrman.h>
#include <addrman_impl.h>
#include <chainparams.h>
#include <clientversion.h>
#include <hash.h>
#include <netbase.h>
#include <random.h>
#include <test/data/asmap.raw.h>
#include <test/util/setup_common.h>
#include <util/asmap.h>
#include <util/string.h>
#include <net.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <string>

using namespace std::literals;
using node::NodeContext;

static NetGroupManager EMPTY_NETGROUPMAN{std::vector<bool>()};
static const bool DETERMINISTIC{true};

static int32_t GetCheckRatio(const NodeContext& node_ctx)
{
    return std::clamp<int32_t>(node_ctx.args->GetIntArg("-checkaddrman", 100), 0, 1000000);
}

static CService ResolveService(const std::string& ip, uint16_t port = 0)
{
    CService serv;
    BOOST_CHECK_MESSAGE(Lookup(ip, serv, port, false), strprintf("failed to resolve: %s:%i", ip, port));
    return serv;
}

static CAddress CreateRandomAddr(FastRandomContext& fast_random_context, Network net)
{
    switch (net) {

    case Network::NET_IPV4:
    {
        const auto addr_str = strprintf("%i.%i.%i.%i", fast_random_context.randrange(255), fast_random_context.randrange(255), fast_random_context.randrange(255), fast_random_context.randrange(255));
        //std::string addr_str = fast_random_context.randrange(255) + "." + fast_random_context.randrange(255) + "." + fast_random_context.randrange(255) + "." + fast_random_context.randrange(255);
        CAddress addr{ResolveService(addr_str, 8333), NODE_NONE};
        return addr;
    }
    case Network::NET_ONION:
    {
        CAddress addr;
        addr.nTime = Now<NodeSeconds>();
        auto tor_addr{fast_random_context.randbytes(ADDR_TORV3_SIZE)};
        BOOST_REQUIRE(addr.SetSpecial(OnionToString(tor_addr)));
        return addr;
    }
    case Network::NET_I2P:
    {
        CAddress addr;
        addr.nTime = Now<NodeSeconds>();
        auto tor_addr{fast_random_context.randbytes(ADDR_I2P_SIZE)};
        BOOST_REQUIRE(addr.SetSpecial(EncodeBase32(tor_addr, false /* don't pad with = */) + ".b32.i2p"));
        return addr;
    }
    case Network::NET_IPV6:
    {
        CAddress addr;
        addr.nTime = Now<NodeSeconds>();
        auto ipv6_addr = fast_random_context.randbytes(ADDR_IPV6_SIZE);
        BOOST_REQUIRE(LookupHost(IPv6ToString(ipv6_addr, 0), addr, false));
        return addr;
    }
    case Network::NET_CJDNS:
    {
        auto ipv6_addr = fast_random_context.randbytes(ADDR_CJDNS_SIZE);
        ipv6_addr[0] = 0xfc;
        auto addr_string = IPv6ToString(ipv6_addr, 0);
        CService serv;
        BOOST_REQUIRE(LookupHost(addr_string, serv, false));
        CAddress addr{MaybeFlipIPv6toCJDNS(serv), NODE_NONE};
        addr.nTime = Now<NodeSeconds>();
        return addr;
    }
    default:
        assert(false); //not implemented
        break;
    }
    return CAddress();
}

BOOST_FIXTURE_TEST_SUITE(mz_addr_tests, BasicTestingSetup)

// how many addresses can we add?
// IPv4: 60-64 buckets
// IPv6: 60-64 buckets
// onion: 12-16 buckets
// i2p: 12-16 buckets
// CJDNS: 12-16 buckets

// Explanation: hash1 in addrman has nKey, GetGroup(src) - which are both const here, and GetGroup(this) -> 16 possibilities for altnet, >64 possibilities for clearnet.
// hash 2 has nKey (const), GetGroup(src) (const), and hash1 as input => 16 possibilitites for altnet (4 bits)
// But hash1 is being taken modulo ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP - if some of its 16 values hash to the same modulo,
// they are treated the same, so the number varies a bit between runs.
BOOST_AUTO_TEST_CASE(one_source)
{
    Network net = NET_CJDNS;
    SetReachable(NET_CJDNS, true);
    auto addrman = std::make_unique<AddrMan>(EMPTY_NETGROUPMAN, !DETERMINISTIC, GetCheckRatio(m_node));
    FastRandomContext fast_random_context;

    CAddress source = CreateRandomAddr(fast_random_context, net);
    for (int i = 0; i < 20000; i++) {
        CAddress addr{CreateRandomAddr(fast_random_context, net)};
        addrman->Add({addr}, source);
    }
    auto addrman_size = addrman->Size(/*net=*/net, /*in_new=*/std::nullopt);
    BOOST_CHECK_EQUAL(addrman_size, addrman->Size() );
    std::cout << "Size:" << addrman_size << " | Buckets:" << addrman->NewBucketsUsed() << std::endl;
}

// IPv4: 1024 buckets (all)
// IPv6: 1024 buckets (all)
// onion: approx. 204 buckets -> it varies when addrman is made non-deterministic!
// i2p: 204 buckets
// CJDNS: 202 buckets
BOOST_AUTO_TEST_CASE(multi_source)
{
    Network net = NET_ONION;
    auto addrman = std::make_unique<AddrMan>(EMPTY_NETGROUPMAN, !DETERMINISTIC, GetCheckRatio(m_node));
    FastRandomContext fast_random_context;

    for (int i = 0; i < 100000; i++) {
        if(i%10000 == 0) std::cout << "MZ wait " << i << std::endl;
        CAddress addr{CreateRandomAddr(fast_random_context, net)};
        CAddress source{CreateRandomAddr(fast_random_context, net)};
        addrman->Add({addr}, source);
    }
    auto addrman_size = addrman->Size(/*net=*/net, /*in_new=*/std::nullopt);
    BOOST_CHECK_EQUAL(addrman_size, addrman->Size() );
    std::cout << "Size:" << addrman_size << " | Buckets:" << addrman->NewBucketsUsed() << std::endl;
}


BOOST_AUTO_TEST_CASE(netgroup)
{
    FastRandomContext fast_random_context;
    NetGroupManager m_netgroupman{std::vector<bool>()}; // use /16
    Network net = NET_CJDNS;
    for (int i = 0; i < 100; i++) {
        CAddress addr{CreateRandomAddr(fast_random_context, net)};
        std::cout << addr.ToStringAddr() << std::endl;
        std::cout << HexStr(m_netgroupman.GetGroup(addr)) << std::endl;
    }
}

BOOST_AUTO_TEST_SUITE_END()
