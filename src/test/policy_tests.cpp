// Copyright (c) 2019 CommerceBlock developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/test_bitcoin.h"
#include "request.h"
#include "policy/policy.h"
#include "policy/requestlist.h"

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(policy_tests)

BOOST_FIXTURE_TEST_CASE(valid_request_test, TestChain100Setup)
{
    CRequest request;
    request.nEndBlockHeight = 100;
    BOOST_CHECK_EQUAL(false, IsValidRequest(request, 100));
    BOOST_CHECK_EQUAL(false, IsValidRequest(request, 101));
    BOOST_CHECK_EQUAL(true, IsValidRequest(request, 99));

    CKey key;
    CPubKey pubkey;
    key.MakeNewKey(true);
    pubkey = key.GetPubKey();
    CDataStream datapubkey2(SER_NETWORK, PROTOCOL_VERSION);
    datapubkey2 << (char)2; // pubkey prefix
    datapubkey2 << uint256();
    CDataStream datapubkey3(SER_NETWORK, PROTOCOL_VERSION);
    datapubkey3 << (char)3; // pubkey prefix
    datapubkey3 << 50; //startBlockHeight.get_int();
    datapubkey3 << 10; //ticket.get_int();
    datapubkey3 << 1000; //decayConst.get_int();
    datapubkey3 << 1;//fee.get_int();
    datapubkey3 << CAmount(100000);
    datapubkey3.resize(33);

    CScript s;
    s << 100 << OP_CHECKLOCKTIMEVERIFY << OP_DROP <<
        OP_1 <<
        ToByteVector(pubkey) <<
        ToByteVector(datapubkey2) <<
        ToByteVector(datapubkey3) <<
        OP_3 << OP_CHECKMULTISIG;

    CTxOut out(CAsset(), 1, s);
    auto someHash = uint256S("0xb4749f017444b051c44dfd2720e88f314ff94f3dd6d56d40ef65854fcd7fff6b");
    auto fGet = GetRequest(out, someHash, 10, request);
    BOOST_CHECK_EQUAL(true, fGet);
    BOOST_CHECK_EQUAL(false, IsValidRequest(request, 100));
    BOOST_CHECK_EQUAL(false, IsValidRequest(request, 101));
    BOOST_CHECK_EQUAL(true, IsValidRequest(request, 99));

    CRequestList list;
    BOOST_CHECK_EQUAL(false, list.LoadRequest(out, someHash, 100, 101));
    BOOST_CHECK_EQUAL(true, list.LoadRequest(out, someHash, 9, 10));
    BOOST_CHECK_EQUAL(true, list.find(someHash).first);
}

BOOST_FIXTURE_TEST_CASE(valid_requestbid_test, TestChain100Setup)
{
    CRequest request;
    request.nEndBlockHeight = 100;
    request.nStartBlockHeight = 50;
    request.nConfirmedBlockHeight = 10;
    request.nStartPrice = CAmount(40);
    request.nDecayConst = 10000;
    request.nNumTickets = 2;
    auto someHash = uint256S("0xb4749f017444b051c44dfd2720e88f314ff94f3dd6d56d40ef65854fcd7fff6b");

    BOOST_CHECK_EQUAL(40, request.GetAuctionPrice(10));
    BOOST_CHECK_EQUAL(38, request.GetAuctionPrice(30));

    CBid bid;
    bid.nLockBlockHeight = 100;
    bid.nStakePrice = CAmount(39);
    bid.nConfirmedBlockHeight = 10;
    BOOST_CHECK_EQUAL(false, IsValidRequestBid(request, bid));
    bid.nConfirmedBlockHeight = 30;
    BOOST_CHECK_EQUAL(true, IsValidRequestBid(request, bid));
    bid.nStakePrice = CAmount(38);
    bid.nConfirmedBlockHeight = 10;
    BOOST_CHECK_EQUAL(false, IsValidRequestBid(request, bid));
    bid.nConfirmedBlockHeight = 30;
    BOOST_CHECK_EQUAL(true, IsValidRequestBid(request, bid));

    bid.nStakePrice = CAmount(39);
    bid.nLockBlockHeight = 90;
    BOOST_CHECK_EQUAL(false, IsValidRequestBid(request, bid));
    bid.nLockBlockHeight = 100;

    bid.nConfirmedBlockHeight = 50;
    BOOST_CHECK_EQUAL(false, IsValidRequestBid(request, bid));

    CKey key;
    CPubKey pubkey;
    key.MakeNewKey(true);
    pubkey = key.GetPubKey();
    CKey key2;
    CPubKey pubkey2;
    key2.MakeNewKey(true);
    pubkey2 = key2.GetPubKey();
    CDataStream datapubkey2(SER_NETWORK, PROTOCOL_VERSION);
    datapubkey2 << (char)2; // pubkey prefix
    datapubkey2 << someHash;

    CScript s;
    s << 100 << OP_CHECKLOCKTIMEVERIFY << OP_DROP <<
        OP_1 <<
        ToByteVector(pubkey) <<
        ToByteVector(datapubkey2) <<
        ToByteVector(pubkey2) <<
        OP_3 << OP_CHECKMULTISIG;

    CRequestList list;
    list.add(someHash, &request);

    auto someAsset = "fa821b0be5e1387adbcb69dbb3ad33edb5e470831c7c938c4e7b344edbe8bb11";
    const CAsset exampleAsset = CAsset(uint256S(someAsset));
    CTxOut out(exampleAsset, 1, s);
    auto outHash = uint256S("0xaa749f017444b051c44dfd2720e88f314ff94f3dd6d56d40ef65854fcd7fff6b");
    vector<CTxOut> vOut{out};
    BOOST_CHECK_EQUAL(true, GetRequestBid(vOut, outHash, 30, bid));
    BOOST_CHECK_EQUAL(false, IsValidRequestBid(request, bid));
    BOOST_CHECK_EQUAL(false, list.LoadBid(vOut, outHash, 30));
    out = CTxOut(exampleAsset, 39, s);
    vOut[0] = out;
    BOOST_CHECK_EQUAL(true, GetRequestBid(vOut, outHash, 30, bid));
    BOOST_CHECK_EQUAL(true, IsValidRequestBid(request, bid));
    BOOST_CHECK_EQUAL(true, list.LoadBid(vOut, outHash, 30));

    auto outHash2 = uint256S("0xbb749f017444b051c44dfd2720e88f314ff94f3dd6d56d40ef65854fcd7fff6b");
    out = CTxOut(exampleAsset, 40, s);
    vOut[0] = out;
    BOOST_CHECK_EQUAL(true, list.LoadBid(vOut, outHash2, 30));

    auto outHash3 = uint256S("0xcc749f017444b051c44dfd2720e88f314ff94f3dd6d56d40ef65854fcd7fff6b");
    BOOST_CHECK_EQUAL(false, list.LoadBid(vOut, outHash3, 28));
    BOOST_CHECK_EQUAL(true, list.LoadBid(vOut, outHash3, 28, true));

    auto res = list.find(someHash);
    BOOST_CHECK_EQUAL(true, res.first);
    auto req = (*res.second).second;

    for (const auto &bid : req.sBids) {
        BOOST_CHECK(bid.hashBid == outHash || bid.hashBid == outHash3);
    }
}

BOOST_AUTO_TEST_SUITE_END()
