// Copyright (c) 2019 The CommerceBlock Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OCEAN_REQUEST_H
#define OCEAN_REQUEST_H

#include "version.h"
#include "streams.h"
#include "uint256.h"
#include "pubkey.h"
#include "amount.h"
#include "script/script.h"

using namespace std;

/** Class for service request winning bids */
class CBid {
public:
    uint256 hashRequest;
    CPubKey feePubKey;

    uint256 hashBid;
    void SetBidHash(const uint256 &hash) { hashBid = hash; };

    static CBid FromSolutions(const vector<vector<unsigned char>> &vSolutions)
    {
        CBid bid;
        char pubInt;
        CDataStream output3(vSolutions[3], SER_NETWORK, PROTOCOL_VERSION);
        output3 >> pubInt;
        output3 >> bid.hashRequest;
        bid.feePubKey = CPubKey(vSolutions[4]);
        return bid;
    }
};

/** Class for service requests */
class CRequest {
public:
    uint32_t nNumTickets;
    uint32_t nDecayConst;
    uint32_t nFeePercentage;
    uint32_t nStartBlockHeight;
    uint32_t nEndBlockHeight;
    uint256 hashGenesis;
    CAmount nStartPrice;

    vector<CBid> vBids;
    void AddBid(const CBid &bid) { vBids.push_back(bid); };

    static CRequest FromSolutions(const vector<vector<unsigned char>> &vSolutions)
    {
        CRequest request;
        request.nEndBlockHeight = CScriptNum(vSolutions[0], true).getint();
        char pubInt;
        CDataStream output3(vSolutions[3], SER_NETWORK, PROTOCOL_VERSION);
        output3 >> pubInt;
        output3 >> request.hashGenesis;
        CDataStream output4(vSolutions[4], SER_NETWORK, PROTOCOL_VERSION);
        output4 >> pubInt;
        output4 >> request.nStartBlockHeight;
        output4 >> request.nNumTickets;
        output4 >> request.nDecayConst;
        output4 >> request.nFeePercentage;
        output4 >> request.nStartPrice;
        return request;
    }
};

#endif // OCEAN_REQUEST_H
