// Copyright (c) 2019 The CommerceBlock Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "requestlist.h"
#include "policy/policy.h"
#include "util.h"

CRequestList::CRequestList(){;}
CRequestList::~CRequestList(){;}

std::pair<bool, CRequestList::baseIter> CRequestList::find(const uint256 &txid)
{
    boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
    baseIter it = base::find(txid);
    if (it != this->end()) {
        return std::make_pair(true, it);
    }
    return std::make_pair(false, this->end());
}

void CRequestList::clear()
{
    boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
    return base::clear();
}

void CRequestList::remove(const uint256 &txid)
{
    boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
    baseIter it = base::find(txid);
    if(it != this->end())
        base::erase(it);
}

CRequestList::base::size_type CRequestList::size()
{
    boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
    return base::size();
}

void CRequestList::add(const uint256 &txid, CRequest *req)
{
    boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
    base::insert(std::make_pair(txid, *req));
}

/** Load request bid from utxo set */
bool CRequestList::LoadBid(vector<CTxOut> outs, uint256 hash, uint32_t nHeight)
{
    txnouttype whichType;
    vector<vector<unsigned char>> vSolutions;
    for (const auto &out : outs) {
        if (out.nAsset.IsExplicit() && !IsPolicy(out.nAsset.GetAsset())
        && Solver(out.scriptPubKey, whichType, vSolutions) && whichType == TX_LOCKED_MULTISIG) {
            auto bid = CBid::FromSolutions(vSolutions);
            auto res = base::find(bid.hashRequest);
            if (res != this->end()) {
                // auction already finished
                if (res->second.nStartBlockHeight <= nHeight)
                    return false;
                // amount less than current auction price
                if (out.nValue.GetAmount() < res->second.GetAuctionPrice(nHeight))
                    return false;
                // stake lock expires before request end
                if ((int32_t)res->second.nEndBlockHeight > CScriptNum(vSolutions[0], true).getint())
                    return false;
                // max tickets filled
                if (res->second.vBids.size() >= res->second.nNumTickets)
                    return false;

                bid.SetBidHash(hash);
                res->second.AddBid(bid);
                return true;
            }
        }
    }
    return false;
}

/** Load request bids from utxo set */
bool CRequestList::LoadBids(CCoinsView *view, uint32_t nHeight)
{
    std::unique_ptr<CCoinsViewCursor> pcursor(view->Cursor());
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        uint256 key;
        CCoins coins;
        if (pcursor->GetKey(key) && pcursor->GetValue(coins)) {
            if (coins.vout.size() > 1){
                this->LoadBid(coins.vout, key, nHeight);
            }
        } else {
            return error("%s: unable to read value", __func__);
        }
        pcursor->Next();
    }
    return true;
}

/** Load request from utxo set */
bool CRequestList::LoadRequest(CTxOut out, uint256 hash, uint32_t nHeight)
{
    vector<vector<unsigned char>> vSolutions;
    txnouttype whichType;
    if (Solver(out.scriptPubKey, whichType, vSolutions) && whichType == TX_LOCKED_MULTISIG) {
        auto request = CRequest::FromSolutions(vSolutions);
        if (request.nEndBlockHeight >= nHeight) {
            this->add(hash, &request);
            return true;
        }
    }
    return false;
}

/** Load request list from utxo set */
bool CRequestList::Load(CCoinsView *view, uint32_t nHeight)
{
    std::unique_ptr<CCoinsViewCursor> pcursor(view->Cursor());
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        uint256 key;
        CCoins coins;
        if (pcursor->GetKey(key) && pcursor->GetValue(coins)) {
            if (coins.vout.size() == 1 && !coins.IsCoinBase() &&
            coins.vout[0].nAsset.IsExplicit() && coins.vout[0].nAsset.GetAsset() == permissionAsset) {
                this->LoadRequest(coins.vout[0], key, nHeight);
            }
        } else {
            return error("%s: unable to read value", __func__);
        }
        pcursor->Next();
    }
    return LoadBids(view, nHeight);
}

/** Remove any expired requests */
void CRequestList::RemoveExpired(uint32_t nHeight)
{
    for (auto it = this->begin(); it != this->cend();)
    {
        if (it->second.nEndBlockHeight < nHeight) {
            it = base::erase(it);
        }
        else {
            ++it;
        }
    }
}
