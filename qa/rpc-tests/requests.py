#!/usr/bin/env python3
# Copyright (c) 2019 CommerceBlock developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

# Test for the request covalence system
class RequestsTest(BitcoinTestFramework):
  def __init__(self):
    super().__init__()
    self.setup_clean_chain = True
    self.num_nodes = 2
    self.extra_args = [["-txindex=1 -initialfreecoins=50000000000000", "-policycoins=50000000000000",
    "-permissioncoinsdestination=76a914bc835aff853179fa88f2900f9003bb674e17ed4288ac",
    "-initialfreecoinsdestination=76a914bc835aff853179fa88f2900f9003bb674e17ed4288ac"] for i in range(2)]
    self.extra_args[1].append("-requestlist=1")

  def setup_network(self, split=False):
    self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                             self.extra_args[:self.num_nodes])
    connect_nodes_bi(self.nodes, 0, 1)
    self.is_network_split = False
    self.sync_all()

  def run_test(self):
    self.nodes[0].importprivkey("cTnxkovLhGbp7VRhMhGThYt8WDwviXgaVAD8DjaVa5G5DApwC6tF")
    self.nodes[0].generate(101)
    self.sync_all()

    # send PERMISSION asset to node 1
    self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 1000, "", "", False, "PERMISSION")
    self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 1000, "", "", False, "PERMISSION")
    self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 1000, "", "", False, "PERMISSION")
    self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 1000, "", "", False, "PERMISSION")
    self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 1000, "", "", False, "CBT")
    self.nodes[0].generate(1)
    self.sync_all()
    assert(self.nodes[1].getbalance()["PERMISSION"] == 4000)

    genhash = self.nodes[0].getblockhash(0)
    genblock = self.nodes[0].getblock(genhash)
    foundPermission = False

    for txid in genblock["tx"]:
        rawtx = self.nodes[0].getrawtransaction(txid,True)
        if "assetlabel" in rawtx["vout"][0]:
            if rawtx["vout"][0]["assetlabel"] == "PERMISSION":
                foundPermission = True
                break

    assert(foundPermission)

    # test create request with incorrect asset
    addr = self.nodes[1].getnewaddress()
    priv = self.nodes[1].dumpprivkey(addr)
    pubkey = self.nodes[1].validateaddress(addr)["pubkey"]
    unspent = self.nodes[1].listunspent(1, 9999999, [], True, "CBT")
    genesis = "867da0e138b1014173844ee0e4d557ff8a2463b14fcaeab18f6a63aa7c7e1d05"
    genesis2 = "967da0e138b1014173844ee0e4d557ff8a2463b14fcaeab18f6a63aa7c7e1d05"
    inputs = {"txid": unspent[0]["txid"], "vout": unspent[0]["vout"]}
    outputs = {"decayConst": 10, "endBlockHeight": 20000, "fee": 1, "genesisBlockHash": genesis,
    "startBlockHeight": 10000, "tickets": 10, "startPrice": 5, "value": unspent[0]["amount"], "pubkey": pubkey}

    # catch errror - missing pubkey from outputs
    try:
        tx = self.nodes[1].createrawrequesttx(inputs, outputs)
        signedtx = self.nodes[1].signrawtransaction(tx)
        self.nodes[1].sendrawtransaction(signedtx["hex"])
    except JSONRPCException as e:
        assert("bad-txns-in-ne-out" in e.error['message'])

    # create new raw request transaction with missing details
    unspent = self.nodes[1].listunspent(1, 9999999, [], True, "PERMISSION")
    inputs = {"txid": unspent[0]["txid"], "vout": unspent[0]["vout"]}
    inputs2 = {"txid": unspent[1]["txid"], "vout": unspent[1]["vout"]}
    inputs_sim = {"txid": unspent[2]["txid"], "vout": unspent[2]["vout"]}
    outputs = {"decayConst": 10, "endBlockHeight": 20000, "fee": 1, "genesisBlockHash": genesis,
    "startBlockHeight": 10000, "tickets": 10, "startPrice": 5, "value": unspent[0]["amount"]}

    # catch errror - missing pubkey from outputs
    try:
        tx = self.nodes[1].createrawrequesttx(inputs, outputs)
    except Exception as e:
        assert(e)

    # re create transaction again and add pubkey
    outputs = {"decayConst": 10, "endBlockHeight": 118, "fee": 1, "genesisBlockHash": genesis,
    "startBlockHeight": 110, "tickets": 10, "startPrice": 5, "value": unspent[0]["amount"], "pubkey": pubkey}
    outputs2 = {"decayConst": 5, "endBlockHeight": 125, "fee": 3, "genesisBlockHash": genesis2,
    "startBlockHeight": 111, "tickets": 5, "startPrice": 5, "value": unspent[1]["amount"], "pubkey": pubkey}
    outputs_sim = {"decayConst": 10, "endBlockHeight": 150, "fee": 1, "genesisBlockHash": genesis,
    "startBlockHeight": 105, "tickets": 10, "startPrice": 5, "value": unspent[2]["amount"], "pubkey": pubkey}

    # send transaction
    tx = self.nodes[1].createrawrequesttx(inputs, outputs)
    signedtx = self.nodes[1].signrawtransaction(tx)
    txid = self.nodes[1].sendrawtransaction(signedtx["hex"])
    tx2 = self.nodes[1].createrawrequesttx(inputs2, outputs2)
    signedtx2 = self.nodes[1].signrawtransaction(tx2)
    txid2 = self.nodes[1]. sendrawtransaction(signedtx2["hex"])
    self.sync_all()
    self.nodes[0].generate(1)
    self.sync_all()
    assert(txid in self.nodes[0].getblock(self.nodes[0].getblockhash(self.nodes[0].getblockcount()))["tx"])
    assert(txid2 in self.nodes[0].getblock(self.nodes[0].getblockhash(self.nodes[0].getblockcount()))["tx"])

    # Check transactions added to wallets unspent list after importing redeem script
    redeemScript = self.nodes[1].decoderawtransaction(tx)["vout"][0]["scriptPubKey"]["hex"]
    redeemScript2 = self.nodes[1].decoderawtransaction(tx2)["vout"][0]["scriptPubKey"]["hex"]
    numSpendables=len(self.nodes[1].listunspent())
    self.nodes[1].importaddress(redeemScript)
    self.nodes[1].importaddress(redeemScript2)
    assert(numSpendables+2 == len(self.nodes[1].listunspent()))

    # test get request method with/without genesis hash parameter
    requests = self.nodes[0].getrequests()
    assert_equal(2, len(self.nodes[1].getrequests()))
    assert_equal(2, len(requests))
    for req in requests:
        if txid == req['txid']:
            assert_equal(req['endBlockHeight'], 118)
            assert_equal(req['genesisBlock'], genesis)
            assert_equal(req['numTickets'], 10)
            assert_equal(req['decayConst'], 10)
            assert_equal(req['feePercentage'], 1)
            assert_equal(req['startBlockHeight'], 110)
            assert_equal(req['confirmedBlockHeight'], 103)
            assert_equal(req['startPrice'], 5)
            assert(float(req['auctionPrice']) == 5)
        elif txid2 == req['txid']:
            assert(True)
        else:
            assert(False)
    requests = self.nodes[0].getrequests(genesis)
    assert_equal(self.nodes[1].getrequests(genesis), requests)
    assert_equal(1, len(requests))
    for req in requests:
        if txid == req['txid']:
            assert_equal(req['endBlockHeight'], 118)
            assert_equal(req['genesisBlock'], genesis)
            assert_equal(req['numTickets'], 10)
            assert_equal(req['decayConst'], 10)
            assert_equal(req['feePercentage'], 1)
            assert_equal(req['startBlockHeight'], 110)
            assert_equal(req['confirmedBlockHeight'], 103)
            assert_equal(req['startPrice'], 5)
            assert(float(req['auctionPrice']) == 5)
        else:
            assert(False)
    requests = self.nodes[0].getrequests(genesis2)
    assert_equal(self.nodes[1].getrequests(genesis2), requests)
    assert_equal(1, len(requests))
    for req in requests:
        if txid2 == req['txid']:
            assert_equal(req['endBlockHeight'], 125)
            assert_equal(req['genesisBlock'], genesis2)
            assert_equal(req['numTickets'], 5)
            assert_equal(req['decayConst'], 5)
            assert_equal(req['feePercentage'], 3)
            assert_equal(req['startBlockHeight'], 111)
            assert_equal(req['confirmedBlockHeight'], 103)
            assert_equal(req['startPrice'], 5)
            assert_equal(req['auctionPrice'], 5)
        else:
            assert(False)

    for req in requests:
        if txid2 == req['txid']:
            fulltr = self.nodes[0].getrawtransaction(req['txid'], True)
            foundRequest = False
            for tout in fulltr['vout']:
                if "request" in tout:
                    rawrequest = tout["request"]
                    assert_equal(req['endBlockHeight'], rawrequest['endBlockHeight'])
                    assert_equal(req['genesisBlock'], rawrequest['genesisBlock'])
                    assert_equal(req['numTickets'], rawrequest['numTickets'])
                    assert_equal(req['decayConst'], rawrequest['decayConst'])
                    assert_equal(req['feePercentage'], rawrequest['feePercentage'])
                    assert_equal(req['startBlockHeight'], rawrequest['startBlockHeight'])
                    assert_equal(req['confirmedBlockHeight'], rawrequest['confirmedBlockHeight'])
                    assert_equal(req['startPrice'], rawrequest['startPrice'])
                    assert_equal(req['auctionPrice'], rawrequest['auctionPrice'])
                    foundRequest = True
                    break
            assert(foundRequest)
        else:
            assert(False)

    requests = self.nodes[0].getrequests("123450e138b1014173844ee0e4d557ff8a2463b14fcaeab18f6a63aa7c7e1d05")
    assert_equal(self.nodes[1].getrequests("123450e138b1014173844ee0e4d557ff8a2463b14fcaeab18f6a63aa7c7e1d05"), [])
    assert_equal(requests, [])

    # add another request that coincides with the first request
    tx_sim = self.nodes[1].createrawrequesttx(inputs_sim, outputs_sim)
    signedtx_sim = self.nodes[1].signrawtransaction(tx_sim)
    txid_sim = self.nodes[1].sendrawtransaction(signedtx_sim["hex"])
    self.sync_all()
    self.nodes[0].generate(1)
    self.sync_all()
    assert(txid_sim in self.nodes[0].getblock(self.nodes[0].getblockhash(self.nodes[0].getblockcount()))["tx"])

    #test stopping and restarting to make sure list is reloaded
    self.stop_node(1)
    self.nodes[1] = start_node(1, self.options.tmpdir, self.extra_args[1])
    assert_equal(3, len(self.nodes[1].getrequests()))
    assert_equal(self.nodes[1].getrequests(genesis), self.nodes[0].getrequests(genesis))
    assert_equal(self.nodes[1].getrequests(genesis2), self.nodes[0].getrequests(genesis2))
    connect_nodes_bi(self.nodes, 0, 1)
    self.sync_all()

    # try send spend transcation
    inputs = {"txid": txid, "vout": 0, "sequence": 4294967294}
    addr = self.nodes[1].getnewaddress()
    outputs = {addr: unspent[0]["amount"]}
    assets = {addr: unspent[0]["asset"]}
    txSpend = self.nodes[1].createrawtransaction([inputs], outputs, self.nodes[1].getblockcount(), assets)
    signedTxSpend = self.nodes[1].signrawtransaction(txSpend)
    assert_equal(signedTxSpend["errors"][0]["error"], "Locktime requirement not satisfied")

    # make request 1 inactive
    self.nodes[0].generate(15)
    self.sync_all()
    requests = self.nodes[0].getrequests()
    assert_equal(requests, self.nodes[1].getrequests())
    assert_equal(2, len(requests))
    for req in requests:
        if txid2 == req['txid']:
            assert_equal(req['endBlockHeight'], 125)
            assert_equal(req['genesisBlock'], genesis2)
            assert_equal(req['numTickets'], 5)
            assert_equal(req['decayConst'], 5)
            assert_equal(req['feePercentage'], 3)
            assert_equal(req['startBlockHeight'], 111)
            assert_equal(req['confirmedBlockHeight'], 103)
            assert_equal(req['startPrice'], 5)
            assert(float(req['auctionPrice']) == 0.40394973)
    requests = self.nodes[0].getrequests(genesis2)
    assert_equal(self.nodes[1].getrequests(genesis2), requests)
    assert_equal(1, len(requests))
    for req in requests:
        if txid2 == req['txid']:
            assert_equal(req['endBlockHeight'], 125)
            assert_equal(req['genesisBlock'], genesis2)
            assert_equal(req['numTickets'], 5)
            assert_equal(req['decayConst'], 5)
            assert_equal(req['feePercentage'], 3)
            assert_equal(req['startBlockHeight'], 111)
            assert_equal(req['confirmedBlockHeight'], 103)
            assert_equal(req['startPrice'], 5)
            assert(float(req['auctionPrice']) == 0.40394973)

    # spend previously locked transaction
    txSpend = self.nodes[1].createrawtransaction([inputs], outputs, self.nodes[1].getblockcount(), assets)
    signedTxSpend = self.nodes[1].signrawtransaction(txSpend)
    txidSpend = self.nodes[1].sendrawtransaction(signedTxSpend["hex"])

    # try spend second transaction
    inputs2 = {"txid": txid2, "vout": 0, "sequence": 4294967294}
    addr2 = self.nodes[1].getnewaddress()
    outputs2 = {addr2: unspent[1]["amount"]}
    assets2 = {addr2: unspent[1]["asset"]}
    txSpend2 = self.nodes[1].createrawtransaction([inputs2], outputs2, self.nodes[1].getblockcount(), assets2)
    signedTxSpend2 = self.nodes[1].signrawtransaction(txSpend2)
    assert_equal(signedTxSpend2["errors"][0]["error"], "Locktime requirement not satisfied")

    # make request 2 inactive
    self.sync_all()
    self.nodes[0].generate(10)
    self.sync_all()

    assert_equal(1, len(self.nodes[0].getrequests()))
    assert_equal(1, len(self.nodes[1].getrequests()))
    assert(self.nodes[1].getbalance()["PERMISSION"] == 2000)

    # send second transaction
    txSpend2 = self.nodes[1].createrawtransaction([inputs2], outputs2, self.nodes[1].getblockcount(), assets2)
    signedTxSpend2 = self.nodes[1].signrawtransaction(txSpend2)
    txidSpend2 = self.nodes[1].sendrawtransaction(signedTxSpend2["hex"])

    self.sync_all()
    self.nodes[0].generate(1)
    self.sync_all()
    assert(self.nodes[1].getbalance()["PERMISSION"] == 3000)

    # test getRequest with/without inAuction parameter set to true
    # create new raw request transaction
    inputs = {"txid": unspent[3]["txid"], "vout": unspent[3]["vout"]}
    outputs = {"decayConst": 10, "endBlockHeight": 150, "fee": 1, "genesisBlockHash": genesis,
    "startBlockHeight": 140, "tickets": 10, "startPrice": 5, "value": unspent[3]["amount"], "pubkey": pubkey}
    tx = self.nodes[1].createrawrequesttx(inputs, outputs)
    signedtx = self.nodes[1].signrawtransaction(tx)
    txid = self.nodes[1].sendrawtransaction(signedtx["hex"])
    self.sync_all()
    self.nodes[0].generate(1)
    self.sync_all()

    # test request tx in auction phase
    assert_equal(2, len(self.nodes[0].getrequests()))
    assert_equal(2, len(self.nodes[1].getrequests()))
    assert_equal(1, len(self.nodes[0].getrequests("",True)))
    assert_equal(1, len(self.nodes[1].getrequests("",True)))
    self.sync_all()
    self.nodes[0].generate(15) # move request into service period
    self.sync_all()
    assert_equal(2, len(self.nodes[0].getrequests()))
    assert_equal(2, len(self.nodes[1].getrequests()))
    assert_equal(0, len(self.nodes[0].getrequests("",True)))
    assert_equal(0, len(self.nodes[1].getrequests("",True)))
    self.sync_all()
    self.nodes[0].generate(5) # move requests out of service period and out of valid period
    self.sync_all()
    assert_equal(0, len(self.nodes[0].getrequests()))
    assert_equal(0, len(self.nodes[1].getrequests()))
    assert_equal(0, len(self.nodes[0].getrequests("",True)))
    assert_equal(0, len(self.nodes[1].getrequests("",True)))

    return

if __name__ == '__main__':
  RequestsTest().main()
