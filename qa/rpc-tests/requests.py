#!/usr/bin/env python3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

# Test for the guardnode system
# TODO: add more tests as work on this progresses
class GuardnodeTest(BitcoinTestFramework):
  def __init__(self):
    super().__init__()
    self.setup_clean_chain = True
    self.num_nodes = 2
    self.extra_args = [["-txindex=1 -initialfreecoins=50000000000000",
    "-permissioncoinsdestination=76a914bc835aff853179fa88f2900f9003bb674e17ed4288ac",
    "-initialfreecoinsdestination=76a914bc835aff853179fa88f2900f9003bb674e17ed4288ac"] for i in range(2)]

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
    self.nodes[0].generate(1)
    self.sync_all()
    assert(self.nodes[1].getbalance()["PERMISSION"] == 1000)

    # create new raw request transaction
    addr = self.nodes[1].getnewaddress()
    priv = self.nodes[1].dumpprivkey(addr)
    pubkey = self.nodes[1].validateaddress(addr)["pubkey"]
    unspent = self.nodes[1].listunspent()
    genesis = "867da0e138b1014173844ee0e4d557ff8a2463b14fcaeab18f6a63aa7c7e1d05"
    inputs = {"txid": unspent[0]["txid"], "vout": unspent[0]["vout"], "asset": unspent[0]["asset"]}
    outputs = {"decayConst": 10, "endBlockHeight": 20000, "fee": 1, "genesisBlockHash": genesis,
    "startBlockHeight": 10000, "tickets": 10, "value": unspent[0]["amount"]}

    # catch errror - missing pubkey from outputs
    try:
        tx = self.nodes[1].createrawrequesttx(inputs, outputs)
    except Exception as e:
        assert(e)

    # re create transaction again and add pubkey
    outputs = {"decayConst": 10, "endBlockHeight": 105, "fee": 1, "genesisBlockHash": genesis,
    "startBlockHeight": 100, "tickets": 10, "value": unspent[0]["amount"], "pubkey": pubkey}

    # send transaction
    tx = self.nodes[1].createrawrequesttx(inputs, outputs)
    signedtx = self.nodes[1].signrawtransaction(tx)
    txid = self.nodes[1].sendrawtransaction(signedtx["hex"])
    self.sync_all()
    self.nodes[0].generate(1)
    self.sync_all()
    assert(txid in self.nodes[0].getblock(self.nodes[0].getblockhash(self.nodes[0].getblockcount()))["tx"])

    # try send spend transaction
    inputs = {"txid": txid, "vout": 0, "sequence": 4294967294}
    fee = Decimal('0.0001')
    addr = self.nodes[1].getnewaddress()
    outputs = {addr: unspent[0]["amount"] - fee, "fee": fee}
    txSpend = self.nodes[1].createrawtransaction([inputs], outputs, self.nodes[1].getblockcount())
    signedTxSpend = self.nodes[1].signrawtransaction(txSpend)
    assert_equal(signedTxSpend["errors"][0]["error"], "Locktime requirement not satisfied")

    # # generate more blocks and try again
    # # CLTV signing not supported in bitcoin
    # self.nodes[0].generate(10)
    # txraw = self.nodes[1].getrawtransaction(txid, 1)
    # txSpend2 = self.nodes[1].createrawtransaction([inputs], outputs, self.nodes[1].getblockcount())
    # signedTxSpend2 = self.nodes[1].signrawtransaction(txSpend2,
    #     [{
    #         "txid": txid,
    #         "vout": 0,
    #         "scriptPubKey": txraw["vout"][0]["scriptPubKey"]["hex"],
    #         "amount": unspent[0]["amount"]
    #     }],
    #     [priv])
    # print(signedTxSpend2)
    # print(self.nodes[1].decoderawtransaction(signedTxSpend2["hex"]))
    # assert_equal(signedTxSpend2["errors"][0]["error"], "")

    return

if __name__ == '__main__':
  GuardnodeTest().main()
