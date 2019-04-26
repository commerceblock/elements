#!/usr/bin/env python3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

# Test for the request bids of the covalence system
class RequestBidsTest(BitcoinTestFramework):
  def __init__(self):
    super().__init__()
    self.setup_clean_chain = True
    self.num_nodes = 2
    self.extra_args = [["-txindex=1 -initialfreecoins=50000000000000",
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

    asset = self.nodes[0].issueasset(500, 0)
    asset_hash = asset['asset']
    self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 50, "", "", False, asset_hash)
    self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 50, "", "", False, asset_hash)
    self.nodes[0].generate(1)
    self.sync_all()
    assert_equal(100, self.nodes[1].getbalance()[asset_hash])

    # test create raw bid transaction
    addr = self.nodes[1].getnewaddress()
    addrFee = self.nodes[1].getnewaddress()
    priv = self.nodes[1].dumpprivkey(addr)
    pubkey = self.nodes[1].validateaddress(addr)["pubkey"]
    pubkeyFee = self.nodes[1].validateaddress(addrFee)["pubkey"]
    unspent = self.nodes[1].listunspent(1, 9999999, [], True, asset_hash)
    requestTxid = "666d55514441333122241110000557ff8a2463b14fcaeab18f6a63aa7c7e1d05"
    inputs = {"txid": unspent[0]["txid"], "vout": unspent[0]["vout"], "asset": asset_hash}
    fee = Decimal('0.0001')
    outputs = {"pubkey": pubkey, "requestTxid": requestTxid, "feePubkey": pubkeyFee,
        "fee": fee, "value": unspent[0]["amount"] - fee, "endBlockHeight": 105}

    tx = self.nodes[1].createrawbidtx(inputs, outputs)
    signedtx = self.nodes[1].signrawtransaction(tx)
    txid = self.nodes[1].sendrawtransaction(signedtx['hex'])

    self.sync_all()
    self.nodes[0].generate(1)
    self.sync_all()
    assert_equal(50, self.nodes[1].getbalance()[asset_hash])

    # try send spend transaction
    inputPrev = {"txid": txid, "vout": 0, "sequence": 4294967294}
    addr = self.nodes[1].getnewaddress()
    txSpend = self.nodes[1].createrawtransaction([inputPrev], {addr: unspent[0]["amount"]}, self.nodes[1].getblockcount(), {addr: asset_hash})
    signedTxSpend = self.nodes[1].signrawtransaction(txSpend)
    assert_equal(signedTxSpend["errors"][0]["error"], "Locktime requirement not satisfied")

    # make bid inactive and spend again
    self.nodes[0].generate(10)
    self.sync_all()

    # need to add another input to pay for fees
    inputFee = {"txid": unspent[1]["txid"], "vout": unspent[1]["vout"]}
    addrChange = self.nodes[1].getnewaddress()
    txSpend = self.nodes[1].createrawtransaction([inputPrev, inputFee],
        {addr: unspent[1]["amount"] - fee, addrChange: unspent[1]["amount"] - fee, "fee": fee},
        self.nodes[1].getblockcount(),
        {addr: asset_hash, addrChange: asset_hash, "fee": asset_hash})
    signedTxSpend = self.nodes[1].signrawtransaction(txSpend)
    txidSpend = self.nodes[1].sendrawtransaction(signedTxSpend["hex"])

    self.sync_all()
    self.nodes[0].generate(1)
    self.sync_all()
    assert_equal(Decimal('99.99980000'), self.nodes[1].getbalance()[asset_hash])

    return

if __name__ == '__main__':
  RequestBidsTest().main()
