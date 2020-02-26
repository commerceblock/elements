#!/usr/bin/env python3
# Copyright (c) 2018-19 CommerceBlock developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class Hardfork (BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.extra_args = [['-issuanceblock'] for i in range(4)]
        self.extra_args[0].append("-txindex")
        self.extra_args[0].append("-policycoins=50000000000000")
        self.extra_args[0].append("-issuancecoinsdestination=76a914bc835aff853179fa88f2900f9003bb674e17ed4288ac")
        self.extra_args[0].append("-signblockscript=512103c4ef1e6deaccbe3b5125321c9ae35966effd222c7d29fb7a13d47fb45ebcb7bf51ae")
        self.extra_args[0].append("-regtest=0")
        self.extra_args[0].append("-con_mandatorycoinbase=512103d81e135e96a8af1e9def5abc14fca971dde478ee9e28eb9eb0df6c750e03fc5551ae")
        self.extra_args[0].append("-coinbasechange=a914c0c2f77663b67e4c6c1b217b5c866095a800839f87:10")
        self.extra_args[0].append("-coinbasechange=76a9143e6b9f66eeb139c693cc8148285133a5ea96f66488ac:22")
        self.extra_args[0].append("-signblockscriptchange=512102fd5b53b1b2b9f3c71ff5b33458129ca77f8c320513a374179c73fa7243cd112051ae:15")
        self.extra_args[0].append("-signblockscriptchange=512103ceb619517539ea81e71fc67aa61a835a396b169e8df62ef66b828a01aeb530d651ae:35")
        self.extra_args[1].append("-txindex")
        self.extra_args[1].append("-policycoins=50000000000000")
        self.extra_args[1].append("-issuancecoinsdestination=76a914bc835aff853179fa88f2900f9003bb674e17ed4288ac")
        self.extra_args[1].append("-signblockscript=512103c4ef1e6deaccbe3b5125321c9ae35966effd222c7d29fb7a13d47fb45ebcb7bf51ae")
        self.extra_args[1].append("-regtest=0")
        self.extra_args[1].append("-con_mandatorycoinbase=512103d81e135e96a8af1e9def5abc14fca971dde478ee9e28eb9eb0df6c750e03fc5551ae")
        self.extra_args[1].append("-coinbasechange=a914c0c2f77663b67e4c6c1b217b5c866095a800839f87:10")
        self.extra_args[1].append("-coinbasechange=76a9143e6b9f66eeb139c693cc8148285133a5ea96f66488ac:22")
        self.extra_args[1].append("-signblockscriptchange=512102fd5b53b1b2b9f3c71ff5b33458129ca77f8c320513a374179c73fa7243cd112051ae:15")
        self.extra_args[1].append("-signblockscriptchange=512103ceb619517539ea81e71fc67aa61a835a396b169e8df62ef66b828a01aeb530d651ae:35")
        self.extra_args[2].append("-txindex")
        self.extra_args[2].append("-policycoins=50000000000000")
        self.extra_args[2].append("-issuancecoinsdestination=76a914bc835aff853179fa88f2900f9003bb674e17ed4288ac")
        self.extra_args[2].append("-signblockscript=512103c4ef1e6deaccbe3b5125321c9ae35966effd222c7d29fb7a13d47fb45ebcb7bf51ae")
        self.extra_args[2].append("-regtest=0")
        self.extra_args[2].append("-con_mandatorycoinbase=512103d81e135e96a8af1e9def5abc14fca971dde478ee9e28eb9eb0df6c750e03fc5551ae")
        self.extra_args[2].append("-coinbasechange=a914c0c2f77663b67e4c6c1b217b5c866095a800839f87:10")
        self.extra_args[2].append("-coinbasechange=76a9143e6b9f66eeb139c693cc8148285133a5ea96f66488ac:22")
        self.extra_args[2].append("-signblockscriptchange=512102fd5b53b1b2b9f3c71ff5b33458129ca77f8c320513a374179c73fa7243cd112051ae:15")
        self.extra_args[2].append("-signblockscriptchange=512103ceb619517539ea81e71fc67aa61a835a396b169e8df62ef66b828a01aeb530d651ae:35")

    def setup_network(self, split=False):
        self.nodes = start_nodes(3, self.options.tmpdir, self.extra_args[:3])
        connect_nodes_bi(self.nodes,0,1)
        connect_nodes_bi(self.nodes,1,2)
        connect_nodes_bi(self.nodes,0,2)
        self.is_network_split=False
        self.sync_all()

    def run_test (self):

        script1 = "512103c4ef1e6deaccbe3b5125321c9ae35966effd222c7d29fb7a13d47fb45ebcb7bf51ae"
        script2 = "512102fd5b53b1b2b9f3c71ff5b33458129ca77f8c320513a374179c73fa7243cd112051ae"
        script3 = "512103ceb619517539ea81e71fc67aa61a835a396b169e8df62ef66b828a01aeb530d651ae"

        coinbase1 = "512103d81e135e96a8af1e9def5abc14fca971dde478ee9e28eb9eb0df6c750e03fc5551ae"
        coinbase2 = "a914c0c2f77663b67e4c6c1b217b5c866095a800839f87"
        coinbase3 = "76a9143e6b9f66eeb139c693cc8148285133a5ea96f66488ac"

        # Check that there's 100 UTXOs on each of the nodes
        assert_equal(len(self.nodes[0].listunspent()), 100)
        assert_equal(len(self.nodes[1].listunspent()), 100)
        assert_equal(len(self.nodes[2].listunspent()), 100)

        self.nodes[0].importprivkey("cTnxkovLhGbp7VRhMhGThYt8WDwviXgaVAD8DjaVa5G5DApwC6tF")
        self.nodes[0].importprivkey("cN1gsj1XJkYdSAWPff3CKvBZgFhPDhfmUHChveFp7uiU5pkvSMZM")
        self.nodes[0].importprivkey("cNYwUgfJkgP4bJpBgHa8xywzM4HmctC1gmh6uJ5M9Z2WA8WJNKVN")
        self.nodes[0].importprivkey("cSi7ogC85vZfmrKPUMGCxom6ejR9EaLpBoMVZcujZh9BauyHWXe5")

        walletinfo = self.nodes[2].getbalance()
        assert_equal(walletinfo["CBT"], 21000000)

        print("Mining block 1")
        newblock = self.nodes[0].getnewblockhex()
        blocksig = self.nodes[0].signblock(newblock)
        signedblock = self.nodes[0].combineblocksigs(newblock,[blocksig])
        self.nodes[0].submitblock(signedblock["hex"])
        self.sync_all()

        asscript = "76a914bc835aff853179fa88f2900f9003bb674e17ed4288ac";

        assert_equal(self.nodes[0].getbalance("", 0, False, "CBT"), 21000000)
        assert_equal(self.nodes[1].getbalance("", 0, False, "CBT"), 21000000)
        assert_equal(self.nodes[2].getbalance("", 0, False, "CBT"), 21000000)

        #Set all OP_TRUE genesis outputs to single node
        self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 21000000, "", "", True)
        print("Mining block 2")
        newblock = self.nodes[0].getnewblockhex()
        blocksig = self.nodes[0].signblock(newblock)
        signedblock = self.nodes[0].combineblocksigs(newblock,[blocksig])
        self.nodes[0].submitblock(signedblock["hex"])
        self.sync_all()

        block = self.nodes[0].getblock(self.nodes[0].getblockhash(2))

        assert_equal(self.nodes[1].getbalance("", 0, False, "CBT"), Decimal("20999999.99915520"))
        assert_equal(self.nodes[0].getbalance("", 0, False, "CBT"), 0)
        assert_equal(self.nodes[2].getbalance("", 0, False, "CBT"), 0)

        block = self.nodes[0].getblock(self.nodes[0].getblockhash(2))
        script = self.nodes[0].decodescript(script1)
        assert_equal(block["bits"],script["asm"])

        coinbase = self.nodes[0].getrawtransaction(block["tx"][0],1)
        assert_equal(coinbase["vout"][0]["scriptPubKey"]["hex"],coinbase1)

        #mine 7 blocks
        for it in range(7):
            newblock = self.nodes[0].getnewblockhex()
            blocksig = self.nodes[0].signblock(newblock)
            signedblock = self.nodes[0].combineblocksigs(newblock,[blocksig])
            self.nodes[0].submitblock(signedblock["hex"])
            self.sync_all()

        self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), 100, "", "", True)
        self.sync_all()
        newblock = self.nodes[0].getnewblockhex()
        blocksig = self.nodes[0].signblock(newblock)
        signedblock = self.nodes[0].combineblocksigs(newblock,[blocksig])
        self.nodes[0].submitblock(signedblock["hex"])
        self.sync_all()

        block = self.nodes[0].getblock(self.nodes[0].getblockhash(10))
        script = self.nodes[0].decodescript(script1)
        assert_equal(block["bits"],script["asm"])

        coinbase = self.nodes[0].getrawtransaction(block["tx"][0],1)
        assert_equal(coinbase["vout"][0]["scriptPubKey"]["hex"],coinbase2)

        #mine 5 blocks
        for it in range(5):
            newblock = self.nodes[0].getnewblockhex()
            blocksig = self.nodes[0].signblock(newblock)
            signedblock = self.nodes[0].combineblocksigs(newblock,[blocksig])
            self.nodes[0].submitblock(signedblock["hex"])
            self.sync_all()

        block = self.nodes[0].getblock(self.nodes[0].getblockhash(15))
        script = self.nodes[0].decodescript(script2)
        assert_equal(block["bits"],script["asm"])

        #mine 6 blocks
        for it in range(6):
            newblock = self.nodes[0].getnewblockhex()
            blocksig = self.nodes[0].signblock(newblock)
            signedblock = self.nodes[0].combineblocksigs(newblock,[blocksig])
            self.nodes[0].submitblock(signedblock["hex"])
            self.sync_all()

        self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), 100, "", "", True)
        self.sync_all()
        newblock = self.nodes[0].getnewblockhex()
        blocksig = self.nodes[0].signblock(newblock)
        signedblock = self.nodes[0].combineblocksigs(newblock,[blocksig])
        self.nodes[0].submitblock(signedblock["hex"])
        self.sync_all()

        block = self.nodes[0].getblock(self.nodes[0].getblockhash(22))
        script = self.nodes[0].decodescript(script2)
        assert_equal(block["bits"],script["asm"])

        coinbase = self.nodes[0].getrawtransaction(block["tx"][0],1)
        assert_equal(coinbase["vout"][0]["scriptPubKey"]["hex"],coinbase3)

        #mine 15 blocks
        for it in range(15):
            newblock = self.nodes[0].getnewblockhex()
            blocksig = self.nodes[0].signblock(newblock)
            signedblock = self.nodes[0].combineblocksigs(newblock,[blocksig])
            self.nodes[0].submitblock(signedblock["hex"])
            self.sync_all()

        block = self.nodes[0].getblock(self.nodes[0].getblockhash(35))
        script = self.nodes[0].decodescript(script3)
        assert_equal(block["bits"],script["asm"])

        return

if __name__ == '__main__':
    Hardfork().main()
