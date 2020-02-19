#!/usr/bin/env python3
# Copyright (c) 2016 The Bitcoin Core developers
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class HardforkDisable (BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.extra_args = [['-txindex'] for i in range(3)]
        self.extra_args[0].append("-recordinflation=1")

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, self.extra_args[:3])
        connect_nodes_bi(self.nodes,0,1)
        connect_nodes_bi(self.nodes,1,2)
        connect_nodes_bi(self.nodes,0,2)
        self.is_network_split=False
        self.sync_all()

    def run_test(self):
        print("Mining blocks...")
        self.nodes[0].generate(10)

        #Set all OP_TRUE genesis outputs to single node
        self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), 21000000, "", "", True)
        self.nodes[0].generate(6)
        self.sync_all()

        #issue new asset with re-issuance token
        asset1 = self.nodes[0].issueasset(Decimal('1000.0'),Decimal('1.0'))
        self.nodes[0].generate(10)
        self.sync_all()

        #check UTXO report on different node
        stats1 = self.nodes[1].getutxoassetinfo()
        iter = 0
        for assetstats in stats1:
            if asset1["asset"] == assetstats["asset"]:
                assert_equal(assetstats["amountspendable"], Decimal('1000.0'))
                assert_equal(assetstats["amountfrozen"], Decimal('0.0'))
                iter += 1
            if asset1["token"] == assetstats["asset"]:
                assert_equal(assetstats["amountspendable"], Decimal('1.0'))
                assert_equal(assetstats["amountfrozen"], Decimal('0.0'))
                iter += 1
        assert(iter == 2)

        #transact in the issued asset
        addr1 = self.nodes[1].getnewaddress()
        addr2 = self.nodes[2].getnewaddress()
        self.nodes[0].sendtoaddress(addr1,Decimal('20.0')," "," ",False,asset1["asset"],True)
        self.nodes[0].generate(10)
        self.sync_all()
        self.nodes[0].sendtoaddress(addr2,Decimal('30.0')," "," ",False,asset1["asset"],True)
        self.nodes[0].generate(10)
        self.sync_all()

        #check that the total amounts are the same
        stats2 = self.nodes[1].getutxoassetinfo()
        iter = 0
        for assetstats in stats2:
            if asset1["asset"] == assetstats["asset"]:
                assert_equal(assetstats["amountspendable"], Decimal('1000.0'))
                assert_equal(assetstats["amountfrozen"], Decimal('0.0'))
                iter +=1
            if asset1["token"] == assetstats["asset"]:
                assert_equal(assetstats["amountspendable"], Decimal('1.0'))
                assert_equal(assetstats["amountfrozen"], Decimal('0.0'))
                iter +=1
        assert(iter == 2)

        # get the txid+n of an output

        txid_disable = self.nodes[1].listunspent()[0]["txid"]
        n_out = self.nodes[1].listunspent()[0]["vout"]

        #Restart node
        self.stop_node(0)
        self.stop_node(1)
        self.stop_node(2)
        time.sleep(2)

        bConnected=True
        try:
            self.nodes[0].getnewaddress()
        except ConnectionRefusedError as e:
            bConnected=False

        assert_equal(bConnected, False)

        #set the disabled output hardfork param
        for iter in range(3):
            self.extra_args[iter].append("-disabledoutput="+txid_disable+":"+str(n_out))

        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, self.extra_args[:3])
        time.sleep(1)
        connect_nodes_bi(self.nodes,0,1)
        connect_nodes_bi(self.nodes,1,2)
        connect_nodes_bi(self.nodes,0,2)

        self.sync_all()
        self.nodes[0].generate(10)
        self.sync_all()

        stats2 = self.nodes[1].getutxoassetinfo()
        iter = 0
        for assetstats in stats2:
            if asset1["asset"] == assetstats["asset"]:
                assert_equal(assetstats["amountspendable"], Decimal('980.0'))
                assert_equal(assetstats["amountfrozen"], Decimal('0.0'))
                iter +=1
            if asset1["token"] == assetstats["asset"]:
                assert_equal(assetstats["amountspendable"], Decimal('1.0'))
                assert_equal(assetstats["amountfrozen"], Decimal('0.0'))
                iter +=1
        assert(iter == 2)

        addr3 = self.nodes[2].getnewaddress()
        send = self.nodes[1].sendtoaddress(addr3,Decimal('20.0')," "," ",True,asset1["asset"],True)        

        self.nodes[0].generate(10)
        self.sync_all()

        try:
            self.nodes[1].getrawtransaction(send,True)
        except:
            rejected = True
        else:
            rejected = False

        assert(rejected)


if __name__ == '__main__':
    HardforkDisable ().main ()
