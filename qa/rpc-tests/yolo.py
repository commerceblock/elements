#!/usr/bin/env python3
# Copyright (c) 2019 CommerceBlock developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import random

class YoloTest (BitcoinTestFramework):
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

        #print(self.nodes[0].listunspent())

        # self.nodes[0].importprivkey("cS29UJMQrpnee7UaUHo6NqJVpGr35TEqUDkKXStTnxSZCGUWavgE")
        # self.nodes[0].importprivkey("cND4nfH6g2SopoLk5isQ8qGqqZ5LmbK6YwJ1QnyoyMVBTs8bVNNd")
        # self.extra_args[1].append("-freezelistcoinsdestination=76a91474168445da07d331faabd943422653dbe19321cd88ac")
        # self.extra_args[1].append("-burnlistcoinsdestination=76a9142166a4cd304b86db7dfbbc7309131fb0c4b645cd88ac")

        address_node1 = self.nodes[0].getnewaddress()
        val_addr_node1 = self.nodes[0].validateaddress(address_node1)
        privkey_node1 = self.nodes[0].dumpprivkey(address_node1)

        address_node2 =self.nodes[1].getnewaddress()
        val_addr_node2 = self.nodes[1].validateaddress(address_node2)
        privkey_node2 =self.nodes[1].dumpprivkey(address_node2)

        #create 2 of 3 multisig P2SH script and address
        multisig = self.nodes[0].createmultisig(1,[val_addr_node1["pubkey"],val_addr_node2["pubkey"]])
        print(multisig)
        print(self.nodes[0].sendtoaddress(multisig['address'], 100))
        self.nodes[0].generate(1)
        self.sync_all()
        print(self.nodes[1].listunspent())
        print(self.nodes[1].validateaddress(multisig['address']))
        print(self.nodes[1].importaddress(multisig['redeemScript'], "", True, True))
        print(self.nodes[1].listunspent())
        print(self.nodes[1].getbalance("", 1, True))
        print(self.nodes[1].validateaddress(multisig['address']))
        print(self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), 10))

        # want to send - all ?





if __name__ == '__main__':
    YoloTest().main()
