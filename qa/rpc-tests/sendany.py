#!/usr/bin/env python3
# Copyright (c) 2019 CommerceBlock developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class SendAnyTest (BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.extra_args = [['-usehd={:d}'.format(i%2==0)] for i in range(4)]
        self.extra_args[0].append("-txindex")
        self.extra_args[0].append("-policycoins=50000000000000")
        self.extra_args[0].append("-whitelistcoinsdestination=76a914427bf8530a3962ed77fd3c07d17fd466cb31c2fd88ac")
        self.extra_args[0].append("-initialfreecoinsdestination=76a914b87ed64e2613422571747f5d968fff29a466e24e88ac")
        self.extra_args[1].append("-txindex")
        self.extra_args[1].append("-policycoins=50000000000000")
        self.extra_args[1].append("-whitelistcoinsdestination=76a914427bf8530a3962ed77fd3c07d17fd466cb31c2fd88ac")
        self.extra_args[1].append("-initialfreecoinsdestination=76a914b87ed64e2613422571747f5d968fff29a466e24e88ac")
        self.extra_args[2].append("-txindex")
        self.extra_args[2].append("-policycoins=50000000000000")
        self.extra_args[2].append("-whitelistcoinsdestination=76a914427bf8530a3962ed77fd3c07d17fd466cb31c2fd88ac")
        self.extra_args[2].append("-initialfreecoinsdestination=76a914b87ed64e2613422571747f5d968fff29a466e24e88ac")
        self.extra_args[3].append("-txindex")
        self.extra_args[3].append("-policycoins=50000000000000")
        self.extra_args[3].append("-whitelistcoinsdestination=76a914427bf8530a3962ed77fd3c07d17fd466cb31c2fd88ac")
        self.extra_args[3].append("-initialfreecoinsdestination=76a914b87ed64e2613422571747f5d968fff29a466e24e88ac")

    def setup_network(self, split=False):
        self.nodes = start_nodes(4, self.options.tmpdir, self.extra_args[:4])
        connect_nodes_bi(self.nodes,0,1)
        connect_nodes_bi(self.nodes,1,2)
        connect_nodes_bi(self.nodes,0,2)
        connect_nodes_bi(self.nodes,3,0)
        connect_nodes_bi(self.nodes,3,1)
        connect_nodes_bi(self.nodes,3,2)
        self.is_network_split=False
        self.sync_all()

    def run_test (self):

        # Check that there's 100 UTXOs on each of the nodes
        self.nodes[0].importprivkey("cQRC9YB11Li3QHqyxMPff3uznfRggMUYdixctbyNdWdnNWr3koZy")
        self.nodes[1].importprivkey("cQRC9YB11Li3QHqyxMPff3uznfRggMUYdixctbyNdWdnNWr3koZy")
        self.nodes[2].importprivkey("cQRC9YB11Li3QHqyxMPff3uznfRggMUYdixctbyNdWdnNWr3koZy")
        assert_equal(len(self.nodes[0].listunspent()), 100)
        assert_equal(len(self.nodes[1].listunspent()), 100)
        assert_equal(len(self.nodes[2].listunspent()), 100)

        walletinfo = self.nodes[2].getbalance()
        assert_equal(walletinfo["CBT"], 21000000)

        # test sendany/createany does not work with policy assets
        self.nodes[3].importprivkey("cNCQhCnpnzyeYh48NszsTJC2G4HPoFMZguUnUgBpJ5X9Vf2KaPYx")
        assert_equal(self.nodes[3].getbalance(), {'WHITELIST': Decimal('500000.00000000')})
        try:
            self.nodes[3].sendanytoaddress(self.nodes[3].getnewaddress(), 100)
        except Exception as exp:
            assert("Insufficient funds for sendany" in exp.error['message'])
        try:
            self.nodes[3].createanytoaddress(self.nodes[3].getnewaddress(), 100)
        except JSONRPCException as exp:
            assert("Insufficient funds for sendany" in exp.error['message'])

        self.nodes[2].generate(101)
        self.sync_all()

        # Issue some assets to use for sendany different cases
        self.nodes[2].issueasset('5.0','0', False)
        self.nodes[2].generate(1)
        self.nodes[2].issueasset('4.99999999','0', False)
        self.nodes[2].generate(1)
        self.nodes[2].issueasset('0.00000001','0', False)
        self.nodes[2].generate(1)
        self.nodes[2].issueasset('4.0','0', False)
        self.nodes[2].generate(1)
        self.nodes[2].issueasset('2.0','0', False)
        self.nodes[2].generate(1)
        self.nodes[2].issueasset('1.0','0', False)
        self.nodes[2].generate(1)
        self.sync_all()

        self.nodes[2].sendtoaddress(self.nodes[1].getnewaddress(), self.nodes[2].getbalance()["CBT"], "", "", True, "CBT")
        assert_equal(self.nodes[1].getbalance("", 0, False, "CBT"), 20790000.00000000)
        assert_equal(self.nodes[2].getbalance("", 0, False, "CBT"), 0)
        self.nodes[2].generate(2)
        self.sync_all()
        # Get completely rid off CBT by sending also the coinbase fee of the previous tx
        tx = self.nodes[2].sendtoaddress(self.nodes[1].getnewaddress(), self.nodes[2].getbalance()["CBT"], "", "", True, "CBT")
        self.nodes[2].generate(1)
        self.sync_all()
        assert_equal(self.nodes[2].getbalance("", 0, False, "CBT"), 0)

        addr1 = self.nodes[1].getnewaddress();

        # Edge case where first asset is 5 and output is 5. Fee makes the asset go over the limit and an extra ones has to be chosen.
        tx = self.nodes[2].sendanytoaddress(addr1, 5, "", "", True, False)
        assert(tx in self.nodes[2].getrawmempool())
        self.nodes[2].generate(1)
        self.sync_all()

        # Descending asset balances for sendany selection
        # createany -> sign -> send should be equivalent to sendany
        txraw = self.nodes[2].createanytoaddress(addr1, 5.5, True, False, 1, False)
        txrawsigned = self.nodes[2].signrawtransaction(txraw[0])
        assert(txrawsigned['complete'])
        tx = self.nodes[2].sendrawtransaction(txrawsigned['hex'])
        assert(tx in self.nodes[2].getrawmempool())
        self.nodes[2].generate(1)
        self.sync_all()

        # Ascending asset balances for sendany selection
        tx = self.nodes[2].sendanytoaddress(addr1, 2.5, "", "", True, False, 2)
        assert(tx in self.nodes[2].getrawmempool())
        self.nodes[2].generate(1)
        self.sync_all()

        # Send all balance
        balance = 0
        for _, val in self.nodes[2].getbalance().items():
            balance += val
        tx = self.nodes[2].sendanytoaddress(addr1, balance - Decimal('0.0002'), "", "", True, False, 2)
        assert(tx in self.nodes[2].getrawmempool())
        self.nodes[2].generate(1)
        self.sync_all()

        # Issue some assets and send them to node 0 and 3
        issue = self.nodes[1].issueasset('10.0','0', False)
        self.nodes[1].generate(1)
        self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), 9, "", "", False, issue["asset"])
        self.nodes[1].generate(1)

        issue = self.nodes[1].issueasset('10.0','0', False)
        self.nodes[1].generate(1)
        self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), 9, "", "", False, issue["asset"])
        self.nodes[1].generate(1)
        self.sync_all()

        address_node1 = self.nodes[3].getnewaddress()
        val_addr_node1 = self.nodes[3].validateaddress(address_node1)
        privkey_node1 = self.nodes[3].dumpprivkey(address_node1)
        address_node2 =self.nodes[2].getnewaddress()
        val_addr_node2 = self.nodes[2].validateaddress(address_node2)
        privkey_node2 =self.nodes[2].dumpprivkey(address_node2)
        multisig = self.nodes[3].createmultisig(1,[val_addr_node1["pubkey"],val_addr_node2["pubkey"]])

        issue = self.nodes[1].issueasset('10.0','0', False)
        self.nodes[1].generate(1)
        self.nodes[1].sendtoaddress(multisig['address'], 9, "", "", False, issue["asset"])
        self.nodes[1].generate(1)

        issue = self.nodes[1].issueasset('10.0','0', False)
        self.nodes[1].generate(1)
        self.nodes[1].sendtoaddress(multisig['address'], 9, "", "", False, issue["asset"])
        self.nodes[1].generate(10)
        self.sync_all()

        # Two balances of 9; send 9
        tx = self.nodes[0].sendanytoaddress(addr1, 9, "", "", True, False)
        assert(tx in self.nodes[0].getrawmempool())
        self.nodes[0].generate(1)
        self.sync_all()

        # Test watch only createanytoaddress
        try:
            txraw = self.nodes[3].createanytoaddress(addr1, 9, True, False, 1, True)
        except JSONRPCException as exp:
            assert("Insufficient funds for sendany" in exp.error['message'])
        else:
            assert(False)

        self.nodes[3].importaddress(multisig['redeemScript'], "", True, True)
        txraw = self.nodes[3].createanytoaddress(addr1, 9, True, True, 2, True)
        txraw = self.nodes[3].createanytoaddress(addr1, 9, True, True, 1, True)
        txrawsigned = self.nodes[3].signrawtransaction(txraw[0])
        assert(txrawsigned['complete'])
        tx = self.nodes[3].sendrawtransaction(txrawsigned['hex'])
        assert(tx in self.nodes[3].getrawmempool())
        self.nodes[3].generate(1)
        self.sync_all()

        # test sendanytoaddress metadata tag
        metadata = 'ec45a16ce1a3eb5784df3dfa196aad6bd57f6c2f6969e97d1eb5402ccd39d627'
        txid = self.nodes[0].sendanytoaddress(addr1, 0.5, "", "", True, False,1,metadata)
        assert(txid in self.nodes[0].getrawmempool())
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].getrawtransaction(txid,True)
        or_md = False
        for outpt in tx["vout"]:
            if outpt["scriptPubKey"]["hex"] == '6a20' + metadata: or_md = True
        assert(or_md)

        # test createanytoaddress metadata tag
        metadata = 'ec45a16ce1a3eb5784df3dfa196aad6bd57f6c2f6969e97d1eb5402ccd39d628'
        tx = self.nodes[0].createanytoaddress(addr1, 0.5, True, False,1,False,metadata)
        txs= self.nodes[0].signrawtransaction(tx[0])
        txid= self.nodes[0].sendrawtransaction(txs['hex'])
        print(txs['hex'])
        assert(txid in self.nodes[0].getrawmempool())
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].getrawtransaction(txid,True)
        or_md = False
        for outpt in tx["vout"]:
            print(outpt)
            if outpt["scriptPubKey"]["hex"] == '6a20' + metadata: or_md = True
        assert(or_md)

if __name__ == '__main__':
    SendAnyTest().main()
B
