#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import filecmp
import time

class ContractForkTest (BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [['-txindex'] for i in range(2)]
        self.extra_args[0].append("-contractchange=55")
        self.extra_args[0].append("-contractintx=1")
        self.extra_args[1].append("-contractchange=55")
        self.extra_args[1].append("-contractintx=1")
        self.extra_args[0].append("-chain=ocean_test")
        self.extra_args[1].append("-chain=ocean_test")
        self.extra_args[0].append("-regtest=0")
        self.extra_args[1].append("-regtest=0")

    def setup_network(self, split=False):
        self.nodes = start_nodes(2, self.options.tmpdir, self.extra_args[:2])
        connect_nodes_bi(self.nodes,0,1)
        self.is_network_split=False
        self.sync_all()

    def run_test (self):
        self.nodes[0].generate(50)
        self.sync_all()

        blockhash = self.nodes[0].getblockhash(50)
        block = self.nodes[0].getblock(blockhash)

        print(block["contracthash"])
        assert(block["contracthash"] == "55f1a7f85f8fdc9d1cae38d30afe24f153bc6c97a6b73f27c6885ef6d0d400f7")

        contracthash = self.nodes[1].getcontracthash()

        assert(contracthash == "55f1a7f85f8fdc9d1cae38d30afe24f153bc6c97a6b73f27c6885ef6d0d400f7")

        contract = self.nodes[1].getcontract()

        assert(contract["contract"] == "These are the old terms and conditions\nApprove to use the CBT network\n")

        self.nodes[0].generate(5)
        self.sync_all()

        blockhash = self.nodes[0].getblockhash(55)
        block = self.nodes[0].getblock(blockhash)

        assert(block["contracthash"] == "858ab0fbcee7654401eb2db40f3318ddcdf679003b00a01f8d8d920a6ce9e3e6")

        contracthash = self.nodes[1].getcontracthash()

        assert(contracthash == "858ab0fbcee7654401eb2db40f3318ddcdf679003b00a01f8d8d920a6ce9e3e6")        

        contract = self.nodes[1].getcontract()

        assert(contract["contract"] == "These are the terms and conditions\nApprove to use the CBT network\n")

        self.nodes[0].generate(50)
        self.sync_all()

        blockhash = self.nodes[0].getblockhash(100)
        block = self.nodes[0].getblock(blockhash)

        assert(block["contracthash"] == "858ab0fbcee7654401eb2db40f3318ddcdf679003b00a01f8d8d920a6ce9e3e6")

        contracthash = self.nodes[1].getcontracthash()

        assert(contracthash == "858ab0fbcee7654401eb2db40f3318ddcdf679003b00a01f8d8d920a6ce9e3e6")        

        contract = self.nodes[1].getcontract()

        assert(contract["contract"] == "These are the terms and conditions\nApprove to use the CBT network\n")


if __name__ == '__main__':
 ContractForkTest().main()
