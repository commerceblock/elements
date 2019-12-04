#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test RPC calls related to blockchain state. Tests correspond to code in
# rpc/blockchain.cpp.
#

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.authproxy import JSONRPCException
from test_framework.util import (
    assert_equal,
    assert_raises,
    assert_is_hex_string,
    assert_is_hash_string,
    start_nodes,
    connect_nodes_bi,
)


class BlockchainTest(BitcoinTestFramework):
    """
    Test blockchain-related RPC calls:

        - gettxoutsetinfo (depreciated)
        - verifychain
        - getsidechaininfo

    """

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = False
        self.num_nodes = 1

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        # self._test_gettxoutsetinfo()
        self._test_getblockheader()
        self._test_getsidechaininfo()
        self.nodes[0].verifychain(4, 0)

    # def _test_gettxoutsetinfo(self):
    #     node = self.nodes[0]
    #     res = node.gettxoutsetinfo()
    #
    #     assert_equal(res['total_amount'], Decimal('8725.00000000'))
    #     assert_equal(res['transactions'], 200)
    #     assert_equal(res['height'], 200)
    #     assert_equal(res['txouts'], 200)
    #     assert_equal(res['bytes_serialized'], 13924),
    #     assert_equal(len(res['bestblock']), 64)
    #     assert_equal(len(res['hash_serialized']), 64)

    def _test_getblockheader(self):
        node = self.nodes[0]

        assert_raises(
            JSONRPCException, lambda: node.getblockheader('nonsense'))

        besthash = node.getbestblockhash()
        secondbesthash = node.getblockhash(199)
        header = node.getblockheader(besthash)

        assert_equal(header['hash'], besthash)
        assert_equal(header['height'], 200)
        assert_equal(header['confirmations'], 1)
        assert_equal(header['previousblockhash'], secondbesthash)
        assert_is_hex_string(header['chainwork'])
        assert_is_hash_string(header['hash'])
        assert_is_hash_string(header['previousblockhash'])
        assert_is_hash_string(header['merkleroot'])
        assert_is_hash_string(header['bits'], length=None)
        assert isinstance(header['time'], int)
        assert isinstance(header['mediantime'], int)
        assert isinstance(header['nonce'], int)
        assert isinstance(header['version'], int)
        assert isinstance(int(header['versionHex'], 16), int)
        assert isinstance(header['difficulty'], int)#always 1

    def _test_getsidechaininfo(self):
        node = self.nodes[0]
        info = node.getsidechaininfo()

        assert_equal(int(info['fedpegscript']), 51)
        assert_is_hex_string(info['pegged_asset'])
        assert_is_hex_string(info['min_peg_diff'])
        assert_is_hex_string(info['parent_blockhash'])
        assert_equal(int(info['addr_prefixes']['PUBKEY_ADDRESS']),235)
        assert_equal(int(info['addr_prefixes']['BLINDED_ADDRESS']),4)
        assert_equal(int(info['addr_prefixes']['SECRET_KEY']),239)
        assert_equal(int(info['addr_prefixes']['SCRIPT_ADDRESS']),75)

if __name__ == '__main__':
    BlockchainTest().main()
