#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class HardforkPolicy (BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [['-txindex'] for i in range(3)]
        self.extra_args[0].append("-freezelist=1")
        self.extra_args[0].append("-burnlist=1")
        self.extra_args[1].append("-freezelist=1")
        self.extra_args[1].append("-burnlist=1")
        self.extra_args[2].append("-freezelist=1")
        self.extra_args[2].append("-burnlist=1")
        self.extra_args[0].append("-policycoins=50000000000000")
        self.extra_args[0].append("-freezelistcoinsdestination=76a91474168445da07d331faabd943422653dbe19321cd88ac")
        self.extra_args[0].append("-burnlistcoinsdestination=76a9142166a4cd304b86db7dfbbc7309131fb0c4b645cd88ac")
        self.extra_args[1].append("-policycoins=50000000000000")
        self.extra_args[1].append("-freezelistcoinsdestination=76a91474168445da07d331faabd943422653dbe19321cd88ac")
        self.extra_args[1].append("-burnlistcoinsdestination=76a9142166a4cd304b86db7dfbbc7309131fb0c4b645cd88ac")
        self.extra_args[2].append("-policycoins=50000000000000")
        self.extra_args[2].append("-freezelistcoinsdestination=76a91474168445da07d331faabd943422653dbe19321cd88ac")
        self.extra_args[2].append("-burnlistcoinsdestination=76a9142166a4cd304b86db7dfbbc7309131fb0c4b645cd88ac")

    def setup_network(self, split=False):
        self.nodes = start_nodes(3, self.options.tmpdir, self.extra_args[:3])
        connect_nodes_bi(self.nodes,0,1)
        connect_nodes_bi(self.nodes,1,2)
        connect_nodes_bi(self.nodes,0,2)
        self.is_network_split=False
        self.sync_all()

    def run_test (self):

        # import the policy keys into node 0
        self.nodes[0].importprivkey("cS29UJMQrpnee7UaUHo6NqJVpGr35TEqUDkKXStTnxSZCGUWavgE")
        self.nodes[0].importprivkey("cND4nfH6g2SopoLk5isQ8qGqqZ5LmbK6YwJ1QnyoyMVBTs8bVNNd")
        self.nodes[0].importprivkey("cTnxkovLhGbp7VRhMhGThYt8WDwviXgaVAD8DjaVa5G5DApwC6tF")


        self.nodes[0].generate(101)
        self.sync_all()

        #find txouts for the freezelistasset and burnlistasset
        flscript = "76a91474168445da07d331faabd943422653dbe19321cd88ac"
        blscript = "76a9142166a4cd304b86db7dfbbc7309131fb0c4b645cd88ac"
        genhash = self.nodes[0].getblockhash(0)
        genblock = self.nodes[0].getblock(genhash)

        for txid in genblock["tx"]:
            rawtx = self.nodes[0].getrawtransaction(txid,True)
            if "assetlabel" in rawtx["vout"][0]:
                if rawtx["vout"][0]["assetlabel"] == "FREEZELIST":
                    flasset = rawtx["vout"][0]["asset"]
                    fltxid = txid
                    flvalue = rawtx["vout"][0]["value"]
                if rawtx["vout"][0]["assetlabel"] == "BURNLIST":
                    blasset = rawtx["vout"][0]["asset"]
                    bltxid = txid
                    blvalue = rawtx["vout"][0]["value"]

        #issue some non-policy asset
        assaddr = self.nodes[0].getnewaddress()
        tokaddr = self.nodes[0].getnewaddress()
        cngaddr = self.nodes[0].getnewaddress()
        sendissue = self.nodes[0].issueasset(1000.0,1.0)

        self.nodes[0].generate(101)
        self.sync_all()

        #generate a public key for the policy wallet
        policyaddress = self.nodes[0].getnewaddress()
        validatepaddress = self.nodes[0].validateaddress(policyaddress)
        policypubkey = validatepaddress['pubkey']

        #get an address for the freezelist
        frzaddress1 = self.nodes[1].getnewaddress()

        #send some coins to that address
        rtxid = self.nodes[0].sendtoaddress(frzaddress1,100)

        self.nodes[0].generate(1)
        self.sync_all()

        #get the vout
        rawtx = self.nodes[1].getrawtransaction(rtxid,True)
        for vout in rawtx["vout"]:
            if vout["value"] == 100.0:
                rvout = vout["n"]


        assert_equal(self.nodes[0].queryfreezelist(frzaddress1), False)

        #generate the tx to freeze the user address
        inputs = []
        vin = {}
        vin["txid"] = fltxid
        vin["vout"] = 0
        inputs.append(vin)
        outputs = []
        outp = {}
        outp["pubkey"] = policypubkey
        outp["value"] = flvalue
        outp["address"] = frzaddress1
        outputs.append(outp)
        frztx = self.nodes[0].createrawpolicytx(inputs,outputs,0,flasset)
        frztx_signed = self.nodes[0].signrawtransaction(frztx)
        assert(frztx_signed["complete"])
        frztx_send = self.nodes[0].sendrawtransaction(frztx_signed["hex"])

        self.nodes[0].generate(1)
        self.sync_all()

        #check that the freezelist has been updated
        assert_equal(self.nodes[0].queryfreezelist(frzaddress1), True)

        #issue new asset to replace the freezelist asset (Node 2 will have the freezelist asset). 
        flaaddr = self.nodes[2].getnewaddress()
        flaissue = self.nodes[2].issueasset(2.0,0.0)

        self.nodes[0].generate(10)
        self.sync_all()

        #Restart nodes
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

        #set the changed policy asset in the config (from height 300)
        for iter in range(3):
            self.extra_args[iter].append("-freezelistassetchange="+flaissue["asset"]+":300")

        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, self.extra_args[:3])
        time.sleep(1)
        connect_nodes_bi(self.nodes,0,1)
        connect_nodes_bi(self.nodes,1,2)
        connect_nodes_bi(self.nodes,0,2)

        self.sync_all()
        self.nodes[0].generate(100)
        self.sync_all()

        #check that the freezelist is correct up to the fork point
        assert_equal(self.nodes[0].queryfreezelist(frzaddress1), True)

        #get new address to add to freezelist
        newaddr = self.nodes[2].getnewaddress()

        #generate the tx to freeze the user address
        #generate a public key for the policy wallet
        fltxout = self.nodes[2].getrawtransaction(flaissue["txid"],True)
        for out in fltxout["vout"]:
            if out["asset"] == flaissue["asset"]: nout = out["n"]
        policyaddress = self.nodes[2].getnewaddress()
        validatepaddress = self.nodes[2].validateaddress(policyaddress)
        policypubkey = validatepaddress['pubkey']
        inputs = []
        vin = {}
        vin["txid"] = flaissue["txid"]
        vin["vout"] = nout
        inputs.append(vin)
        outputs = []
        outp = {}
        outp["pubkey"] = policypubkey
        outp["value"] = 2.0
        outp["address"] = newaddr
        outputs.append(outp)
        frztx = self.nodes[2].createrawpolicytx(inputs,outputs,0,flaissue["asset"])
        print(self.nodes[2].decoderawtransaction(frztx))
        frztx_signed = self.nodes[2].signrawtransaction(frztx)
        print(frztx_signed)
        assert(frztx_signed["complete"])
        frztx_send = self.nodes[2].sendrawtransaction(frztx_signed["hex"])

        self.nodes[0].generate(10)
        self.sync_all()
        self.nodes[0].generate(10)

        #check that the freezelist is updated with the new policy asset
        assert_equal(self.nodes[2].queryfreezelist(newaddr), True)

        #try to freeze and address using the old freezelist asset
        newaddr2 = self.nodes[0].getnewaddress()
        inputs = []
        vin = {}
        vin["txid"] = fltxid
        vin["vout"] = 1
        inputs.append(vin)
        outputs = []
        outp = {}
        outp["pubkey"] = policypubkey
        outp["value"] = flvalue
        outp["address"] = newaddr2
        outputs.append(outp)
        frztx = self.nodes[0].createrawpolicytx(inputs,outputs,0,flasset)
        frztx_signed = self.nodes[0].signrawtransaction(frztx)
        assert(frztx_signed["complete"])
        frztx_send = self.nodes[0].sendrawtransaction(frztx_signed["hex"])

        self.nodes[0].generate(10)
        self.sync_all()
        self.nodes[0].generate(10)

        #check that the freezelist is updated with the new policy asset
        assert_equal(self.nodes[0].queryfreezelist(newaddr2), False)        

        return

if __name__ == '__main__':
    HardforkPolicy().main()
