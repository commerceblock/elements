#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import filecmp
import time
import string
import urllib.parse
import array as arr

class OnboardManualCITTest (BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.extra_args = [['-txindex'] for i in range(4)]
        self.extra_args[0].append("-contractintx=1")
        self.extra_args[0].append("-pkhwhitelist=1")
        self.extra_args[0].append("-pkhwhitelist-encrypt=0")
        self.extra_args[0].append("-initialfreecoins=2100000000000000")
        self.extra_args[0].append("-policycoins=50000000000000")
        self.extra_args[0].append("-regtest=0")
        self.extra_args[0].append("-initialfreecoinsdestination=76a914bc835aff853179fa88f2900f9003bb674e17ed4288ac")
        self.extra_args[0].append("-whitelistcoinsdestination=76a914427bf8530a3962ed77fd3c07d17fd466cb31c2fd88ac")
        self.extra_args[1].append("-contractintx=1")
        self.extra_args[1].append("-regtest=0")
        self.extra_args[1].append("-pkhwhitelist=1")
        self.extra_args[1].append("-pkhwhitelist-encrypt=0")
        self.extra_args[1].append("-initialfreecoins=2100000000000000")
        self.extra_args[1].append("-policycoins=50000000000000")
        self.extra_args[1].append("-initialfreecoinsdestination=76a914bc835aff853179fa88f2900f9003bb674e17ed4288ac")
        self.extra_args[1].append("-whitelistcoinsdestination=76a914427bf8530a3962ed77fd3c07d17fd466cb31c2fd88ac")
        self.extra_args[2].append("-contractintx=1")
        self.extra_args[2].append("-regtest=0")
        self.extra_args[2].append("-pkhwhitelist=1")
        self.extra_args[2].append("-pkhwhitelist-encrypt=0")
        self.extra_args[2].append("-initialfreecoins=2100000000000000")
        self.extra_args[2].append("-policycoins=50000000000000")
        self.extra_args[2].append("-initialfreecoinsdestination=76a914bc835aff853179fa88f2900f9003bb674e17ed4288ac")
        self.extra_args[2].append("-whitelistcoinsdestination=76a914427bf8530a3962ed77fd3c07d17fd466cb31c2fd88ac")
        self.extra_args[3].append("-contractintx=1")
        self.extra_args[3].append("-regtest=0")
        self.extra_args[3].append("-pkhwhitelist=1")
        self.extra_args[3].append("-pkhwhitelist-encrypt=0")
        self.extra_args[3].append("-initialfreecoins=2100000000000000")
        self.extra_args[3].append("-policycoins=50000000000000")
        self.extra_args[3].append("-initialfreecoinsdestination=76a914bc835aff853179fa88f2900f9003bb674e17ed4288ac")
        self.extra_args[3].append("-whitelistcoinsdestination=76a914427bf8530a3962ed77fd3c07d17fd466cb31c2fd88ac")
        self.files=[]

    def connect_nodes(self):
        connect_nodes_bi(self.nodes,0,1)
        connect_nodes_bi(self.nodes,1,2)
        connect_nodes_bi(self.nodes,0,2)
        connect_nodes_bi(self.nodes,2,3)
        
    def setup_network(self, split=False):
        self.nodes = start_nodes(4, self.options.tmpdir, self.extra_args[:4])
        self.connect_nodes()
        self.is_network_split=True
        self.sync_all()

        #Set up wallet path and dump the wallet
        wlwalletname="wlwallet.dat"
        self.wlwalletpath=self.initfile(os.path.join(self.options.tmpdir,wlwalletname))
        self.nodes[0].backupwallet(self.wlwalletpath)
        #Stop the nodes
        stop_nodes(self.nodes)

        #Copy the wallet file to the node 0 and 3 data dirs
        #Give nodes 0 and 3 the same wallet (whitelist wallet)
        node0path=os.path.join(self.options.tmpdir, "node"+str(0))
        node3path=os.path.join(self.options.tmpdir, "node"+str(3))

        self.dest0=self.initfile(os.path.join(node0path, "ocean_test"))
        self.dest0=self.initfile(os.path.join(self.dest0, wlwalletname))
        self.dest3=self.initfile(os.path.join(node3path, "ocean_test"))
        self.dest3=self.initfile(os.path.join(self.dest3, wlwalletname))

        shutil.copyfile(self.wlwalletpath,self.dest0)
        shutil.copyfile(self.wlwalletpath,self.dest3)

        #Start the nodes again with a different wallet path argument
        self.extra_args[0].append("-wallet="+wlwalletname)
        self.extra_args[3].append("-wallet="+wlwalletname)
        self.nodes = start_nodes(4, self.options.tmpdir, self.extra_args[:4])

        time.sleep(5)

        #Node0 and node3 wallets should be the same
        addr0=self.nodes[0].getnewaddress()
        addr3=self.nodes[3].getnewaddress()

        assert(addr0 == addr3)

        self.connect_nodes()
        self.is_network_split=False
        self.sync_all()
        
    def linecount(self, file):
        nlines=0
        with open(file) as f:
            for nlines, l in enumerate(f):
                pass
        return nlines

    def initfile(self, filename):
        self.files.append(filename)
        self.removefileifexists(filename)
        return filename

    def removefileifexists(self, filename):
        if filename in self.files:
            self.files.remove(filename)
        if(os.path.isfile(filename)):
            os.remove(filename)
        

    def cleanup_files(self):
        for file in self.files:
            self.removefileifexists(file)


    def get_nmine(self, kycpubkeysfile):
        nmine=0
        kycpk=''
        kycpk_address=''
        with open(kycpubkeysfile) as fp:
            for line in fp:
                if line[0] == '#':
                    continue
                sline=line.split(' ')
                if len(sline) == 3:
                    if int(sline[2]) == int(1):
                        kycpk_address=sline[0]
                        kycpk=sline[1]
                        nmine=nmine+1
        return nmine, kycpk_address, kycpk

            
    def run_test (self):
        keypool=1

        # import the policy keys into node 0
        self.nodes[0].importprivkey("cS29UJMQrpnee7UaUHo6NqJVpGr35TEqUDkKXStTnxSZCGUWavgE")
        self.nodes[0].importprivkey("cNCQhCnpnzyeYh48NszsTJC2G4HPoFMZguUnUgBpJ5X9Vf2KaPYx")

        self.nodes[0].generate(101)
        self.sync_all()

        #find txouts for the freezelistasset and burnlistasset
        pascript = "76a914bc835aff853179fa88f2900f9003bb674e17ed4288ac"
        wlscript = "76a914427bf8530a3962ed77fd3c07d17fd466cb31c2fd88ac"
        genhash = self.nodes[0].getblockhash(0)
        genblock = self.nodes[0].getblock(genhash)

        for txid in genblock["tx"]:
            rawtx = self.nodes[0].getrawtransaction(txid,True)
            if rawtx["vout"][0]["scriptPubKey"]["hex"] == pascript:
                paasset = rawtx["vout"][0]["asset"]
                patxid = txid
                pavalue = rawtx["vout"][0]["value"]
            if "assetlabel" in rawtx["vout"][0]:
                if rawtx["vout"][0]["assetlabel"] == "WHITELIST":
                    wlasset = rawtx["vout"][0]["asset"]
                    wltxid = txid
                    wlvalue = rawtx["vout"][0]["value"]

        #Initial WHITELIST token balance
        wb0_1=float(self.nodes[0].getbalance("", 1, False, "WHITELIST"))
        coin=float(1e8)
        assert_equal(wb0_1*coin,float(50000000000000))
                    
        #Whitelist node 0 addresses
        self.nodes[0].dumpderivedkeys("keys.main")
        self.nodes[0].readwhitelist("keys.main")
        os.remove("keys.main")

        #Try and create kycfile when no KYC pub keys available
        kycfile_test=self.initfile(os.path.join(self.options.tmpdir,"kycfile_test.dat"))
        try:
            userOnboardPubKey=self.nodes[1].createkycfile(kycfile_test,[], []);
            #expect an exception
            assert(False)
        except JSONRPCException as e:
            message=e.error['message']
            assert('No unassigned KYC public keys available.' in message)
        self.removefileifexists(kycfile_test)

        #Register a KYC public key manually
        policyaddr=self.nodes[0].getnewaddress()
        assert(self.nodes[0].querywhitelist(policyaddr))
        policypubkey=self.nodes[0].validateaddress(policyaddr)["pubkey"]
        kycaddr=self.nodes[0].getnewaddress()
        kycpubkey=self.nodes[0].validateaddress(kycaddr)["pubkey"]

        inputs=[]
        vin = {}
        vin["txid"]= wltxid
        vin["vout"]= 0
        inputs.append(vin)
        outputs = []
        outp = {}
        outp["pubkey"]=policypubkey
        outp["value"]=wlvalue
        outp["userkey"]=kycpubkey
        outputs.append(outp)
        wltx=self.nodes[0].createrawpolicytx(inputs, outputs, 0, wlasset)
        wltx_signed=self.nodes[0].signrawtransaction(wltx)
        assert(wltx_signed["complete"])
        wltx_send = self.nodes[0].sendrawtransaction(wltx_signed["hex"])

        self.nodes[0].generate(1)
        self.sync_all()

        assert_equal(self.nodes[0].getnunassignedkycpubkeys(), 1)

        #Remove the manually registered kyc public key and create a new one
        self.nodes[0].removekycpubkey(kycpubkey)
        self.nodes[0].generate(1)
        self.sync_all()

        assert_equal(self.nodes[0].getnunassignedkycpubkeys(), 0)
        self.nodes[0].topupkycpubkeys(1)
        self.nodes[0].generate(1)
        self.sync_all()
        assert_equal(self.nodes[0].getnunassignedkycpubkeys(), 1)
        assert_equal(self.nodes[1].getnunassignedkycpubkeys(), 1)
        
        #Onboard node1
        kycfile=self.initfile(os.path.join(self.options.tmpdir,"kycfile.dat"))
        kycfile_normal=self.initfile(os.path.join(self.options.tmpdir,"kycfile_normal.dat"))
        kycfile_p2sh=self.initfile(os.path.join(self.options.tmpdir,"kycfile_p2sh.dat"))
        kycfile_p2pkh=self.initfile(os.path.join(self.options.tmpdir,"kycfile_p2pkh.dat"))
        kycfile_multisig=self.initfile(os.path.join(self.options.tmpdir,"kycfile_multisig.dat"))
        kycfile_oversize=self.initfile(os.path.join(self.options.tmpdir,"kycfile_oversize.dat"))
        kycfile_large=self.initfile(os.path.join(self.options.tmpdir,"kycfile_large.dat"))
        kycfile_empty=self.initfile(os.path.join(self.options.tmpdir,"kycfile_empty.dat"))
        #userOnboardPubKey=self.nodes[1].dumpkycfile(kycfile)

        #P2SH
        onboardAddress1=self.nodes[1].validateaddress(self.nodes[1].getnewaddress())
        onboardAddress2=self.nodes[1].validateaddress(self.nodes[1].getnewaddress())
        onboardAddress3=self.nodes[1].validateaddress(self.nodes[1].getnewaddress())
        onboardAddress4=self.nodes[1].validateaddress(self.nodes[1].getnewaddress())
        onboardAddress5=self.nodes[1].validateaddress(self.nodes[1].getnewaddress())
        multisigAddress1=self.nodes[1].createmultisig(2,[onboardAddress1['address'],onboardAddress2['address'],onboardAddress3['address']])['address'];
        multisigAddress2=self.nodes[1].createmultisig(2,[onboardAddress3['address'],onboardAddress4['address'],onboardAddress5['address']])['address'];

        witnessAddress1=self.nodes[1].addwitnessaddress(self.nodes[1].getnewaddress())
        
        #P2SH
        try:
            userOnboardPubKey=self.nodes[1].createkycfile(kycfile_p2sh, [{"address":multisigAddress1},{"address":multisigAddress2},{"address":witnessAddress1}],[]);
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        valkyc=self.nodes[0].validatekycfile(kycfile_p2sh, True)
        assert(valkyc["iswhitelisted"] == False)
        assert(len(valkyc["addresses"]) == 3)

        assert(self.nodes[0].querywhitelist(multisigAddress1) == False)
        assert(self.nodes[0].querywhitelist(multisigAddress2) == False)
        assert(self.nodes[0].querywhitelist(witnessAddress1) == False)
        
        try:
            self.nodes[0].onboarduser(kycfile_p2sh)
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        self.nodes[0].generate(1)
        self.sync_all()

        valkyc=self.nodes[0].validatekycfile(kycfile_p2sh)
        assert(valkyc["iswhitelisted"] == True)

        assert(self.nodes[0].querywhitelist(multisigAddress1) == True)
        assert(self.nodes[0].querywhitelist(multisigAddress2) == True)
        assert(self.nodes[0].querywhitelist(witnessAddress1) == True)

        #Blacklist
        try:
            self.nodes[0].blacklistuser(kycfile_p2sh)
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        self.nodes[0].generate(1)
        self.sync_all()

        valkyc=self.nodes[0].validatekycfile(kycfile_p2sh)
        assert(valkyc["iswhitelisted"] == False)

        #Onboard again using registeraddresss script version 0 (will fail to whitelist)
        try:
            self.nodes[0].onboarduser(kycfile_p2sh, 0)
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        self.nodes[0].generate(1)
        self.sync_all()

        valkyc=self.nodes[0].validatekycfile(kycfile_p2sh)
        assert(valkyc["iswhitelisted"] == False)


        #P2PkH
        try:
            userOnboardPubKey=self.nodes[1].createkycfile(kycfile_p2pkh, [{"address":onboardAddress4['address']},{"address":onboardAddress5['address']}],[]);
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        valkyc=self.nodes[0].validatekycfile(kycfile_p2pkh, True)
        assert(valkyc["iswhitelisted"] == False)
        assert(len(valkyc["addresses"]) == 2)

        assert(self.nodes[0].querywhitelist(onboardAddress4['address']) == False)
        assert(self.nodes[0].querywhitelist(onboardAddress5['address']) == False)
        
        try:
            self.nodes[0].onboarduser(kycfile_p2pkh)
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        self.nodes[0].generate(1)
        self.sync_all()

        valkyc=self.nodes[0].validatekycfile(kycfile_p2pkh)
        assert(valkyc["iswhitelisted"] == True)

        assert(self.nodes[0].querywhitelist(onboardAddress4['address']) == True)
        assert(self.nodes[0].querywhitelist(onboardAddress5['address']) == True)


        #Blacklist
        try:
            self.nodes[0].blacklistuser(kycfile_p2pkh)
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        self.nodes[0].generate(1)
        self.sync_all()

        valkyc=self.nodes[0].validatekycfile(kycfile_p2pkh)
        assert(valkyc["iswhitelisted"] == False)

        #Onboard again using registeraddresss script version 0 (will fail to whitelist)
        try:
            self.nodes[0].onboarduser(kycfile_p2pkh, 0)
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        self.nodes[0].generate(1)
        self.sync_all()

        valkyc=self.nodes[0].validatekycfile(kycfile_p2pkh)
        assert(valkyc["iswhitelisted"] == False)

            
        
        #Test invalid parameters
        try:
            userOnboardPubKey=self.nodes[1].createkycfile(kycfile_test,None, None);
            #expect an exception
            assert(False)
        except JSONRPCException as e:
            message=e.error['message']
            assert("Invalid parameters, arguments 2 and 3 can't both be null" in message)
        
        #Create empty file and check validity
        try:
            userOnboardPubKey=self.nodes[1].createkycfile(kycfile_empty,[], []);
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        try:
            self.nodes[0].validatekycfile(kycfile_empty)
        except JSONRPCException as e:
            print(e.error['message'])
            assert('no address data in file' in e.error['message'])

            
        onboardAddress1=self.nodes[1].validateaddress(self.nodes[1].getnewaddress())
        onboardAddress2=self.nodes[1].validateaddress(self.nodes[1].getnewaddress())
        try:
            userOnboardPubKey=self.nodes[1].createkycfile(kycfile_normal, [{"address":onboardAddress1['address'],"pubkey":onboardAddress1['derivedpubkey']},{"address":onboardAddress2['address'],
                "pubkey":onboardAddress2['derivedpubkey']}], 
                []);
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        valkyc=self.nodes[0].validatekycfile(kycfile_normal, True)
        assert(valkyc["iswhitelisted"] == False)
        assert(len(valkyc["addresses"]) == 2)
        
        self.nodes[0].generate(1)
        self.sync_all()


        try:
            userOnboardPubKey=self.nodes[1].createkycfile(kycfile_test, [{"address":"myInvalidAddress","pubkey":onboardAddress1['derivedpubkey']},{"address":onboardAddress2['address'],"pubkey":onboardAddress2['derivedpubkey']}], []);
            #expect an exception
            assert(False)
        except JSONRPCException as e:
            message=e.error['message']
            assert("Invalid address in pubkeylist: myInvalidAddress" in message)

        try:
            userOnboardPubKey=self.nodes[1].createkycfile(kycfile_test, [{"address":onboardAddress1['address'],"pubkey":"myInvalidPubKey"},{"address":onboardAddress2['address'],
                "pubkey":onboardAddress2['derivedpubkey']}], []);
            #expect an exception
            assert(False)
        except JSONRPCException as e:
            message=e.error['message']
            assert("Invalid pubkey in pubkeylist: myInvalidPubKey" in message)

        balance_1=self.nodes[0].getwalletinfo()["balance"]["WHITELIST"]
        try:
            self.nodes[0].onboarduser(kycfile_normal)
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        self.nodes[0].generate(1)
        self.sync_all()

        valkyc=self.nodes[0].validatekycfile(kycfile_normal)
        assert(valkyc["iswhitelisted"] == True)

        #Blacklist
        try:
            self.nodes[0].blacklistuser(kycfile_normal)
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        self.nodes[0].generate(1)
        self.sync_all()

        valkyc=self.nodes[0].validatekycfile(kycfile_normal)
        assert(valkyc["iswhitelisted"] == False)

        #Onboard again using registeraddresss script version 0
        try:
            self.nodes[0].onboarduser(kycfile_normal, 0)
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        self.nodes[0].generate(1)
        self.sync_all()

        valkyc=self.nodes[0].validatekycfile(kycfile_normal)
        assert(valkyc["iswhitelisted"] == True)
        

        #P2SH
        onboardAddress3=self.nodes[1].validateaddress(self.nodes[1].getnewaddress())
        multisigAddress1=self.nodes[1].createmultisig(2,[onboardAddress1['address'],onboardAddress2['address'],onboardAddress3['address']])['address'];
                                                      
        try:
            userOnboardPubKey=self.nodes[1].createkycfile(kycfile_p2sh, [{"address":multisigAddress1}], 
                []);
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        valkyc=self.nodes[0].validatekycfile(kycfile_p2sh, True)
        assert(valkyc["iswhitelisted"] == False)
        assert(len(valkyc["addresses"]) == 1)
        
        self.nodes[0].generate(1)
        self.sync_all()

        #Test invalid parameters
        try:
            userOnboardPubKey=self.nodes[1].createkycfile(kycfile_test, [{"address":"myInvalidAddress"}], []);
            #expect an exception
            assert(False)
        except JSONRPCException as e:
            message=e.error['message']
            assert("Invalid address in pubkeylist: myInvalidAddress" in message)

        balance_1=self.nodes[0].getwalletinfo()["balance"]["WHITELIST"]
        try:
            self.nodes[0].onboarduser(kycfile_p2sh)
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        self.nodes[0].generate(1)
        self.sync_all()

        valkyc=self.nodes[0].validatekycfile(kycfile_p2sh)
        assert(valkyc["iswhitelisted"] == True)



        onboardAddress1=self.nodes[1].validateaddress(self.nodes[1].getnewaddress())
        onboardAddress2=self.nodes[1].validateaddress(self.nodes[1].getnewaddress())
        onboardAddress3=self.nodes[1].validateaddress(self.nodes[1].getnewaddress())
        onboardAddress4=self.nodes[1].validateaddress(self.nodes[1].getnewaddress())
        untweakedPubkeys=[onboardAddress1['derivedpubkey'],onboardAddress2['derivedpubkey'],onboardAddress3['derivedpubkey']]
        untweakedPubkeys2=[onboardAddress2['derivedpubkey'],onboardAddress3['derivedpubkey'],onboardAddress4['derivedpubkey']]
        untweakedPubkeys3=[onboardAddress3['derivedpubkey'],onboardAddress4['derivedpubkey']]
        try:
            userOnboardPubKey=self.nodes[1].createkycfile(kycfile_multisig, [], [{"nmultisig":2,"pubkeys":untweakedPubkeys},{"nmultisig":2,"pubkeys":untweakedPubkeys2},{"nmultisig":2,"pubkeys":untweakedPubkeys3}]);
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        valkyc=self.nodes[0].validatekycfile(kycfile_multisig, True)
        assert(valkyc["iswhitelisted"] == False)
        assert(len(valkyc["addresses"]) == 3)
        
        try:
            self.nodes[0].onboarduser(kycfile_multisig)
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        self.nodes[0].generate(1)
        self.sync_all()

        valkyc=self.nodes[0].validatekycfile(kycfile_multisig)
        assert(valkyc["iswhitelisted"] == True)

        #Blacklist
        try:
            self.nodes[0].blacklistuser(kycfile_multisig)
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        self.nodes[0].generate(1)
        self.sync_all()

        valkyc=self.nodes[0].validatekycfile(kycfile_multisig)
        assert(valkyc["iswhitelisted"] == False)

        #Onboard again using registeraddresss script version 0
        try:
            self.nodes[0].onboarduser(kycfile_multisig, 0)
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        self.nodes[0].generate(1)
        self.sync_all()

        valkyc=self.nodes[0].validatekycfile(kycfile_multisig)
        assert(valkyc["iswhitelisted"] == True)
        
        


        #Test invalid parameters
        try:
            userOnboardPubKey=self.nodes[1].createkycfile(kycfile_test, [], [{"pubkeys":untweakedPubkeys},{"nmultisig":2,"pubkeys":untweakedPubkeys2},{"nmultisig":2,"pubkeys":untweakedPubkeys3}]);
            #expect an exception
            assert(False)
        except JSONRPCException as e:
            message=e.error['message']
            assert("nmultisig missing in multisiglist" in message)

        try:
            userOnboardPubKey=self.nodes[1].createkycfile(kycfile_test, [], [{"nmultisig":2},{"nmultisig":2,"pubkeys":untweakedPubkeys2},{"nmultisig":2,"pubkeys":untweakedPubkeys3}]);
            #expect an exception
            assert(False)
        except JSONRPCException as e:
            message=e.error['message']
            assert("pubkeys missing in multisiglist" in message)
                    
        try:
            userOnboardPubKey=self.nodes[1].createkycfile(kycfile_test, [], [{"nmultisig":2.1,"pubkeys":untweakedPubkeys},{"nmultisig":2,"pubkeys":untweakedPubkeys2},{"nmultisig":2,"pubkeys":untweakedPubkeys3}]);
            #expect an exception
            assert(False)
        except JSONRPCException as e:
            message=e.error['message']
            assert("JSON integer out of range" in message)
        
        try:
            userOnboardPubKey=self.nodes[1].createkycfile(kycfile_test, [], [{"nmultisig":16,"pubkeys":untweakedPubkeys},{"nmultisig":2,"pubkeys":untweakedPubkeys2},{"nmultisig":2,"pubkeys":untweakedPubkeys3}]);
            #expect an exception
            assert(False)
        except JSONRPCException as e:
            message=e.error['message']
            assert("nmultisig must be an integer between 1 and 15")

        try:
            userOnboardPubKey=self.nodes[1].createkycfile(kycfile_test, [], [{"nmultisig":0,"pubkeys":untweakedPubkeys},{"nmultisig":2,"pubkeys":untweakedPubkeys2},{"nmultisig":2,"pubkeys":untweakedPubkeys3}]);
            #expect an exception
            assert(False)
        except JSONRPCException as e:
            message=e.error['message']
            assert("nmultisig must be an integer between 1 and 15")
    

        invalidPubkeys=['myInvalidPubKey',onboardAddress2['derivedpubkey'],onboardAddress3['derivedpubkey']]

        try:
            userOnboardPubKey=self.nodes[1].createkycfile(kycfile_test, [], [{"nmultisig":2,"pubkeys":invalidPubkeys},{"nmultisig":2,"pubkeys":untweakedPubkeys2},{"nmultisig":2,"pubkeys":untweakedPubkeys3}]);
            #expect an exception
            assert(False)
        except JSONRPCException as e:
            message=e.error['message']
            assert("Invalid pubkey in multisiglist: " in message)
        

        onboardAddress1=self.nodes[1].validateaddress(self.nodes[1].getnewaddress())
        onboardAddress2=self.nodes[1].validateaddress(self.nodes[1].getnewaddress())
        onboardAddress3=self.nodes[1].validateaddress(self.nodes[1].getnewaddress())
        onboardAddress4=self.nodes[1].validateaddress(self.nodes[1].getnewaddress())
        untweakedPubkeys=[onboardAddress1['derivedpubkey'],onboardAddress2['derivedpubkey'],onboardAddress3['derivedpubkey']]
        untweakedPubkeys2=[onboardAddress2['derivedpubkey'],onboardAddress3['derivedpubkey'],onboardAddress4['derivedpubkey']]
        untweakedPubkeys3=[onboardAddress3['derivedpubkey'],onboardAddress4['derivedpubkey']]
        try:
            userOnboardPubKey=self.nodes[1].createkycfile(kycfile, [{"address":onboardAddress1['address'],"pubkey":onboardAddress1['derivedpubkey']},{"address":onboardAddress2['address'],"pubkey":onboardAddress2['derivedpubkey']}], [{"nmultisig":2,"pubkeys":untweakedPubkeys},{"nmultisig":2,"pubkeys":untweakedPubkeys2},{"nmultisig":2,"pubkeys":untweakedPubkeys3}]);
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        try:
            result=userOnboardPubKey=self.nodes[1].createkycfile("", [{"address":onboardAddress1['address'],"pubkey":onboardAddress1['derivedpubkey']},{"address":onboardAddress2['address'],"pubkey":onboardAddress2['derivedpubkey']}], [{"nmultisig":2,"pubkeys":untweakedPubkeys},{"nmultisig":2,"pubkeys":untweakedPubkeys2},{"nmultisig":2,"pubkeys":untweakedPubkeys3}]);
            kycstring=result["kycfile"]
            okey=result["onboardpubkey"]
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        valkyc=self.nodes[0].validatekycfile(kycfile, True)
        print(valkyc)
        assert(len(valkyc["addresses"]) == 5)
        assert(valkyc["iswhitelisted"] == False)

        kycfile_plain="kycfile_plain.dat"
        self.nodes[0].readkycfile(kycfile,kycfile_plain)

        kycfile_fromstr="kycfile_fromstr.dat"
        kycfile_fromstr_plain="kycfile_fromstr_plain.dat"

        with open(kycfile_fromstr, "w") as f:
            f.write(kycstring)

        self.nodes[0].readkycfile(kycfile_fromstr,kycfile_fromstr_plain)

        with open(kycfile_plain) as f1:
            with open(kycfile_fromstr_plain) as f2:
                different = set(f1).difference(f2)

        discard=set()
        for line in different:
            if line[0] == '#':
                discard.add(line)

        different=different.difference(discard)

        discard=set()
        for line in different:
            sline=line.split(' ')
            if len(sline) == 3 and sline[0] == okey:
                discard.add(line)
                
        different=different.difference(discard)

        assert(len(different) == 0)


        try:
            self.nodes[0].onboarduser(kycfile)
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)
        
        self.nodes[0].generate(1)
        self.sync_all()

        valkyc=self.nodes[0].validatekycfile(kycfile)
        assert(valkyc["iswhitelisted"] == True)


        #Blacklist
        try:
            self.nodes[0].blacklistuser(kycfile)
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        self.nodes[0].generate(1)
        self.sync_all()

        valkyc=self.nodes[0].validatekycfile(kycfile)
        assert(valkyc["iswhitelisted"] == False)

        #Onboard again using registeraddresss script version 0
        try:
            self.nodes[0].onboarduser(kycfile, 0)
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        self.nodes[0].generate(1)
        self.sync_all()

        valkyc=self.nodes[0].validatekycfile(kycfile)
        assert(valkyc["iswhitelisted"] == True)
        

        
        balance_2=self.nodes[0].getwalletinfo()["balance"]["WHITELIST"]
        #Make sure the onboard transaction fee was zero
        assert((balance_1-balance_2) == 0)

        node1addr=self.nodes[1].getnewaddress()
        try:
            iswl=self.nodes[0].querywhitelist(onboardAddress1['address'])
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)
        assert(iswl)

        try:
            iswl=self.nodes[0].querywhitelist(onboardAddress2['address'])
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)
        assert(iswl)

        multiAdr=self.nodes[1].createmultisig(2,[onboardAddress1['pubkey'],onboardAddress2['pubkey'],onboardAddress3['pubkey']])
        try:
            iswl2=self.nodes[0].querywhitelist(multiAdr['address'])
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)
        assert(iswl2)

        multiAdr=self.nodes[1].createmultisig(2,[onboardAddress2['pubkey'],onboardAddress3['pubkey'],onboardAddress4['pubkey']])
        try:
            iswl2=self.nodes[0].querywhitelist(multiAdr['address'])
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)
        assert(iswl2)

        multiAdr=self.nodes[1].createmultisig(2,[onboardAddress3['pubkey'],onboardAddress4['pubkey']])
        try:
            iswl2=self.nodes[0].querywhitelist(multiAdr['address'])
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)
        assert(iswl2)

        #Test that txs do not send WHITELIST tokens
        wb0_2=float(self.nodes[0].getbalance("", 1, False, "WHITELIST"))
        assert_equal(wb0_1-float(1/coin), wb0_2)

        #Test for large kycfile
        MAX_SCRIPT_SIZE=50000
        pkeys=[]
        nBytesAddress=5
        nAddresses=0
        while True:
            onboardAddress1=self.nodes[2].validateaddress(self.nodes[2].getnewaddress())
            onboardAddress2=self.nodes[2].validateaddress(self.nodes[2].getnewaddress())
            onboardAddress3=self.nodes[2].validateaddress(self.nodes[2].getnewaddress())
            untweakedPubkeys=[onboardAddress1['derivedpubkey'],onboardAddress2['derivedpubkey'],onboardAddress3['derivedpubkey']]
            pkeys.append({"nmultisig":2,"pubkeys":untweakedPubkeys})
            nBytesAddress+=(3*33)+20+2
            nAddresses+=1
            if nBytesAddress > MAX_SCRIPT_SIZE:
                break
            
        try:
            userOnboardPubKey=self.nodes[1].createkycfile(kycfile_oversize, [], pkeys)
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        valkyc=self.nodes[0].validatekycfile(kycfile_oversize, True)
        assert(valkyc["iswhitelisted"] == False)
        assert(len(valkyc["addresses"]) == nAddresses)
        
        self.nodes[0].generate(1)
        self.sync_all()

        try:
            onboardtx=self.nodes[0].onboarduser(kycfile_oversize, 0)
            assert(False)
        except JSONRPCException as e:
            assert 'Onboarding script size exceeds MAX_SCRIPT_SIZE' in e.error['message']


        pkeysLarge=pkeys[:-1]
        nAddresses-=1
        
        try:
            userOnboardPubKey=self.nodes[1].createkycfile(kycfile_large, [], pkeysLarge)
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

        valkyc=self.nodes[0].validatekycfile(kycfile_large, True)
        assert(valkyc["iswhitelisted"] == False)
        assert(len(valkyc["addresses"]) == nAddresses)
        
        self.nodes[0].generate(1)
        self.sync_all()

        try:
            onboardtx=self.nodes[0].onboarduser(kycfile_large, 0)
        except JSONRPCException as e:
            print(e.error['message'])
            assert(False)

            
        self.nodes[0].generate(1)
        self.sync_all()

        #Check that the TX size > MAX_SCRIPT_SIZE
        rawtx=self.nodes[0].getrawtransaction(onboardtx)
        
        vouts=self.nodes[0].decoderawtransaction(rawtx)['vout']

        nchars=0
        for vout in vouts:
            temp = len(vout['scriptPubKey']['hex'])
            if temp > nchars:
                nchars = temp

        valkyc=self.nodes[0].validatekycfile(kycfile_large)
        assert(valkyc["iswhitelisted"] == True)
        
        
        #Check that all the addresses in the kycfiles are whitelisted
        for file in self.files:
            valkyc=self.nodes[0].validatekycfile(file, True)
            if len(valkyc["addresses"]) > 0:
                assert(valkyc["iswhitelisted"] == True)


        #Add some more kycpubkeys
        self.nodes[0].topupkycpubkeys(100)
        self.nodes[0].generate(1)
        self.sync_all()

        assert_equal(self.nodes[0].getnunassignedkycpubkeys(),100)

        #Restart node
        self.stop_node(0)
        time.sleep(2)

        bConnected=True
        try:
            self.nodes[0].validatekycfile(kycfile_large)
        except ConnectionRefusedError as e:
            bConnected=False

        assert_equal(bConnected, False)

        self.nodes[0] = start_node(0, self.options.tmpdir, self.extra_args[0])

        time.sleep(1)
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)
        self.sync_all()

        #Check that all the addresses in the kycfiles are whitelisted
        for file in self.files:
            print("Validating kycfile: " + str(file))
            valkyc=self.nodes[0].validatekycfile(file, True)
            if len(valkyc["addresses"]) > 0:
                assert(valkyc["iswhitelisted"] == True)

        #Check we still have the correct number of kycpubkeys
        assert_equal(self.nodes[0].getnunassignedkycpubkeys(),100)

        self.cleanup_files()
        return

if __name__ == '__main__':
 OnboardManualCITTest().main()


