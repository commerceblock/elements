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

class RecoverEncryptionKeysTest (BitcoinTestFramework):

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
        # import the policy keys into node 0
        self.nodes[0].importprivkey("cS29UJMQrpnee7UaUHo6NqJVpGr35TEqUDkKXStTnxSZCGUWavgE")
        self.nodes[0].importprivkey("cNCQhCnpnzyeYh48NszsTJC2G4HPoFMZguUnUgBpJ5X9Vf2KaPYx")

        self.nodes[0].generate(101)
        self.sync_all()

        
        #Add somekycpubkeys
        nkeys=200
        nkeys_part=100
        for i in range(int(nkeys/nkeys_part)):
            n=int((i+1)*nkeys_part)
            self.nodes[0].topupkycpubkeys(n)
            self.nodes[0].generate(1)
            self.sync_all()

        assert_equal(self.nodes[0].getnunassignedkycpubkeys(),nkeys)
        assert_equal(self.nodes[3].getnunassignedkycpubkeys(),nkeys)
        
        #Restart node
        self.stop_node(0)
        time.sleep(2)

        bConnected=True
        try:
            self.nodes[0].getblockcount()
        except ConnectionRefusedError as e:
            bConnected=False

        assert_equal(bConnected, False)
            
        self.nodes[0] = start_node(0, self.options.tmpdir, self.extra_args[0])
            
        time.sleep(1)
        self.connect_nodes()

        self.sync_all()

        #Check we still have the correct number of kycpubkeys
        assert_equal(self.nodes[0].getnunassignedkycpubkeys(),nkeys)
        assert_equal(self.nodes[3].getnunassignedkycpubkeys(),nkeys)
        
        #Check we still have the private keys for the kycpubkeys
        kycpubkeysfile=self.initfile(os.path.join(self.options.tmpdir,"kycpubkeys.dat"))

        self.nodes[0].dumpkycpubkeys(kycpubkeysfile)
        
        nmine, kycpk_address, kycpk=self.get_nmine(kycpubkeysfile)

        assert(nmine == nkeys)

        #Confirm node3 has not generated the kyc keys yet 
        self.nodes[3].dumpkycpubkeys(kycpubkeysfile)
        nmine, dum1, dum2=self.get_nmine(kycpubkeysfile)
        assert(nmine == 0)

        #Recover one kycpubkey
        val=self.nodes[3].validateaddress(kycpk_address)
        assert(val['ismine'] == False)
        assert(self.nodes[3].recoverencryptionkey(kycpk, nkeys))
        val=self.nodes[3].validateaddress(kycpk_address)
        assert(val['ismine'] == True)

        #Recover all pubkeys node0 
        assert(self.nodes[0].recoverkyckeys())
        #Confirm recovered
        self.nodes[0].dumpkycpubkeys(kycpubkeysfile)
        nmine, dum1, dum2=self.get_nmine(kycpubkeysfile)
        assert(nmine == nkeys)

        #Recover all pubkeys node 3
        assert(self.nodes[3].recoverkyckeys(nkeys))
            
        #Confirm recovered
        self.nodes[3].dumpkycpubkeys(kycpubkeysfile)
        nmine, dum1, dum2=self.get_nmine(kycpubkeysfile)
        assert(nmine == nkeys)

        #Restart node
        self.stop_node(3)
        time.sleep(2)

        bConnected=True
        try:
            self.nodes[3].getblockcount()
        except ConnectionRefusedError as e:
            bConnected=False

        assert_equal(bConnected, False)
            
        self.nodes[3] = start_node(3, self.options.tmpdir, self.extra_args[3])
            
        time.sleep(1)
        self.connect_nodes()
        self.sync_all()
        self.nodes[3].dumpkycpubkeys(kycpubkeysfile)
        nmine, dum1, dum2=self.get_nmine(kycpubkeysfile)
        assert(nmine == nkeys)


        #Reset wallet and restart the node - keys will not be recovered yet 
        self.stop_node(3)
        time.sleep(2)
        bConnected=True
        try:
            self.nodes[3].getblockcount()
        except ConnectionRefusedError as e:
            bConnected=False
        assert_equal(bConnected, False)

        shutil.copyfile(self.wlwalletpath,self.dest3)

        self.nodes[3] = start_node(3, self.options.tmpdir, self.extra_args[3])

        time.sleep(1)
        self.connect_nodes()
        self.sync_all()
        self.nodes[3].dumpkycpubkeys(kycpubkeysfile)
        nmine, dum1, dum2=self.get_nmine(kycpubkeysfile)
        assert(nmine == 0)

        #Restart the node with the recoverwhitelistkeys flag - keys will be recovered
        self.stop_node(3)
        time.sleep(2)
        bConnected=True
        try:
            self.nodes[3].getblockcount()
        except ConnectionRefusedError as e:
            bConnected=False
        assert_equal(bConnected, False)

        self.extra_args[3].append("-recoverwhitelistkeys=1")
        
        self.nodes[3] = start_node(3, self.options.tmpdir, self.extra_args[3])

        time.sleep(1)
        self.connect_nodes()
        self.sync_all()
        self.nodes[3].dumpkycpubkeys(kycpubkeysfile)
        nmine, dum1, dum2=self.get_nmine(kycpubkeysfile)
        assert(nmine == nkeys)
        
        self.cleanup_files()
        return

if __name__ == '__main__':
 RecoverEncryptionKeysTest().main()


