#!/usr/bin/env python3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
#===============================================================================
# Test 1 : Normal Configuration Without Procedural Error
#===============================================================================
def test_validBurn_1(node):
  #=============================================================================
  # Create Address
  #=============================================================================
  addr0 = node.getnewaddress()
  addr1 = node.getnewaddress()
  addr2 = node.getnewaddress()
  addr3 = node.getnewaddress()
  #=============================================================================
  # Add address to FreezeList
  #=============================================================================
  # node.addtoburnlist(addr0)
  # node.addtoburnlist(addr1)
  # node.addtoburnlist(addr2)
  # node.addtoburnlist(addr3)
  #=============================================================================
  # Create Inputs & Outputs
  #=============================================================================
  unspent = node.listunspent()
  fee = Decimal('0.0001')
  # Make Inputs
  print(unspent[0]["txid"])
  print(unspent[0]["vout"])
  print(unspent[0]["amount"])

  inputs = [{
    "txid": unspent[0]["txid"],
    "vout": unspent[0]["vout"],
    "nValue": unspent[0]["amount"]
  }]
  # Make Outputs
  outputs = {
    addr0 : 1,
    addr1 : 1,
    addr2 : 1,
    addr3 : unspent[0]["amount"] - 3 - fee,
    "fee": fee
  }
  #=============================================================================
  # Create Transaction & Signed Transaction
  #=============================================================================
  tx = node.createrawtransaction(inputs, outputs);
  signedtx = node.signrawtransaction(tx)
  #=============================================================================
  # Send Transaction and try if is valid or not valid
  #=============================================================================
  txid = node.sendrawtransaction(signedtx["hex"])



  print("-------------------------=======================")




  # Make Inputs
  inputs = [{
    "txid": txid,
    "vout": unspent[0]["vout"],
    "nValue": unspent[0]["amount"]
  }]
  # Make Outputs
  outputs = {
    "data" : "0000000000000000000000000000000000000000",
    addr0 : 1,
    addr1 : 1,
    addr2 : 1,
    addr3 : unspent[0]["amount"] - 3 - fee,
    "fee": fee
  }
  #=============================================================================
  # Create Transaction & Signed Transaction
  #=============================================================================
  tx = node.createrawtransaction(inputs, outputs);
  signedtx = node.signrawtransaction(tx)
  #=============================================================================
  # Send Transaction and try if is valid or not valid
  #=============================================================================
  try:
    txid = node.sendrawtransaction(signedtx["hex"])
    return True
  except:
    return False

class validBurnTest (BitcoinTestFramework):
  def __init__(self):
    super().__init__()
    self.setup_clean_chain = True
    self.num_nodes = 4
    self.extra_args = [['-usehd={:d}'.format(i % 2 == 0), '-keypool=100']
                       for i in range(self.num_nodes)]
    # self.extra_args[0].append("-freezelist=1")
    self.extra_args[0].append("-burnlist=1")

  def setup_network(self, split=False):
    self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                             self.extra_args[:self.num_nodes])
    connect_nodes_bi(self.nodes, 0, 1)
    connect_nodes_bi(self.nodes, 1, 2)
    connect_nodes_bi(self.nodes, 1, 3)
    connect_nodes_bi(self.nodes, 2, 3)
    self.is_network_split = False
    self.sync_all()

  def run_test(self):
    self.nodes[0].generate(101)
    self.sync_all()
    failed = False
    #===========================================================================
    # Test : 1
    #===========================================================================
    if test_validBurn_1(self.nodes[0]) == True:
      print("Test 1 :\033[1;32;40m OK\033[0m")
    else:
      failed = True
      print("Test 1 :\033[1;31;40m KO\033[0m")
    #===========================================================================
    # End
    #===========================================================================
    assert failed == False
    print("End.")
#===============================================================================
# Main, Entry Point
#===============================================================================
if __name__ == '__main__':
  validBurnTest().main()
