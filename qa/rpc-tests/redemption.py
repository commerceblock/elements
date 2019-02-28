#!/usr/bin/env python3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
#===============================================================================
# Test 1 : Normal Configuration Without Procedural Error
#===============================================================================
def test_redemption_1(node):
  #=============================================================================
  # Create Address
  #=============================================================================
  addr0 = "2dZRkPX3hrPtuBrmMkbGtxTxsuYYgAaFrXZ"
  addr1 = node.getnewaddress()
  addr2 = node.getnewaddress()
  addr3 = node.getnewaddress()
  #=============================================================================
  # Add address to FreezeList
  #=============================================================================
  node.addtofreezelist(addr1)
  node.addtofreezelist(addr2)
  node.addtofreezelist(addr3)
  #=============================================================================
  # Create Inputs & Outputs
  #=============================================================================
  unspent = node.listunspent()
  fee = Decimal('0.0001')
  # Make Inputs
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
  txid = node.testmempoolaccept(signedtx["hex"])
  if txid["allowed"] == 0:
    print(txid)
    return False
  return True
#===============================================================================
# Test 2 : Test With an Address not Listed in FreezeList
#===============================================================================
def test_redemption_2(node):
  #=============================================================================
  # Create Address
  #=============================================================================
  addr0 = "2dZRkPX3hrPtuBrmMkbGtxTxsuYYgAaFrXZ"
  addr1 = node.getnewaddress()
  addr2 = node.getnewaddress()
  addr3 = node.getnewaddress()
  #=============================================================================
  # Add address to FreezeList
  #=============================================================================
  node.addtofreezelist(addr1)
  node.addtofreezelist(addr2)
  #=============================================================================
  # Create Inputs & Outputs
  #=============================================================================
  unspent = node.listunspent()
  fee = Decimal('0.0001')
  # Make Inputs
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
  txid = node.testmempoolaccept(signedtx["hex"])
  if txid["allowed"] == 0:
    return True
  return False
#===============================================================================
# Test 3 : Test With no Address Listed in FreezeList
#===============================================================================
def test_redemption_3(node):
  #=============================================================================
  # Create Address
  #=============================================================================
  addr0 = "2dZRkPX3hrPtuBrmMkbGtxTxsuYYgAaFrXZ"
  addr1 = node.getnewaddress()
  addr2 = node.getnewaddress()
  addr3 = node.getnewaddress()
  #=============================================================================
  # Create Inputs & Outputs
  #=============================================================================
  unspent = node.listunspent()
  fee = Decimal('0.0001')
  # Make Inputs
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
  txid = node.testmempoolaccept(signedtx["hex"])
  if txid["allowed"] == 0:
    return True
  return False
#===============================================================================
# Test 4 : Just Test With not Null Addresses
#===============================================================================
def test_redemption_4(node):
  #=============================================================================
  # Create Address
  #=============================================================================
  addr0 = node.getnewaddress()
  addr1 = node.getnewaddress()
  addr2 = node.getnewaddress()
  addr3 = node.getnewaddress()
  #=============================================================================
  # Create Inputs & Outputs
  #=============================================================================
  unspent = node.listunspent()
  fee = Decimal('0.0001')
  # Make Inputs
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
  txid = node.testmempoolaccept(signedtx["hex"])
  if txid["allowed"] == 0:
    print(txid)
    return False
  return True
#===============================================================================
# Test 5 : Test With a Null Address that is not at the Top of the List
#===============================================================================
def test_redemption_5(node):
  #=============================================================================
  # Create Address
  #=============================================================================
  addr0 = node.getnewaddress()
  addr1 = "2dZRkPX3hrPtuBrmMkbGtxTxsuYYgAaFrXZ"
  addr2 = node.getnewaddress()
  addr3 = node.getnewaddress()
  #=============================================================================
  # Create Inputs & Outputs
  #=============================================================================
  unspent = node.listunspent()
  fee = Decimal('0.0001')
  # Make Inputs
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
  txid = node.testmempoolaccept(signedtx["hex"])
  if txid["allowed"] == 0:
    return True
  return False
#===============================================================================
# Test 6 : Test With a Single Null Address in the List
#===============================================================================
def test_redemption_6(node):
  #=============================================================================
  # Create Address
  #=============================================================================
  addr0 = "2dZRkPX3hrPtuBrmMkbGtxTxsuYYgAaFrXZ"
  #=============================================================================
  # Create Inputs & Outputs
  #=============================================================================
  unspent = node.listunspent()
  fee = Decimal('0.0001')
  # Make Inputs
  inputs = [{
    "txid": unspent[0]["txid"],
    "vout": unspent[0]["vout"],
    "nValue": unspent[0]["amount"]
  }]
  # Make Outputs
  outputs = {
    addr0 : unspent[0]["amount"] - fee,
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
  txid = node.testmempoolaccept(signedtx["hex"])
  if txid["allowed"] == 0:
    return True
  print(txid)
  return False
#===============================================================================
# Test 7 : Test With Several Null Addresses in the List
#===============================================================================
def test_redemption_7(node):
  #=============================================================================
  # Create Address
  #=============================================================================
  addr0 = "2dZRkPX3hrPtuBrmMkbGtxTxsuYYgAaFrXZ"
  addr1 = node.getnewaddress()
  addr2 = "2dZRkPX3hrPtuBrmMkbGtxTxsuYYgAaFrXZ"
  addr3 = node.getnewaddress()
  #=============================================================================
  # Add address to FreezeList
  #=============================================================================
  node.addtofreezelist(addr1)
  node.addtofreezelist(addr3)
  #=============================================================================
  # Create Inputs & Outputs
  #=============================================================================
  unspent = node.listunspent()
  fee = Decimal('0.0001')
  # Make Inputs
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
  txid = node.testmempoolaccept(signedtx["hex"])
  if txid["allowed"] == 0:
    print(txid)
    return False
  return True

class RedemptionTest (BitcoinTestFramework):
  def __init__(self):
    super().__init__()
    self.setup_clean_chain = True
    self.num_nodes = 4
    self.extra_args = [['-usehd={:d}'.format(i % 2 == 0), '-keypool=100']
                       for i in range(self.num_nodes)]
    self.extra_args[0].append("-freezelist=1")

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
    if test_redemption_1(self.nodes[0]) == True:
      print("Test 1 :\033[1;32;40m OK\033[0m")
    else:
      failed = True
      print("Test 1 :\033[1;31;40m KO\033[0m")
    #===========================================================================
    # Test : 2
    #===========================================================================
    if test_redemption_2(self.nodes[0]) == True:
      print("Test 2 :\033[1;32;40m OK\033[0m")
    else:
      failed = True
      print("Test 2 :\033[1;31;40m KO\033[0m")
    #===========================================================================
    # Test : 3
    #===========================================================================
    if test_redemption_3(self.nodes[0]) == True:
      print("Test 3 :\033[1;32;40m OK\033[0m")
    else:
      failed = True
      print("Test 3 :\033[1;31;40m KO\033[0m")
    #===========================================================================
    # Test : 4
    #===========================================================================
    if test_redemption_4(self.nodes[0]) == True:
      print("Test 4 :\033[1;32;40m OK\033[0m")
    else:
      failed = True
      print("Test 4 :\033[1;31;40m KO\033[0m")
    #===========================================================================
    # Test : 5
    #===========================================================================
    if test_redemption_5(self.nodes[0]) == True:
      print("Test 5 :\033[1;32;40m OK\033[0m")
    else:
      failed = True
      print("Test 5 :\033[1;31;40m KO\033[0m")
    #===========================================================================
    # Test : 6
    #===========================================================================
    if test_redemption_6(self.nodes[0]) == True:
      print("Test 6 :\033[1;32;40m OK\033[0m")
    else:
      failed = True
      print("Test 6 :\033[1;31;40m KO\033[0m")
    #===========================================================================
    # Test : 7
    #===========================================================================
    if test_redemption_7(self.nodes[0]) == True:
      print("Test 7 :\033[1;32;40m OK\033[0m")
    else:
      failed = True
      print("Test 7 :\033[1;31;40m KO\033[0m")
    #===========================================================================
    # End
    #===========================================================================
    assert failed == False
    print("End.")
#===============================================================================
# Main, Entry Point
#===============================================================================
if __name__ == '__main__':
  RedemptionTest().main()
