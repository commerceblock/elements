#!/bin/bash
shopt -s expand_aliases

alias ocd="oceand -datadir=$HOME/co-client-dir"
alias ocl="ocean-cli -datadir=$HOME/co-client-dir"

ocl stop
sleep 1

rm -r ~/co-client-dir
mkdir ~/co-client-dir

printf '%s\n' '#!/bin/sh' 'rpcuser=user1' \
    'rpcpassword=password1' \
    'rpcport=5555' \
    'rpcallowip=0.0.0.0/0'\
    'port=6666' \
    'initialfreecoins=2100000000000000' \
    'policycoins=2100000000000000' \
    'daemon=1' \
    'listen=1' \
    'txindex=1' \
    'initialfreecoinsdestination=76a914be70510653867b1c648b43cfb3b0edf8420f08d788ac' \
    'permissioncoinsdestination=76a914be70510653867b1c648b43cfb3b0edf8420f08d788ac' \
    'challengecoinsdestination=76a914be70510653867b1c648b43cfb3b0edf8420f08d788ac' > ~/co-client-dir/ocean.conf

ocd
sleep 5

echo "Importing challenger key"
ocl importprivkey cScSHCQp9AEwzZoucRpX9bMRkLCJ4LoQWBNFTZuD6tPX9qwNMWfQ
sleep 2

# Create request
echo "Create request"
pub=`ocl validateaddress $(ocl getnewaddress) | jq -r ".pubkey"`
unspent=`ocl listunspent 1 9999999 [] true "PERMISSION" | jq .[0]`
value=`echo $unspent | jq -r ".amount"`
genesis=`ocl getblockhash 0`

inputs="{\"txid\":$(echo $unspent | jq ".txid"),\"vout\":$(echo $unspent | jq -r ".vout")}"
outputs="{\"decayConst\":1000,\"endBlockHeight\":10,\"fee\":3,\"genesisBlockHash\":\"$genesis\",\
\"startBlockHeight\":5,\"tickets\":2,\"startPrice\":50,\"value\":$value,\"pubkey\":\"$pub\"}"

signedtx=`ocl signrawtransaction $(ocl createrawrequesttx $inputs $outputs)`
request_txid=`ocl sendrawtransaction $(echo $signedtx | jq -r ".hex")`

ocl generate 1
ocl getrequests

# Create bid
echo "Create request bid"

# Create tx for bid to spend from
bid_txid=$(ocl sendtoaddress `ocl getnewaddress` 100 "" "" false "CBT")
ocl generate 1

addr=`ocl getnewaddress`
pub=`ocl validateaddress $addr | jq -r ".pubkey"`
bid_tx=$(ocl decoderawtransaction `ocl getrawtransaction $bid_txid`)
value=$(echo $bid_tx | jq '.vout[0].value')
if [ $value = 100 ]   # Find correct vout
then
  vout=$(echo $bid_tx | jq '.vout[0].n')
else
  vout=$(echo $bid_tx | jq '.vout[1].n')
fi
domain_asset=$(echo $bid_tx | jq '.vout['$vout'].asset')


inputs="[{\"txid\":\"$bid_txid\",\"vout\":$vout,\"asset\":$domain_asset}]"
outputs="{\"endBlockHeight\":10,\"requestTxid\":\"$request_txid\",\"pubkey\":\"$pub\",\
\"feePubkey\":\"026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3\",\
\"value\":55,\"change\":\"44.999\",\"changeAddress\":\"$addr\",\"fee\":0.001}"

signedtx=`ocl signrawtransaction $(ocl createrawbidtx $inputs $outputs)`
txid=`ocl sendrawtransaction $(echo $signedtx | jq -r ".hex")`

# Create bid for test with guardnode repo
echo "Importing guardnode key"
ocl importprivkey cPjJhtAgmbkovqCd1BgnY2nxGftX2tqen6UzaMxvFeH8xT3PWUod
sleep 2

echo "Create another request bid"
# Create tx for bid to spend from
bid_txid2=$(ocl sendtoaddress `ocl getnewaddress` 100 "" "" false "CBT")
ocl generate 1

addr=`ocl getnewaddress`
pub=`ocl validateaddress $addr | jq -r ".pubkey"`
bid_tx=$(ocl decoderawtransaction `ocl getrawtransaction $bid_txid2`)
value=$(echo $bid_tx | jq '.vout[0].value')
if [ $value = 100 ]
then
  vout=$(echo $bid_tx | jq '.vout[0].n')
else
  vout=$(echo $bid_tx | jq '.vout[1].n')
fi
domain_asset=$(echo $bid_tx | jq '.vout['$vout'].asset')

inputs="[{\"txid\":\"$bid_txid2\",\"vout\":$vout,\"asset\":$domain_asset}]"
outputs="{\"endBlockHeight\":10,\"requestTxid\":\"$request_txid\",\"pubkey\":\"$pub\",\
\"feePubkey\":\"026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3\",
\"value\":55,\"change\":\"44.999\",\"changeAddress\":\"$addr\",\"fee\":0.001}"

signedtx=`ocl signrawtransaction $(ocl createrawbidtx $inputs $outputs)`
txid=`ocl sendrawtransaction $(echo $signedtx | jq -r ".hex")`

echo "mempool"
ocl getrawmempool
ocl generate 1
ocl getrequestbids $(ocl getrequests | jq -r ".[].txid")
echo "Guardnode txid: $txid"
