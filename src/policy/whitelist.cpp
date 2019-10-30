// Copyright (c) 2018 The CommerceBlock Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain.h"
#include "whitelist.h"
#ifdef ENABLE_WALLET
#endif
#include "ecies_hex.h"
#include "rpc/server.h"
#include "random.h"
#include <fstream>
#include <iostream>
#include <typeinfo>
#include "validation.h"

const unsigned int CWhiteList::nMultisigSize=1;
const unsigned int CWhiteList::addrSize=20;
const unsigned int CWhiteList::_minDataSize=CWhiteList::addrSize;

CWhiteList::CWhiteList(){
  _asset=whitelistAsset;
  //The written code behaviour expects nMultisigSize to be of length 1 at the moment. If it is changed in the future the code needs to be adjusted accordingly.
  assert(nMultisigSize == 1);
}

CWhiteList::~CWhiteList(){;}

void CWhiteList::init_defaults(){
  if (fRequireWhitelistCheck || fScanWhitelist) {
    const CChainParams& chainparams = Params();
    if (chainparams.GetConsensus().mandatory_coinbase_destination != CScript()){
      CTxDestination man_con_dest;
      if(ExtractDestination(chainparams.GetConsensus().mandatory_coinbase_destination, man_con_dest)){
	if(!is_whitelisted(man_con_dest)){
	    try{
	      add_destination(man_con_dest); 
	    } catch (std::invalid_argument e){
	      LogPrintf(std::string("Error adding coinbase destination to whitelist: ") + std::string(e.what()) + "\n");
	    }
	}
	}
      }
    }
}

bool CWhiteList::Load(CCoinsView *view)
{
    CCoinsViewCache coins(view);
    std::unique_ptr<CCoinsViewCursor> pcursor(coins.Cursor());
    LOCK(cs_main);

      //main loop over coins (transactions with > 0 unspent outputs
    while (pcursor->Valid()) {
      boost::this_thread::interruption_point();
      uint256 key;
      CCoins coins;
      if (!(pcursor->GetKey(key) && pcursor->GetValue(coins))) 
        return error("%s: unable to read value", __func__);
             
      //loop over all vouts within a single transaction
      for (unsigned int i=0; i<coins.vout.size(); i++) {
        const CTxOut &out = coins.vout[i];
        //null vouts are spent
        if (!out.IsNull() && (out.nAsset.GetAsset() == _asset)) {
          std::vector<std::vector<unsigned char> > vSolutions;
          txnouttype whichType;
        
          if (!Solver(out.scriptPubKey, whichType, vSolutions)) 
            continue;
              
          // extract address from second multisig public key and add to the freezelist
          // encoding: 33 byte public key: address is encoded in the last 20 bytes (i.e. byte 14 to 33)
          if (whichType == TX_MULTISIG && vSolutions.size() == 4){
            std::vector<unsigned char> vKycPub(vSolutions[2].begin(), vSolutions[2].begin() + 33);
            //The last bytes of the KYC public key are
            //in reverse to prevent spending, 
            std::reverse(vKycPub.begin() + 3, vKycPub.end());
            CPubKey kycPubKey(vKycPub.begin(), vKycPub.end());
            if (!kycPubKey.IsFullyValid()) {
              //  LogPrintf("POLICY: not adding invalid KYC pub key"+HexStr(kycPubKey.begin(), kycPubKey.end())+"\n");
            } else {
              //LogPrintf("POLICY: added unassigned KYC pub key "+HexStr(kycPubKey.begin(), kycPubKey.end())+"\n");
              COutPoint outPoint(key, i);
              add_unassigned_kyc(kycPubKey, outPoint);
            }
          } else if ((whichType == TX_REGISTERADDRESS_V1 || 
                      whichType == TX_REGISTERADDRESS_V0 || 
                      whichType == TX_DEREGISTERADDRESS_V1 ||
                      whichType == TX_DEREGISTERADDRESS_V0)
                      &! fReindex &! fReindexChainState ) {
            ParseRegisterAddressOutput(whichType, vSolutions);
          }
        }
      }
      pcursor->Next();
    }

  sync_whitelist_wallet();

  return true;
}

//Modifies a vector of the kyc public keys whose private keys were not found in the wallet.
void CWhiteList::sync_whitelist_wallet(std::vector<CPubKey>& keysNotFound){
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);  
  #ifdef ENABLE_WALLET
  LOCK2(cs_main, pwalletMain->cs_wallet);
  EnsureWalletIsUnlocked();
  keysNotFound.clear();
  int nTries = 0;
  int nKeys = _kycUnassignedSet.size();
  int nTriesMax = MAX_KYCPUBKEY_GAP + nKeys;
  bool bKeyFound = true;
  for(auto key : _kycUnassignedSet){
    bKeyFound=true;
    CKeyID kycKey=key.GetID();
    CKey privKey;
    while(!pwalletMain->GetKey(kycKey, privKey)){
      pwalletMain->GenerateNewKey(true);
      if(++nTries > nTriesMax){
        keysNotFound.push_back(key);
        bKeyFound=false;
        break;
      }
    }
    //Reset the gap if a key was found.
    if(bKeyFound) nTries=std::min(nTries, nKeys);
  }
  #endif //#ifdef ENABLE_WALLET
}

void CWhiteList::sync_whitelist_wallet(){
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);  
  std::vector<CPubKey> keysNotFound;
  sync_whitelist_wallet(keysNotFound);
}
  

void CWhiteList::add_destination(const CTxDestination& dest){
    boost::recursive_mutex::scoped_lock scoped_lock(_mtx);  
    if (dest.which() == ((CTxDestination)CNoDestination()).which()){
        throw std::invalid_argument(std::string(std::string(__func__) + 
        ": invalid destination"));
    }   
    add_sorted(dest);
}

void CWhiteList::add_derived(const CBitcoinAddress& address, const CPubKey& pubKey, 
        const std::unique_ptr<CPubKey>& kycPubKey){
    add_derived(address, pubKey);
}

void CWhiteList::add_derived(const CBitcoinAddress& address, const CPubKey& pubKey){
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);

  CDerivedData dat;
  dat.Set(pubKeyPair(address.Get(), pubKey));

  add_sorted(dat.GetDest());
}

void CWhiteList::add_derived(const std::string& sAddress, const std::string& sPubKey, 
        const std::string& sKYCPubKey){
    add_derived(sAddress, sPubKey);
}

void CWhiteList::add_derived(const std::string& sAddress, const std::string& sPubKey){
    boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
    CBitcoinAddress address;
  if (!address.SetString(sAddress))
    throw std::invalid_argument(std::string(std::string(__func__) + 
      ": invalid Bitcoin address: ") + sAddress);
  
  std::vector<unsigned char> pubKeyData(ParseHex(sPubKey));
  CPubKey pubKey = CPubKey(pubKeyData.begin(), pubKeyData.end());

  std::unique_ptr<CPubKey> kycPubKey(new CPubKey());
  add_derived(address, pubKey);
}

void CWhiteList::add_multisig_whitelist(const CBitcoinAddress& address, const std::vector<CPubKey>& pubKeys, 
        const std::unique_ptr<CPubKey>& kycPubKey, const uint8_t nMultisig){
    add_multisig_whitelist(address, pubKeys, nMultisig);
}

void CWhiteList::add_multisig_whitelist(const CBitcoinAddress& address, const std::vector<CPubKey>& pubKeys, 
  const uint8_t m){
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);

  CMultisigData dat;

  CTxDestination dest = address.Get();

  dat.Set(dest, pubKeys, m);

  //insert new address into sorted CWhiteList vector
  add_sorted(dat.GetDest());
}

void CWhiteList::add_multisig_whitelist(const std::string& addressIn, const UniValue& keys, 
        const std::string& sKYCAddress, const uint8_t nMultisig){
    add_multisig_whitelist(addressIn, keys, nMultisig);
}

void CWhiteList::add_multisig_whitelist(const std::string& sAddress, const UniValue& sPubKeys, 
  const uint8_t mMultisig){

  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
  CBitcoinAddress address;
  if (!address.SetString(sAddress))
    throw std::invalid_argument(std::string(std::string(__func__) + 
    ": invalid Bitcoin address: ") + sAddress);

  std::vector<CPubKey> pubKeyVec;
  for (unsigned int i = 0; i < sPubKeys.size(); ++i){
    std::string parseStr = sPubKeys[i].get_str();
    std::vector<unsigned char> pubKeyData(ParseHex(parseStr.c_str()));
    CPubKey pubKey = CPubKey(pubKeyData.begin(), pubKeyData.end());
    pubKeyVec.push_back(pubKey);
   }

   add_multisig_whitelist(address, pubKeyVec, mMultisig);
}

bool CWhiteList::RegisterAddress(const CTransaction& tx, const CBlockIndex* pindex){
  #ifdef ENABLE_WALLET
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
  CCoinsViewCache mapInputs(pcoinsTip);
  mapInputs.SetBestBlock(pindex->GetBlockHash());
  return RegisterAddress(tx, mapInputs);
  #else //#ifdef ENABLE_WALLET
    LogPrintf("POLICY: wallet not enabled - unable to process registeraddress transaction.\n");
    return false;
  #endif //#ifdef ENABLE_WALLET
}

bool CWhiteList::RegisterAddress(const CTransaction& tx, const CCoinsViewCache& mapInputs){
  #ifdef ENABLE_WALLET
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
  if(!mapInputs.HaveInputs(tx)) 
    return false; // No inputs for tx in cache

  if (tx.IsCoinBase())
    return false; // Coinbases don't use vin normally

  return RegisterAddress(tx.vout);

  #else //#ifdef ENABLE_WALLET
    LogPrintf("POLICY: wallet not enabled - unable to process registeraddress transaction.\n");
      return false;
  #endif //#ifdef ENABLE_WALLET
}

bool CWhiteList::RegisterAddress(const std::vector<CTxOut>& vout){
  #ifdef ENABLE_WALLET
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);

  LOCK2(cs_main, pwalletMain->cs_wallet);
  EnsureWalletIsUnlocked();

  //Check if this is a TX_REGISTERADDRESS or TX_DEREGISTERADDRESS. If so, read the data into a byte vector.
  txnouttype whichType;

  // For each TXOUT, if a TX_REGISTERADDRESS, read the istdata
  BOOST_FOREACH (const CTxOut& txout, vout) {
    if (!IsWhitelistAsset(txout)) continue;
    std::vector<std::vector<unsigned char> > vSolutions;
    if (!Solver(txout.scriptPubKey, whichType, vSolutions)) return false;
    if(whichType == TX_REGISTERADDRESS_V1 ||
      whichType == TX_REGISTERADDRESS_V0 || 
      whichType == TX_DEREGISTERADDRESS_V1 ||
      whichType == TX_DEREGISTERADDRESS_V0) {
      return ParseRegisterAddressOutput(whichType, vSolutions);
    }
  }
  return false;
  #else //#ifdef ENABLE_WALLET
    LogPrintf("POLICY: wallet not enabled - unable to process registeraddress transaction.\n");
      return false;
  #endif //#ifdef ENABLE_WALLET
}

bool CWhiteList::ParseRegisterAddressOutput(const txnouttype& whichType, const std::vector<uc_vec>& solutions){
  #ifdef ENABLE_WALLET
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);

  const uc_vec& bytes = solutions[0];

  //Confirm data read from the TX_REGISTERADDRESS
  if(bytes.size()<_minDataSize) return false;

  //Read the message data
  std::vector<unsigned char> data(bytes.begin(), bytes.end());
  return RegisterDecryptedAddresses(whichType, data);

  #else //#ifdef ENABLE_WALLET
    LogPrintf("POLICY: wallet not enabled - unable to process registeraddress transaction.\n");
      return false;
  #endif //#ifdef ENABLE_WALLET
}



bool CWhiteList::RegisterDecryptedAddresses(const txnouttype& whichType, const std::vector<unsigned char>& data){
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);

  CRegisterAddressData* dat;
  std::vector<CRegisterAddressData*> vDat;

  CRegisterAddressDataFactory* fact;

  //Selects the appropriate factory for the registeraddress script format
  if ( whichType == TX_REGISTERADDRESS_V1 || whichType == TX_DEREGISTERADDRESS_V1 ){
    fact = new CRegisterAddressDataFactory_v1(data);
  } else if( whichType == TX_REGISTERADDRESS_V0 || whichType == TX_DEREGISTERADDRESS_V0 ){
    fact = new CRegisterAddressDataFactory(data);
  } else {
    return false;
  }
    
  while(dat = fact->GetNext()){
    vDat.push_back(dat);
  }

  //Everything was valid if the factory reached the end of the byte vector
  if (!fact->IsEnd()) {
    delete fact;
    return false;
  }

  //If entire stream was read successfully, add the addresssses to the whitelist
  if((whichType == TX_DEREGISTERADDRESS_V1) || (whichType == TX_DEREGISTERADDRESS_V0)){
    for (auto aDat : vDat){
      remove(aDat);
    }
  } else {
    for (auto aDat : vDat){
      add(aDat);
    }
  }

  delete fact;
  return true;
}

void CWhiteList::add(CRegisterAddressData* d){
  CTxDestination dest = d->GetDest();
  if!((dest == _noDest)) CPolicyList::add_sorted(dest);
}

void CWhiteList::remove(CRegisterAddressData* d){
  CPolicyList::remove(d->GetDest());
}

//Update from transaction
bool CWhiteList::Update(const CTransaction& tx, const CCoinsViewCache& mapInputs)
{
    boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
    if (tx.IsCoinBase())
      return false; // Coinbases don't use vin normally

    // check inputs for encoded address data
    // The first dummy key in the multisig is the (scrambled) kyc public key.
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CTxOut& prev = mapInputs.GetOutputFor(tx.vin[i]);
        if(prev.nAsset.GetAsset() != whitelistAsset)
          return false;
        std::vector<std::vector<unsigned char> > vSolutions;
        txnouttype whichType;

        const CScript& prevScript = prev.scriptPubKey;
        if (!Solver(prevScript, whichType, vSolutions)) continue;

        // extract address from second multisig public key and remove from whitelist
        // bytes 0-32: KYC public key assigned by the server, bytes reversed
        
        if (whichType == TX_MULTISIG && vSolutions.size() == 4)
        {
            std::vector<unsigned char> vKycPub(vSolutions[2].begin(), vSolutions[2].begin() + 33);
            //The last bytes of the KYC public key are
            //in reverse to prevent spending, 
            std::reverse(vKycPub.begin()+3, vKycPub.end());
            CPubKey kycPubKey(vKycPub.begin(), vKycPub.end());
            
            if (!kycPubKey.IsFullyValid()) {
              LogPrintf("POLICY: not removing invalid KYC pub key"+HexStr(kycPubKey.begin(), kycPubKey.end())+"\n");
            }

            if(remove_unassigned_kyc(kycPubKey))
                LogPrintf("POLICY: removed KYC pubkey "+HexStr(kycPubKey.begin(), kycPubKey.end())+"\n");
        }
    }

    //check outputs for encoded address data
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];

        std::vector<std::vector<unsigned char> > vSolutions;
        txnouttype whichType;

        if (!Solver(txout.scriptPubKey, whichType, vSolutions)) continue;

        // extract address from second multisig public key and add it to the whitelist
        // bytes 0-32: KYC public key assigned by the server, bytes reversed
        if (whichType == TX_MULTISIG && vSolutions.size() == 4)
        {
            std::vector<unsigned char> vKycPub(vSolutions[2].begin(), vSolutions[2].begin() + 33);
            //The last bytes of the KYC public key are
            //in reverse to prevent spending, 
            std::reverse(vKycPub.begin() + 3, vKycPub.end());
            CPubKey kycPubKey(vKycPub.begin(), vKycPub.end());
            if (!kycPubKey.IsFullyValid()) {
                LogPrintf("POLICY: not adding invalid KYC pub key"+HexStr(kycPubKey.begin(), kycPubKey.end())+"\n");
            } else {
                COutPoint outPoint(tx.GetHash(), i);
                add_unassigned_kyc(kycPubKey, outPoint);    
                LogPrintf("POLICY: added KYC pub key "+HexStr(kycPubKey.begin(), kycPubKey.end())+"\n");
            }
        }
    }
    return true;
}

bool CWhiteList::get_unassigned_kyc(CPubKey& pubKey){
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
  if(!peek_unassigned_kyc(pubKey)) return false;
  remove_unassigned_kyc(pubKey);
  return true;
}

bool CWhiteList::peek_unassigned_kyc(CPubKey& pubKey){
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
    std::set<CPubKey>::size_type size = _kycUnassignedSet.size();
  if (size == 0) return false;
  auto it = _kycUnassignedSet.begin();
  std::advance(it,GetRand(size-1));
  pubKey= *it;
  return true;
}

bool CWhiteList::is_unassigned_kyc(const CPubKey& kycPubKey){
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
  auto it = _kycUnassignedSet.find(kycPubKey);
  if (it == _kycUnassignedSet.end()) return false;
  return true;
}

void CWhiteList::add_unassigned_kyc(const CPubKey& kycPubKey, const COutPoint& outPoint){
    boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
    CKeyID kycKey=kycPubKey.GetID();    
    _kycPubkeyOutPointMap[kycKey]=outPoint;
    _kycUnassignedSet.insert(kycPubKey);
}

bool CWhiteList::remove_unassigned_kyc(const CPubKey& id){
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
  return _kycUnassignedSet.erase(id);
}


void CWhiteList::dump_unassigned_kyc(std::ofstream& fStream){
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
  // add the base58check encoded tweaked public key and untweaked pubkey hex
  for(auto it = _kycUnassignedSet.begin(); it != _kycUnassignedSet.end(); ++it) {
        const CPubKey &pubKey = *it;
        const CKeyID keyid = pubKey.GetID();
        const CBitcoinAddress address(keyid);
        std::string strAddr = address.ToString();
        fStream << strAddr;
        fStream << " ";
        fStream << std::string(HexStr(pubKey.begin(), pubKey.end()));
        fStream << " ";
        bool bMine = false;
        #ifdef ENABLE_WALLET
        isminetype mine = pwalletMain ? IsMine(*pwalletMain, keyid) : ISMINE_NO;
        if (mine != ISMINE_NO && address.IsBlinded() && address.GetBlindingKey() 
            != pwalletMain->GetBlindingPubKey(GetScriptForDestination(keyid))) {
            // Note: this will fail to return ismine for deprecated static blinded addresses.
            mine = ISMINE_NO;
        }
        bMine =  (mine & ISMINE_SPENDABLE) ? true : false;
        #endif //#ifdef ENABLE_WALLET
        fStream << bMine;
        fStream << std::endl;
    }
}

void CWhiteList::clear(){
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
  CPolicyList::clear();
}

bool CWhiteList::is_whitelisted(const CTxDestination keyId){
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
  return find(keyId);
}

void CWhiteList::add_my_pending(const CTxDestination id){
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
  _myPending.insert(id);
}

void CWhiteList::remove_my_pending(const CTxDestination id){
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
  _myPending.erase(id);
}

bool CWhiteList::is_my_pending(const CTxDestination id){
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
  return (_myPending.find(id) != _myPending.end());
} 

unsigned int CWhiteList::n_my_pending(){
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
  return _myPending.size();
}

bool CWhiteList::get_kycpubkey_outpoint(const CKeyID& keyId, COutPoint& outPoint){
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
  auto it = _kycPubkeyOutPointMap.find(keyId);
  if (it == _kycPubkeyOutPointMap.end()) return false;
  outPoint = it->second;
  return true;
}

bool CWhiteList::get_kycpubkey_outpoint(const CPubKey& pubKey, COutPoint& outPoint){
  boost::recursive_mutex::scoped_lock scoped_lock(_mtx);
  if(!pubKey.IsFullyValid())
    return false;
  return get_kycpubkey_outpoint(pubKey.GetID(), outPoint);
}



//===============================================
//CRegisterAddressDataFactory
//-----------------------------------------------

CRegisterAddressData* CRegisterAddressDataFactory::GetNext(){
  CRegisterAddressData* data;
  if( data = GetNextMultisig() ) return data;
  return GetNextDerived();
}


CMultisigData* CRegisterAddressDataFactory::GetNextMultisig(){

  MarkReset();

  ucvec_it cursor = _cursor; 
  if(!AdvanceCursor(cursor, CWhiteList::nMultisigSize)){
    return nullptr;
  }
  
  std::vector<unsigned char> mMultisigChars(_cursor,cursor);

  uint8_t mMultisig = mMultisigChars[0];

  CMultisigData* data = new CMultisigData();

  try{
    data->SetM(mMultisig);
  } catch (std::invalid_argument e) {
    ResetCursor();
    delete data;
    return nullptr;
  }

  _cursor = cursor;

  if(!AdvanceCursor(cursor, CWhiteList::nMultisigSize)){
    ResetCursor();
    delete data;
    return nullptr;
  }
      
  std::vector<unsigned char> nMultisigChars(_cursor,cursor);

  uint8_t nMultisig = nMultisigChars[0];

  _cursor = cursor;

  if(!AdvanceCursor(cursor, CWhiteList::addrSize)){
    ResetCursor();
    delete data;
    return nullptr;
  }

  std::vector<unsigned char> addrChars(_cursor,cursor);

  //Try and set the multisig dest
  try{
    data->SetDest(CScriptID(uint160(addrChars))); 
  } catch (std::invalid_argument e) {
    ResetCursor();
    delete data;
    return nullptr;
  }

  _cursor=cursor;

  unsigned int pubkeyNr = static_cast<unsigned int>(nMultisig);

  for (unsigned int j=0; j < pubkeyNr; ++j){

    if(!AdvanceCursor(cursor, _pubkeySize)){
      ResetCursor();
      delete data;
      return nullptr;
    }

    CPubKey pubKeyNew = CPubKey(_cursor,cursor);
    try{
      data->AddPubKey(pubKeyNew);
    } catch (std::invalid_argument e) {
      ResetCursor();
      delete data;
      return nullptr;
    }

    _cursor=cursor;      
  }

  try{
      data->TryValid(pubkeyNr);
  } catch (std::invalid_argument e) {
      ResetCursor();
      delete data;
      return nullptr;
  }

  return data;
}

CDerivedData* CRegisterAddressDataFactory::GetNextDerived(){

  MarkReset();

  CDerivedData* data = new CDerivedData();

  ucvec_it cursor = _cursor;

  if(!AdvanceCursor(cursor, CWhiteList::addrSize)){
    ResetCursor();
    delete data;
    return nullptr;
  }

  std::vector<unsigned char> addrChars(_cursor,cursor);
  CTxDestination addr = CKeyID(uint160(addrChars));
            
  _cursor = cursor;

  if(!AdvanceCursor(cursor, _pubkeySize)){
    ResetCursor();
    delete data;
    return nullptr;
  }

  CPubKey pubKeyNew = CPubKey(_cursor,cursor);
  _cursor=cursor;

  pubKeyPair p(addr, pubKeyNew);

  try{
    data->Set(p);
  } catch (std::invalid_argument e) {
      ResetCursor();
      delete data;
      return nullptr;
  }
  return data;
}

CP2SHData* CRegisterAddressDataFactory::GetNextP2SH(){
  return nullptr;
}

CRegisterAddressData* CRegisterAddressDataFactory_v1::GetNext(){
  CWhiteList::AddrType nAddrType;
  if(!GetNextAddrType(nAddrType))
    return nullptr;
  switch(nAddrType){
    case CWhiteList::AddrType::MULTI:
      return GetNextMultisig(); 
    case CWhiteList::AddrType::DERIVED:
      return GetNextDerived();
    case CWhiteList::AddrType::P2SH:
      return GetNextP2SH();
    case CWhiteList::AddrType::P2PKH:
      return GetNextP2PKH();
    default:
      return nullptr;;
  }
}

bool CRegisterAddressDataFactory_v1::GetNextAddrType( CWhiteList::AddrType& type){
  unsigned int t = *_cursor;
  if (t >= CWhiteList::AddrType::LAST)
    return false;
  type = CWhiteList::AddrType(t);
  return AdvanceCursor();
}

CP2PKHData* CRegisterAddressDataFactory_v1::GetNextP2PKH(){
  MarkReset();

  CP2PKHData* data = new CP2PKHData();

  ucvec_it cursor = GetCursor();

  if(!AdvanceCursor(cursor, CWhiteList::addrSize)){
    ResetCursor();
    delete data;
    return nullptr;
  }

  std::vector<unsigned char> addrChars(_cursor,cursor);
  CTxDestination addr = CKeyID(uint160(addrChars));
            
   try{
    data->Set(addr);
    } catch (std::invalid_argument e) {
      ResetCursor();
      delete data;
      return nullptr;
    }

  _cursor = cursor;

  return data;
}

CP2SHData* CRegisterAddressDataFactory_v1::GetNextP2SH(){
  MarkReset();

  CP2SHData* data = new CP2SHData();

  ucvec_it cursor = GetCursor();

  if(!AdvanceCursor(cursor, CWhiteList::addrSize)){
    ResetCursor();
    delete data;
    return nullptr;
  }

  std::vector<unsigned char> addrChars(_cursor,cursor);
  CTxDestination addr = CScriptID(uint160(addrChars));
            
   try{
    data->Set(addr);
    } catch (std::invalid_argument e) {
      ResetCursor();
      delete data;
      return nullptr;
    }

  _cursor = cursor;

  return data;
}

void CDerivedData::Set(const pubKeyPair& pair){
    pubKeyPair p = pair;
      if (!p.second.IsFullyValid()) 
          throw std::invalid_argument(std::string(std::string(__func__) + 
            ": invalid public key"));


      CBitcoinAddress addr(p.first);
      if(!addr.IsValid())
        throw std::invalid_argument(std::string(std::string(__func__) + 
          ": invalid base58check address\n"));

       if(!Params().ContractInTx() && 
        !::Consensus::CheckValidTweakedAddress(p))
          throw std::invalid_argument(std::string(std::string(__func__) + 
            ": address does not derive from public key when tweaked with contract hash"));

        _pubKeyPair = p;
    }

void CMultisigData::TryValid(const uint8_t& n){
  if(Params().ContractInTx()) return;

  //Check m-of-n validity
  if (_m > n ||  n > MAX_P2SH_SIGOPS || n == 0){
    throw std::invalid_argument(std::string(std::string(__func__) + 
    ": invalid m-of-n\n"));
  }

  //Check dest built from pubkeys, m, n
  if(!Params().ContractInTx() && !::Consensus::CheckValidTweakedAddress(_dest, _pubKeys, _m)){
    throw std::invalid_argument(std::string(std::string(__func__) + 
      ": address does not derive from public keys when tweaked with contract hash\n"));
  }
}

