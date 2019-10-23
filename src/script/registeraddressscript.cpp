// Copyright (c) 2018 The CommerceBlock Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// An ecrypted "register address" transaction script.

#include "registeraddressscript.h"
#include "util.h"

namespace
{
    class CByteVecVisitor : public boost::static_visitor<bool>{
        private:
            CRegisterAddressScript* script;

        public:
            CByteVecVisitor(CRegisterAddressScript* scriptIn) : script(scriptIn) {}

            bool operator()(const CKeyID& id) const { 
                std::vector<unsigned char> v = ToByteVector(id);
                script->Append(v);
                return true;
            }

            bool operator()(const CScriptID& id) const { 
                std::vector<unsigned char> v = ToByteVector(id);
                script->Append(v);
                return true;
            }
             
            bool operator()(const CNoDestination& no) const { return false; }
    };
} //anon namespace



CRegisterAddressScript::CRegisterAddressScript(RegisterAddressType type){
    whitelistType = type;
}

CRegisterAddressScript::CRegisterAddressScript(const CRegisterAddressScript* script, RegisterAddressType type){
    _payload = script->_payload;
    _encrypted = script->_encrypted;
    whitelistType = type;
}

CRegisterAddressScript::~CRegisterAddressScript(){
}

//Encrypt the payload, buid the script and return it.
bool CRegisterAddressScript::Finalize(CScript& script, const CPubKey& ePubKey, const CKey& ePrivKey){
    _encrypted.clear();
    CECIES_hex encryptor;
    encryptor.Encrypt(_encrypted, _payload, ePubKey, ePrivKey);
//    _encrypted.insert(_encrypted.begin(),_payload.begin(), _payload.end());
    //Prepend the initialization vector used in the encryption
    ucvec sendData;
    sendData.insert(sendData.end(), _encrypted.begin(), _encrypted.end()); 
    //Assemble the script and return
    script.clear();
    script << _opcode << sendData; 
    return true;
}

bool CRegisterAddressScript::FinalizeUnencrypted(CScript& script){
    ucvec sendData;
    sendData.resize(AES_BLOCKSIZE);
    sendData.insert(sendData.end(), _payload.begin(), _payload.end()); 
    script.clear();
    script << _opcode << sendData; 
    return true;
}

bool CRegisterAddressScript::Append(const CPubKey& pubKey){
    if(whitelistType != RA_PUBLICKEY && whitelistType != RA_ONBOARDING)
        return false;   
    std::vector<unsigned char> v = ToByteVector(pubKey);
    Append(v);
    return true;
}

bool CRegisterAddressScript::Append(const std::vector<pubKeyPair>& keyPairs){
   if(whitelistType != RA_PUBLICKEY && whitelistType != RA_ONBOARDING)
        return false;

    for (auto p : keyPairs){
        if(!Append(p))
            return false;
    }
    return true;
}

bool CRegisterAddressScript::Append(const pubKeyPair& p){
    if(whitelistType != RA_PUBLICKEY && whitelistType != RA_ONBOARDING)
        return false;

    if(!Params().ContractInTx() && !Consensus::CheckValidTweakedAddress(p.first, p.second))
        return false;
    
    CBitcoinAddress addr(p.first);

    if(!addr.IsValid())
        return false;

    if(!boost::apply_visitor(CByteVecVisitor(this), p.first)) 
        return false;

    //Pubkey not needed for contactintx
    if (!Params().ContractInTx())
        Append(p.second);

    return true;
}

bool CRegisterAddressScript::Append(const std::vector<CTxDestination>& dests){
    if(whitelistType != RA_PUBLICKEY && whitelistType != RA_ONBOARDING)
        return false;

    for(CTxDestination dest : dests){
        if (!Append(dest))
            return false;
    }
    return true;
}


bool CRegisterAddressScript::Append(const CTxDestination& dest){
    if(whitelistType != RA_PUBLICKEY && whitelistType != RA_ONBOARDING)
        return false;

    CTxDestination d = dest;

    if (!Params().ContractInTx()){
        uint256 contract = chainActive.Tip() ? chainActive.Tip()->hashContract : GetContractHash();
        if (!contract.IsNull())
            return false;
    }
    
    CBitcoinAddress addr(dest);

    if(!addr.IsValid())
        return false;

    if(!boost::apply_visitor(CByteVecVisitor(this), dest)) 
        return false;

    return true;
}

bool CRegisterAddressScript::Append(const std::vector<CPubKey>& keys){
    if(whitelistType != RA_PUBLICKEY && whitelistType != RA_ONBOARDING)
        return false;

    for(CPubKey pubKey : keys){
        if (!Append(pubKey))
            return false;
    }
    return true;
}



bool CRegisterAddressScript::Append(const uint8_t nMultisig, const CTxDestination keyID, const std::vector<CPubKey>& keys){
    if(whitelistType != RA_MULTISIG && whitelistType != RA_ONBOARDING)
        return false;

    if (!Params().ContractInTx() && !(Consensus::CheckValidTweakedAddress(keyID, keys, nMultisig)))
        return false;

    if (!Params().ContractInTx()){
    
        _payload.insert(_payload.end(), 
                    (unsigned char)nMultisig);

        _payload.insert(_payload.end(), 
                    (unsigned char)keys.size());

    }

    if(!boost::apply_visitor(CByteVecVisitor(this), keyID)) 
        return false;

    if (!Params().ContractInTx()){
        for(unsigned int i = 0; i < keys.size(); ++i){
            Append(keys[i]);
        }
    }
    
    return true;
}

bool CRegisterAddressScript::Append(const std::vector<OnboardMultisig>& _data){
    if(whitelistType != RA_MULTISIG && whitelistType != RA_ONBOARDING)
        return false;

    for(OnboardMultisig _multi : _data){
        if (!Append(_multi.nMultisig, _multi.scriptID, _multi.pubKeys))
            return false;
    }
    return true;
}

void CRegisterAddressScript::Append(const std::vector<unsigned char> v){
    _payload.insert(_payload.end(), 
                v.begin(), 
                v.end()); 
}


