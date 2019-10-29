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
            bool bAppendType=true;

        public:
            CByteVecVisitor(CRegisterAddressScript* scriptIn, 
                bool bAppendTypeIn=true) : script(scriptIn), 
                bAppendType(bAppendTypeIn) {}

            bool operator()(const CKeyID& id) const {
                if(bAppendType)
                    script->Append(AddrType::P2PKH);
                std::vector<unsigned char> v = ToByteVector(id);
                script->Append(v);
                return true;
            }

            bool operator()(const CScriptID& id) const { 
                if(bAppendType)
                    script->Append(AddrType::P2SH);
                std::vector<unsigned char> v = ToByteVector(id);
                script->Append(v);
                return true;
            }
             
            bool operator()(const CNoDestination& no) const { return false; }
    };
} //anon namespace



CRegisterAddressScript::CRegisterAddressScript(RegisterAddressType type){

    _whitelistType = type;
    _nScriptVersion = fWhitelistEncrypt ? 0 : 1;
}

CRegisterAddressScript::CRegisterAddressScript(const CRegisterAddressScript* script, 
    RegisterAddressType type) : CRegisterAddressScript(type){
    _payload = script->_payload;
    _encrypted = script->_encrypted;
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
    return BuildScript(script, sendData);
}

bool CRegisterAddressScript::FinalizeUnencrypted(CScript& script){
    ucvec sendData;
    sendData.resize(AES_BLOCKSIZE);
    sendData.insert(sendData.end(), _payload.begin(), _payload.end()); 
    return BuildScript(script, sendData);
}

bool CRegisterAddressScript::BuildScript(CScript& script, const ucvec& sendData){
    script.clear();
    switch(_nScriptVersion){
        case 0:
            script << _opcode << sendData;
            break;
        case 1:
            script << _opcode << OP_1 << sendData;
            break;
        default:
            script << _opcode << sendData;
            break;
    };
    return true;
}

bool CRegisterAddressScript::Append(const AddrType& addr){
    unsigned char t;
    switch(_nScriptVersion){
        case 1:
            t = (unsigned char)addr;
            AppendChar(t);
            return true;
        default:
            return false;
    };
}

bool CRegisterAddressScript::Append(const CPubKey& pubKey){
    if(_whitelistType != RA_PUBLICKEY && _whitelistType != RA_ONBOARDING)
        return false;   
    std::vector<unsigned char> v = ToByteVector(pubKey);
    Append(v);
    return true;
}




bool CRegisterAddressScript::Append(const pubKeyPair& p){
    if(_whitelistType != RA_PUBLICKEY && _whitelistType != RA_ONBOARDING)
        return false;

    if(!Params().ContractInTx()){
        if(!Consensus::CheckValidTweakedAddress(p.first, p.second))
            return false;

        CBitcoinAddress addr(p.first);

        if(!addr.IsValid())
            return false;

        Append(AddrType::DERIVED);

        if(!boost::apply_visitor(CByteVecVisitor(this, false), p.first)) 
            return false;

        Append(p.second);
    } else {
        Append(p.first);
    }

    return true;
}

bool CRegisterAddressScript::Append(const CTxDestination& dest){
    if(_whitelistType != RA_PUBLICKEY && _whitelistType != RA_ONBOARDING)
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


bool CRegisterAddressScript::Append(const uint8_t nMultisig, const CTxDestination keyID, const std::vector<CPubKey>& keys){
    if(_whitelistType != RA_MULTISIG && _whitelistType != RA_ONBOARDING)
        return false;

    if (!Params().ContractInTx()){

        if(!(Consensus::CheckValidTweakedAddress(keyID, keys, nMultisig)))
            return false;

        unsigned int nAppend=0;
        if(Append(AddrType::MULTI)) ++nAppend;
        AppendChar((unsigned char)nMultisig);
        ++nAppend;
        AppendChar((unsigned char)keys.size());
        ++nAppend;

        if(!boost::apply_visitor(CByteVecVisitor(this, false), keyID)) {
            PopBack(nAppend);
            return false;
        }

        for(unsigned int i = 0; i < keys.size(); ++i){
            Append(keys[i]);
        }
    } else {
        Append(keyID);
    }
    return true;
}

bool CRegisterAddressScript::Append(const OnboardMultisig& data){
    if(_whitelistType != RA_MULTISIG && _whitelistType != RA_ONBOARDING)
        return false;

    return Append(data.nMultisig, data.scriptID, data.pubKeys);
}

void CRegisterAddressScript::Append(const std::vector<unsigned char>& v){
    _payload.insert(_payload.end(), 
                v.begin(), 
                v.end()); 
}

bool CRegisterAddressScript::Append(const std::vector<pubKeyPair>& v){
    if(_whitelistType != RA_PUBLICKEY && _whitelistType != RA_ONBOARDING)
        return false;

    for (auto p : v){
        if(!Append(p))
            return false;
    }
    return true;
}

bool CRegisterAddressScript::Append(const std::vector<CTxDestination>& v){
    if(_whitelistType != RA_PUBLICKEY && _whitelistType != RA_ONBOARDING)
        return false;

    for (auto p : v){
        if(!Append(p))
            return false;
    }
    return true;
}

bool CRegisterAddressScript::Append(const std::vector<OnboardMultisig>& v){
    if(_whitelistType != RA_PUBLICKEY && _whitelistType != RA_ONBOARDING)
        return false;

    for (auto p : v){
        if(!Append(p))
            return false;
    }
    return true;
}
