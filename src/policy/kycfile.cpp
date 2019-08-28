// Copyright (c) 2018 The CommerceBlock Developers
// Distributed under the MIT software license, see the accompanying                                                                             
// file COPYING or http://www.opensource.org/licenses/mit-license.php.  

#include "kycfile.h"
#include <boost/algorithm/string.hpp>
#include "policy/policy.h"

CKYCFile::CKYCFile(){

}

CKYCFile::~CKYCFile(){
    clear();
}

void CKYCFile::clear(){
    _addressKeys.clear();
    _decryptedStream.clear();
    delete _onboardPubKey;
    delete _onboardUserPubKey;
}

bool CKYCFile::close(){
    _file.close();
    return (_file.is_open() == false);
}

bool CKYCFile::open(std::string filename){
    close();
    _file.open(filename, std::ios::in | std::ios::ate);
    if (!_file.is_open())
        throw std::invalid_argument(
          std::string(std::string(__func__) +  ": cannot open kyc file"));

    _file.seekg(0, _file.beg);
    return true;
}

bool CKYCFile::read(std::string filename){
    open(filename);
    return read();
}

bool CKYCFile::read(){
    clear();

    // parse file to extract bitcoin address - untweaked pubkey pairs and validate derivation

    std::stringstream ss;
    ss.str("");
    unsigned long nBytesTotal=0;
    std::string data("");

    clear();

    CKey onboardPrivKey;   

    CECIES encryptor;

    while (_file.good()){
        //Skip the header, footer
        std::string line;
        std::getline(_file, line);
        if(ss.str().size() >= nBytesTotal){
           if (line.empty() || line[0] == '#'){
                _decryptedStream << line << "\n";
                continue;
            }
        }

        //Read the metadata and initialize the decryptor
        if(!_onboardUserPubKey){
            _decryptedStream << line << "\n";
            std::vector<std::string> vstr;
            boost::split(vstr, line, boost::is_any_of(" "));
            if (vstr.size() != 3)
                throw std::invalid_argument(
                    std::string(std::string(__func__) +  ": invalid KYC file"));

            std::vector<unsigned char> pubKeyData(ParseHex(vstr[0]));      
            _onboardPubKey = new CPubKey(pubKeyData.begin(), pubKeyData.end());

            if(!_onboardPubKey->IsFullyValid())
                        throw std::invalid_argument(
                        std::string(std::string(__func__) +  ": invalid kyc pub key in KYC file"));

            if(!pwalletMain->GetKey(_onboardPubKey->GetID(), onboardPrivKey))
                throw std::invalid_argument(
                        std::string(std::string(__func__) +  ": cannot get onboard private key"));
  
            std::vector<unsigned char> userPubKeyData(ParseHex(vstr[1]));    
            _onboardUserPubKey = new CPubKey(userPubKeyData.begin(), userPubKeyData.end());
            if(!_onboardUserPubKey->IsFullyValid())
                 throw std::invalid_argument(
                        std::string(std::string(__func__) +  ": invalid onboard user pub key in kyc file"));

            std::stringstream ssNBytes;
            ssNBytes << vstr[2];
            ssNBytes >> nBytesTotal;

            continue;
        }

        //Read in encrypted data, decrypt and output to file
        ss << line;        
        unsigned long size = ss.str().size();
        if(size > nBytesTotal){
            throw std::invalid_argument(
            std::string(std::string(__func__) +  ": invalid KYC file: encrypted data stream too long"));
        }
        if(size == nBytesTotal){
            if(data.size()==0){
                std::string str=ss.str();
                std::vector<unsigned char> vch(str.begin(), str.end());
                std::vector<unsigned char> vdata;
                if(!encryptor.Decrypt(vdata, vch, onboardPrivKey))
                    throw std::invalid_argument(
                        std::string(std::string(__func__) +  ": KYC file decryption failed"));
        
                data = std::string(vdata.begin(), vdata.end());
                std::stringstream ss_data;
                ss_data << data;
                //Get the addresses
                for(std::string line; std::getline(ss_data, line);){
                    std::vector<std::string> vstr;
                    if (line.empty() || line[0] == '#'){
                        _decryptedStream << line << "\n";
                        continue;
                    }
                    boost::split(vstr, line, boost::is_any_of(" "));
                    if (vstr.size() < 2){
                        continue;
                    }
                    else if (vstr.size() == 2){
                        if(parseMAC(vstr,line,vdata))
                            continue;
                        parsePubkeyPair(vstr,line);
                    }
                    //Current line is a multisig line if there are more than two elements
                    else{
                        parseMultisig(vstr,line);
                    }
                }
            }
        }
    }
    if(ss.str().size() < nBytesTotal || ss.str().size() == 0){
         throw std::invalid_argument(
                        std::string(std::string(__func__) +  ": invalid KYC file: encrypted data stream too short"));
    }
    return true;
}

bool CKYCFile::parseMAC(const std::vector<std::string> vstr, const std::string line, 
    const std::vector<unsigned char>& vData){
    if(vstr[0].compare("MAC:"))
        return false;
    CKey* onboardPrivKey = new CKey();
    pwalletMain->GetKey(_onboardPubKey->GetID(), *onboardPrivKey);
    auto it2 = vData.end();
    it2 -= line.size();
    it2 -= 1;
    std::vector<unsigned char> vDataNoMAC(vData.begin(), it2);
    CPubKey tweaked(_addressKeys[0]);

    uint256 contract = chainActive.Tip() ? chainActive.Tip()->hashContract : GetContractHash();
    if (!contract.IsNull() && !Params().ContractInTx())
        tweaked.AddTweakToPubKey((unsigned char*)contract.begin());

    CECIES::GetMAC(tweaked, *onboardPrivKey, vDataNoMAC, _mac_calc);
    std::stringstream ss_mac;
    ss_mac.str("");
    ss_mac << HexStr(std::begin(_mac_calc), std::end(_mac_calc));
    //_fMAC true if the MAC code is correct.
    _fMAC = (vstr[1].compare(ss_mac.str())==0);
    if(!_fMAC){
        _decryptedStream << line << ": invalid kycfile signature (MAC) - expected " + ss_mac.str() +  "\n";
    } else {
        _decryptedStream << line << "\n";
    }
    return true;
}

bool CKYCFile::parsePubkeyPair(const std::vector<std::string> vstr, const std::string line){
    CBitcoinAddress address;
    if (!address.SetString(vstr[0])) {
        _decryptedStream << line << ": invalid base58check address: "  << vstr[0] << "\n";
        return false;
    }

    std::vector<unsigned char> pubKeyData(ParseHex(vstr[1]));
    CPubKey pubKey = CPubKey(pubKeyData.begin(), pubKeyData.end());
    if(!pubKey.IsFullyValid()){
        _decryptedStream << line << ": invalid public key\n";
       return false;
    }

    //Check the key tweaking
    CKeyID addressKeyId;
    if(address.GetKeyID(addressKeyId)){
        if(!Params().ContractInTx()){
            if(!Consensus::CheckValidTweakedAddress(addressKeyId, pubKey)){
                _decryptedStream << line << ": invalid key tweaking\n";
                return false;
            }
        }
    }
    else{
        _decryptedStream << line << ": invalid keyid\n";
        return false;
    }


    //Addresses valid, write to map
    _addressKeys.push_back(pubKey);
    _decryptedStream << line << "\n";
    return true;
}

void CKYCFile::parseMultisig(const std::vector<std::string> vstr, const std::string line){
    if(vstr[0].length() == 0){
        _decryptedStream << line << ": invalid nmultisig\n";
        return;
    }

    uint8_t nMultisig = std::stoi(vstr[0]);

    if(nMultisig < 1 || nMultisig > MAX_P2SH_SIGOPS){
        _decryptedStream << line << ": invalid nmultisig size\n";
        return;
    }
    
    CBitcoinAddress address;
    if (!address.SetString(vstr[1])) {
        _decryptedStream << line << ": invalid base58check address: "  << vstr[1] << "\n";
        return;
    }

    std::vector<CPubKey> pubKeys;
    for (unsigned int i = 2; i < vstr.size(); ++i){
        std::vector<unsigned char> pubKeyData(ParseHex(vstr[i]));
        CPubKey pubKey = CPubKey(pubKeyData.begin(), pubKeyData.end());
        if(!pubKey.IsFullyValid()){
            _decryptedStream << line << ": invalid public key\n";
            return;
        }
        pubKeys.push_back(pubKey);
    }

    //Check the key tweaking
    //Will throw an error if address is not a valid derived address.
    CTxDestination multiKeyId;
    multiKeyId = address.Get();
    if (!(multiKeyId.which() == ((CTxDestination)CNoDestination()).which())) {
        if(!Params().ContractInTx()){
            if(!Consensus::CheckValidTweakedAddress(multiKeyId, pubKeys, nMultisig)){
                _decryptedStream << line << ": invalid key tweaking\n";
                return;
            }
        }
    }
    else{
        _decryptedStream << line << ": invalid keyid\n";
        return;
    }


    //Multi Address is valid, write to map
    _multisigData.push_back(OnboardMultisig(nMultisig, multiKeyId, pubKeys));
    _decryptedStream << line << "\n";
}

bool CKYCFile::getOnboardingScript(CScript& script, bool fBlacklist){
    if(!_fMAC) 
        throw std::invalid_argument(std::string(std::string(__func__) +  
                ": signature (MAC)invalid"));
        

    COnboardingScript obScript;
    obScript.SetDeregister(fBlacklist);

    // Lookup the KYC public key assigned to the user from the whitelist
    //addressWhiteList.

    if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();

    if(_addressKeys.size() != 0)
        if(!obScript.Append(_addressKeys)) return false;

    if(_multisigData.size() != 0)
        if(!obScript.Append(_multisigData)) return false;


    // Get an unassigned KYC key from the addressWhitelist
    if(fWhitelistEncrypt){
        CPubKey kycPubKey;

        if(!addressWhitelist->get_unassigned_kyc(kycPubKey))
            throw std::invalid_argument(
            std::string(std::string(__func__) +  ": no unassigned whitelist KYC keys available"));

        CKeyID kycKeyID(kycPubKey.GetID());
        // Look up the public key
        CKey kycKey;
        if(!pwalletMain->GetKey(kycKeyID, kycKey)){
            addressWhitelist->add_unassigned_kyc(kycPubKey);
            throw std::invalid_argument(
            std::string(std::string(__func__) +  ": cannot get KYC private key from wallet"));
        }
        if(!obScript.Finalize(script, *_onboardUserPubKey, kycKey)) return false;
    } else {
        if(!obScript.FinalizeUnencrypted(script)) return false;
    }

    return true;
}

std::ostream& operator<<(std::ostream& os, const CKYCFile& fl){
    os << fl.getStream().str();
    return os; 
}


