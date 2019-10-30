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
    _pubKeyPairs.clear();
    _destinations.clear();
    _decryptedStream.clear();
    _errorStream.clear();
    _multisigData.clear();
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

    _fAddressesValid=true;

    while (_file.good()){
        //Skip the header, footer
        std::string line;
        std::getline(_file, line);
        if(ss.str().size() >= nBytesTotal){
           if (line.empty() || line[0] == '#'){
                appendOutStream(line);
                continue;
            }
        }

        //Read the metadata and initialize the decryptor
        if(!_onboardUserPubKey){
            appendOutStream(line);
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

  
            std::vector<unsigned char> userPubKeyData(ParseHex(vstr[1]));    
            _onboardUserPubKey = new CPubKey(userPubKeyData.begin(), userPubKeyData.end());
            if(!_onboardUserPubKey->IsFullyValid())
                 throw std::invalid_argument(
                        std::string(std::string(__func__) +  ": invalid onboard user pub key in kyc file"));

            if(!pwalletMain->GetKey(_onboardPubKey->GetID(), onboardPrivKey))
                if(!pwalletMain->GetKey(_onboardUserPubKey->GetID(), onboardPrivKey))
                    throw std::invalid_argument(
                        std::string(std::string(__func__) +  ": cannot get onboard private key"));

            std::stringstream ssNBytes;
            ssNBytes << vstr[2];
            ssNBytes >> nBytesTotal;

            continue;
        }

	//Remove whitespace from line
	line=trim(line);
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
                if(!encryptor.Decrypt(vdata, vch, onboardPrivKey)){
                    if((_onboardPubKey == nullptr) |! encryptor.Decrypt(vdata, vch, onboardPrivKey, *_onboardPubKey))
                        throw std::invalid_argument(
                            std::string(std::string(__func__) +  ": KYC file decryption failed"));
                }

                data = std::string(vdata.begin(), vdata.end());
                std::stringstream ss_data;
                ss_data << data;
                //Get the addresses
                for(std::string line; std::getline(ss_data, line);){
                    std::vector<std::string> vstr;
                    if (line.empty() || line[0] == '#'){
                        appendOutStream(line);
                        continue;
                    }
                    boost::split(vstr, line, boost::is_any_of(" "));
                    if (vstr.size() < 1){
                        continue;
                    }
                    else if (vstr.size() == 1){
                        if(!parseAddress(vstr,line)) _fAddressesValid = false;
                        continue;
                    }
                    else if (vstr.size() == 2){
                        if(parseContractHash(vstr,line))
                            continue;
                        if(!parsePubkeyPair(vstr,line)) _fAddressesValid = false;
                    }
                    //Current line is a multisig line if there are more than two elements
                    else{
                        if(!parseMultisig(vstr,line)) _fAddressesValid = false;
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

bool CKYCFile::parseContractHash(const std::vector<std::string> vstr, const std::string line){
    if(vstr[0].compare("contracthash:"))
        return false;
    if(_fContractHash_parsed)
        return true;
    _fContractHash_parsed = true;

    uint256 contract = chainActive.Tip() ? chainActive.Tip()->hashContract : GetContractHash();
    if(!contract.ToString().compare(vstr[1])){
        _fContractHash=true;
    }

    if(!_fContractHash){
        appendOutStream(line, ": incorrect contract hash - expected " + contract.ToString());
    } 
        
    appendOutStream(line);
    return true;
}

void CKYCFile::appendOutStream(std::string line){
    _decryptedStream << line << std::endl;
}

void CKYCFile::appendOutStream(std::string line, std::string error){
    std::stringstream ss;
    ss << line << error;
    _errorStream << ss.str() << std::endl;
    appendOutStream(ss.str());
}

bool CKYCFile::parseAddress(const std::vector<std::string> vstr, const std::string line){
    CBitcoinAddress address;
    if (!address.SetString(vstr[0])) {
        std::stringstream ss(": invalid base58check address: ");
        ss << vstr[0];
        appendOutStream(line, ss.str());
        return false;
    }

    //Addresses valid, write to map
    _destinations.push_back(address.Get());
    appendOutStream(line);
    return true;
}

bool CKYCFile::parsePubkeyPair(const std::vector<std::string> vstr, const std::string line){
    CBitcoinAddress address;
    if (!address.SetString(vstr[0])) {
        std::stringstream ss(": invalid base58check address: ");
        ss << vstr[0];
        appendOutStream(line, ss.str());
        return false;
    }

    std::vector<unsigned char> pubKeyData(ParseHex(vstr[1]));
    CPubKey pubKey = CPubKey(pubKeyData.begin(), pubKeyData.end());
    if(!pubKey.IsFullyValid()){
        appendOutStream(line, ": invalid public key");
       return false;
    }

    //Check the key tweaking
    CKeyID addressKeyId;
    pubKeyPair p;
    if(address.GetKeyID(addressKeyId)){
        p = pubKeyPair(addressKeyId, pubKey);
        if(!Params().ContractInTx()){
            if(!Consensus::CheckValidTweakedAddress(p)){
                appendOutStream(line, ": invalid key tweaking");
                return false;
            }
        }
    }
    else{
        appendOutStream(line, ": invalid keyid");
        return false;
    }


    //Addresses valid, write to map
    _pubKeyPairs.push_back(p);
    appendOutStream(line);
    return true;
}

bool CKYCFile::parseMultisig(const std::vector<std::string> vstr, const std::string line){
    if(vstr[0].length() == 0){
        appendOutStream(line, ": invalid nmultisig");
        return false;
    }

     uint8_t nMultisig = 0;
    try{
        nMultisig = std::stoi(vstr[0]);
    } catch (const std::exception& e){
        appendOutStream(line, ": invalid nmultisig size");
        return false;
    }

    if(nMultisig < 1 || nMultisig > MAX_P2SH_SIGOPS){
        appendOutStream(line, ": invalid nmultisig size");
        return false;
    }
    
    CBitcoinAddress address;
    if (!address.SetString(vstr[1])) {
        std::stringstream ss(": invalid base58check address: ");
        ss << vstr[1];
        appendOutStream(line, ss.str());
        return false;
    }

    std::vector<CPubKey> pubKeys;
    for (unsigned int i = 2; i < vstr.size(); ++i){
        std::vector<unsigned char> pubKeyData(ParseHex(vstr[i]));
        CPubKey pubKey = CPubKey(pubKeyData.begin(), pubKeyData.end());
        if(!pubKey.IsFullyValid()){
            appendOutStream(line, ": invalid public key");
            return false;
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
                appendOutStream(line, ": invalid key tweaking");
                return false;
            }
        } 
    }
    else{
        appendOutStream(line, ": invalid keyid");
        return false;
    }


    //Multi Address is valid, write to map
    _multisigData.push_back(OnboardMultisig(nMultisig, multiKeyId, pubKeys));
    appendOutStream(line);
    return true;
}

bool CKYCFile::is_valid(){
    CScript script;
    if(is_empty())
        throw std::invalid_argument(std::string(std::string(__func__) +  
                ": no address data in file"));
    return getOnboardingScript(script);
}

bool CKYCFile::is_empty(){
    if(_pubKeyPairs.size() > 0) return false;
    if(_destinations.size() > 0) return false;
    if(_multisigData.size() > 0) return false;
    return true;
}

bool CKYCFile::getOnboardingScript(CScript& script, bool fBlacklist, int nVersion){
    uint256 contract = chainActive.Tip() ? chainActive.Tip()->hashContract : GetContractHash();
    if(!contract.IsNull() && Params().ContractInKYCFile()){
        if(!_fContractHash_parsed) 
            throw std::invalid_argument(std::string(std::string(__func__) +  
                "no contract hash in kycfile"));
    
        if(!_fContractHash) 
            throw std::invalid_argument(std::string(std::string(__func__) +  
                "contract hash incorrect in kycfile"));
    }

    if(!_fAddressesValid) {
        std::stringstream ss(std::string(std::string(__func__)));
        ss << "invalid addresses in kycfile: " << _errorStream.str();
        throw std::invalid_argument(ss.str());
    }


    COnboardingScript obScript;
    if(nVersion >=0) obScript.ScriptVersion(nVersion);
    obScript.SetDeregister(fBlacklist);

    // Lookup the KYC public key assigned to the user from the whitelist
    //addressWhiteList.

    if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();

    if(_multisigData.size() != 0)
        if(!obScript.Append(_multisigData)) return false;

    if(_pubKeyPairs.size() != 0)
        if(!obScript.Append(_pubKeyPairs)) return false;

    if(_destinations.size() != 0)
        if(!obScript.Append(_destinations)) return false;


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


bool CKYCFile::is_whitelisted(){
    bool fOk = true;
    for(auto k : _destinations){
        if(!addressWhitelist->is_whitelisted(k)){
            fOk = false;
            break;
        }
    }
    for(auto k : _pubKeyPairs){
        if(!addressWhitelist->is_whitelisted(k.first)){
            fOk = false;
            break;
        }
    }
    for(auto k : _multisigData){
        if(!addressWhitelist->is_whitelisted(k.scriptID)){
            fOk = false;
            break;
        }
    }
    return fOk;
}

std::vector<CTxDestination> CKYCFile::getAddresses() const{
    std::vector<CTxDestination> result = _destinations;
    for(auto k : _pubKeyPairs){
        result.push_back(k.first);
    }
    for(auto k : _multisigData){
        result.push_back(k.scriptID);
    }
    return result;
}






