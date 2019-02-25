#include "kycfile.h"
#include <boost/algorithm/string.hpp>

CKYCFile::CKYCFile(){

}

CKYCFile::~CKYCFile(){
    clear();
}

void CKYCFile::clear(){
    _addressKeys.clear();
    _decryptedStream.clear();
    delete _encryptor;
    delete _onboardPubKey;
    delete _onboardUserPubKey;
    delete _initVec;
}

bool CKYCFile::close(){
    _file.close();
    return (_file.is_open() == false);
}

bool CKYCFile::open(std::string filename){
    close();
    _filename=filename;
    _file.open(filename, std::ios::in | std::ios::ate);
    if (!_file.is_open())
        throw std::system_error(
          std::error_code(CKYCFile::Errc::FILE_IO_ERROR, std::system_category()),
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

    unsigned long nBytesToRead=0;
    std::string encryptedData("");

    clear();

    
    while (_file.good()){
        //Skip the header, footer
        std::string line;
        std::getline(_file, line);
        if (line.empty() || line[0] == '#'){
            _decryptedStream << line << "\n";
            continue;
        }

        //Read the metadata and initialize the decryptor
        if(!_onboardUserPubKey){
            std::vector<std::string> vstr;
            boost::split(vstr, line, boost::is_any_of(" "));
            if (vstr.size() != 4)
                throw std::system_error(
                    std::error_code(CKYCFile::Errc::FILE_IO_ERROR, std::system_category()),
                    std::string(std::string(__func__) +  ": invalid KYC file"));

            std::vector<unsigned char> pubKeyData(ParseHex(vstr[0]));      
            _onboardPubKey = new CPubKey(pubKeyData.begin(), pubKeyData.end());

            if(!_onboardPubKey->IsFullyValid())
                        throw std::system_error(
                        std::error_code(CKYCFile::Errc::INVALID_ADDRESS_OR_KEY, std::system_category()),
                        std::string(std::string(__func__) +  ": invalid kyc pub key in KYC file"));

            CKey onboardPrivKey;
            if(!pwalletMain->GetKey(_onboardPubKey->GetID(), onboardPrivKey))
                throw std::system_error(
                        std::error_code(CKYCFile::Errc::WALLET_KEY_ACCESS_ERROR, std::system_category()),
                        std::string(std::string(__func__) +  ": cannot get onboard private key"));
  
            std::vector<unsigned char> userPubKeyData(ParseHex(vstr[1]));    
            _onboardUserPubKey = new CPubKey(userPubKeyData.begin(), userPubKeyData.end());
            if(!_onboardUserPubKey->IsFullyValid())
                 throw std::system_error(
                        std::error_code(CKYCFile::Errc::INVALID_ADDRESS_OR_KEY, std::system_category()),
                        std::string(std::string(__func__) +  ": invalid onboard user pub key in kyc file"));

            _initVec = new std::vector<unsigned char>(ParseHex(vstr[2]));
            if(_initVec->size() != AES_BLOCKSIZE)
                 throw std::system_error(
                        std::error_code(CKYCFile::Errc::INVALID_PARAMETER, std::system_category()),
                        std::string(std::string(__func__) +  ": invalid initialization vector in KYC file"));

            initEncryptor(&onboardPrivKey, _onboardUserPubKey, _initVec);
            std::stringstream ssNBytes;
            ssNBytes << vstr[3];
            ssNBytes >> nBytesToRead;
            break;
        }
    }

    //Open the file in binary mode. Move the cursor to the start of the binary data.
    std::streampos nCursor=_file.tellg();
    _file.close();

    _file.open(_filename, std::ios::in | std::ios::binary);
    if (!_file.is_open())
        throw std::system_error(
          std::error_code(CKYCFile::Errc::FILE_IO_ERROR, std::system_category()),
          std::string(std::string(__func__) +  ": cannot open kyc file"));
    _file.clear();
    _file.seekg(nCursor);

    //Read the encrypted data and close the file 
    unsigned char arrCh[nBytesToRead];
    _file.read((char*) &arrCh[0], nBytesToRead);
    nCursor=_file.tellg();
    _file.close();

    std::vector<unsigned char> vch(arrCh, arrCh+nBytesToRead);

    std::vector<unsigned char> vdata;
    if(!_encryptor->Decrypt(vdata, vch))
        throw std::system_error(
            std::error_code(CKYCFile::Errc::ENCRYPTION_ERROR, std::system_category()),
            std::string(std::string(__func__) +  ": KYC file decryption failed"));
        
    std::string data(vdata.begin(), vdata.end());
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
        if (vstr.size() != 2)
            continue;


        CBitcoinAddress address;
        if (!address.SetString(vstr[0])) 
            continue;

        std::vector<unsigned char> pubKeyData(ParseHex(vstr[1]));
        CPubKey pubKey = CPubKey(pubKeyData.begin(), pubKeyData.end());
        if(!pubKey.IsFullyValid())
            continue;

        //Addresses valid, write to map
        _addressKeys.push_back(pubKey);
        _decryptedStream << line << "\n";
    }
        

    _file.open(_filename, std::ios::in);
    _file.clear();
    _file.seekg(nCursor);
    while (_file.good()){
        //Skip the header, footer
        std::string line;
        std::getline(_file, line);
        if (line.empty() || line[0] == '#'){
            _decryptedStream << line << "\n";
            continue;
        }
    }


    return true;
}

bool CKYCFile::initEncryptor(CKey* privKey, CPubKey* pubKey, uc_vec* initVec){
    _onboardUserPubKey=pubKey;
    _initVec=initVec;
    delete _encryptor;
     if(_initVec)
        _encryptor = new CECIES(*privKey, *_onboardUserPubKey, *_initVec);
    _encryptor = new CECIES(*privKey, *_onboardUserPubKey);
    return _encryptor->OK();
}

 bool CKYCFile::getOnboardingScript(CScript& script){
    COnboardingScript obScript;

    // Lookup the KYC public key assigned to the user from the whitelist
    //addressWhiteList.

    if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();

    // Get an unassigned KYC key from the addressWhitelist
    CKeyID kycKeyID;
    if(!addressWhitelist.get_unassigned_kyc(kycKeyID))
        throw std::system_error(
        std::error_code(CKYCFile::Errc::WHITELIST_KEY_ACCESS_ERROR, std::system_category()),
        std::string(std::string(__func__) +  ": no unassigned whitelist KYC keys available"));

    // Look up the public key
    CKey kycKey;
    if(!pwalletMain->GetKey(kycKeyID, kycKey)){
        addressWhitelist.add_unassigned_kyc(kycKeyID);
        throw std::system_error(
        std::error_code(CKYCFile::Errc::WALLET_KEY_ACCESS_ERROR, std::system_category()),
        std::string(std::string(__func__) +  ": cannot get KYC private key from wallet"));
    }

    if(!obScript.SetKeys(&kycKey, _onboardUserPubKey)) return false;
    if(!obScript.Append(_addressKeys)) return false;
    if(!obScript.Finalize(script)) return false;
    return true;
}