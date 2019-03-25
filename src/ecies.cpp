// Copyright (c) 2018 The CommerceBlock Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//An implementation of ECIES AES256CBC Encryption

#include "ecies.h"
#include "random.h"
#include "utilstrencodings.h"
#include <sstream>
#include <iostream>


//Keys are randomly selected.
CECIES::CECIES(){
   	_privKey.MakeNewKey(true);
	_pubKey = CPubKey(_privKey.GetPubKey());
	_privKey.MakeNewKey(true);
	Initialize();
}

//Keys are specified. My private key, recipient's public key.
CECIES::CECIES(const CKey& privKey, const CPubKey& pubKey){
	_privKey=CKey(privKey);
	_pubKey=CPubKey(pubKey);
	//Initialize();
}

void CECIES::check(const CKey& privKey, const CPubKey& pubKey){
  _bOK=false;
  if(!privKey.GetPubKey().IsFullyValid()) return;
  if(!pubKey.IsFullyValid()) return;
  _bOK=true;
}

CECIES::~CECIES(){
	delete _encryptor;
	delete _decryptor;
}

//Decryptor requires ephemeral public key from message header.
bool CECIES::Initialize(){
	return InitEncryptor();	
}

bool CECIES::InitEncryptor(){
	delete _encryptor;

	_ephemeralKey.MakeNewKey(true);
	check(_ephemeralKey, _pubKey);
	if(!_bOK) return false;
	uint256 ecdh_key = _ephemeralKey.ECDH(_pubKey);
	
	//sha512 hash of the elliptic curve diffie-hellman key to produce an encryption key and a MAC key
	CSHA512 sha512;
	sha512.Write(ecdh_key.begin(), ecdh_key.size());
	unsigned char arrKey[sha512.OUTPUT_SIZE];
	sha512.Finalize(arrKey);

	unsigned char k[AES256_KEYSIZE];
	memcpy(k, &arrKey[0], sizeof(k));
	memcpy(_k_mac_encrypt, &arrKey[0]+sizeof(k), sizeof(_k_mac_encrypt));
	CHMAC_SHA256 hmac_sha256(&_k_mac_encrypt[0], sizeof(_k_mac_encrypt));
	//Generate a pseudorandom initialization vector using sha1
	CSHA1 sha1;
	sha1.Reset();
	sha1.Write(&arrKey[0], sizeof(arrKey));
	unsigned char iv_tmp[sha1.OUTPUT_SIZE];
	sha1.Finalize(iv_tmp);
	//Copy the required number of bytes to _iv
	unsigned char iv[AES_BLOCKSIZE];
	memcpy(iv, &iv_tmp[0], sizeof(iv));

	_encryptor=new AES256CBCEncrypt(k, iv, true);
	return true;
}

bool CECIES::InitDecryptor(const uCharVec& encryptedMessage){
	delete _decryptor;

	// ecdh shared secret from ephemeral public key (in message header) and my private key
	CPubKey ephemeralPub(encryptedMessage.begin()+_magic.size(), 
		encryptedMessage.begin()+_magic.size()+CPubKey().size());
	check(_privKey, ephemeralPub);
	if(!_bOK) return false;
	uint256 ecdh_key = _privKey.ECDH(ephemeralPub);
	
	//sha512 hash of the elliptic curve diffie-hellman key to produce an encryption key and a MAC key
	CSHA512 sha512;
	sha512.Write(ecdh_key.begin(), ecdh_key.size());
	unsigned char arrKey[sha512.OUTPUT_SIZE];
	sha512.Finalize(arrKey);

	unsigned char k[AES256_KEYSIZE];
	memcpy(k, &arrKey[0], sizeof(k));
	memcpy(_k_mac_decrypt, &arrKey[0]+sizeof(k), sizeof(_k_mac_decrypt));
	CHMAC_SHA256 hmac_sha256(&_k_mac_decrypt[0], sizeof(_k_mac_decrypt));
	//Generate a pseudorandom initialization vector using sha1
	CSHA1 sha1;
	sha1.Reset();
	sha1.Write(&arrKey[0], sizeof(arrKey));
	unsigned char iv_tmp[sha1.OUTPUT_SIZE];
	sha1.Finalize(iv_tmp);
	//Copy the required number of bytes to _iv
	unsigned char iv[AES_BLOCKSIZE];
	memcpy(iv, &iv_tmp[0], sizeof(iv));

	//Check the message authentication code (MAC)
	uCharVec MAC_written(encryptedMessage.end()-CSHA256::OUTPUT_SIZE, encryptedMessage.end());
	//Generate MAC
	uCharVec payload(encryptedMessage.begin(), encryptedMessage.end()-MAC_written.size());
	hmac_sha256.Write(&payload[0], payload.size());
	unsigned char mac[CSHA256::OUTPUT_SIZE];
	hmac_sha256.Finalize(mac);
	uCharVec MAC_calculated(&mac[0], &mac[0]+sizeof(mac));
	if(MAC_written != MAC_calculated) return false;
	
	_decryptor= new AES256CBCDecrypt(k, iv, true);
	return true;
}

bool CECIES::CheckMagic(const uCharVec& encryptedMessage) const{
	uCharVec magic(encryptedMessage.begin(), encryptedMessage.begin() + _magic.size());
	return (magic == _magic);
}
	

//Encryption: generate ephmeral private key, and include it's public key in the header.
//Generate a dhared secret using the ephemeral private key and the recipient's public key.
bool CECIES::Encrypt(uCharVec& em, 
 	const uCharVec& m){
	int size=m.size();
	uCharVec ciphertext(size+AES_BLOCKSIZE);

	int paddedSize=_encryptor->Encrypt(m.data(), size, ciphertext.data());
	ciphertext.resize(paddedSize);
	//Payload: _magic + pubkey + ciphertext

	uCharVec msg(_magic.begin(), _magic.end());
	msg.insert(msg.end(), _pubKey.begin(), _pubKey.end());
	msg.insert(msg.end(), ciphertext.begin(), ciphertext.end());
	//Generate MAC
	CHMAC_SHA256 hmac_sha256(&_k_mac_encrypt[0], sizeof(_k_mac_encrypt));

	hmac_sha256.Write(&msg[0], msg.size());
	unsigned char mac[CSHA256::OUTPUT_SIZE];
	hmac_sha256.Finalize(mac);
	//Message: payload + MAC
	msg.insert(msg.end(),std::begin(mac), std::end(mac));
	//Base64 encode
	std::string strEncoded=EncodeBase64(&msg[0], msg.size());
	em=uCharVec(strEncoded.begin(), strEncoded.end());
    return true;
}

bool CECIES::Decrypt(uCharVec& m, 
 	const uCharVec& em){
	std::string sem(em.begin(), em.end());
	bool bInvalid;
	uCharVec decoded=DecodeBase64(sem.c_str(), &bInvalid);
	if(bInvalid) return false;
	if(!CheckMagic(decoded)) return false;
	if(!InitDecryptor(decoded)) return false;
	int paddedSize = decoded.size();
	m.resize(paddedSize);
	int size=_decryptor->Decrypt(decoded.data(), paddedSize, m.data());
	//Remove the padding.
	m.resize(size);
    return true;
}

bool CECIES::Encrypt(std::string& em, 
 	const std::string& m){
	uCharVec vem;
	uCharVec vm(m.begin(), m.end());
	bool bResult=Encrypt(vem, vm);
	if(bResult) em=std::string(vem.begin(), vem.end());
    return bResult;
}

bool CECIES::Decrypt(std::string& m, 
 	const std::string& em){
	uCharVec vem(em.begin(), em.end());
	uCharVec vm;
	bool bResult=Decrypt(vm, vem);
	if (bResult) m=std::string(vm.begin(), vm.end());
    return bResult;
}

bool CECIES::Test1(){
	Initialize();
	std::string spm = "Test message for ECIES.";
	std::vector<unsigned char> pm(spm.begin(), spm.end());
	std::vector<unsigned char> em;
	std::vector<unsigned char> dm;
	std::cout << spm << std::endl;
	//EncryptMessage(em, pm);
	std::cout << std::string(em.begin(), em.end()) << std::endl;
//	DecryptMessage(dm, em);
	std::cout << std::string(dm.begin(), dm.end()) << std::endl;
	return true;
}


