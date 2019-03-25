// Copyright (c) 2018 The CommerceBlock Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//An implementation of ECIES AES256CBC Encryption

#pragma once

#include "key.h"
#include "crypto/aes.h"
#include "crypto/sha1.h"
#include "crypto/sha512.h"
#include "crypto/hmac_sha256.h"

typedef std::vector<unsigned char> uCharVec;

class CECIES{
public:
	CECIES();
	CECIES(const CKey& privKey, const CPubKey& pubKey);

	~CECIES();
	
	/**
    * Encrypt/decrypt a message string.
    */

	bool Encrypt(uCharVec& em, 
   	const uCharVec& m);

    bool Decrypt(uCharVec& m, 
    	const uCharVec& em);
    bool Encrypt(std::string& em, 
    	const std::string& m);
    bool Decrypt(std::string& m, 
    	const std::string& em);

    bool Test1();

	bool OK(){return _bOK;}

private:
	CPubKey _pubKey;
	CKey _privKey;
	CKey _ephemeralKey;

	unsigned char _k_mac_encrypt[CSHA1::OUTPUT_SIZE];
	unsigned char _k_mac_decrypt[CSHA1::OUTPUT_SIZE];

	AES256CBCEncrypt* _encryptor;
	AES256CBCDecrypt* _decryptor;

	bool Initialize();
	bool InitEncryptor();
	bool InitDecryptor(const uCharVec& encryptedMessage);
	bool CheckMagic(const uCharVec& encryptedMessage) const;

	bool _bOK = false;

	void check(const CKey& privKey, const CPubKey& pubKey);

	//Use the electrum wallet default "magic" string
	const uCharVec _magic{'B', 'I', 'E', '1'};
};
