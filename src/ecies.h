// Copyright (c) 2018 The CommerceBlock Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//A wrapper class for AES256CBCEncryption

#pragma once

#include "key.h"
#include "crypto/aes.h"

typedef std::vector<unsigned char> uCharVec;

class CECIES{
public:
	~CECIES();

	CECIES(const CKey& privKey, const CPubKey& pubKey, const uCharVec& iv);
	CECIES(const CKey& privKey, const CPubKey& pubKey);
	
	/**
    * Encrypt/decrypt a message string.
    */

    bool Encrypt(uCharVec& em, 
    	uCharVec& m) const;
    bool Decrypt(uCharVec& m, 
    	uCharVec& em) const;
    bool Encrypt(std::string& em, 
    	std::string& m) const;
    bool Decrypt(std::string& m, 
    	std::string& em) const;

    bool Test1();

	uCharVec get_iv() const {return _iv;};

	bool OK() const;

private:
	CECIES();
	uCharVec _iv;
	uCharVec _k;

	unsigned char _padChar=0;

	AES256CBCEncrypt* _encryptor;
	AES256CBCDecrypt* _decryptor;

	bool _bOK;

};
