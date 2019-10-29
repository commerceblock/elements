// Copyright (c) 2018 The CommerceBlock Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// A "register address" transaction script.

#pragma once
#include "script.h"
#include "ecies_hex.h"
#include "validation.h"

using ucvec=std::vector<unsigned char>;
using pubKeyPair=std::pair<CTxDestination, CPubKey>;
using AddrType = CWhiteList::AddrType;

struct OnboardMultisig {
    uint8_t nMultisig;
    CTxDestination scriptID;
    std::vector<CPubKey> pubKeys;
    OnboardMultisig(uint8_t _nMultisig, CTxDestination _scriptID, std::vector<CPubKey> _pubKeys){
    	nMultisig = _nMultisig;
    	scriptID = _scriptID;
    	pubKeys = _pubKeys;
    }
};

enum RegisterAddressType { RA_PUBLICKEY, RA_MULTISIG, RA_ONBOARDING };

class CRegisterAddressScript {
public:
	CRegisterAddressScript(RegisterAddressType type);
	CRegisterAddressScript(const CRegisterAddressScript* script, RegisterAddressType type);
	virtual ~CRegisterAddressScript();

	//Encrypt the payload using the public, private key and build the script.
	virtual bool Finalize(CScript& script, const CPubKey& ePubKey, const CKey& ePrivKey);
	virtual bool FinalizeUnencrypted(CScript& script);
    bool BuildScript(CScript& script, const ucvec& sendData);
	bool Append(const AddrType& addr);
	bool Append(const pubKeyPair& keyPair);
	bool Append(const CTxDestination& dest);
	bool Append(const OnboardMultisig& data);
	bool Append(const std::vector<pubKeyPair>& v);
	bool Append(const std::vector<CTxDestination>& v);
	bool Append(const std::vector<OnboardMultisig>& v);

	bool Append(const uint8_t nMultisig, const CTxDestination keyID, 
		const std::vector<CPubKey>& keys);
	void Append(const std::vector<unsigned char>& v);

	bool ScriptVersion(unsigned int nVersion){
		if (nVersion >1) return false;
		_nScriptVersion = nVersion;
		return true;
	}

	unsigned int ScriptVersion() const{
		return _nScriptVersion;
	}


	void AppendChar(const unsigned char& c){
		_payload.push_back(c);
	}

	std::size_t getPayloadSize() { return _payload.size(); }

	virtual void clear(){_payload.clear(); _encrypted.clear(); ((CScript*)this)->clear();}

	//Make this a "deregister" transaction (remove address from whitelist).
	virtual void SetDeregister(bool bDereg){
		bDereg ? _opcode = OP_DEREGISTERADDRESS: _opcode = OP_REGISTERADDRESS;
	}

	void PopBack(){
		_payload.pop_back();
	}

	void PopBack(unsigned int n){
		for(unsigned int i=0; i<n; i++){
			PopBack();
		}
	}

protected:
	ucvec _payload;
	ucvec _encrypted;
	RegisterAddressType _whitelistType;
	opcodetype _opcode = OP_REGISTERADDRESS;

	bool Append(const CPubKey& key);
	bool Append(const std::vector<CPubKey>& keys);

	unsigned int _nScriptVersion = 1;

};