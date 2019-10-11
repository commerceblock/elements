// Copyright (c) 2018 The CommerceBlock Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// A class for read/write for an encrypted KYC file used in the user onboarding process

#pragma once

#include "policy/whitelist.h"
#include "validation.h"
#include "ecies.h"
#include <fstream>
#include <algorithm> 
#include <functional> 
#include <cctype>
#include <locale>
#include "script/onboardingscript.h"

using uc_vec=std::vector<unsigned char>;

class CKYCFile{
	public:
		CKYCFile();
		virtual ~CKYCFile();

		void clear();

		bool read();
		bool read(std::string filename);
		bool write();
		bool write(std::string filename);

		bool close();
		bool open(std::string filename);

		bool initEncryptor();

		std::vector<CPubKey> getAddressKeys() const {return _addressKeys;}
		std::vector<CTxDestination> getAddressKeyIds() const {return _addressKeyIds;}

		const CPubKey* getOnboardPubKey() const {return _onboardPubKey;}
		const CPubKey* getOnboardUserPubKey() const {return _onboardUserPubKey;}

		bool parsePubkeyPair(const std::vector<std::string> vstr, const std::string line);
		bool parseContractHash(const std::vector<std::string> vstr, const std::string line);
		bool parseMultisig(const std::vector<std::string> vstr, const std::string line);

		const std::stringstream& getStream() const {return _decryptedStream;}

	 	bool getOnboardingScript(CScript& script, bool fBlacklist=false);

	 	bool is_whitelisted();

	 	bool is_empty();

	 	bool is_valid();

	private:
		std::ifstream _file;
		CECIES* _encryptor = nullptr;
		CPubKey* _onboardPubKey = nullptr;
		CPubKey* _onboardUserPubKey = nullptr;
    	
    	CWhiteList* _whitelist=nullptr;

    	// The user address keys to be whitelisted
    	std::vector<CPubKey> _addressKeys; 
    	std::vector<CTxDestination> _addressKeyIds; 

    	std::vector<OnboardMultisig> _multisigData;

    	std::stringstream _decryptedStream;
    	std::stringstream _errorStream;

    	std::string _filename;

    	unsigned char _mac_calc[CECIES::MACSIZE];

    	bool _fContractHash = false;
    	bool _fContractHash_parsed = false;
    	bool _fAddressesValid = true;

    	void appendOutStream(std::string line, std::string error);
    	void appendOutStream(std::string line);

       static inline std::string &ltrim(std::string &s) {
	 s.erase(s.begin(), std::find_if(s.begin(), s.end(),
					 std::not1(std::ptr_fun<int, int>(std::isspace))));
	 return s;
       }

       static inline std::string &rtrim(std::string &s) {
	 s.erase(std::find_if(s.rbegin(), s.rend(),
			    std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
	 return s;
       }

       static inline std::string &trim(std::string &s) {
	 return ltrim(rtrim(s));
       }
};

std::ostream& operator<<(std::ostream& os, const CKYCFile& fl); 
