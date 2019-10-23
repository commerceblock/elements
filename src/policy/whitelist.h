// Copyright (c) 2018 The CommerceBlock Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once
#include "policylist.h"
#include <map>
#include "univalue/include/univalue.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif
#include "chain.h"
#include <queue>
#include <iterator>
#include "policy/policy.h"
#include "pubkey.h"


using ucvec_it = std::vector<unsigned char>::const_iterator;
using pubKeyPair = std::pair<CTxDestination, CPubKey>;

class CRegisterAddressData{
	public:
		CRegisterAddressData(){;}
		virtual ~CRegisterAddressData(){;}

		virtual CTxDestination GetDest() = 0;

};

class CWhiteList : public CPolicyList{
public:
	CWhiteList();
	virtual ~CWhiteList();

	static constexpr int64_t MAX_UNASSIGNED_KYCPUBKEYS=1000;
	static constexpr int64_t MAX_KYCPUBKEY_GAP=MAX_UNASSIGNED_KYCPUBKEYS;

		//The written code behaviour expects nMultisigSize to be of length 1 at the moment. If it is changed in the future the code needs to be adjusted accordingly.
  	static constexpr unsigned int nMultisigSize=1;

  	static constexpr unsigned int addrSize=20;

  	static constexpr unsigned int _minDataSize=addrSize;




    void init_defaults();
  
	virtual bool Load(CCoinsView *view);

	virtual void add_destination(const CTxDestination& dest);

	virtual void add_derived(const CBitcoinAddress& address, const CPubKey& pubKey, 
		const std::unique_ptr<CPubKey>& kycPubKey);

	virtual void add_derived(const CBitcoinAddress& address, const CPubKey& pubKey);

	virtual void add_derived(const std::string& sAddress, const std::string& sPubKey, 
		const std::string& sKYCPubKey);

	virtual void add_derived(const std::string& sAddress, const std::string& sKey);


	//Multisig whitelisting below
	virtual void add_multisig_whitelist(const std::string& sAddress, const UniValue& sPubKeys, 
  		const std::string& sKYCAddress, const uint8_t nMultisig);

	virtual void add_multisig_whitelist(const std::string& addressIn, const UniValue& sPubKeys, 
		const uint8_t nMultisig);

	virtual void add_multisig_whitelist(const CBitcoinAddress& address, const std::vector<CPubKey>& pubKeys, 
  		const std::unique_ptr<CPubKey>& kycPubKey, const uint8_t nMultisig);

	virtual void add_multisig_whitelist(const CBitcoinAddress& address, const std::vector<CPubKey>& pubKeys,
		const uint8_t nMultisig);

  	bool RegisterDecryptedAddresses(const std::vector<unsigned char>& data, const bool bBlacklist=false);

  	virtual bool RegisterAddress(const CTransaction& tx, const CBlockIndex* pindex);
  	
	virtual bool RegisterAddress(const CTransaction& tx, const CCoinsViewCache& mapInputs);
	
	virtual bool RegisterAddress(const std::vector<CTxOut>& vout);

	bool ParseRegisterAddressOutput(const CTxOut& txout, bool fBlacklist);
  
	void add(CRegisterAddressData* d);

	baseIter remove(CRegisterAddressData* d);

	CPolicyList::baseIter remove(CTxDestination d){
		return CPolicyList::remove(d);
	}

  	//Update from transaction
  	virtual bool Update(const CTransaction& tx, const CCoinsViewCache& mapInputs);

  	virtual void clear();

  	virtual bool is_whitelisted(const CTxDestination keyId);

  	virtual bool get_unassigned_kyc(CPubKey& pubKey);

  	virtual bool peek_unassigned_kyc(CPubKey& pubKey);

  	void dump_unassigned_kyc(std::ofstream& fStream);

	virtual bool LookupKYCKey(const CTxDestination& keyId, CKeyID& kycKeyIdFound){return false;}
  	virtual bool LookupKYCKey(const CTxDestination& keyId, CPubKey& pubKeyFound){return false;}
  	virtual bool LookupKYCKey(const CTxDestination& keyId, CKeyID& kycKeyIdFound, CPubKey& kycPubKeyFound){return false;}


  	virtual bool find_kyc_whitelisted(const CKeyID& keyId){
  		return false;
  	}

	// My ending addresses - added to whitelist by me in a add to whitelist transaction waiting to be included in a block
	virtual void add_my_pending(const CTxDestination keyId);

	virtual void remove_my_pending(const CTxDestination keyId);

	virtual bool is_my_pending(const CTxDestination keyId);

	virtual unsigned int n_my_pending();

    int64_t n_unassigned_kyc_pubkeys() const{
        return _kycUnassignedSet.size();
    }

    //Does nothing for unencrypted whitelist.
    virtual void whitelist_kyc(const CPubKey& pubKey, const COutPoint* outPoint=nullptr){;}

    bool get_kycpubkey_outpoint(const CKeyID& kycPubKeyId, COutPoint& outPoint);

	bool get_kycpubkey_outpoint(const CPubKey& kycPubKey, COutPoint& outPoint);

 	virtual void add_unassigned_kyc(const CPubKey& pubKey){
 		;
 	}

	void sync_whitelist_wallet(std::vector<CPubKey>& keysNotFound);

	void sync_whitelist_wallet();



protected:
	std::set<CTxDestination> _myPending;

	//KYC pub keys not yet assigned to any user
	std::set<CPubKey> _kycUnassignedSet;
	virtual bool remove_unassigned_kyc(const CPubKey& pubKey);
  	virtual bool is_unassigned_kyc(const CPubKey& pubKey);
	//Make add_sorted private because we only want verified derived keys 
	//to be added to the CWhiteList.
	using CPolicyList::add_sorted;

	using CPolicyList::find;

  	const unsigned int minPayloadSize=2;

    std::map<CKeyID, COutPoint> _kycPubkeyOutPointMap;

  	enum class RAType { single, pair, multisig, none };

  	RAType GetRAType(const std::vector<unsigned char>::const_iterator start, 
  		  const std::vector<unsigned char>::const_iterator vend);

private:
	void add_unassigned_kyc(const CPubKey& pubKey, const COutPoint& outPoint);
};

class CDestData : public CRegisterAddressData{
	public: 	
		CDestData(){;}
		virtual ~CDestData(){;}

		virtual CTxDestination GetDest(){
			return _dest;
		}

		void Set(const CTxDestination& dest){
			if (!Params().ContractInTx())
	        	throw std::invalid_argument(
	        		std::string(std::string(__func__) + 
	        		"attempting to register address without key tweaking checks for contractintx=0")
	        	);

			CBitcoinAddress addr(dest);
			if(!addr.IsValid())
				throw std::invalid_argument(std::string(std::string(__func__) + 
     		 	std::string(": invalid base58check address\n")));
	
			_dest = dest;
		}

	private:
		CTxDestination _dest;
};

class CDerivedData : public CRegisterAddressData{
	public: 	
		CDerivedData(){;}
		CDerivedData(const pubKeyPair& p){
			pubKeyPair pc = p;
			Set(pc);
		}
		virtual ~CDerivedData(){;}

		pubKeyPair Get(){
			return _pubKeyPair;
		}

		virtual CTxDestination GetDest(){
			return _pubKeyPair.first;
		}

		void Set(const pubKeyPair& p);

	private:
		pubKeyPair _pubKeyPair;
};

class CMultisigData : public CRegisterAddressData{
	public: 	
		CMultisigData(){;}
		virtual ~CMultisigData(){;}

		virtual CTxDestination GetDest(){
			TryValid();
			return _dest;
		}

		void Set(const CTxDestination& dest, const std::vector<CPubKey>& pubKeys,
			uint8_t m){
			Clear();
			SetM(m);
			SetDest(dest);
			for (auto k: pubKeys){
				AddPubKey(k);
			}
			TryValid();
		}

		void SetM(const uint8_t& m){
			if (m > MAX_P2SH_SIGOPS || m == 0) {
				throw std::invalid_argument(std::string(std::string(__func__) + 
     		 	": invalid m\n"));
			}
			_m=m;
		}

		void SetDest(const CTxDestination& dest){
			CBitcoinAddress addr(dest);
			if(!addr.IsValid()) {
				throw std::invalid_argument(std::string(std::string(__func__) + 
     		 ": invalid dest: " + addr.ToString() + "\n"));
			}
			_dest = dest;
		}

		void AddPubKey(const CPubKey& k){
			if(!k.IsFullyValid()){
				  throw std::invalid_argument(std::string(std::string(__func__) + 
        		": invalid public key\n"));
			}
			_pubKeys.push_back(k);
		}

		void TryValid(){
			if(Params().ContractInTx()) return;

			if(_pubKeys.size() > MAX_P2SH_SIGOPS){
				throw std::invalid_argument(std::string(std::string(__func__) + 
      				": n > MAX_P2SH_SIGOPS\n"));
			}
			uint8_t n = _pubKeys.size();
			TryValid(n);
		}

		void TryValid(const uint8_t& n);

		virtual void Clear(){
			_pubKeys.clear();
		}

	private:
		CTxDestination _dest;
		std::vector<CPubKey> _pubKeys;
		uint8_t _m;

};

class CRegisterAddressDataFactory{
	public:
	 CRegisterAddressDataFactory(){
	 	;
	 }
	 CRegisterAddressDataFactory(const ucvec_it& start, const ucvec_it& end){
	 	CRegisterAddressDataFactory();
	 	SetCursor(start, end);
	 }
	 ~CRegisterAddressDataFactory(){;}



	 void SetCursor(const ucvec_it& start,
	 	const ucvec_it& end){
	 	_start=start;
	 	_cursor=start;
	 	_end=end;
	 	_prev_cursor=_cursor;
	 }

	 	//Returns the next data object
		CRegisterAddressData* GetNext();

	 bool IsEnd(){ 
	 	return (_cursor == _end); 
	 }

	 private:
	 	unsigned int _pubkeySize=CPubKey::COMPRESSED_PUBLIC_KEY_SIZE;

	 	ucvec_it _start;
		ucvec_it _end;
		ucvec_it _cursor;
		ucvec_it _prev_cursor;

		CMultisigData* GetNextMultisig();
		CDerivedData* GetNextDerived();
		CDestData* GetNextDest();

		void ResetCursor(){_cursor=_prev_cursor;}

		void MarkReset(const ucvec_it& cursor){_prev_cursor = cursor;}

		void MarkReset(){MarkReset(_cursor);}

		bool AdvanceCursor(ucvec_it& cursor, const unsigned int& nSteps=1){
			if ( std::distance(cursor, _end) < nSteps)
				return false;
			std::advance(cursor, nSteps);
			return true;
		}

		bool AdvanceCursor(const unsigned int& nSteps=1){
			return AdvanceCursor(_cursor, nSteps);
		}
};

const unsigned int CWhiteList::nMultisigSize;

const unsigned int CWhiteList::addrSize;

const int64_t CWhiteList::MAX_UNASSIGNED_KYCPUBKEYS;
	
const int64_t CWhiteList::MAX_KYCPUBKEY_GAP;

