// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key.h"
#include "ecies.h"

#include "base58.h"
#include "script/script.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include "test/test_bitcoin.h"

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

static const std::string strSecret1     ("5KErXvjbXDXedpgnp1vDgk27LHZbNeUp8UEmzZZeBMySKdV9CXC");
static const std::string strSecret2     ("5KFvfMyhsgNHMq9vQLbtmRwpJAeWYp2Q4GA4BXFNk74ixVNKsEe");
static const std::string strSecret1C    ("L3W9dWB1NNJH7XUdCX3tzQstx86riYRm1yDob4j56ja6m8hYA95j");
static const std::string strSecret2C    ("L3asrKbHQgkwCwYNi1X1V76wkmaZRQZAmPty3SWSyFmSBprUe9h2");
static const CBitcoinAddress addr1 ("CMkk6fjxVzgeCKHFi1JeNnhrJKUmg9xCTq");
static const CBitcoinAddress addr2 ("CLYV6XeMTZ3KCcee9tenBYiHvyMiG6RjhX");
static const CBitcoinAddress addr1C("CWJDCZRoTwtH9mAxJjBjTaJoGnU5vVE65p");
static const CBitcoinAddress addr2C("CNq71B1YgvfJ4eiYSLb2VGQVhhwtmJRCtX");


static const std::string strAddressBad("1HV9Lc3sNHZxwj4Zk6fB38tEmBryq2cBiF");


#ifdef KEY_TESTS_DUMPINFO
void dumpKeyInfo(uint256 privkey)
{
    CKey key;
    key.resize(32);
    memcpy(&secret[0], &privkey, 32);
    std::vector<unsigned char> sec;
    sec.resize(32);
    memcpy(&sec[0], &secret[0], 32);
    printf("  * secret (hex): %s\n", HexStr(sec).c_str());

    for (int nCompressed=0; nCompressed<2; nCompressed++)
    {
        bool fCompressed = nCompressed == 1;
        printf("  * %s:\n", fCompressed ? "compressed" : "uncompressed");
        CBitcoinSecret bsecret;
        bsecret.SetSecret(secret, fCompressed);
        printf("    * secret (base58): %s\n", bsecret.ToString().c_str());
        CKey key;
        key.SetSecret(secret, fCompressed);
        std::vector<unsigned char> vchPubKey = key.GetPubKey();
        printf("    * pubkey (hex): %s\n", HexStr(vchPubKey).c_str());
        printf("    * address (base58): %s\n", CBitcoinAddress(vchPubKey).ToString().c_str());
    }
}
#endif


BOOST_FIXTURE_TEST_SUITE(key_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(key_test1)
{
    CBitcoinSecret bsecret1, bsecret2, bsecret1C, bsecret2C, baddress1;
    BOOST_CHECK( bsecret1.SetString (strSecret1));
    BOOST_CHECK( bsecret2.SetString (strSecret2));
    BOOST_CHECK( bsecret1C.SetString(strSecret1C));
    BOOST_CHECK( bsecret2C.SetString(strSecret2C));
    BOOST_CHECK(!baddress1.SetString(strAddressBad));

    CKey key1  = bsecret1.GetKey();
    BOOST_CHECK(key1.IsCompressed() == false);
    CKey key2  = bsecret2.GetKey();
    BOOST_CHECK(key2.IsCompressed() == false);
    CKey key1C = bsecret1C.GetKey();
    BOOST_CHECK(key1C.IsCompressed() == true);
    CKey key2C = bsecret2C.GetKey();
    BOOST_CHECK(key2C.IsCompressed() == true);

    CPubKey pubkey1  = key1. GetPubKey();
    CPubKey pubkey2  = key2. GetPubKey();
    CPubKey pubkey1C = key1C.GetPubKey();
    CPubKey pubkey2C = key2C.GetPubKey();

    BOOST_CHECK(key1.VerifyPubKey(pubkey1));
    BOOST_CHECK(!key1.VerifyPubKey(pubkey1C));
    BOOST_CHECK(!key1.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key1.VerifyPubKey(pubkey2C));

    BOOST_CHECK(!key1C.VerifyPubKey(pubkey1));
    BOOST_CHECK(key1C.VerifyPubKey(pubkey1C));
    BOOST_CHECK(!key1C.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key1C.VerifyPubKey(pubkey2C));

    BOOST_CHECK(!key2.VerifyPubKey(pubkey1));
    BOOST_CHECK(!key2.VerifyPubKey(pubkey1C));
    BOOST_CHECK(key2.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key2.VerifyPubKey(pubkey2C));

    BOOST_CHECK(!key2C.VerifyPubKey(pubkey1));
    BOOST_CHECK(!key2C.VerifyPubKey(pubkey1C));
    BOOST_CHECK(!key2C.VerifyPubKey(pubkey2));
    BOOST_CHECK(key2C.VerifyPubKey(pubkey2C));

    BOOST_CHECK(addr1.Get()  == CTxDestination(pubkey1.GetID()));
    BOOST_CHECK(addr2.Get()  == CTxDestination(pubkey2.GetID()));
    BOOST_CHECK(addr1C.Get() == CTxDestination(pubkey1C.GetID()));
    BOOST_CHECK(addr2C.Get() == CTxDestination(pubkey2C.GetID()));


    for (int n=0; n<16; n++)
    {
        std::string strMsg = strprintf("Very secret message %i: 11", n);
        uint256 hashMsg = Hash(strMsg.begin(), strMsg.end());

        // normal signatures

        std::vector<unsigned char> sign1, sign2, sign1C, sign2C;

        BOOST_CHECK(key1.Sign (hashMsg, sign1));
        BOOST_CHECK(key2.Sign (hashMsg, sign2));
        BOOST_CHECK(key1C.Sign(hashMsg, sign1C));
        BOOST_CHECK(key2C.Sign(hashMsg, sign2C));

        BOOST_CHECK( pubkey1.Verify(hashMsg, sign1));
        BOOST_CHECK(!pubkey1.Verify(hashMsg, sign2));
        BOOST_CHECK( pubkey1.Verify(hashMsg, sign1C));
        BOOST_CHECK(!pubkey1.Verify(hashMsg, sign2C));

        BOOST_CHECK(!pubkey2.Verify(hashMsg, sign1));
        BOOST_CHECK( pubkey2.Verify(hashMsg, sign2));
        BOOST_CHECK(!pubkey2.Verify(hashMsg, sign1C));
        BOOST_CHECK( pubkey2.Verify(hashMsg, sign2C));

        BOOST_CHECK( pubkey1C.Verify(hashMsg, sign1));
        BOOST_CHECK(!pubkey1C.Verify(hashMsg, sign2));
        BOOST_CHECK( pubkey1C.Verify(hashMsg, sign1C));
        BOOST_CHECK(!pubkey1C.Verify(hashMsg, sign2C));

        BOOST_CHECK(!pubkey2C.Verify(hashMsg, sign1));
        BOOST_CHECK( pubkey2C.Verify(hashMsg, sign2));
        BOOST_CHECK(!pubkey2C.Verify(hashMsg, sign1C));
        BOOST_CHECK( pubkey2C.Verify(hashMsg, sign2C));

        // compact signatures (with key recovery)

        std::vector<unsigned char> csign1, csign2, csign1C, csign2C;

        BOOST_CHECK(key1.SignCompact (hashMsg, csign1));
        BOOST_CHECK(key2.SignCompact (hashMsg, csign2));
        BOOST_CHECK(key1C.SignCompact(hashMsg, csign1C));
        BOOST_CHECK(key2C.SignCompact(hashMsg, csign2C));

        CPubKey rkey1, rkey2, rkey1C, rkey2C;

        BOOST_CHECK(rkey1.RecoverCompact (hashMsg, csign1));
        BOOST_CHECK(rkey2.RecoverCompact (hashMsg, csign2));
        BOOST_CHECK(rkey1C.RecoverCompact(hashMsg, csign1C));
        BOOST_CHECK(rkey2C.RecoverCompact(hashMsg, csign2C));

        BOOST_CHECK(rkey1  == pubkey1);
        BOOST_CHECK(rkey2  == pubkey2);
        BOOST_CHECK(rkey1C == pubkey1C);
        BOOST_CHECK(rkey2C == pubkey2C);
    }

    // test deterministic signing

    std::vector<unsigned char> detsig, detsigc;
    std::string strMsg = "Very deterministic message";
    uint256 hashMsg = Hash(strMsg.begin(), strMsg.end());
    BOOST_CHECK(key1.Sign(hashMsg, detsig));
    BOOST_CHECK(key1C.Sign(hashMsg, detsigc));
    BOOST_CHECK(detsig == detsigc);
    BOOST_CHECK(detsig == ParseHex("3045022100e0cf49a04d5676892023cb5f9fc0e2bab2b8d02fc21a9bad5f7970aca228b96202204c9896145b0025d6630a9ab81942c9938e37ee662808e1ad6de7764bdd63002b"));
    BOOST_CHECK(key2.Sign(hashMsg, detsig));
    BOOST_CHECK(key2C.Sign(hashMsg, detsigc));
    BOOST_CHECK(detsig == detsigc);
    BOOST_CHECK(detsig == ParseHex("3045022100ca8a6a22e00d084a707e58d0f01ff2fd583ec76e56cedb660a8138dbc824a10e02205dcb0b9a3c4ac03d61b480af5d4a624222cfe9532a363f5b793b44093ad70924"));
    BOOST_CHECK(key1.SignCompact(hashMsg, detsig));
    BOOST_CHECK(key1C.SignCompact(hashMsg, detsigc));
    BOOST_CHECK(detsig == ParseHex("1ce0cf49a04d5676892023cb5f9fc0e2bab2b8d02fc21a9bad5f7970aca228b9624c9896145b0025d6630a9ab81942c9938e37ee662808e1ad6de7764bdd63002b"));
    BOOST_CHECK(detsigc == ParseHex("20e0cf49a04d5676892023cb5f9fc0e2bab2b8d02fc21a9bad5f7970aca228b9624c9896145b0025d6630a9ab81942c9938e37ee662808e1ad6de7764bdd63002b"));
    BOOST_CHECK(key2.SignCompact(hashMsg, detsig));
    BOOST_CHECK(key2C.SignCompact(hashMsg, detsigc));
    BOOST_CHECK(detsig == ParseHex("1bca8a6a22e00d084a707e58d0f01ff2fd583ec76e56cedb660a8138dbc824a10e5dcb0b9a3c4ac03d61b480af5d4a624222cfe9532a363f5b793b44093ad70924"));
    BOOST_CHECK(detsigc == ParseHex("1fca8a6a22e00d084a707e58d0f01ff2fd583ec76e56cedb660a8138dbc824a10e5dcb0b9a3c4ac03d61b480af5d4a624222cfe9532a363f5b793b44093ad70924"));

    //Test Diffie-Hellman shared secret
    uint256 dh12 = key1.ECDH(pubkey2);
    uint256 dh21 = key2.ECDH(pubkey1);
    BOOST_CHECK(dh12 == dh21);
    //test DH for comapact keys
    uint256 dh12C = key1C.ECDH(pubkey2C);
    uint256 dh21C = key2C.ECDH(pubkey1C);
    BOOST_CHECK(dh12C == dh21C);


    CECIES* ecies1 = new CECIES();
    CECIES* ecies2 = new CECIES();
    const unsigned int nblocks=20;
    const unsigned int extrabytes=3;
    std::vector<unsigned char> vm;


    unsigned char buff[AES_BLOCKSIZE];
    for(unsigned int i=0; i<nblocks; i++){
      GetStrongRandBytes(buff, AES_BLOCKSIZE);
      vm.insert(vm.end(), &buff[0], &buff[0]+AES_BLOCKSIZE);
    }
    GetStrongRandBytes(buff, extrabytes);
    vm.insert(vm.end(), &buff[0], &buff[0]+extrabytes);
    std::vector<unsigned char> vem1, vem3, vdm1, vdm3;


    BOOST_CHECK(ecies1->Encrypt(vem1, vm, pubkey1C, key2C));
    BOOST_CHECK(ecies2->Decrypt(vdm1, vem1, key1C));
    BOOST_CHECK(vem1 != vm);
    BOOST_CHECK(vdm1 == vm);

    BOOST_CHECK(ecies1->Encrypt(vem1, vm, pubkey1C, key2C));
    BOOST_CHECK(ecies2->Decrypt(vdm1, vem1, key2C, pubkey1C));
    BOOST_CHECK(vem1 != vm);
    BOOST_CHECK(vdm1 == vm);

    CECIES* ecies4 = new CECIES();
    CECIES* ecies3 = new CECIES();
    BOOST_CHECK(ecies3->Encrypt(vem3, vm, pubkey2C, key1C));
    BOOST_CHECK(ecies4->Decrypt(vdm3, vem3, key2C));
    BOOST_CHECK(vem3 != vm);
    BOOST_CHECK(vdm3 == vm);

    std::string sm=HexStr(vm.begin(), vm.end());
    std::string sdm;
    std::string sem;
    BOOST_CHECK(ecies3->Encrypt(sem, sm, pubkey2C));
    BOOST_CHECK(ecies4->Decrypt(sdm, sem, key2C));
    BOOST_CHECK(sem != sm);
    BOOST_CHECK(sdm == sm);

    delete ecies1;
    delete ecies2;
    delete ecies3;
    delete ecies4;
}

BOOST_AUTO_TEST_SUITE_END()
