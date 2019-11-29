// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.h"
#include "test/test_bitcoin.h"

#include <string>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(getarg_tests, BasicTestingSetup)

static void ResetArgs(const std::string& strArg)
{
    std::vector<std::string> vecArg;
    if (strArg.size())
      boost::split(vecArg, strArg, boost::is_space(), boost::token_compress_on);

    // Insert dummy executable name:
    vecArg.insert(vecArg.begin(), "testbitcoin");

    // Convert to char*:
    std::vector<const char*> vecChar;
    BOOST_FOREACH(std::string& s, vecArg)
        vecChar.push_back(s.c_str());

    ParseParameters(vecChar.size(), &vecChar[0]);
}

BOOST_AUTO_TEST_CASE(boolarg)
{
    ResetArgs("-par");
    BOOST_CHECK(GetBoolArg("-par", false));
    BOOST_CHECK(GetBoolArg("-par", true));

    BOOST_CHECK(!GetBoolArg("-pa", false));
    BOOST_CHECK(GetBoolArg("-pa", true));

    BOOST_CHECK(!GetBoolArg("-paro", false));
    BOOST_CHECK(GetBoolArg("-paro", true));

    ResetArgs("-par=0");
    BOOST_CHECK(!GetBoolArg("-par", false));
    BOOST_CHECK(!GetBoolArg("-par", true));

    ResetArgs("-par=1");
    BOOST_CHECK(GetBoolArg("-par", false));
    BOOST_CHECK(GetBoolArg("-par", true));

    // New 0.6 feature: auto-map -nosomething to !-something:
    ResetArgs("-nopar");
    BOOST_CHECK(!GetBoolArg("-par", false));
    BOOST_CHECK(!GetBoolArg("-par", true));

    ResetArgs("-nopar=1");
    BOOST_CHECK(!GetBoolArg("-par", false));
    BOOST_CHECK(!GetBoolArg("-par", true));

    ResetArgs("-par -nopar");  // -nopar should win
    BOOST_CHECK(!GetBoolArg("-par", false));
    BOOST_CHECK(!GetBoolArg("-par", true));

    ResetArgs("-par=1 -nopar=1");  // -nopar should win
    BOOST_CHECK(!GetBoolArg("-par", false));
    BOOST_CHECK(!GetBoolArg("-par", true));

    ResetArgs("-par=0 -nopar=0");  // -nopar=0 should win
    BOOST_CHECK(GetBoolArg("-par", false));
    BOOST_CHECK(GetBoolArg("-par", true));

    // New 0.6 feature: treat -- same as -:
    ResetArgs("-par=1");
    BOOST_CHECK(GetBoolArg("-par", false));
    BOOST_CHECK(GetBoolArg("-par", true));

    ResetArgs("--nopar=1");
    BOOST_CHECK(!GetBoolArg("-par", false));
    BOOST_CHECK(!GetBoolArg("-par", true));

}

BOOST_AUTO_TEST_CASE(stringarg)
{
    ResetArgs("");
    BOOST_CHECK_EQUAL(GetArg("-par", ""), "");
    BOOST_CHECK_EQUAL(GetArg("-par", "eleven"), "eleven");

    ResetArgs("-par -pid");
    BOOST_CHECK_EQUAL(GetArg("-par", ""), "");
    BOOST_CHECK_EQUAL(GetArg("-par", "eleven"), "");

    ResetArgs("-par=");
    BOOST_CHECK_EQUAL(GetArg("-par", ""), "");
    BOOST_CHECK_EQUAL(GetArg("-par", "eleven"), "");

    ResetArgs("-par=11");
    BOOST_CHECK_EQUAL(GetArg("-par", ""), "11");
    BOOST_CHECK_EQUAL(GetArg("-par", "eleven"), "11");

    ResetArgs("-par=eleven");
    BOOST_CHECK_EQUAL(GetArg("-par", ""), "eleven");
    BOOST_CHECK_EQUAL(GetArg("-par", "eleven"), "eleven");

}

BOOST_AUTO_TEST_CASE(intarg)
{
    ResetArgs("");
    BOOST_CHECK_EQUAL(GetArg("-par", 11), 11);
    BOOST_CHECK_EQUAL(GetArg("-par", 0), 0);

    ResetArgs("-par -pid");
    BOOST_CHECK_EQUAL(GetArg("-par", 11), 0);
    BOOST_CHECK_EQUAL(GetArg("-pid", 11), 0);

    ResetArgs("-par=11 -pid=12");
    BOOST_CHECK_EQUAL(GetArg("-par", 0), 11);
    BOOST_CHECK_EQUAL(GetArg("-pid", 11), 12);

    ResetArgs("-par=NaN -pid=NotANumber");
    BOOST_CHECK_EQUAL(GetArg("-par", 1), 0);
    BOOST_CHECK_EQUAL(GetArg("-pid", 11), 0);
}

BOOST_AUTO_TEST_CASE(doubledash)
{
    ResetArgs("-par");
    BOOST_CHECK_EQUAL(GetBoolArg("-par", false), true);

    ResetArgs("-par=verbose --pid=1");
    BOOST_CHECK_EQUAL(GetArg("-par", ""), "verbose");
    BOOST_CHECK_EQUAL(GetArg("-pid", 0), 1);
}

BOOST_AUTO_TEST_CASE(boolargno)
{
    ResetArgs("-nopar");
    BOOST_CHECK(!GetBoolArg("-par", true));
    BOOST_CHECK(!GetBoolArg("-par", false));

    ResetArgs("-nopar=1");
    BOOST_CHECK(!GetBoolArg("-par", true));
    BOOST_CHECK(!GetBoolArg("-par", false));

    ResetArgs("-nopar=0");
    BOOST_CHECK(GetBoolArg("-par", true));
    BOOST_CHECK(GetBoolArg("-par", false));

    ResetArgs("-par --nopar"); // --nopar should win
    BOOST_CHECK(!GetBoolArg("-par", true));
    BOOST_CHECK(!GetBoolArg("-par", false));

    ResetArgs("-nopar -par"); // par always wins:
    BOOST_CHECK(GetBoolArg("-par", true));
    BOOST_CHECK(GetBoolArg("-par", false));
}

BOOST_AUTO_TEST_SUITE_END()
