/************************************************************
 *
 *                 OPEN TRANSACTIONS
 *
 *       Financial Cryptography and Digital Cash
 *       Library, Protocol, API, Server, CLI, GUI
 *
 *       -- Anonymous Numbered Accounts.
 *       -- Untraceable Digital Cash.
 *       -- Triple-Signed Receipts.
 *       -- Cheques, Vouchers, Transfers, Inboxes.
 *       -- Basket Currencies, Markets, Payment Plans.
 *       -- Signed, XML, Ricardian-style Contracts.
 *       -- Scripted smart contracts.
 *
 *  EMAIL:
 *  fellowtraveler@opentransactions.org
 *
 *  WEBSITE:
 *  http://www.opentransactions.org/
 *
 *  -----------------------------------------------------
 *
 *   LICENSE:
 *   This Source Code Form is subject to the terms of the
 *   Mozilla Public License, v. 2.0. If a copy of the MPL
 *   was not distributed with this file, You can obtain one
 *   at http://mozilla.org/MPL/2.0/.
 *
 *   DISCLAIMER:
 *   This program is distributed in the hope that it will
 *   be useful, but WITHOUT ANY WARRANTY; without even the
 *   implied warranty of MERCHANTABILITY or FITNESS FOR A
 *   PARTICULAR PURPOSE.  See the Mozilla Public License
 *   for more details.
 *
 ************************************************************/

#include "opentxs/opentxs.hpp"
#include "opentxs/core/crypto/Bip32.hpp"
#include "opentxs/core/crypto/TrezorCrypto.hpp"
#include "opentxs/api/crypto/Bip47.hpp"
#include <gtest/gtest.h>

extern "C" {

#define FROMHEX_MAXLEN 256
#include <trezor-crypto/bip32.h>
#include <trezor-crypto/ecdsa.h>
  const uint8_t *fromhex(const char *str)
  {
	static uint8_t buf[FROMHEX_MAXLEN];
	size_t len = strlen(str) / 2;
	if (len > FROMHEX_MAXLEN) len = FROMHEX_MAXLEN;
	for (size_t i = 0; i < len; i++) {
      uint8_t c = 0;
      if (str[i * 2] >= '0' && str[i*2] <= '9') c += (str[i * 2] - '0') << 4;
      if ((str[i * 2] & ~0x20) >= 'A' && (str[i*2] & ~0x20) <= 'F') c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
      if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9') c += (str[i * 2 + 1] - '0');
      if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F') c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
      buf[i] = c;
	}
	return buf;
  }
}
using namespace opentxs;

namespace
{

class Test_TrezorCrypto : public ::testing::Test
{
public:
  std::string A_Fingerprint, A_Mnemonic, A_NotificationAddress, A_NymID, B_Mnemonic, SharedSecret_0;
  PaymentCode& B_PaymentCode = PaymentCode::Factory("PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97");
  //opentxs::NymData A_NymData;
  
  Test_TrezorCrypto()
  {
      A_Mnemonic = "response seminar brave tip suit recall often sound stick owner lottery motion";
      A_Fingerprint = opentxs::OT::App().API().Exec().Wallet_ImportSeed(A_Mnemonic, "");
      A_NotificationAddress = "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW";
      A_NymID = opentxs::OT::App().API().Exec().CreateNymHD(proto::CITEMTYPE_INDIVIDUAL, "A", A_Fingerprint, 0);
      SharedSecret_0 = "f5bb84706ee366052471e6139e6a9a969d586e5fe6471a9b96c3d8caefe86fef";
  }
      
};

TEST_F(Test_TrezorCrypto, test_PaymentCode)
{
  ASSERT_TRUE(true);

  //auto currency = opentxs::proto::CITEMTYPE_BTC;
  //ASSERT_STREQ("PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA", A_NymData.PaymentCode(currency).c_str()); 
}

TEST_F(Test_TrezorCrypto, test_NotificationAddress)
{
    ASSERT_TRUE(true);
    const ConstNym A_Nym = opentxs::OT::App().Wallet().Nym(Identifier(A_NymID));
    ASSERT_STREQ(A_NotificationAddress.c_str(), OT::App().Crypto().BIP47().NotificationAddress(*A_Nym, proto::CITEMTYPE_BTC).c_str());
}

OTPassword& fromHex(std::string& h)
{
  //OTPassword& output = *(new OTPassword());
  //return output;
}

bool parseHex(const std::string& in)
{
    std::vector<std::uint8_t> v;

    for (unsigned int i = 0; i < in.length(); i += 2) {
        std::string byteString = in.substr(i, 2);
        std::uint8_t byte =
            static_cast<std::uint8_t>(strtol(byteString.c_str(), NULL, 16));
        v.push_back(byte);
    }

    return false;
}

TEST_F(Test_TrezorCrypto, test_incoming)
{
    
}
/* Test: Gets the last paymentcode to be set as primary
*/
TEST_F(Test_TrezorCrypto, test_issecp256k1)
{

  /*
m = AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522
X = 34F9460F0E4F08393D192B3C5133A6BA099AA0AD9FD54EBCCFACDFA239FF49C6
Y = 0B71EA9BD730FD8923F6D25A7A91E7DD7728A960686CB5A901BB419E0F2CA232*/
  
    bignum256 m;
    bn_read_be(fromhex("AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522"), &m);
    
    OTPassword& m_scalar = (*new OTPassword());
    std::array<std::uint8_t, 32> output{};
    m_scalar.setMemory(output.data(), sizeof(output));
    ASSERT_TRUE(m_scalar.isMemory());
    bn_write_be(&m, static_cast<std::uint8_t*>(m_scalar.getMemoryWritable()));

    //Data& mG = Data::Factory();
    //OT::App().Crypto().BIP32().ScalarBaseMultiply(m_scalar, mG); // mG = m*G

    //bignum256 a;
    
    //ASSERT_STREQ();
    ASSERT_EQ(1,0);
}

} // namespace
