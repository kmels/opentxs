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

class Test_Bip47 : public ::testing::Test
{
public:
  std::string A_Fingerprint, A_Mnemonic, A_NotificationAddress, A_NymID, SharedSecret_0;
  std::string B_Paycode = "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97";

  std::string B_Fingerprint, B_Mnemonic, B_NotificationAddress, B_NymID;
  std::string A_Paycode = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA";
  // opentxs::NymData A_NymData, B_NymData;

  Test_Bip47() {
      A_Mnemonic = "response seminar brave tip suit recall often sound stick owner lottery motion";
      A_Fingerprint = opentxs::OT::App().API().Exec().Wallet_ImportSeed(A_Mnemonic, "");
      A_NotificationAddress = "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW";
      A_NymID = opentxs::OT::App().API().Exec().CreateNymHD(proto::CITEMTYPE_INDIVIDUAL, "A", A_Fingerprint, 0);
      //A_NymData = OT::App().Wallet().mutable_Nym(Identifier(A_NymID));
      //A_NymData.AddPaymentCode(A_Paycode, proto::CITEMTYPE_BTC, true, true);

      B_Mnemonic = "reward upper indicate eight swift arch injury crystal super wrestle already dentist";
      B_Fingerprint = opentxs::OT::App().API().Exec().Wallet_ImportSeed(B_Mnemonic, "");
      B_NotificationAddress = "1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV";
      B_NymID = opentxs::OT::App().API().Exec().CreateNymHD(proto::CITEMTYPE_INDIVIDUAL, "B", B_Fingerprint, 0);
      //B_NymData = OT::App().Wallet().mutable_Nym(Identifier(B_NymID));
      //B_NymData.AddPaymentCode(B_Paycode, proto::CITEMTYPE_BTC, true, true);

      SharedSecret_0 = "f5bb84706ee366052471e6139e6a9a969d586e5fe6471a9b96c3d8caefe86fef";
  }
      
};

TEST_F(Test_Bip47, test_PaymentCode)
{
  //auto currency = opentxs::proto::CITEMTYPE_BTC;
  //ASSERT_STREQ("PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA", A_NymData.PaymentCode(currency).c_str());
}

TEST_F(Test_Bip47, test_NotificationAddress)
{
    ASSERT_TRUE(true);
    const ConstNym A_Nym = opentxs::OT::App().Wallet().Nym(Identifier(A_NymID));
    ASSERT_STREQ(A_NotificationAddress.c_str(), OT::App().Crypto().BIP47().NotificationAddress(*A_Nym, proto::CITEMTYPE_BTC).c_str());

    ASSERT_TRUE(true);
    const ConstNym B_Nym = opentxs::OT::App().Wallet().Nym(Identifier(B_NymID));
    ASSERT_STREQ(B_NotificationAddress.c_str(), OT::App().Crypto().BIP47().NotificationAddress(*B_Nym, proto::CITEMTYPE_BTC).c_str());
}

TEST_F(Test_Bip47, test_B_incoming)
{
    const ConstNym A_Nym = opentxs::OT::App().Wallet().Nym(Identifier(A_NymID));
    const ConstNym B_Nym = opentxs::OT::App().Wallet().Nym(Identifier(B_NymID));

    std::cout << "Constructing A payment code?";
    OTPaymentCode A_PaymentCode = PaymentCode::Factory(A_Fingerprint, 0, 1);
    OTPaymentCode B_PaymentCode = PaymentCode::Factory(B_Fingerprint, 0, 1);
    
    SerializedPaymentCode A_SPaycode = A_PaymentCode->Serialize();
    ASSERT_TRUE(A_SPaycode->has_key());

    //ASSERT_EQ(1, A_Paycode->version());
    ASSERT_EQ(33, A_SPaycode->key().size());

    ASSERT_STREQ(A_Paycode.c_str(), A_PaymentCode->asBase58().c_str());
    
    ASSERT_TRUE(A_PaymentCode->VerifyInternally());

    PaymentCode& refPay = A_PaymentCode;

    int idx = 0;
    auto B_InPubKey_0 = OT::App().Crypto().BIP47().IncomingPubkey(*B_Nym, A_PaymentCode, proto::CITEMTYPE_BTC, idx);
    auto A_InPubKey_0 = OT::App().Crypto().BIP47().IncomingPubkey(*A_Nym, B_PaymentCode, proto::CITEMTYPE_BTC, idx);
    auto A_OutPubKey_0 = OT::App().Crypto().BIP47().OutgoingPubkey(*A_Nym, B_PaymentCode, proto::CITEMTYPE_BTC, idx);
    auto B_OutPubKey_0 = OT::App().Crypto().BIP47().OutgoingPubkey(*B_Nym, A_PaymentCode, proto::CITEMTYPE_BTC, idx);
    EXPECT_STREQ("141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK", OT::App().Crypto().BIP47().PubKeyAddress(B_InPubKey_0, proto::CITEMTYPE_BTC).c_str());
    EXPECT_STREQ("141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK", OT::App().Crypto().BIP47().PubKeyAddress(A_InPubKey_0, proto::CITEMTYPE_BTC).c_str());
    EXPECT_STREQ("141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK", OT::App().Crypto().BIP47().PubKeyAddress(A_OutPubKey_0, proto::CITEMTYPE_BTC).c_str());
    EXPECT_STREQ("141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK", OT::App().Crypto().BIP47().PubKeyAddress(B_OutPubKey_0, proto::CITEMTYPE_BTC).c_str());
}

/* TEST_F(Test_Bip47, test_outgoing)
{
    
} */
;
} // namespace
