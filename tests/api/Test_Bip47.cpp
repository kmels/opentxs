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

    auto acc_a = OT::App().Crypto().BIP47().Bip47ID(*A_Nym, proto::CITEMTYPE_BTC);
    auto acc_b = OT::App().Crypto().BIP47().Bip47ID(*B_Nym, proto::CITEMTYPE_BTC);

    auto [a0_, a0] = OT::App().Crypto().BIP47().EphemeralPrivkey(acc_a, 0);
    auto [a1_, a1] = OT::App().Crypto().BIP47().EphemeralPrivkey(acc_a, 1);
    auto [b0_, b0] = OT::App().Crypto().BIP47().EphemeralPrivkey(acc_b, 0);
    auto [b1_, b1] = OT::App().Crypto().BIP47().EphemeralPrivkey(acc_b, 1);
    ASSERT_TRUE(a0_); //ASSERT_TRUE(a1_);
    ASSERT_TRUE(b0_); ASSERT_TRUE(b1_);
    
    //EXPECT_STREQ("D687F6B820E6E3D47296B01F3B73CCDC930EDED39D559921A7DD8ED81B2C8F82", B_0th_privhex.c_str());
    EXPECT_STREQ("8D6A8ECD8EE5E0042AD0CB56E3A971C760B5145C3917A8E7BEAF0ED92D7A520C", a0.asHex().c_str());
    EXPECT_STREQ("60E44A7849045946C177FA76A7039F3600F35691D4E8D9CA0F56C2AEE503A751", a1.asHex().c_str());
    EXPECT_STREQ("04448FD1BE0C9C13A5CA0B530E464B619DC091B299B98C5CAB9978B32B4A1B8B", b0.asHex().c_str());
    EXPECT_STREQ("6BFA917E4C44349BFDF46346D389BF73A18CEC6BC544CE9F337E14721F06107B", b1.asHex().c_str());
    // expected is actual <-> priv bytes == accountKey
    
    // 04448fd1be0c9c13a5ca0b530e464b619dc091b299b98c5cab9978b32b4a1b8b
    auto [A0_, A0] = OT::App().Crypto().BIP47().EphemeralPubkey(A_PaymentCode, 0);
    auto [A1_, A1] = OT::App().Crypto().BIP47().EphemeralPubkey(A_PaymentCode, 1);
    auto [B0_, B0] = OT::App().Crypto().BIP47().EphemeralPubkey(B_PaymentCode, 0);
    auto [B1_, B1] = OT::App().Crypto().BIP47().EphemeralPubkey(B_PaymentCode, 1);
    ASSERT_TRUE(B0_); ASSERT_TRUE(B1_);
    
    // 0353883a146a23f988e0f381a9507cbdb3e3130cd81b3ce26daf2af088724ce683 // is derived pubkey
    
    EXPECT_STREQ("0353883A146A23F988E0F381A9507CBDB3E3130CD81B3CE26DAF2AF088724CE683", A0->asHex().c_str());
    // EXPECT_STREQ("0353883A146A23F988E0F381A9507CBDB3E3130CD81B3CE26DAF2AF088724CE683", A1->asHex().c_str());
    EXPECT_STREQ("036C6CC9446891A80184188533FE81D56110432A160E74B94D5E2294B9F13DAAE6", A1->asHex().c_str());
    
    EXPECT_STREQ("024CE8E3B04EA205FF49F529950616C3DB615B1E37753858CC60C1CE64D17E2AD8", B0->asHex().c_str());

    // EXPECT_STREQ("024CE8E3B04EA205FF49F529950616C3DB615B1E37753858CC60C1CE64D17E2AD8", B1->asHex().c_str());
    EXPECT_STREQ("03E092E58581CF950FF9C8FC64395471733E13F97DEDAC0044EBD7D60CCC1EEA4D", B1->asHex().c_str());
    
    // EXPECT_STREQ("03E092E58581CF950FF9C8FC64395471733E13F97DEDAC0044EBD7D60CCC1EEA4D", B1->asHex().c_str());    
    // actual: 2435D8554C8C94021CB78C2A5D1F083437011A222EA20388D4D63042E9B5C46E
    
    auto [S0_, S0] = OT::App().Crypto().BIP47().SecretPoint(*B_Nym, A_PaymentCode, proto::CITEMTYPE_BTC, 0);
    auto [S0_prime_, S0_prime] = OT::App().Crypto().BIP47().SecretPoint(*A_Nym, B_PaymentCode, proto::CITEMTYPE_BTC, 0);

    ASSERT_TRUE(S0_); ASSERT_TRUE(S0_prime_);
    EXPECT_STREQ(S0.asHex().c_str(), S0_prime.asHex().c_str());
    EXPECT_STREQ("F5BB84706EE366052471E6139E6A9A969D586E5FE6471A9B96C3D8CAEFE86FEF", S0.asHex().c_str());
    EXPECT_STREQ("F5BB84706EE366052471E6139E6A9A969D586E5FE6471A9B96C3D8CAEFE86FEF", S0_prime.asHex().c_str());
    
    auto [S1_, S1] = OT::App().Crypto().BIP47().SecretPoint(*B_Nym, A_PaymentCode, proto::CITEMTYPE_BTC, 1);
    auto [S1_prime_, S1_prime] = OT::App().Crypto().BIP47().SecretPoint(*A_Nym, B_PaymentCode, proto::CITEMTYPE_BTC, 1);

    ASSERT_TRUE(S1_); ASSERT_TRUE(S1_prime_);
    // EXPECT_STREQ(S1.asHex().c_str(), S1_prime.asHex().c_str());    
    EXPECT_STREQ("ADFB9B18EE1C4460852806A8780802096D67A8C1766222598DC801076BEB0B4D", S1.asHex().c_str());
    // EXPECT_STREQ("ADFB9B18EE1C4460852806A8780802096D67A8C1766222598DC801076BEB0B4D", S1_prime.asHex().c_str());
    
}

TEST_F(Test_Bip47, test_shared_addresses)
{
  /*auto A_Receive_0 = OT::App().Crypto().BIP47().IncomingPubkey(*A_Nym, B_PaymentCode, proto::CITEMTYPE_BTC, 0);
    auto A_Send_0 = OT::App().Crypto().BIP47().OutgoingPubkey(*A_Nym, B_PaymentCode, proto::CITEMTYPE_BTC, 0);
    auto A_Send_1 = OT::App().Crypto().BIP47().OutgoingPubkey(*A_Nym, B_PaymentCode, proto::CITEMTYPE_BTC, 1);

    auto B_Receive_0 = OT::App().Crypto().BIP47().IncomingPubkey(*B_Nym, A_PaymentCode, proto::CITEMTYPE_BTC, 0);
    auto B_Receive_1 = OT::App().Crypto().BIP47().IncomingPubkey(*B_Nym, A_PaymentCode, proto::CITEMTYPE_BTC, 1);
    auto B_Send_0 = OT::App().Crypto().BIP47().OutgoingPubkey(*B_Nym, A_PaymentCode, proto::CITEMTYPE_BTC, 0);
    auto B_Send_1 = OT::App().Crypto().BIP47().OutgoingPubkey(*B_Nym, A_PaymentCode, proto::CITEMTYPE_BTC, 1);
    
    EXPECT_STREQ("141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK", OT::App().Crypto().BIP47().PubKeyAddress(A_Receive_0, proto::CITEMTYPE_BTC).c_str());
    EXPECT_STREQ("141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK", OT::App().Crypto().BIP47().PubKeyAddress(A_Send_0, proto::CITEMTYPE_BTC).c_str());
    EXPECT_STREQ("12u3Uued2fuko2nY4SoSFGCoGLCBUGPkk6X", OT::App().Crypto().BIP47().PubKeyAddress(A_Send_1, proto::CITEMTYPE_BTC).c_str());    
    EXPECT_STREQ("141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK", OT::App().Crypto().BIP47().PubKeyAddress(B_Receive_0, proto::CITEMTYPE_BTC).c_str());
    EXPECT_STREQ("12u3Uued2fuko2nY4SoSFGCoGLCBUGPkk6", OT::App().Crypto().BIP47().PubKeyAddress(B_Receive_1, proto::CITEMTYPE_BTC).c_str());    
    EXPECT_STREQ("141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK", OT::App().Crypto().BIP47().PubKeyAddress(B_Send_0, proto::CITEMTYPE_BTC).c_str()); */
}

/* TEST_F(Test_Bip47, test_outgoing)
{
    
} */
;
} // namespace
