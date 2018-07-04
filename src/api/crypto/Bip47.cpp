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
#include "stdafx.hpp"

#include "Bip47.hpp"

#if OT_CRYPTO_SUPPORTED_SOURCE_BIP47

#include "opentxs/api/Blockchain.hpp"
#include "opentxs/api/crypto/Crypto.hpp"
#include "opentxs/core/crypto/Bip32.hpp"
#include "opentxs/core/crypto/Bip39.hpp"
#include "opentxs/OT.hpp"
#include "opentxs/core/Nym.hpp"
#include <opentxs/api/Native.hpp>
#include "opentxs/core/crypto/AsymmetricKeyEC.hpp"

#define OT_METHOD "opentxs::Bip47::"

namespace opentxs::api::crypto::implementation
{

/* Derives a deposit pubkey at m/47'/0'/index to receive transactions
 * from remote's paymentcode.
 *
 * \param[in] nym        The local nym who owns the channel
 * \param[in] remote     A payment code belonging to the contact
 * \param[in] chain      The coin type
 * \param[in] index      The zero-based index of the address to return
 */
proto::AsymmetricKey Bip47::IncomingPubkey(
    const Nym& local,
    [[maybe_unused]] const PaymentCode& remote,
    [[maybe_unused]] const proto::ContactItemType chain,
    const std::uint32_t index) const
{
    proto::HDPath accountPath;

    // nym's original purpose will be set at BIP43Purpose::NYM (hardened) / nym
    if (!local.Path(accountPath)) {
        otErr << __FUNCTION__ << ": Failed to get nym path." << std::endl;
        return {};
    }

    // extract seed id
    auto fingerprint = accountPath.root();

    // extract coin
    auto coin = 1;
    // TODO:
    // static_cast<std::uint32_t>(OT::App().Blockchain().GetBip44Type(chain));

    OT_ASSERT(accountPath.child_size() > 1);

    // check if nym is HD
    OT_ASSERT(
        accountPath.child(0) ==
        (static_cast<std::uint32_t>(Bip43Purpose::NYM) |
         static_cast<std::uint32_t>(Bip32Child::HARDENED)));

    auto nym = accountPath.child(accountPath.child_size() - 1);

    // calculate m/47'/coin'/nym'/index private key
    serializedAsymmetricKey ECDH_privkey =
        Bip47HDKey(fingerprint, coin, nym, index, false);

    // OTPassword* pNewKey = new OTPassword(
    //    static_cast<void*>(&tmp_data[0]), CryptoConfig::SymmetricKeySize());

    OTPassword* privateDHKey = new OTPassword();
    const std::string* keyBytes = ECDH_privkey->mutable_key();
    Data& privkey_data = Data::Factory(keyBytes, keyBytes->size());
    privateDHKey->setMemory(privkey_data);

    /* get payment code's xpub at m/47'/0'/0'/index publib */
    const Data& ECDH_pubkey = remote.DerivePubKeyAt(index);

    // SerializedPaymentCode pcode = remote.Serialize();
    // proto::AsymmetricKey xpub = *xpubKey;
    // opentxs::AsymmetricKeyEC publicKey = new opentxs::AsymmetricKeyEC(xpub);
    // const std::string& pubKey = pcode->key();
    // const std::string& chainCode = pcode->chaincode();

    /*
    const Data& publicDHKey = Data::Factory();

    if (!publicKey.GetKey(publicDHKey)) {
        otErr << __FUNCTION__ << ": Failed to get public key." << std::endl;
        return {};
    }*/

    const OTPassword& ECDH_privk = *privateDHKey;
    BinarySecret ECDH_secret(
        OT::App().Crypto().AES().InstantiateBinarySecretSP());
    const bool haveECDH = ECDH(ECDH_pubkey, ECDH_privk, *ECDH_secret);

    if (!haveECDH) {
        otErr << OT_METHOD << __FUNCTION__
              << ": ECDH shared secret negotiation failed." << std::endl;

        return {};
    }
    return {};
}

proto::AsymmetricKey Bip47::OutgoingPubkey(
    [[maybe_unused]] const Nym& local,
    [[maybe_unused]] const PaymentCode& remote,
    [[maybe_unused]] const proto::ContactItemType chain,
    [[maybe_unused]] const std::uint32_t index) const
{
    // TODO

    return {};
}

/* Returns the key at path: m/47'/coin'/nym'/index'
 */
serializedAsymmetricKey Bip47::Bip47HDKey(
    std::string& fingerprint,
    const std::uint32_t coin,
    const std::uint32_t nym,
    const std::uint32_t index,
    const bool hardened_index) const
{
    serializedAsymmetricKey output;
    std::uint32_t notUsed = 0;
    auto seed = OT::App().Crypto().BIP39().Seed(fingerprint, notUsed);

    if (!seed) { return output; }

    proto::HDPath path;
    path.set_root(fingerprint);
    path.add_child(
        static_cast<std::uint32_t>(Bip43Purpose::PAYCODE) |
        static_cast<std::uint32_t>(Bip32Child::HARDENED));
    path.add_child(coin | static_cast<std::uint32_t>(Bip32Child::HARDENED));
    path.add_child(nym | static_cast<std::uint32_t>(Bip32Child::HARDENED));
    path.add_child(
        index | hardened_index
            ? static_cast<std::uint32_t>(Bip32Child::HARDENED)
            : 0);

    output = GetHDKey(EcdsaCurve::SECP256K1, *seed, path);

    return output;
}

}  // namespace opentxs::api::crypto::implementation
#endif
