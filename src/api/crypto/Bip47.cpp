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

#include "opentxs/api/Blockchain.hpp"
#include "opentxs/api/crypto/Crypto.hpp"
#include "opentxs/api/crypto/Hash.hpp"
#include "opentxs/core/crypto/Bip32.hpp"
#include "opentxs/core/crypto/Bip39.hpp"
#include "opentxs/core/crypto/CryptoHash.hpp"
#include "opentxs/core/crypto/Ecdsa.hpp"
#include "opentxs/core/crypto/Libsecp256k1.hpp"
#include "opentxs/OT.hpp"
#include "opentxs/core/Nym.hpp"
#include <opentxs/api/Native.hpp>
#include "opentxs/core/crypto/AsymmetricKeyEC.hpp"
#if OT_CRYPTO_SUPPORTED_KEY_SECP256K1
#include "opentxs/core/crypto/AsymmetricKeySecp256k1.hpp"
#endif
#include <opentxs/core/crypto/OTPasswordData.hpp>
#include <trezor-crypto/ecdsa.h>
#include "Bip47.hpp"
#include "opentxs/core/crypto/AsymmetricKeySecp256k1.hpp"
#include "opentxs/core/crypto/OTAsymmetricKey.hpp"
#include "opentxs/api/crypto/Encode.hpp"

#if OT_CRYPTO_SUPPORTED_SOURCE_BIP47
class B;

#define OT_METHOD "opentxs::Bip47::"

namespace opentxs::api::crypto::implementation
{

std::string Bip47::PubKeyAddress(
    const proto::AsymmetricKey serialized,
    const proto::ContactItemType chain) const
{
    // TODO: refactor to blockchain interface
    std::unique_ptr<OTAsymmetricKey> key{nullptr};
    std::unique_ptr<AsymmetricKeySecp256k1> ecKey{nullptr};
    key.reset(OTAsymmetricKey::KeyFactory(serialized));

    if (false == bool(key)) {
        otErr << OT_METHOD << __FUNCTION__ << ": Unable to instantiate key."
              << std::endl;

        return {};
    }

    ecKey.reset(dynamic_cast<AsymmetricKeySecp256k1*>(key.release()));

    if (false == bool(ecKey)) {
        otErr << OT_METHOD << __FUNCTION__ << ": Incorrect key type."
              << std::endl;

        return {};
    }

    auto pubkey = Data::Factory();

    if (false == ecKey->GetPublicKey(pubkey)) {
        otErr << OT_METHOD << __FUNCTION__ << ": Unable to extract public key."
              << std::endl;

        return {};
    }

    if (33 != pubkey->GetSize()) {
        otErr << OT_METHOD << __FUNCTION__ << ": Incorrect pubkey size ("
              << pubkey->GetSize() << ")." << std::endl;

        return {};
    }

    auto sha256 = Data::Factory();
    auto ripemd160 = Data::Factory();
    auto pubkeyHash = Data::Factory();

    if (!OT::App().Crypto().Hash().Digest(
            proto::HASHTYPE_SHA256, pubkey, sha256)) {
        otErr << OT_METHOD << __FUNCTION__ << ": Unable to calculate sha256."
              << std::endl;

        return {};
    }

    if (!OT::App().Crypto().Hash().Digest(
            proto::HASHTYPE_RIMEMD160, sha256, pubkeyHash)) {
        otErr << OT_METHOD << __FUNCTION__ << ": Unable to calculate rimemd160."
              << std::endl;

        return {};
    }

    const auto prefix = OT::App().Blockchain().GetAddressPrefix(chain);
    auto preimage = Data::Factory(&prefix, sizeof(prefix));

    OT_ASSERT(1 == preimage->GetSize());

    preimage += pubkeyHash;

    OT_ASSERT(21 == preimage->GetSize());

    return OT::App().Crypto().Encode().IdentifierEncode(preimage);
}

using Bip47Identity =
    std::tuple<bool, std::uint32_t, std::uint32_t, std::string>;
/* success, nym, coin, fingerprint */
using HashedSecret =
    std::tuple<bool, OTPassword&, OTPassword&, Data&, std::string>;
/* success, secret, designated private key, designated public key, fingerprint
 */

HashedSecret Bip47::SharedSecret(
    const Nym& local,
    const PaymentCode* remote,
    const proto::ContactItemType chain,
    const std::uint32_t index) const
{
    HashedSecret result{
        false, *(new OTPassword()), *(new OTPassword()), Data::Factory(), ""};

    auto& success_ = std::get<0>(result);
    auto& s = std::get<1>(result);
    auto& a = std::get<2>(result);
    // auto& B = std::get<3>(result);

    // local nym derives a BIP47 account derived from seed
    std::cout << "Getting account \n";
    auto [success, nym, coin, fingerprint] = get_account(local, chain);

    if (!success) {
        otErr << OT_METHOD << __FUNCTION__ << ": Failed to get account."
              << std::endl;

        return result;
    }

    // local derives a deposit pubkey to watch to receive payments from remote's
    // payment code

    // i. local selects the ith private key `a` derived from
    // m / 47' / coin' / nym' / i
    Data& privkey_data = Data::Factory();

    serializedAsymmetricKey serialized_priv =
        Bip47HDKey(fingerprint, coin, nym, index, false);

    OT_ASSERT(proto::KEYMODE_PRIVATE == serialized_priv->mode());
    OTPassword key, chaincode;
    OTPasswordData password(__FUNCTION__);

    OT_ASSERT(!serialized_priv->encryptedkey().text());
    OT_ASSERT(!serialized_priv->chaincode().text());

    Ecdsa::DecryptPrivateKey(
        (*serialized_priv).encryptedkey(),
        serialized_priv->chaincode(),
        password,
        a,
        chaincode);

    OT_ASSERT(a.isMemory());
    OT_ASSERT(chaincode.isMemory());

    // ii. local derives the ith public key `B` derived from remote's payment
    // code m/47'/0'/0'/index
    serializedAsymmetricKey serialized_xpub = remote->DerivePubKeyAt(index);
    OT_ASSERT(proto::KEYMODE_PUBLIC == serialized_xpub->mode());
    auto publicKey = static_cast<AsymmetricKeySecp256k1*>(
        OTAsymmetricKey::KeyFactory(*serialized_xpub));

    auto B_ = Data::Factory();
    const auto havePubkey = publicKey->GetKey(B_);
    OT_ASSERT(havePubkey);
    //    B.Assign(B_->GetPointer(), B_->GetSize());

    // iii. local calculates a secret point:
    // S = aB
    OTPassword* S = new OTPassword();
    bool haveECDH = ECDH(B_, a, *S);

    if (!haveECDH) {
        otErr << OT_METHOD << __FUNCTION__
              << ": ECDH shared secret negotiation failed." << std::endl;

        privkey_data.zeroMemory();
        return result;
    }

    // iv. local calculates a scalar shared secret using the x value of S:
    // s = SHA256(Sx)
    const auto& Sx = S;
    OTPassword& secret_point = *(new OTPassword());
    if (!(OT::App().Crypto().Hash().Digest(
            proto::HASHTYPE_SHA256, *Sx, secret_point))) {
        otErr << OT_METHOD << __FUNCTION__ << ": Unable to calculate sha256."
              << std::endl;

        return result;
    }

    success_ = IsSecp256k1(secret_point);

    if (success_) {
        s = secret_point;
        auto& fingerprint_ = std::get<4>(result);
        fingerprint_ = fingerprint;
    }

    return result;
}

/* local derives a deposit pubkey given Alice remote pubkey. .
 *
 * \param[in] nym        The local nym who owns the channel
 * \param[in] remote     A payment code belonging to the contact
 * \param[in] chain      The coin type
 * \param[in] index      The zero-based index of the address to return
 */
proto::AsymmetricKey Bip47::IncomingPubkey(
    const Nym& local,
    const PaymentCode& remote,
    const proto::ContactItemType chain,
    const std::uint32_t index) const
{
    OT_ASSERT(remote.VerifyInternally());
    // i. local calculates a shared secrets with remote, using the public key
    // derived remote's payment code

    auto hashed = SharedSecret(local, &remote, chain, index);
    auto& success = std::get<0>(hashed);
    auto& s = std::get<1>(hashed);
    auto& a = std::get<2>(hashed);

    // ii. local calculates the ephemeral deposit addresses using the same
    // procedure as remote: B' B + sG
    // auto& B_prime = B; // B' := B
    // Data& sG = Data::Factory();
    // ScalarBaseMultiply(s, sG); // sG := sG
    // AddSecp256k1(sG, B_prime); // B' := sG + B'

    // iii. local calculates the private key for each ephemeral address as:
    // a' = a + s
    if (!success || !AddSecp256k1(s, a)) { return {}; }
    // a := s + a
    OT_ASSERT(ValidPrivateKey(a));
    OT_ASSERT(a.isMemory());

    proto::AsymmetricKey receivePrivKey{};

    receivePrivKey.set_version(1);
    receivePrivKey.set_type(proto::AKEYTYPE_SECP256K1);
    receivePrivKey.set_mode(proto::KEYMODE_PRIVATE);
    receivePrivKey.set_role(proto::KEYROLE_AUTH);

    auto& encryptedKey = *receivePrivKey.mutable_encryptedkey();
    OTPasswordData password(__FUNCTION__);
    OTPassword privateKey;
    privateKey.setMemory(a.getMemory(), a.getMemorySize());
    Ecdsa::EncryptPrivateKey(privateKey, password, encryptedKey);

    receivePrivKey.set_key(a.getMemory(), a.getMemorySize());

    // Data& DepositPubKey = Data::Factory();
    // ScalarBaseMultiply(a, DepositPubKey); // B = bG

    proto::AsymmetricKey receivePubKey{};
    bool haveKey{false};
    haveKey = static_cast<const Libsecp256k1&>(OT::App().Crypto().SECP256K1())
                  .PrivateToPublic(receivePrivKey, receivePubKey);

    if (!haveKey) { return {}; }

    return receivePubKey;
}

proto::AsymmetricKey Bip47::OutgoingPubkey(
    const Nym& local,
    const PaymentCode& remote,
    const proto::ContactItemType chain,
    const std::uint32_t index) const
{
    auto hashed = SharedSecret(local, &remote, chain, index);
    auto& success = std::get<0>(hashed);
    auto& s = std::get<1>(hashed);

    if (!success) { return {}; }
    // v. local uses the scalar shared secret to calculate the ephemeral public
    // key used to generate the P2PKH address for this transaction: B' = B + sG

    serializedAsymmetricKey serialized_xpub = remote.DerivePubKeyAt(index);
    OT_ASSERT(proto::KEYMODE_PUBLIC == serialized_xpub->mode());
    auto publicKey = static_cast<AsymmetricKeySecp256k1*>(
        OTAsymmetricKey::KeyFactory(*serialized_xpub));
    auto B_prime = Data::Factory();
    OT_ASSERT(publicKey->GetKey(B_prime));  // B' := B

    OTData sG = Data::Factory();
    ScalarBaseMultiply(s, sG);  // sG := sG
    AddSecp256k1(sG, B_prime);  // B' := sG + B'

    proto::AsymmetricKey sendKey;
    sendKey.set_version(1);
    sendKey.set_type(proto::AKEYTYPE_SECP256K1);
    sendKey.set_mode(proto::KEYMODE_PUBLIC);
    sendKey.set_role(proto::KEYROLE_AUTH);

    OT_ASSERT(B_prime->GetSize() == 33);
    sendKey.set_key(B_prime->GetPointer(), B_prime->GetSize());

    return sendKey;
}

Bip47Identity Bip47::get_account(
    const Nym& local,
    const proto::ContactItemType chain)
{
    Bip47Identity result{false, 0, 0, ""};
    auto& [success, nym, coin, fingerprint] = result;

    proto::HDPath accountPath;
    if (!local.Path(accountPath)) {
        otErr << __FUNCTION__ << ": Failed to get nym path." << std::endl;
        return result;
    }

    if (accountPath.child_size() < 2) { return result; }

    success = accountPath.child(0) ==
              (static_cast<std::uint32_t>(Bip43Purpose::NYM) |
               static_cast<std::uint32_t>(Bip32Child::HARDENED));

    if (!success) { return result; }

    nym = accountPath.child(accountPath.child_size() - 1);
    coin =
        static_cast<std::uint32_t>(OT::App().Blockchain().GetBip44Type(chain));
    fingerprint = accountPath.root();

    return result;
}

/* Returns the key at path: m/47'/coin'/nym'/index'
 */
serializedAsymmetricKey Bip47::Bip47HDKey(
    std::string& fingerprint,
    const uint32_t coin,
    const uint32_t nym,
    const uint32_t index,
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
    path.add_child(0 | static_cast<std::uint32_t>(Bip32Child::HARDENED));
    path.add_child(0 | static_cast<std::uint32_t>(Bip32Child::HARDENED));

    if (hardened_index) {
        path.add_child(
            index | static_cast<std::uint32_t>(Bip32Child::HARDENED));
    } else {
        path.add_child(index);
    }

    output = GetHDKey(EcdsaCurve::SECP256K1, *seed, path);

    return output;
}

std::string Bip47::NotificationAddress(
    const Nym& local,
    proto::ContactItemType chain) const
{
    // m / 47' / coin_type' / identity' / 0
    auto [success, nym, coin, fingerprint] = get_account(local, chain);
    if (!success) { return ""; }
    auto notificationKey = Bip47HDKey(fingerprint, coin, nym, 0, false);
    return PubKeyAddress(*notificationKey, chain);
}

}  // namespace opentxs::api::crypto::implementation
#endif
