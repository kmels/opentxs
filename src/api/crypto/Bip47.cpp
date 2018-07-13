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
#include "opentxs/api/crypto/Symmetric.hpp"
#include "opentxs/core/crypto/Bip32.hpp"
#include "opentxs/core/crypto/Bip39.hpp"
#include "opentxs/core/crypto/CryptoHash.hpp"
#include "opentxs/core/crypto/OTPasswordData.hpp"
#include "opentxs/core/crypto/SymmetricKey.hpp"
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

std::tuple<bool, OTPassword&> Bip47::EphemeralPrivkey(
    const Bip47Identity& account,
    const std::uint32_t& index) const
{
    std::tuple<bool, OTPassword&> result{false, *(new OTPassword())};
    auto& success = std::get<0>(result);
    auto& a = std::get<1>(result);

    // auto& [success, nym, coin, fingerprint] = account;
    success = std::get<0>(account);
    auto& nym = std::get<1>(account);
    auto& coin = std::get<2>(account);
    auto fingerprint = std::get<3>(account);

    serializedAsymmetricKey serialized_priv =
        Bip47HDKey(fingerprint, coin, nym, index, false);

    OT_ASSERT(proto::KEYMODE_PRIVATE == serialized_priv->mode());

    auto privateKey = static_cast<AsymmetricKeySecp256k1*>(
        OTAsymmetricKey::KeyFactory(*serialized_priv));

    OTPasswordData password(__FUNCTION__);
    proto::Ciphertext dataPrivkey;
    OT_ASSERT(privateKey->GetKey(dataPrivkey));

    auto key = OT::App().Crypto().Symmetric().Key(
        dataPrivkey.key(), dataPrivkey.mode());

    if (!key) { return result; }

    const bool decrypted = key->Decrypt(dataPrivkey, password, a);
    OT_ASSERT(decrypted);

    OT_ASSERT(proto::KEYMODE_PRIVATE == serialized_priv->mode());
    OTPassword key1, chaincode;
    ValidPrivateKey(a);
    OT_ASSERT(a.isMemory());

    return result;
}

std::tuple<bool, OTData> Bip47::EphemeralPubkey(
    const PaymentCode& remote,
    const std::uint32_t& index) const
{
    std::tuple<bool, OTData> result{false, Data::Factory()};
    auto& havePubKey = std::get<0>(result);
    auto& B = std::get<1>(result);

    serializedAsymmetricKey serialized_xpub = remote.DerivePubKeyAt(index);
    OT_ASSERT(proto::KEYMODE_PUBLIC == serialized_xpub->mode());
    auto publicKey = static_cast<AsymmetricKeySecp256k1*>(
        OTAsymmetricKey::KeyFactory(*serialized_xpub));

    if (publicKey->GetPublicKey(B)) { havePubKey = true; }
    OT_ASSERT(havePubKey);
    return result;
}

std::tuple<bool, OTPassword&> Bip47::HashSecret(const OTPassword* Sx) const
{
    std::tuple<bool, OTPassword&> result{false, *(new OTPassword())};
    auto& success_ = std::get<0>(result);
    auto& h = std::get<1>(result);
    OTPassword& hashed_secret = *(new OTPassword());

    if (!(OT::App().Crypto().Hash().Digest(
            proto::HASHTYPE_SHA256, *Sx, hashed_secret))) {
        otErr << OT_METHOD << __FUNCTION__ << ": Unable to calculate sha256."
              << std::endl;

        return result;
    }

    success_ = IsSecp256k1(hashed_secret);
    OT_ASSERT(success_);

    if (success_) { h = hashed_secret; }
    return result;
}

std::tuple<bool, OTPassword&> Bip47::SecretPoint(
    const OTPassword& a,
    const OTData B) const
{
    std::tuple<bool, OTPassword&> result{false, *(new OTPassword())};
    auto& success_ = std::get<0>(result);
    auto& s = std::get<1>(result);

    OTPassword* S = new OTPassword();
    success_ = ECDH(B, a, *S);

    if (!success_) {
        otErr << OT_METHOD << __FUNCTION__
              << ": ECDH shared secret negotiation failed." << std::endl;

        // a.zeroMemory();
        return result;
    }

    s = *S;
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
    auto acc = Bip47ID(local, chain);

    // i. local calculates n shared secrets with remote, using the 0th
    // public key derived remote's payment code,
    // and private keys derived from the ith local's payment code

    auto [privk_ok, a] = EphemeralPrivkey(acc, index);
    OT_ASSERT(privk_ok);

    auto [pubk_ok, B] = EphemeralPubkey(remote, 0);
    OT_ASSERT(pubk_ok);

    auto [ecdh_success, Sx] = SecretPoint(a, B);
    auto [hash_success, s] = HashSecret(&Sx);

    // ii. local calculates the ephemeral deposit addresses using the same
    // procedure as remote: A' = A + sG
    if (!hash_success || !ecdh_success) {
        otErr << OT_METHOD << __FUNCTION__
              << ": Unable to calculate ephemeral private key." << std::endl;
        return {};
    }

    OTData sG = Data::Factory();
    OTData A = Data::Factory();
    ScalarBaseMultiply(s, sG);  // sG := sG
    ScalarBaseMultiply(a, A);   // A := aG
    AddSecp256k1(sG, A);        // A' := sG + A

    proto::AsymmetricKey receiveKey;
    receiveKey.set_version(1);
    receiveKey.set_type(proto::AKEYTYPE_SECP256K1);
    receiveKey.set_mode(proto::KEYMODE_PUBLIC);
    receiveKey.set_role(proto::KEYROLE_AUTH);
    OT_ASSERT(A->GetSize() == 33);
    receiveKey.set_key(A->GetPointer(), A->GetSize());
    return receiveKey;
}

proto::AsymmetricKey Bip47::OutgoingPubkey(
    const Nym& local,
    const PaymentCode& remote,
    const proto::ContactItemType chain,
    const std::uint32_t index) const
{
    OT_ASSERT(remote.VerifyInternally());
    auto acc = Bip47ID(local, chain);

    // i. local selects the ith private key `a` derived from
    // m / 47' / coin' / nym' / i
    auto [privk_ok, a] = EphemeralPrivkey(acc, 0);
    OT_ASSERT(privk_ok);

    // ii. local derives the ith public key `B` derived from remote's payment
    // code m/47'/0'/0'/index
    auto [pubk_ok, B] = EphemeralPubkey(remote, index);
    OT_ASSERT(pubk_ok);

    // iii. local calculates a secret point:
    // S = aB

    auto [ecdh_success, Sx] = SecretPoint(a, B);

    // iv. local calculates a scalar shared secret using the x value of S:
    // s = SHA256(Sx)

    auto [hash_success, s] = HashSecret(&Sx);

    if (!ecdh_success || !hash_success) { return {}; }

    // v. local uses the scalar shared secret to calculate the ephemeral public
    // key used to generate the P2PKH address for this transaction: B' = B + sG

    serializedAsymmetricKey serialized_xpub = remote.DerivePubKeyAt(index);
    OT_ASSERT(proto::KEYMODE_PUBLIC == serialized_xpub->mode());
    auto publicKey = static_cast<AsymmetricKeySecp256k1*>(
        OTAsymmetricKey::KeyFactory(*serialized_xpub));

    auto B_prime = Data::Factory();
    auto sG = Data::Factory();

    OT_ASSERT(publicKey->GetKey(B_prime));  // B' := B
    ScalarBaseMultiply(s, sG);              // sG := sG
    AddSecp256k1(sG, B_prime);              // B' := sG + B'

    proto::AsymmetricKey sendKey;
    sendKey.set_version(1);
    sendKey.set_type(proto::AKEYTYPE_SECP256K1);
    sendKey.set_mode(proto::KEYMODE_PUBLIC);
    sendKey.set_role(proto::KEYROLE_AUTH);

    OT_ASSERT(B_prime->GetSize() == 33);
    sendKey.set_key(B_prime->GetPointer(), B_prime->GetSize());

    return sendKey;
}

Bip47Identity Bip47::Bip47ID(
    const Nym& local,
    const proto::ContactItemType chain) const
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

    if (!success) {
        otErr << OT_METHOD << __FUNCTION__ << ": Failed to get account."
              << std::endl;
        return result;
    }

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
    path.add_child(coin | static_cast<std::uint32_t>(Bip32Child::HARDENED));
    path.add_child(nym | static_cast<std::uint32_t>(Bip32Child::HARDENED));

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
    auto [success, nym, coin, fingerprint] = Bip47ID(local, chain);
    if (!success) { return ""; }
    auto notificationKey = Bip47HDKey(fingerprint, coin, nym, 0, false);
    return PubKeyAddress(*notificationKey, chain);
}

}  // namespace opentxs::api::crypto::implementation
#endif
