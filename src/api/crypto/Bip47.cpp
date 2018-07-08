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
#include <opentxs/core/crypto/OTPasswordData.hpp>
#include <trezor-crypto/ecdsa.h>
#include "Bip47.hpp"

#if OT_CRYPTO_SUPPORTED_SOURCE_BIP47
class B;

#define OT_METHOD "opentxs::Bip47::"

namespace opentxs::api::crypto::implementation
{
using Bip47Identity =
    std::tuple<bool, std::uint32_t, std::uint32_t, std::string>;
/* success, nym, coin, fingerprint */
using HashedSecret =
    std::tuple<bool, OTPassword&, OTPassword&, Data&, std::string>;
/* success, secret, designated private key, designated public key, fingerprint
 */

HashedSecret Bip47::shared_secret(
    const Nym& local,
    const PaymentCode& remote,
    const proto::ContactItemType chain,
    const std::uint32_t index) const
{
    HashedSecret result{
        false, *(new OTPassword()), *(new OTPassword()), Data::Factory(), ""};

    auto& success_ = std::get<0>(result);
    auto& s = std::get<1>(result);
    auto& a = std::get<2>(result);
    auto& B = std::get<3>(result);
    // local nym derives a BIP47 account derived from seed
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

    auto ECDH_privkey = Bip47HDKey(fingerprint, coin, nym, index, false)->key();

    // privkey_data.Assign(ECDH_privkey->mutable_key(),
    // ECDH_privkey->mutable_key()->size());
    privkey_data.Assign(&ECDH_privkey, (&ECDH_privkey)->size());
    a.setMemory(privkey_data);

    // ii. local derives the ith public key `B` derived from remote's payment
    // code m/47'/0'/0'/index
    Data& B_ = remote.DerivePubKeyAt(index);
    B.Assign(B_.GetPointer(), B_.GetSize());

    // iii. local calculates a secret point:
    // S = aB
    OTPassword* S = new OTPassword();
    bool haveECDH = ECDH(B, a, *S);

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
    // i. local calculates a shared secrets with remote, using the public key
    // derived remote's payment code
    auto hashed = shared_secret(local, remote, chain, index);
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
    [[maybe_unused]] const Nym& local,
    [[maybe_unused]] const PaymentCode& remote,
    [[maybe_unused]] const proto::ContactItemType chain,
    [[maybe_unused]] const std::uint32_t index) const
{
    auto hashed = shared_secret(local, remote, chain, index);
    auto& success = std::get<0>(hashed);
    auto& s = std::get<1>(hashed);
    auto& B = std::get<3>(hashed);
    // auto& fingerprint = std::get<4>(hashed);

    if (!success) { return {}; }
    // v. local uses the scalar shared secret to calculate the ephemeral public
    // key used to generate the P2PKH address for this transaction: B' = B + sG
    // = (s+B)
    // const Data& B = remote.DerivePubKeyAt(index);
    auto& B_prime = const_cast<Data&>(B);  // B' := B
    Data& sG = Data::Factory();
    ScalarBaseMultiply(s, sG);  // sG := sG
    AddSecp256k1(sG, B_prime);  // B' := sG + B'

    proto::AsymmetricKey sendKey;
    sendKey.set_version(1);
    sendKey.set_type(proto::AKEYTYPE_SECP256K1);
    sendKey.set_mode(proto::KEYMODE_PUBLIC);
    sendKey.set_role(proto::KEYROLE_AUTH);
    sendKey.set_key(B_prime.GetPointer(), B_prime.GetSize());

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

    success = accountPath.child(0) !=
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
