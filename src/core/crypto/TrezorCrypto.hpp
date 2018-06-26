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

#ifndef OPENTXS_CORE_CRYPTO_TREZOR_CRYPTO_HPP
#define OPENTXS_CORE_CRYPTO_TREZOR_CRYPTO_HPP

#include "Internal.hpp"

#if OT_CRYPTO_USING_TREZOR
#if OT_CRYPTO_WITH_BIP32
#include "opentxs/core/crypto/Bip32.hpp"
#endif
#if OT_CRYPTO_WITH_BIP39
#include "opentxs/core/crypto/Bip39.hpp"
#endif
#include "opentxs/core/crypto/CryptoAsymmetric.hpp"
#include "opentxs/core/crypto/CryptoEncoding.hpp"
#include "opentxs/core/crypto/Ecdsa.hpp"
#include "opentxs/Types.hpp"

#if OT_CRYPTO_SUPPORTED_SOURCE_BIP47
#include "api/crypto/Bip47.hpp"
#endif

extern "C" {
#include <trezor-crypto/base58.h>
#if OT_CRYPTO_WITH_BIP32
#include <trezor-crypto/bip32.h>
#endif
#include <trezor-crypto/ecdsa.h>
}

#include <cstdint>
#include <memory>
#include <string>

namespace opentxs
{
namespace api
{
namespace implementation
{
class Crypto;
}  // namespace implementation
}  // namespace api

class TrezorCrypto : public CryptoEncoding
#if OT_CRYPTO_WITH_BIP39
    ,
                     public Bip39
#endif
#if OT_CRYPTO_WITH_BIP32
    ,
                     public Bip32
#endif
#if OT_CRYPTO_SUPPORTED_SOURCE_BIP47
    ,
                     public api::crypto::implementation::Bip47
#endif
#if OT_CRYPTO_SUPPORTED_KEY_SECP256K1
    ,
                     public Ecdsa
#endif
{
private:
    friend class api::implementation::Crypto;
    friend class Libsecp256k1;

    typedef bool DerivationMode;
    const DerivationMode DERIVE_PRIVATE = true;
    const DerivationMode DERIVE_PUBLIC = false;

    const std::uint8_t KeyMax[32]{
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F};

    api::Native& native_;

#if OT_CRYPTO_WITH_BIP39
    bool toWords(const OTPassword& seed, OTPassword& words) const override;
    void WordsToSeed(
        const OTPassword& words,
        OTPassword& seed,
        const OTPassword& passphrase) const override;
#endif

#if OT_CRYPTO_WITH_BIP32
    const curve_info* secp256k1_{nullptr};

    static std::string CurveName(const EcdsaCurve& curve);

    static std::unique_ptr<HDNode> InstantiateHDNode(
        const EcdsaCurve& curve,
        const OTPassword& seed);
    static std::unique_ptr<HDNode> InstantiateHDNode(const EcdsaCurve& curve);
    static std::unique_ptr<HDNode> GetChild(
        const HDNode& parent,
        const std::uint32_t index,
        const DerivationMode privateVersion);

    std::unique_ptr<HDNode> DeriveChild(
        const EcdsaCurve& curve,
        const OTPassword& seed,
        proto::HDPath& path) const;
    std::unique_ptr<HDNode> SerializedToHDNode(
        const proto::AsymmetricKey& serialized) const;
    serializedAsymmetricKey HDNodeToSerialized(
        const proto::AsymmetricKeyType& type,
        const HDNode& node,
        const DerivationMode privateVersion) const;
    bool ValidPrivateKey(const OTPassword& key) const;
#endif

#if OT_CRYPTO_SUPPORTED_KEY_SECP256K1
    bool ECDH(
        const Data& publicKey,
        const OTPassword& privateKey,
        OTPassword& secret) const override;
    bool ScalarBaseMultiply(const OTPassword& privateKey, Data& publicKey)
        const override;
#endif

    TrezorCrypto(api::Native& native);
    TrezorCrypto() = delete;
    TrezorCrypto(const TrezorCrypto&) = delete;
    TrezorCrypto(TrezorCrypto&&) = delete;
    TrezorCrypto& operator=(const TrezorCrypto&) = delete;
    TrezorCrypto& operator=(TrezorCrypto&&) = delete;

public:
#if OT_CRYPTO_WITH_BIP32
    serializedAsymmetricKey GetChild(
        const proto::AsymmetricKey& parent,
        const std::uint32_t index) const override;
    serializedAsymmetricKey GetHDKey(
        const EcdsaCurve& curve,
        const OTPassword& seed,
        proto::HDPath& path) const override;
    bool RandomKeypair(OTPassword& privateKey, Data& publicKey) const override;
    std::string SeedToFingerprint(
        const EcdsaCurve& curve,
        const OTPassword& seed) const override;
    serializedAsymmetricKey SeedToPrivateKey(
        const EcdsaCurve& curve,
        const OTPassword& seed) const override;
#endif
    std::string Base58CheckEncode(
        const std::uint8_t* inputStart,
        const std::size_t& inputSize) const override;
    bool Base58CheckDecode(const std::string&& input, RawData& output)
        const override;
    bool RIPEMD160(
        const std::uint8_t* input,
        const size_t inputSize,
        std::uint8_t* output) const;

    ~TrezorCrypto() = default;
};
}  // namespace opentxs
#endif  // OT_CRYPTO_USING_TREZOR
#endif  // OPENTXS_CORE_CRYPTO_TREZOR_CRYPTO_HPP
