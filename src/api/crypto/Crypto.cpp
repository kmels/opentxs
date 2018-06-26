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

#include "Crypto.hpp"

#if OT_CRYPTO_WITH_BIP32
#include "opentxs/core/crypto/Bip32.hpp"
#endif
#if OT_CRYPTO_WITH_BIP39
#include "opentxs/core/crypto/Bip39.hpp"
#endif
#include "opentxs/core/crypto/CryptoAsymmetric.hpp"
#include "opentxs/core/crypto/CryptoSymmetric.hpp"
#if OT_CRYPTO_USING_LIBSECP256K1
#include "opentxs/core/crypto/Libsecp256k1.hpp"
#endif
#include "opentxs/core/crypto/Libsodium.hpp"
#if OT_CRYPTO_USING_OPENSSL
#include "opentxs/core/crypto/OpenSSL.hpp"
#endif
#include "opentxs/core/crypto/SymmetricKey.hpp"
#if OT_CRYPTO_USING_TREZOR
#include "opentxs/core/crypto/OTCachedKey.hpp"
#endif
#include "opentxs/core/util/Assert.hpp"
#include "opentxs/core/Identifier.hpp"
#include "opentxs/core/Log.hpp"

#include <functional>
#include <ostream>
#include <vector>

extern "C" {
#ifdef _WIN32
#else
#include <sys/resource.h>
#endif
}

#if OT_CRYPTO_USING_TREZOR
#include "core/crypto/TrezorCrypto.hpp"
#endif
#include "Encode.hpp"
#include "Hash.hpp"
#include "Symmetric.hpp"

#define OT_METHOD "opentxs::Crypto::"

namespace opentxs::api::implementation
{

Crypto::Crypto(api::Native& native)
    : native_(native)
    , cached_key_lock_()
    , primary_key_(nullptr)
    , cached_keys_()
#if OT_CRYPTO_USING_TREZOR
    , bitcoincrypto_(new TrezorCrypto(native_))
#endif
    , ed25519_(new Curve25519)
    , ssl_(new SSLImplementation)
{
    Init();
}

#if OT_CRYPTO_SUPPORTED_ALGO_AES
const CryptoSymmetric& Crypto::AES() const
{
    OT_ASSERT(nullptr != ssl_);

    return *ssl_;
}
#endif

#if OT_CRYPTO_WITH_BIP32
const Bip32& Crypto::BIP32() const
{
    OT_ASSERT(nullptr != bitcoincrypto_);

    return *bitcoincrypto_;
}
#endif

#if OT_CRYPTO_WITH_BIP39
const Bip39& Crypto::BIP39() const
{
    OT_ASSERT(nullptr != bitcoincrypto_);

    return *bitcoincrypto_;
}
#endif

#if OT_CRYPTO_SUPPORTED_SOURCE_BIP47
const api::crypto::Bip47& Crypto::BIP47() const
{
    OT_ASSERT(nullptr != bitcoincrypto_);

    return *bitcoincrypto_;
}
#endif

const OTCachedKey& Crypto::CachedKey(const Identifier& id) const
{
    Lock lock(cached_key_lock_);

    auto& output = cached_keys_[id];

    if (false == bool(output)) {
        OT_FAIL_MSG("This function is broken, this never should have "
                    "happened.");

        output.reset(new OTCachedKey(OT_MASTER_KEY_TIMEOUT));
    }

    OT_ASSERT(output);

    return *output;
}

const OTCachedKey& Crypto::CachedKey(const OTCachedKey& source) const
{
    Lock lock(cached_key_lock_);
    const auto id = Identifier::Factory(source);
    auto& output = cached_keys_[id];

    if (false == bool(output)) {
        OTASCIIArmor serialized{};
        const bool haveSerialized = source.SerializeTo(serialized);

        OT_ASSERT(haveSerialized);

        output.reset(new OTCachedKey(serialized));
    }

    OT_ASSERT(output);

    return *output;
}

void Crypto::Cleanup()
{
#if OT_CRYPTO_SUPPORTED_KEY_SECP256K1
    secp256k1_->Cleanup();
#endif
    ssl_->Cleanup();
}

const OTCachedKey& Crypto::DefaultKey() const
{
    Lock lock(cached_key_lock_);

    init_default_key(lock);

    OT_ASSERT(primary_key_);

    return *primary_key_;
}

Editor<OTCachedKey> Crypto::mutable_DefaultKey() const
{
    OT_ASSERT(primary_key_);

    std::function<void(OTCachedKey*, Lock&)> callback = [&](OTCachedKey*,
                                                            Lock&) -> void {};

    return Editor<OTCachedKey>(cached_key_lock_, primary_key_.get(), callback);
}

const CryptoAsymmetric& Crypto::ED25519() const
{
    OT_ASSERT(nullptr != ed25519_);

    return *ed25519_;
}

const crypto::Encode& Crypto::Encode() const
{
    OT_ASSERT(encode_);

    return *encode_;
}

const crypto::Hash& Crypto::Hash() const
{
    OT_ASSERT(hash_);

    return *hash_;
}

void Crypto::Init()
{
#if OT_CRYPTO_SUPPORTED_KEY_SECP256K1
    secp256k1_.reset(new secp256k1(*ssl_, *bitcoincrypto_));
#endif
    encode_.reset(new api::crypto::implementation::Encode(*bitcoincrypto_));
    hash_.reset(new api::crypto::implementation::Hash(
        *encode_,
        *ssl_,
        *ed25519_
#if OT_CRYPTO_USING_TREZOR
        ,
        *bitcoincrypto_
#endif
        ));
    symmetric_.reset(new api::crypto::implementation::Symmetric(*ed25519_));

    otWarn << OT_METHOD << __FUNCTION__
           << ": Setting up rlimits, and crypto libraries...\n";

// Here is a security measure intended to make it more difficult to
// capture a core dump. (Not used in debug mode, obviously.)
//
#if !defined(PREDEF_MODE_DEBUG) && defined(PREDEF_PLATFORM_UNIX)
    struct rlimit rlim;
    getrlimit(RLIMIT_CORE, &rlim);
    rlim.rlim_max = rlim.rlim_cur = 0;
    if (setrlimit(RLIMIT_CORE, &rlim)) {
        OT_FAIL_MSG("Crypto::Init: ASSERT: setrlimit failed. (Used for "
                    "preventing core dumps.)\n");
    }
#endif

    ssl_->Init();
#if OT_CRYPTO_SUPPORTED_KEY_SECP256K1
    // WARNING: The below call to secp256k1_->Init() DEPENDS on the fact
    // that the above call to ssl_->Init() happened FIRST.
    secp256k1_->Init();
#endif
    ed25519_->Init();
}

void Crypto::init_default_key(const Lock&) const
{
    if (false == bool(primary_key_)) {
        primary_key_.reset(new OTCachedKey(OT_MASTER_KEY_TIMEOUT));
    }
}

const OTCachedKey& Crypto::LoadDefaultKey(const OTASCIIArmor& serialized) const
{
    Lock lock(cached_key_lock_);

    init_default_key(lock);

    OT_ASSERT(primary_key_);

    primary_key_->SetCachedKey(serialized);

    return *primary_key_;
}

#if OT_CRYPTO_SUPPORTED_KEY_RSA
const CryptoAsymmetric& Crypto::RSA() const
{
    OT_ASSERT(nullptr != ssl_);

    return *ssl_;
}
#endif

#if OT_CRYPTO_SUPPORTED_KEY_SECP256K1
const CryptoAsymmetric& Crypto::SECP256K1() const
{
    OT_ASSERT(nullptr != secp256k1_);

    return *secp256k1_;
}
#endif

void Crypto::SetTimeout(const std::chrono::seconds& timeout) const
{
    Lock lock(cached_key_lock_);

    init_default_key(lock);

    OT_ASSERT(primary_key_);

    primary_key_->SetTimeoutSeconds(timeout.count());
}

void Crypto::SetSystemKeyring(const bool useKeyring) const
{
    Lock lock(cached_key_lock_);

    init_default_key(lock);

    OT_ASSERT(primary_key_);

    primary_key_->UseSystemKeyring(useKeyring);
}

const crypto::Symmetric& Crypto::Symmetric() const
{
    OT_ASSERT(symmetric_);

    return *symmetric_;
}

const crypto::Util& Crypto::Util() const
{
    OT_ASSERT(nullptr != ssl_);

    return *ssl_;
}

std::unique_ptr<SymmetricKey> Crypto::GetStorageKey(__attribute__((unused))
                                                    std::string& seed) const
{
#if OT_CRYPTO_WITH_BIP39
    auto serialized = BIP32().GetStorageKey(seed);

    if (false == bool(serialized)) {
        otErr << OT_METHOD << __FUNCTION__ << ": Failed to load encryption key."
              << std::endl;

        return {};
    }

    OTPassword keySource{};
    auto sessionKey = Symmetric().Key(
        serialized->encryptedkey().key(), serialized->encryptedkey().mode());
    OTPasswordData blank(__FUNCTION__);
    const bool decrypted =
        sessionKey->Decrypt(serialized->encryptedkey(), blank, keySource);

    if (false == decrypted) { return {}; }

    return Symmetric().Key(keySource);
#else
    return {};
#endif
}

Crypto::~Crypto() { Cleanup(); }
}  // namespace opentxs::api::implementation
