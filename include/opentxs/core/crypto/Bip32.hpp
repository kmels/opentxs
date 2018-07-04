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

#ifndef OPENTXS_CORE_CRYPTO_BIP32_HPP
#define OPENTXS_CORE_CRYPTO_BIP32_HPP

#include "opentxs/Forward.hpp"

#if OT_CRYPTO_WITH_BIP32

#include "opentxs/core/crypto/CryptoSymmetric.hpp"
#include "opentxs/core/crypto/OTAsymmetricKey.hpp"
#include "opentxs/Proto.hpp"
#include "opentxs/Types.hpp"

#include <cstdint>
#include <string>

namespace opentxs
{
class OTPassword;

std::string Print(const proto::HDPath& node);

class Bip32
{
public:
    virtual std::string SeedToFingerprint(
        const EcdsaCurve& curve,
        const OTPassword& seed) const = 0;
    virtual serializedAsymmetricKey SeedToPrivateKey(
        const EcdsaCurve& curve,
        const OTPassword& seed) const = 0;
    virtual serializedAsymmetricKey GetChild(
        const proto::AsymmetricKey& parent,
        const std::uint32_t index) const = 0;
    virtual serializedAsymmetricKey GetHDKey(
        const EcdsaCurve& curve,
        const OTPassword& seed,
        proto::HDPath& path) const = 0;

    serializedAsymmetricKey AccountChildKey(
        const proto::HDPath& path,
        const BIP44Chain internal,
        const std::uint32_t index) const;
    std::string Seed(const std::string& fingerprint = "") const;
    serializedAsymmetricKey GetPaymentCode(
        std::string& fingerprint,
        const std::uint32_t nym) const;
    serializedAsymmetricKey GetStorageKey(std::string& seed) const;

    virtual serializedAsymmetricKey MasterPubKeyFromBytes(
        const EcdsaCurve& curve,
        const uint8_t* pubkey,
        const uint8_t* chain_code) const = 0;
};
}  // namespace opentxs

#endif  // OT_CRYPTO_WITH_BIP32
#endif  // OPENTXS_CORE_CRYPTO_BIP32_HPP
