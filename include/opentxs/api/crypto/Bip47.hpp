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

#ifndef OPENTXS_API_CRYPTO_BIP47_HPP
#define OPENTXS_API_CRYPTO_BIP47_HPP

#include "opentxs/Forward.hpp"

#include "opentxs/Proto.hpp"

#include <cstdint>

#if OT_CRYPTO_SUPPORTED_SOURCE_BIP47

namespace opentxs
{
namespace api
{
namespace crypto
{
using Bip47Identity =
    std::tuple<bool, std::uint32_t, std::uint32_t, std::string>;

class Bip47
{
public:
    EXPORT virtual Bip47Identity Bip47ID(
        const Nym& local,
        const proto::ContactItemType chain) const = 0;
    EXPORT virtual std::tuple<bool, OTPassword&> LocalPaymentCode(
        const Bip47Identity& local,
        const std::uint32_t& index) const = 0;
    EXPORT virtual std::tuple<bool, OTData> RemotePaymentCode(
        const PaymentCode& remote,
        const std::uint32_t& index) const = 0;
    EXPORT virtual std::tuple<bool, OTPassword&> HashSecret(
        const OTPassword* secret) const = 0;
    EXPORT virtual std::tuple<bool, OTPassword&> SecretPoint(
        const OTPassword& privkey,
        const OTData pubkey) const = 0;
    EXPORT virtual std::string PubKeyAddress(
        const proto::AsymmetricKey key,
        const proto::ContactItemType chain) const = 0;
    EXPORT virtual proto::AsymmetricKey IncomingPubkey(
        const Nym& local,
        const PaymentCode& remote,
        const proto::ContactItemType chain,
        const std::uint32_t index) const = 0;
    EXPORT virtual proto::AsymmetricKey OutgoingPubkey(
        const Nym& local,
        const PaymentCode& remote,
        const proto::ContactItemType chain,
        const std::uint32_t index) const = 0;
    EXPORT virtual std::string NotificationAddress(
        const Nym& local,
        proto::ContactItemType chain) const = 0;
    EXPORT virtual ~Bip47() = default;

protected:
    Bip47() = default;

private:
    Bip47(const Bip47&) = delete;
    Bip47(Bip47&&) = delete;
    Bip47& operator=(const Bip47&) = delete;
    Bip47& operator=(Bip47&&) = delete;
};
}  // namespace crypto
}  // namespace api
}  // namespace opentxs
#endif  // OT_CRYPTO_SUPPORTED_SOURCE_BIP47
#endif  // OPENTXS_API_CRYPTO_BIP47_HPP
