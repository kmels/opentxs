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

//#define OT_METHOD "opentxs::Bip47::"

namespace opentxs::api::crypto::implementation
{
proto::AsymmetricKey Bip47::IncomingPubkey(
    [[maybe_unused]] const Nym& local,
    [[maybe_unused]] const PaymentCode& remote,
    [[maybe_unused]] const proto::ContactItemType chain,
    [[maybe_unused]] const std::uint32_t index) const
{
    // TODO

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
}  // namespace opentxs::api::crypto::implementation
#endif
