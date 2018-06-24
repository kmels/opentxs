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
 *  fellowtraveler\opentransactions.org
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

#ifndef OPENTXS_API_BLOCKCHAIN_HPP
#define OPENTXS_API_BLOCKCHAIN_HPP

#include "opentxs/Forward.hpp"

#if OT_CRYPTO_SUPPORTED_KEY_HD
#include "opentxs/Proto.hpp"
#include "opentxs/Types.hpp"

#include <cstdint>
#include <memory>
#include <tuple>

#define DEFAULT_BIP47_LOOKAHEAD 10

namespace opentxs
{
namespace api
{
class Blockchain
{
public:
    virtual std::shared_ptr<proto::Bip44Account> Account(
        const Identifier& nymID,
        const Identifier& accountID) const = 0;
    virtual std::set<OTIdentifier> AccountList(
        const Identifier& nymID,
        const proto::ContactItemType type) const = 0;
    virtual std::unique_ptr<proto::Bip44Address> AllocateAddress(
        const Identifier& nymID,
        const Identifier& accountID,
        const std::string& label = "",
        const BIP44Chain chain = EXTERNAL_CHAIN) const = 0;
    /** Calculate the next incoming or outgoing address for a channel
     *
     *  \param[in] nymid        The local nym for the channel
     *  \param[in] channelID    The channel to be modified
     *  \param[in] incoming     Passing true will increment the channel in the
     *                          incoming direction. Passing false will increment
     *                          the channel in the outgoing transaction
     *
     *  \returns The newly allocated address, or an empty smart pointer if the
     *  channel did not exist or is full in the specified direction
     */
    virtual std::unique_ptr<proto::Bip47Address> AllocatePaycodeAddress(
        const Identifier& nymID,
        const Identifier& channelID,
        const bool incoming) const = 0;
    virtual bool AssignAddress(
        const Identifier& nymID,
        const Identifier& accountID,
        const std::uint32_t index,
        const Identifier& contactID,
        const BIP44Chain chain = EXTERNAL_CHAIN) const = 0;
    virtual std::string CalculateAddress(
        const proto::AsymmetricKey serialized,
        const proto::ContactItemType type) const = 0;
    /** Set up a new BIP-47 channel
     *
     *  \usage     The local nym must already exist in the wallet and the local
     *             payment code must be one for which the private keys are
     *             available.
     *
     *             If the contact identifier is not empty, then the specified
     *             contact must already exist. If the contact identifier is
     *             empty a new contact will be created.
     *
     *             If the remote payment code is not already associated with the
     *             contact then it will be added to the contact
     *
     *  \param[in] nymid             The local nym who owns the channel
     *  \param[in] localPaymentCode  A payment code belonging to the local nym
     *  \param[in] contactid         The contact with whom the channel exists
     *  \param[in] remotePaymentCode A payment code belonging to the contact
     *  \param[in] chain             The blockchain on which the channel exists
     *  \param[in] incomingNotification The txid of the incoming notification
     *                                  transaction. May be blank.
     *  \param[in] outgoingNotification The txid of the outgoing notification
     *                                  transaction. May be blank.
     *  \param[in] lookahead         The number of addresses to calculate both
     *                               in the incoming and the outgoing direction
     *
     *  \returns The channel identifier for the new channel if it has been
     *   created, or the existing channel identifier if it already exists, or
     *   an empty identifier if the channel can not be created
     */
    virtual OTIdentifier CreatePaycodeChannel(
        const Identifier& nymID,
        const PaymentCode& localPaymentCode,
        const Identifier& contactID,
        const PaymentCode& remotePaymentCode,
        const proto::ContactItemType chain,
        const std::string& incomingNotification,
        const std::string& outgoingNotification,
        const std::uint32_t lookahead = DEFAULT_BIP47_LOOKAHEAD) const = 0;
    virtual Bip44Type GetBip44Type(const proto::ContactItemType type) const = 0;
    virtual std::unique_ptr<proto::Bip44Address> LoadAddress(
        const Identifier& nymID,
        const Identifier& accountID,
        const std::uint32_t index,
        const BIP44Chain chain) const = 0;
    /** Load a BIP-47 address
     *
     *  \param[in] nymid        The local nym who owns the channel
     *  \param[in] channelID    The channel to be loaded
     *  \param[in] index        The zero-based index of the address to return
     *  \param[in] incoming     Passing true will select an address on the
     *                          incoming chain. Passing false will select an
     *                          address on the outgoing chain
     *
     *  \returns an instantiated Bip47Address if it has been calculated, or an
     *   empty smart pointer if the channel does not exist or the address has
     *   not been allocated
     */
    virtual std::unique_ptr<proto::Bip47Address> LoadPaycodeAddress(
        const Identifier& nymID,
        const Identifier& channelID,
        const std::uint32_t index,
        const bool incoming) const = 0;
    /** Check if an address is associated with a BIP-47 channel
     *
     *  \params[in] address     The address for which to search
     *
     *  \returns a (nym ID, channel ID) pair if the address is found
     *   or a pair of empty identifier if the address is not found
     */
    virtual std::pair<OTIdentifier, OTIdentifier> LookupChannelByAddress(
        const std::string& address) const = 0;
    virtual OTIdentifier NewAccount(
        const Identifier& nymID,
        const BlockchainAccountType standard,
        const proto::ContactItemType type) const = 0;
    /** Load a BIP-47 channel
     *
     *  \param[in] nymid        The local nym who owns the channel
     *  \param[in] channelID    The channel to be loaded
     *
     *  \returns an instantiated Bip47Channel if it exists, or an empty smart
     *   pointer if the channel does not exist
     */
    virtual std::shared_ptr<proto::Bip47Channel> PaycodeChannel(
        const Identifier& nymID,
        const Identifier& channelID) const = 0;
    /** Get a filtered list of BIP-47 channels
     *
     *  \param[in] nymid    The local nym whose channels will be returned
     *  \param[in] type     The currency by which to filter the output. A value
     *                      of proto::CITEMTYPE_ERROR will return all channels
     *
     *  \returns The set of channel identifiers who patch the provided
     *  parameters
     */
    virtual std::set<OTIdentifier> PaycodeChannelList(
        const Identifier& nymID,
        const proto::ContactItemType type) const = 0;
    virtual bool StoreIncoming(
        const Identifier& nymID,
        const Identifier& accountID,
        const std::uint32_t index,
        const BIP44Chain chain,
        const proto::BlockchainTransaction& transaction) const = 0;
    /** Store an incoming BIP-47 transaction, or notification transaction
     *
     *  \usage     Adding a transaction to a BIP-47 address will calculate the
     *             next receiving address unless the address specified by the
     *             index parameter has already received a transaction
     *
     *  \param[in] nymid        The local nym who owns the channel
     *  \param[in] channelID    The channel which received the transaction
     *  \param[in] index        The zero-based index of the address which
     *                          received the transaction for regular
     *                          transactions. A negative value designates a
     *                          notification transaction
     *  \param[in] transaction  The serialized transaction
     *
     *  \returns True if the transaction was stored. False if the channel does
     *   not exist, or if the address has not been previously allocated.
     */
    virtual bool StoreIncoming(
        const Identifier& nymID,
        const Identifier& channelID,
        const std::int32_t index,
        const proto::BlockchainTransaction& transaction) const = 0;
    virtual bool StoreOutgoing(
        const Identifier& senderNymID,
        const Identifier& accountID,
        const Identifier& recipientContactID,
        const proto::BlockchainTransaction& transaction) const = 0;
    /** Store an outgoing BIP-47 transaction, or notification transaction
     *
     *  \usage     Adding a transaction to a BIP-47 address will calculate the
     *             next sending address unless the address specified by the
     *             index parameter has already received a transaction
     *
     *  \param[in] nymid        The local nym who owns the channel
     *  \param[in] channelID    The channel which generated the receiving
     *                          address
     *  \param[in] index        The zero-based index of receiving address for
     *                          regular transactions. A negative value
     *                          designates a notification transaction
     *  \param[in] transaction  The serialized transaction
     *
     *  \returns True if the transaction was stored. False if the channel does
     *   not exist, or if the address has not been previously allocated.
     */
    virtual bool StoreOutgoing(
        const Identifier& senderNymID,
        const Identifier& channelID,
        const std::int32_t index,
        const proto::BlockchainTransaction& transaction) const = 0;
    virtual std::shared_ptr<proto::BlockchainTransaction> Transaction(
        const std::string& id) const = 0;

    virtual ~Blockchain() = default;

protected:
    Blockchain() = default;

private:
    Blockchain(const Blockchain&) = delete;
    Blockchain(Blockchain&&) = delete;
    Blockchain& operator=(const Blockchain&) = delete;
    Blockchain& operator=(Blockchain&&) = delete;
};
}  // namespace api
}  // namespace opentxs
#endif  // OT_CRYPTO_SUPPORTED_KEY_HD
#endif  // OPENTXS_API_BLOCKCHAIN_HPP
