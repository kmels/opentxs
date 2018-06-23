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

#ifndef OPENTXS_STORAGE_TREE_BIP47_CHANNELS_HPP
#define OPENTXS_STORAGE_TREE_BIP47_CHANNELS_HPP

#include "Internal.hpp"

#include "opentxs/core/Identifier.hpp"

#include "Node.hpp"

#include <map>
#include <set>
#include <shared_mutex>
#include <tuple>

namespace opentxs::storage
{
class Bip47Channels : public Node
{
public:
    using ChannelList = std::set<OTIdentifier>;

    OTIdentifier AddressToChannel(const std::string& address) const;
    proto::ContactItemType Chain(const Identifier& channelID) const;
    ChannelList ChannelsByContact(const Identifier& contactID) const;
    ChannelList ChannelsByChain(const proto::ContactItemType chain) const;
    ChannelList ChannelsByLocalPaymentCode(const std::string& code) const;
    ChannelList ChannelsByRemotePaymentCode(const std::string& code) const;
    OTIdentifier Contact(const Identifier& channelID) const;
    bool Load(
        const Identifier& id,
        std::shared_ptr<proto::Bip47Channel>& output,
        const bool checking) const;
    std::string LocalPaymentCode(const Identifier& channelID) const;
    std::string RemotePaymentCode(const Identifier& channelID) const;

    bool Delete(const std::string& id);
    bool Store(const proto::Bip47Channel& data, Identifier& channelID);

    ~Bip47Channels() = default;

private:
    friend class Nym;

    /** Channel ID, addresses */
    using AddressMap = std::map<OTIdentifier, std::set<std::string>>;
    /** Address, channel ID */
    using AddressReverseMap = std::map<std::string, OTIdentifier>;
    /** local payment code, chain, contact, remote payment code */
    using ChannelData = std::
        tuple<std::string, proto::ContactItemType, OTIdentifier, std::string>;
    /** channel id, channel data */
    using ReverseIndex = std::map<OTIdentifier, ChannelData>;

    mutable std::shared_mutex index_lock_;
    AddressMap address_index_;
    AddressReverseMap address_reverse_index_;
    std::map<proto::ContactItemType, ChannelList> chain_map_;
    std::map<OTIdentifier, ChannelList> contact_map_;
    std::map<std::string, ChannelList> local_map_;
    std::map<std::string, ChannelList> remote_map_;
    mutable ReverseIndex channel_data_{};

    static void calculate_id(
        const proto::Bip47Channel& data,
        Identifier& channelID);
    static void extract_addresses(
        const proto::Bip47Direction& input,
        std::set<std::string>& output);

    template <typename I, typename V>
    typename V::mapped_type extract_set(const I& id, const V& index) const;
    template <typename L>
    ChannelData& get_channel_data(const L& lock, const Identifier& id) const;
    template <typename L>
    ChannelData& _get_channel_data(const L& lock, OTIdentifier&& id) const;
    void init(const std::string& hash) override;
    bool save(const Lock& lock) const override;
    proto::StorageBip47Contexts serialize() const;

    std::set<std::string>& get_address_set(
        const eLock& lock,
        const Identifier& channelID);
    std::set<std::string>& _get_address_set(
        const eLock& lock,
        OTIdentifier&& id);
    void index_addresses(
        const eLock& lock,
        const Identifier& channelID,
        const proto::Bip47Channel& data);
    void reverse_index_addresses(const eLock& lock);

    Bip47Channels(
        const opentxs::api::storage::Driver& storage,
        const std::string& hash);
    Bip47Channels() = delete;
    Bip47Channels(const Bip47Channels&) = delete;
    Bip47Channels(Bip47Channels&&) = delete;
    Bip47Channels operator=(const Bip47Channels&) = delete;
    Bip47Channels operator=(Bip47Channels&&) = delete;
};
}  // namespace opentxs::storage
#endif  // OPENTXS_STORAGE_TREE_BIP47_CHANNELS_HPP
