// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "stdafx.hpp"

#include "opentxs/api/client/Contacts.hpp"
#include "opentxs/api/client/Manager.hpp"
#include "opentxs/api/client/OTX.hpp"
#include "opentxs/api/Endpoints.hpp"
#include "opentxs/api/Factory.hpp"
#include "opentxs/contact/Contact.hpp"
#include "opentxs/contact/ContactData.hpp"
#include "opentxs/core/crypto/PaymentCode.hpp"
#include "opentxs/core/identifier/Nym.hpp"
#include "opentxs/core/Identifier.hpp"
#include "opentxs/core/Log.hpp"
#include "opentxs/network/zeromq/Context.hpp"
#include "opentxs/network/zeromq/ListenCallback.hpp"
#include "opentxs/network/zeromq/FrameIterator.hpp"
#include "opentxs/network/zeromq/FrameSection.hpp"
#include "opentxs/network/zeromq/Frame.hpp"
#include "opentxs/network/zeromq/Message.hpp"
#include "opentxs/network/zeromq/SubscribeSocket.hpp"
#include "opentxs/ui/ContactListItem.hpp"

#include "ContactListItemBlank.hpp"

#include <map>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#include "ContactList.hpp"

#define OT_METHOD "opentxs::ui::implementation::ContactList::"

namespace opentxs
{
ui::implementation::ContactListExternalInterface* Factory::ContactList(
    const api::client::Manager& api,
    const network::zeromq::PublishSocket& publisher,
    const Identifier& nymID)
{
    return new ui::implementation::ContactList(api, publisher, nymID);
}
}  // namespace opentxs

namespace opentxs::ui::implementation
{
ContactList::ContactList(
    const api::client::Manager& api,
    const network::zeromq::PublishSocket& publisher,
    const Identifier& nymID)
    : ContactListList(api, publisher, nymID)
    , listeners_({
          {api_.Endpoints().ContactUpdate(),
           new MessageProcessor<ContactList>(&ContactList::process_contact)},
      })
    , owner_contact_id_(api_.Contacts().ContactID(nymID))
    , owner_(nullptr)
{
    owner_.reset(Factory::ContactListItem(
        *this, api, publisher_, owner_contact_id_, "Owner"));

    OT_ASSERT(owner_)

    last_id_ = owner_contact_id_;

    OT_ASSERT(false == owner_contact_id_->empty())

    init();
    setup_listeners(listeners_);
    startup_.reset(new std::thread(&ContactList::startup, this));

    OT_ASSERT(startup_)
}

std::string ContactList::AddContact(
    const std::string& label,
    const std::string& paymentCode,
    const std::string& nymID) const
{
    const auto contact = api_.Contacts().NewContact(
        label,
        identifier::Nym::Factory(nymID),
        api_.Factory().PaymentCode(paymentCode));
    const auto& id = contact->ID();
    api_.OTX().CanMessage(nym_id_, id, true);

    return id.str();
}

void ContactList::add_item(
    const ContactListRowID& id,
    const ContactListSortKey& index,
    const CustomData& custom)
{
    LogVerbose(OT_METHOD)(__FUNCTION__)(": Widget ID: ")(WidgetID()).Flush();

    if (owner_contact_id_ == id) {
        owner_->reindex(index, custom);
        UpdateNotify();

        return;
    }

    ContactListList::add_item(id, index, custom);
}

void ContactList::construct_row(
    const ContactListRowID& id,
    const ContactListSortKey& index,
    const CustomData&) const
{
    names_.emplace(id, index);
    items_[index].emplace(
        id, Factory::ContactListItem(*this, api_, publisher_, id, index));
}

#if OT_QT
QVariant ContactList::data(const QModelIndex& index, int role) const
{
    if (false == index.isValid()) { return {}; }

    if (columnCount() < index.column()) { return {}; }

    const ContactListItem* pRow{
        (0 == index.row())
            ? owner_.get()
            : static_cast<ContactListItem*>(index.internalPointer())};

    if (nullptr == pRow) { return {}; }

    const auto& row = *pRow;

    switch (role) {
        case IDRole: {
            return row.ContactID().c_str();
        }
        case NameRole: {
            return row.DisplayName().c_str();
        }
        case ImageRole: {
            return row.ImageURI().c_str();
        }
        case SectionRole: {
            return row.Section().c_str();
        }
        default: {
            return {};
        }
    }

    return {};
}
#endif

/** Returns owner contact. Sets up iterators for next row */
std::shared_ptr<const ContactListRowInternal> ContactList::first(
    const Lock& lock) const
{
    OT_ASSERT(verify_lock(lock))

    have_items_->Set(first_valid_item(lock));
    start_->Set(!have_items_.get());
    last_id_ = owner_contact_id_;

    return owner_;
}

#if OT_QT
QModelIndex ContactList::index(int row, int column, const QModelIndex& parent)
    const
{
    if (columnCount() < column) { return {}; }

    if (0 == row) {

        return createIndex(row, column, owner_.get());
    } else {
        Lock lock(lock_);
        int i{start_row()};
        ContactListItem* item{nullptr};

        for (const auto& [sortKey, map] : items_) {
            for (const auto& [index, pRow] : map) {
                if (i == row) {
                    item = pRow.get();
                    goto exit;
                } else {
                    ++i;
                }
            }
        }

    exit:
        if (nullptr == item) { return {}; }

        return createIndex(row, column, item);
    }
}
#endif

void ContactList::process_contact(const network::zeromq::Message& message)
{
    wait_for_startup();

    OT_ASSERT(1 == message.Body().size());

    const auto contactID = Identifier::Factory(*message.Body().begin());

    OT_ASSERT(false == contactID->empty())

    const auto name = api_.Contacts().ContactName(contactID);
    add_item(contactID, name, {});
}

#if OT_QT
QHash<int, QByteArray> ContactList::roleNames() const
{
    QHash<int, QByteArray> output;
    output[IDRole] = "id";
    output[NameRole] = "name";
    output[ImageRole] = "image";
    output[SectionRole] = "section";

    return output;
}
#endif

void ContactList::startup()
{
    const auto contacts = api_.Contacts().ContactList();
    LogVerbose(OT_METHOD)(__FUNCTION__)(": Loading ")(contacts.size())(
        " contacts.")
        .Flush();

    for (const auto& [id, alias] : contacts) {
        add_item(Identifier::Factory(id), alias, {});
    }

    startup_complete_->On();
}

ContactList::~ContactList()
{
    for (auto& it : listeners_) { delete it.second; }
}
}  // namespace opentxs::ui::implementation
