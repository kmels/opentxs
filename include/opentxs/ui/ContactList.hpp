// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_UI_CONTACTLIST_HPP
#define OPENTXS_UI_CONTACTLIST_HPP

#include "opentxs/Forward.hpp"

#include "opentxs/ui/List.hpp"

#ifdef SWIG
// clang-format off
%rename(UIContactList) opentxs::ui::ContactList;
// clang-format on
#endif  // SWIG

namespace opentxs
{
namespace ui
{
class ContactList : virtual public List
{
#if OT_QT
    Q_OBJECT

public:
    enum ContactListRoles {
        IDRole = Qt::UserRole + 1,
        NameRole = Qt::UserRole + 2,
        ImageRole = Qt::UserRole + 3,
        SectionRole = Qt::UserRole + 4,
    };
#endif

public:
    EXPORT virtual std::string AddContact(
        const std::string& label,
        const std::string& paymentCode = "",
        const std::string& nymID = "") const = 0;
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::ContactListItem> First()
        const = 0;
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::ContactListItem> Next()
        const = 0;

    EXPORT virtual ~ContactList() = default;

protected:
    ContactList() = default;

private:
    ContactList(const ContactList&) = delete;
    ContactList(ContactList&&) = delete;
    ContactList& operator=(const ContactList&) = delete;
    ContactList& operator=(ContactList&&) = delete;
};
}  // namespace ui
}  // namespace opentxs
#endif
