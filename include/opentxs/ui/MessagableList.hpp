// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_UI_MESSAGABLELIST_HPP
#define OPENTXS_UI_MESSAGABLELIST_HPP

#include "opentxs/Forward.hpp"

#include "opentxs/ui/List.hpp"

#ifdef SWIG
// clang-format off
%rename(UIMessagableList) opentxs::ui::MessagableList;
// clang-format on
#endif  // SWIG

namespace opentxs
{
namespace ui
{
class MessagableList : virtual public List
{
#if OT_QT
    Q_OBJECT
#endif

public:
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::ContactListItem> First()
        const = 0;
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::ContactListItem> Next()
        const = 0;

    EXPORT virtual ~MessagableList() = default;

protected:
    MessagableList() = default;

private:
    MessagableList(const MessagableList&) = delete;
    MessagableList(MessagableList&&) = delete;
    MessagableList& operator=(const MessagableList&) = delete;
    MessagableList& operator=(MessagableList&&) = delete;
};
}  // namespace ui
}  // namespace opentxs
#endif
