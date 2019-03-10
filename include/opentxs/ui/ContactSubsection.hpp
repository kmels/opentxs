// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_UI_CONTACTSUBSECTION_HPP
#define OPENTXS_UI_CONTACTSUBSECTION_HPP

#include "opentxs/Forward.hpp"

#include "opentxs/ui/List.hpp"
#include "opentxs/ui/ListRow.hpp"
#include "opentxs/Proto.hpp"

#include <string>

#ifdef SWIG
// clang-format off
%extend opentxs::ui::ContactSubsection {
    int Type() const
    {
        return static_cast<int>($self->Type());
    }
}
%ignore opentxs::ui::ContactSubsection::Type;
%ignore opentxs::ui::ContactSubsection::Update;
%template(OTUIContactSubsection) opentxs::SharedPimpl<opentxs::ui::ContactSubsection>;
%rename(UIContactSubsection) opentxs::ui::ContactSubsection;
// clang-format on
#endif  // SWIG

namespace opentxs
{
namespace ui
{
class ContactSubsection : virtual public List, virtual public ListRow
{
#if OT_QT
    Q_OBJECT
#endif

public:
    EXPORT virtual std::string Name(const std::string& lang) const = 0;
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::ContactItem> First()
        const = 0;
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::ContactItem> Next()
        const = 0;
    EXPORT virtual proto::ContactItemType Type() const = 0;

    EXPORT virtual ~ContactSubsection() = default;

protected:
    ContactSubsection() = default;

private:
    ContactSubsection(const ContactSubsection&) = delete;
    ContactSubsection(ContactSubsection&&) = delete;
    ContactSubsection& operator=(const ContactSubsection&) = delete;
    ContactSubsection& operator=(ContactSubsection&&) = delete;
};
}  // namespace ui
}  // namespace opentxs
#endif
