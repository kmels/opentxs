// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_UI_ISSUERITEM_HPP
#define OPENTXS_UI_ISSUERITEM_HPP

#include "opentxs/Forward.hpp"

#include <string>

#include "opentxs/ui/List.hpp"
#include "opentxs/ui/ListRow.hpp"

#ifdef SWIG
// clang-format off
%template(OTUIIssuerItem) opentxs::SharedPimpl<opentxs::ui::IssuerItem>;
%rename(UIIssuerItem) opentxs::ui::IssuerItem;
// clang-format on
#endif  // SWIG

namespace opentxs
{
namespace ui
{
class IssuerItem : virtual public List, virtual public ListRow
{
#if OT_QT
    Q_OBJECT
#endif

public:
    EXPORT virtual bool ConnectionState() const = 0;
    EXPORT virtual std::string Debug() const = 0;
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::AccountSummaryItem> First()
        const = 0;
    EXPORT virtual std::string Name() const = 0;
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::AccountSummaryItem> Next()
        const = 0;
    EXPORT virtual bool Trusted() const = 0;

    EXPORT virtual ~IssuerItem() = default;

protected:
    IssuerItem() = default;

private:
    IssuerItem(const IssuerItem&) = delete;
    IssuerItem(IssuerItem&&) = delete;
    IssuerItem& operator=(const IssuerItem&) = delete;
    IssuerItem& operator=(IssuerItem&&) = delete;
};
}  // namespace ui
}  // namespace opentxs
#endif
