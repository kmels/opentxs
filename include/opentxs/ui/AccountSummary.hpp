// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_UI_ACCOUNTSUMMARY_HPP
#define OPENTXS_UI_ACCOUNTSUMMARY_HPP

#include "opentxs/Forward.hpp"

#include "opentxs/ui/List.hpp"

#ifdef SWIG
// clang-format off
%rename(UIAccountSummary) opentxs::ui::AccountSummary;
// clang-format on
#endif  // SWIG

namespace opentxs
{
namespace ui
{
class AccountSummary : virtual public List
{
#if OT_QT
    Q_OBJECT
#endif

public:
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::IssuerItem> First()
        const = 0;
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::IssuerItem> Next()
        const = 0;

    EXPORT virtual ~AccountSummary() = default;

protected:
    AccountSummary() = default;

private:
    AccountSummary(const AccountSummary&) = delete;
    AccountSummary(AccountSummary&&) = delete;
    AccountSummary& operator=(const AccountSummary&) = delete;
    AccountSummary& operator=(AccountSummary&&) = delete;
};
}  // namespace ui
}  // namespace opentxs
#endif
