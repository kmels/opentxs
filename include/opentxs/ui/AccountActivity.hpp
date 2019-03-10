// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_UI_ACCOUNTACTIVITY_HPP
#define OPENTXS_UI_ACCOUNTACTIVITY_HPP

#include "opentxs/Forward.hpp"

#include "opentxs/ui/List.hpp"

#ifdef SWIG
// clang-format off
%rename(UIAccountActivity) opentxs::ui::AccountActivity;
// clang-format on
#endif  // SWIG

namespace opentxs
{
namespace ui
{
class AccountActivity : virtual public List
{
#if OT_QT
    Q_OBJECT
#endif

public:
    EXPORT virtual Amount Balance() const = 0;
    EXPORT virtual std::string DisplayBalance() const = 0;
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::BalanceItem> First()
        const = 0;
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::BalanceItem> Next()
        const = 0;

    EXPORT virtual ~AccountActivity() = default;

protected:
    AccountActivity() = default;

private:
    AccountActivity(const AccountActivity&) = delete;
    AccountActivity(AccountActivity&&) = delete;
    AccountActivity& operator=(const AccountActivity&) = delete;
    AccountActivity& operator=(AccountActivity&&) = delete;
};
}  // namespace ui
}  // namespace opentxs
#endif
