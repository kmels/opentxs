// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_UI_ACTIVITYSUMMARY_HPP
#define OPENTXS_UI_ACTIVITYSUMMARY_HPP

#include "opentxs/Forward.hpp"

#include "opentxs/ui/List.hpp"

#ifdef SWIG
// clang-format off
%rename(UIActivitySummary) opentxs::ui::ActivitySummary;
// clang-format on
#endif  // SWIG

namespace opentxs
{
namespace ui
{
class ActivitySummary : virtual public List
{
#if OT_QT
    Q_OBJECT
#endif

public:
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::ActivitySummaryItem>
    First() const = 0;
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::ActivitySummaryItem> Next()
        const = 0;

    EXPORT virtual ~ActivitySummary() = default;

protected:
    ActivitySummary() = default;

private:
    ActivitySummary(const ActivitySummary&) = delete;
    ActivitySummary(ActivitySummary&&) = delete;
    ActivitySummary& operator=(const ActivitySummary&) = delete;
    ActivitySummary& operator=(ActivitySummary&&) = delete;
};
}  // namespace ui
}  // namespace opentxs
#endif
