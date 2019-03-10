// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_UI_ACTIVITYTHREAD_HPP
#define OPENTXS_UI_ACTIVITYTHREAD_HPP

#include "opentxs/Forward.hpp"

#include "opentxs/ui/List.hpp"
#include "opentxs/Proto.hpp"

#include <string>

#ifdef SWIG
// clang-format off
%extend opentxs::ui::ActivityThread {
    std::string PaymentCode(const int currency) const
    {
        return $self->PaymentCode(
            static_cast<opentxs::proto::ContactItemType>(currency));
    }
}
%ignore opentxs::ui::ActivityThread::PaymentCode;
%rename(UIActivityThread) opentxs::ui::ActivityThread;
// clang-format on
#endif  // SWIG

namespace opentxs
{
namespace ui
{
class ActivityThread : virtual public List
{
#if OT_QT
    Q_OBJECT
#endif

public:
    EXPORT virtual std::string DisplayName() const = 0;
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::ActivityThreadItem> First()
        const = 0;
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::ActivityThreadItem> Next()
        const = 0;
    EXPORT virtual std::string GetDraft() const = 0;
    EXPORT virtual std::string Participants() const = 0;
    EXPORT virtual bool Pay(
        const Amount amount,
        const Identifier& sourceAccount,
        const std::string& memo = "",
        const PaymentType type = PaymentType::Cheque) const = 0;
    EXPORT virtual std::string PaymentCode(
        const proto::ContactItemType currency) const = 0;
    EXPORT virtual bool SendDraft() const = 0;
    EXPORT virtual bool SetDraft(const std::string& draft) const = 0;
    EXPORT virtual std::string ThreadID() const = 0;

    EXPORT virtual ~ActivityThread() = default;

protected:
    ActivityThread() = default;

private:
    ActivityThread(const ActivityThread&) = delete;
    ActivityThread(ActivityThread&&) = delete;
    ActivityThread& operator=(const ActivityThread&) = delete;
    ActivityThread& operator=(ActivityThread&&) = delete;
};
}  // namespace ui
}  // namespace opentxs
#endif
