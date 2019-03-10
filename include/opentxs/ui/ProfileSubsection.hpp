// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_UI_PROFILESUBSECTION_HPP
#define OPENTXS_UI_PROFILESUBSECTION_HPP

#include "opentxs/Forward.hpp"

#include "opentxs/ui/List.hpp"
#include "opentxs/ui/ListRow.hpp"
#include "opentxs/Proto.hpp"

#include <string>

#ifdef SWIG
// clang-format off
%extend opentxs::ui::ProfileSubsection {
    int Type() const
    {
        return static_cast<int>($self->Type());
    }
}
%ignore opentxs::ui::ProfileSubsection::Type;
%ignore opentxs::ui::ProfileSubsection::Update;
%template(OTUIProfileSubsection) opentxs::SharedPimpl<opentxs::ui::ProfileSubsection>;
%rename(UIProfileSubsection) opentxs::ui::ProfileSubsection;
// clang-format on
#endif  // SWIG

namespace opentxs
{
namespace ui
{
class ProfileSubsection : virtual public List, virtual public ListRow
{
#if OT_QT
    Q_OBJECT
#endif

public:
    EXPORT virtual bool AddItem(
        const std::string& value,
        const bool primary,
        const bool active) const = 0;
    EXPORT virtual bool Delete(const std::string& claimID) const = 0;
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::ProfileItem> First()
        const = 0;
    EXPORT virtual std::string Name(const std::string& lang) const = 0;
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::ProfileItem> Next()
        const = 0;
    EXPORT virtual bool SetActive(const std::string& claimID, const bool active)
        const = 0;
    EXPORT virtual bool SetPrimary(
        const std::string& claimID,
        const bool primary) const = 0;
    EXPORT virtual bool SetValue(
        const std::string& claimID,
        const std::string& value) const = 0;
    EXPORT virtual proto::ContactItemType Type() const = 0;

    EXPORT virtual ~ProfileSubsection() = default;

protected:
    ProfileSubsection() = default;

private:
    ProfileSubsection(const ProfileSubsection&) = delete;
    ProfileSubsection(ProfileSubsection&&) = delete;
    ProfileSubsection& operator=(const ProfileSubsection&) = delete;
    ProfileSubsection& operator=(ProfileSubsection&&) = delete;
};
}  // namespace ui
}  // namespace opentxs
#endif
