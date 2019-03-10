// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_UI_PROFILE_HPP
#define OPENTXS_UI_PROFILE_HPP

#include "opentxs/Forward.hpp"

#include "opentxs/ui/List.hpp"
#include "opentxs/Proto.hpp"

#include <string>
#include <tuple>
#include <vector>

#ifdef SWIG
#include <algorithm>
#include <tuple>
#include <vector>

// clang-format off
%extend opentxs::ui::Profile {
    bool AddClaim(
        const int section,
        const int type,
        const std::string& value,
        const bool primary,
        const bool active) const
    {
        return $self->AddClaim(
            static_cast<opentxs::proto::ContactSectionName>(section),
            static_cast<opentxs::proto::ContactItemType>(type),
            value,
            primary,
            active);
    }
    std::vector<std::pair<int, std::string>> AllowedItems(
        const int section,
        const std::string& lang)
    {
        const auto types = opentxs::ui::ProfileSection::AllowedItems(
            static_cast<opentxs::proto::ContactSectionName>(section),
            lang);
        std::vector<std::pair<int, std::string>> output;
        std::transform(
            types.begin(),
            types.end(),
            std::inserter(output, output.end()),
            [](std::pair<opentxs::proto::ContactItemType, std::string> type) ->
                std::pair<int, std::string> {
                    return {static_cast<int>(type.first), type.second};} );

        return output;
    }
    std::vector<std::pair<int, std::string>> AllowedSections(
        const std::string& lang)
    {
        const auto sections = $self->AllowedSections(lang);
        std::vector<std::pair<int, std::string>> output;
        std::transform(
            sections.begin(),
            sections.end(),
            std::inserter(output, output.end()),
            [](std::pair<opentxs::proto::ContactSectionName, std::string> type) ->
                std::pair<int, std::string> {
                    return {static_cast<int>(type.first), type.second};} );

        return output;
    }
}
%ignore opentxs::ui::Profile::AddClaim;
%ignore opentxs::ui::Profile::AllowedItems;
%ignore opentxs::ui::Profile::AllowedSections;
%rename(UIProfile) opentxs::ui::Profile;
// clang-format on
#endif  // SWIG

namespace opentxs
{
namespace ui
{
class Profile : virtual public List
{
#if OT_QT
    Q_OBJECT
#endif

public:
    using ItemType = std::pair<proto::ContactItemType, std::string>;
    using ItemTypeList = std::vector<ItemType>;
    using SectionType = std::pair<proto::ContactSectionName, std::string>;
    using SectionTypeList = std::vector<SectionType>;

    EXPORT virtual bool AddClaim(
        const proto::ContactSectionName section,
        const proto::ContactItemType type,
        const std::string& value,
        const bool primary,
        const bool active) const = 0;
    EXPORT virtual ItemTypeList AllowedItems(
        const proto::ContactSectionName section,
        const std::string& lang) const = 0;
    EXPORT virtual SectionTypeList AllowedSections(
        const std::string& lang) const = 0;
    EXPORT virtual bool Delete(
        const int section,
        const int type,
        const std::string& claimID) const = 0;
    EXPORT virtual std::string DisplayName() const = 0;
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::ProfileSection> First()
        const = 0;
    EXPORT virtual std::string ID() const = 0;
    EXPORT virtual opentxs::SharedPimpl<opentxs::ui::ProfileSection> Next()
        const = 0;
    EXPORT virtual std::string PaymentCode() const = 0;
    EXPORT virtual bool SetActive(
        const int section,
        const int type,
        const std::string& claimID,
        const bool active) const = 0;
    EXPORT virtual bool SetPrimary(
        const int section,
        const int type,
        const std::string& claimID,
        const bool primary) const = 0;
    EXPORT virtual bool SetValue(
        const int section,
        const int type,
        const std::string& claimID,
        const std::string& value) const = 0;

    EXPORT virtual ~Profile() = default;

protected:
    Profile() = default;

private:
    Profile(const Profile&) = delete;
    Profile(Profile&&) = delete;
    Profile& operator=(const Profile&) = delete;
    Profile& operator=(Profile&&) = delete;
};
}  // namespace ui
}  // namespace opentxs
#endif
