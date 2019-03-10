// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include "Internal.hpp"

#include "opentxs/ui/ProfileSubsection.hpp"
#include "opentxs/ui/Widget.hpp"

#include "internal/ui/UI.hpp"

namespace opentxs::ui::implementation
{
class ProfileSubsectionBlank final : public ProfileSectionRowInternal
{
public:
#if OT_QT
    int columnCount(const QModelIndex& parent = QModelIndex()) const override
    {
        return 0;
    }
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole)
        const override
    {
        return {};
    }
    QModelIndex index(
        int row,
        int column,
        const QModelIndex& parent = QModelIndex()) const override
    {
        return {};
    }
    QModelIndex parent(const QModelIndex& index) const override { return {}; }
    int rowCount(const QModelIndex& parent = QModelIndex()) const override
    {
        return 0;
    }
#endif
    bool AddItem(const std::string&, const bool, const bool) const override
    {
        return false;
    }
    bool Delete(const std::string&) const override { return false; }
    OTUIProfileItem First() const override
    {
        const std::shared_ptr<const ui::ProfileItem> empty;

        return OTUIProfileItem{empty};
    }
    bool Last() const override { return true; }
    std::string Name(const std::string&) const override { return {}; }
    OTUIProfileItem Next() const override
    {
        const std::shared_ptr<const ui::ProfileItem> empty;

        return OTUIProfileItem{empty};
    }
    proto::ContactItemType Type() const override { return {}; }
    bool SetActive(const std::string&, const bool) const override
    {
        return false;
    }
    bool SetPrimary(const std::string&, const bool) const override
    {
        return false;
    }
    bool SetValue(const std::string&, const std::string&) const override
    {
        return false;
    }
    bool Valid() const override { return false; }
    OTIdentifier WidgetID() const override { return Identifier::Factory(); }

    void reindex(const ProfileSortKey&, const CustomData&) override {}
    bool last(const ProfileSubsectionRowID&) const override { return false; }
    const Identifier& NymID() const override { return nym_id_; }
    proto::ContactSectionName Section() const override { return {}; }

    ProfileSubsectionBlank() = default;
    ~ProfileSubsectionBlank() = default;

private:
    const OTIdentifier nym_id_{Identifier::Factory()};

    ProfileSubsectionBlank(const ProfileSubsectionBlank&) = delete;
    ProfileSubsectionBlank(ProfileSubsectionBlank&&) = delete;
    ProfileSubsectionBlank& operator=(const ProfileSubsectionBlank&) = delete;
    ProfileSubsectionBlank& operator=(ProfileSubsectionBlank&&) = delete;
};
}  // namespace opentxs::ui::implementation
