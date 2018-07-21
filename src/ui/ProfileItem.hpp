// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_UI_PROFILE_ITEM_IMPLEMENTATION_HPP
#define OPENTXS_UI_PROFILE_ITEM_IMPLEMENTATION_HPP

#include "Internal.hpp"

template class opentxs::SharedPimpl<opentxs::ui::ProfileItem>;

namespace opentxs::ui::implementation
{
using ProfileItemRow =
    Row<ProfileSubsectionRowInternal,
        ProfileSubsectionInternalInterface,
        ProfileSubsectionRowID>;

class ProfileItem final : public ProfileItemRow
{
public:
    std::string ClaimID() const override
    {
        sLock lock(shared_lock_);

        return row_id_->str();
    }
    bool Delete() const override;
    bool IsActive() const override
    {
        sLock lock(shared_lock_);

        return item_->isActive();
    }
    bool IsPrimary() const override
    {
        sLock lock(shared_lock_);

        return item_->isPrimary();
    }
    bool SetActive(const bool& active) const override;
    bool SetPrimary(const bool& primary) const override;
    bool SetValue(const std::string& value) const override;
    std::string Value() const override
    {
        sLock lock(shared_lock_);

        return item_->Value();
    }

    void reindex(const ProfileSubsectionSortKey& key, const CustomData& custom)
        override;

    ~ProfileItem() = default;

private:
    friend Factory;

    const api::client::Wallet& wallet_;
    std::unique_ptr<opentxs::ContactItem> item_{nullptr};

    bool add_claim(const Claim& claim) const;
    Claim as_claim() const;

    ProfileItem(
        const ProfileSubsectionInternalInterface& parent,
        const network::zeromq::Context& zmq,
        const network::zeromq::PublishSocket& publisher,
        const api::ContactManager& contact,
        const ProfileSubsectionRowID& rowID,
        const ProfileSubsectionSortKey& sortKey,
        const CustomData& custom,
        const api::client::Wallet& wallet);
    ProfileItem() = delete;
    ProfileItem(const ProfileItem&) = delete;
    ProfileItem(ProfileItem&&) = delete;
    ProfileItem& operator=(const ProfileItem&) = delete;
    ProfileItem& operator=(ProfileItem&&) = delete;
};
}  // namespace opentxs::ui::implementation
#endif  // OPENTXS_UI_PROFILE_ITEM_IMPLEMENTATION_HPP
