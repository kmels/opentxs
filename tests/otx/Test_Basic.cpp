// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "opentxs/opentxs.hpp"

#include <gtest/gtest.h>
#include <opentxs/api/Factory.hpp>
#include <opentxs/Types.hpp>
#include <opentxs/api/Factory.hpp>
#include <opentxs/api/Factory.hpp>
#include <opentxs/api/Factory.hpp>
#include <opentxs/api/Factory.hpp>

using namespace opentxs;

namespace
{
bool init_{false};

class Test_Basic : public ::testing::Test
{
public:
    static const std::string alice_name_;
    static const std::string bob_name_;
    static const opentxs::ArgList args_;
    static const std::string SeedA_;
    static const std::string SeedB_;
    static const std::string Alice_;
    static const std::string Bob_;
    static const OTIdentifier alice_nym_id_;
    static const OTIdentifier bob_nym_id_;
    static const std::shared_ptr<const ServerContract> server_contract_;

    const opentxs::api::client::Manager& alice_wallet_;
    const opentxs::api::client::Manager& bob_wallet_;
    const opentxs::api::server::Manager& server_;
    const Identifier& server_id_;

    Test_Basic()
        : alice_wallet_(OT::App().StartClient(args_, 2))
        , bob_wallet_(OT::App().StartClient(args_, 3))
        , server_(OT::App().StartServer(args_, 1, true))
        , server_id_(server_.ID())
    {
        if (false == init_) { init(); }
    }

    void import_server_contract(
        const ServerContract& contract,
        const opentxs::api::client::Manager& client)
    {
        auto clientVersion =
            client.Wallet().Server(server_contract_->PublicContract());

        OT_ASSERT(clientVersion)

        client.Sync().SetIntroductionServer(*clientVersion);
    }

    void init()
    {
        const_cast<std::string&>(SeedA_) = alice_wallet_.Exec().Wallet_ImportSeed(
            "spike nominee miss inquiry fee nothing belt list other "
            "daughter leave valley twelve gossip paper",
            "");
        const_cast<std::string&>(SeedB_) = bob_wallet_.Exec().Wallet_ImportSeed(
            "trim thunder unveil reduce crop cradle zone inquiry "
            "anchor skate property fringe obey butter text tank drama "
            "palm guilt pudding laundry stay axis prosper",
            "");
        const_cast<std::string&>(Alice_) = alice_wallet_.Exec().CreateNymHD(
            proto::CITEMTYPE_INDIVIDUAL, alice_name_, SeedA_, 0);
        const_cast<std::string&>(Bob_) = bob_wallet_.Exec().CreateNymHD(
            proto::CITEMTYPE_INDIVIDUAL, bob_name_, SeedB_, 0);
        const_cast<OTIdentifier&>(alice_nym_id_) = Identifier::Factory(Alice_);
        const_cast<OTIdentifier&>(bob_nym_id_) = Identifier::Factory(Bob_);
        const_cast<std::shared_ptr<const ServerContract>&>(server_contract_) =
            server_.Wallet().Server(server_id_);

        OT_ASSERT(server_contract_);
        OT_ASSERT(false == server_id_.empty());

        import_server_contract(*server_contract_, alice_wallet_);
        import_server_contract(*server_contract_, bob_wallet_);
        
        init_ = true;
    }

    void widget_updated_alice(const opentxs::network::zeromq::Message& incoming)
    {
    }
};

const std::string Test_Basic::alice_name_{"Alice"};
const std::string Test_Basic::bob_name_{"Bob"};
const opentxs::ArgList Test_Basic::args_{
    {{OPENTXS_ARG_STORAGE_PLUGIN, {"mem"}}}};
const std::string Test_Basic::SeedA_{""};
const std::string Test_Basic::SeedB_{""};
const std::string Test_Basic::Alice_{""};
const std::string Test_Basic::Bob_{""};
const OTIdentifier Test_Basic::alice_nym_id_{Identifier::Factory()};
const OTIdentifier Test_Basic::bob_nym_id_{Identifier::Factory()};
const std::shared_ptr<const ServerContract> Test_Basic::server_contract_{
    nullptr};

TEST_F(Test_Basic, add_payment_codes)
{    
    // 1. A test that simulates Alice and Bob both setting up stash wallet creation for the first time up to the point at which the main screen is displayed.
    
    alice_wallet_.Sync().Refresh();
    bob_wallet_.Sync().Refresh();

    auto alice = alice_wallet_.Wallet().mutable_Nym(alice_nym_id_);
    auto bob = bob_wallet_.Wallet().mutable_Nym(bob_nym_id_);

    EXPECT_EQ(proto::CITEMTYPE_INDIVIDUAL, alice.Type());
    EXPECT_EQ(proto::CITEMTYPE_INDIVIDUAL, bob.Type());

    auto aliceScopeSet = alice.SetScope(proto::CITEMTYPE_INDIVIDUAL, alice_name_, true);
    auto bobScopeSet = bob.SetScope(proto::CITEMTYPE_INDIVIDUAL, bob_name_, true);

    EXPECT_TRUE(aliceScopeSet);
    EXPECT_TRUE(bobScopeSet);

    alice_wallet_.Sync().Refresh();
    bob_wallet_.Sync().Refresh();
    
    const auto servers = alice_wallet_.Wallet().ServerList();

    const auto& itr = servers.begin();
    ASSERT_STREQ(itr->first.c_str(), server_id_.str().c_str());
    ASSERT_STREQ("localhost", itr->second.c_str());
    ASSERT_EQ(1, servers.size());
    
    alice_wallet_.Sync().Refresh();
    bob_wallet_.Sync().Refresh();
    
    auto task = alice_wallet_.Sync().RegisterNym(alice_nym_id_, server_id_, false, true);
    ASSERT_NE("", task->str());
    
    //alice_wallet_.Sync().Refresh();
    
    //while (false == alice_wallet_.Exec().IsNym_RegisteredAtServer(alice_nym_id_->str(), server_id_.str())) {
    //    opentxs::Log::Sleep(std::chrono::milliseconds(50));
    //}
    
    //ASSERT_TRUE(alice_wallet_.Exec().IsNym_RegisteredAtServer(alice_nym_id_->str(), server_id_.str()));
    //ASSERT_TRUE(bob_wallet_.Exec().IsNym_RegisteredAtServer(bob_nym_id_->str(), server_id_.str()));
    
    // Get UI Profile
    ASSERT_EQ(1, alice_wallet_.Exec().GetNymCount());
    auto nym_ = alice_wallet_.Exec().GetNym_ID(0);
    auto& alice_ui_profile_ = alice_wallet_.UI().Profile(Identifier::Factory(nym_));
    
    EXPECT_STREQ("",alice_ui_profile_.PaymentCode().c_str()); 
    EXPECT_STREQ(alice_name_.c_str(), alice_ui_profile_.DisplayName().c_str());
    
    const auto& profile_section_ = alice_ui_profile_.First();
    ASSERT_FALSE(profile_section_->Valid());
    ASSERT_STREQ("", profile_section_->Name("en").c_str());
    
    auto has_next_ = !profile_section_->Last();
    ASSERT_FALSE(has_next_);
    
    // todo
    auto widgetCallback = opentxs::network::zeromq::ListenCallback::Factory(
          [=](const opentxs::network::zeromq::Message& incoming)
              -> void { this->widget_updated_alice(incoming);});
    auto widgetSocket = alice_wallet_.ZeroMQ().SubscribeSocket(widgetCallback);

    const auto started = widgetSocket->Start(alice_wallet_.Endpoints().WidgetUpdate());

    EXPECT_TRUE(started);
}

}  // namespace
