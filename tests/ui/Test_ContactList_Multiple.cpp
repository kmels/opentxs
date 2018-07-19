/************************************************************
 *
 *                 OPEN TRANSACTIONS
 *
 *       Financial Cryptography and Digital Cash
 *       Library, Protocol, API, Server, CLI, GUI
 *
 *       -- Anonymous Numbered Accounts.
 *       -- Untraceable Digital Cash.
 *       -- Triple-Signed Receipts.
 *       -- Cheques, Vouchers, Transfers, Inboxes.
 *       -- Basket Currencies, Markets, Payment Plans.
 *       -- Signed, XML, Ricardian-style Contracts.
 *       -- Scripted smart contracts.
 *
 *  EMAIL:
 *  fellowtraveler@opentransactions.org
 *
 *  WEBSITE:
 *  http://www.opentransactions.org/
 *
 *  -----------------------------------------------------
 *
 *   LICENSE:
 *   This Source Code Form is subject to the terms of the
 *   Mozilla Public License, v. 2.0. If a copy of the MPL
 *   was not distributed with this file, You can obtain one
 *   at http://mozilla.org/MPL/2.0/.
 *
 *   DISCLAIMER:
 *   This program is distributed in the hope that it will
 *   be useful, but WITHOUT ANY WARRANTY; without even the
 *   implied warranty of MERCHANTABILITY or FITNESS FOR A
 *   PARTICULAR PURPOSE.  See the Mozilla Public License
 *   for more details.
 *
 ************************************************************/

#include "opentxs/opentxs.hpp"

#include <gtest/gtest.h>

#define ALICE_NYM_ID "ot2CyrTzwREHzboZ2RyCT8QsTj3Scaa55JRG"
#define ALICE_NYM_NAME "Alice"
#define DEFAULT_ME_NAME "Owner"
#define BOB_PAYMENT_CODE                                                       \
    "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxt" \
    "eQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97"
#define BOB_NYM_NAME "Bob"

#define CHARLY_PAYMENT_CODE                                                    \
    "PM8TJWedQTvxaoJpt9Wh25HR54oj5vmor6arAByFk4UTgUh1Tna2srsZLUo2xS3ViBot1ftf" \
    "4p8ZUN8khB2zvViHXZkrwkfjcePSeEgsYapESKywge9F"
#define CHARLY_NYM_NAME "Charly"

#define DAVE_PAYMENT_CODE                                                    \
    "PM8TJWedQTvxaoJpt9Wh25HR54oj5vmor6arAByFk4UTgUh1Tna2srsZLUo2xS3ViBot1ftf" \
    "4p8ZUN8khB2zvViHXZkrwkfjcePSeEgsYapESKywge9F"
#define DAVE_NYM_NAME "Dave"

using namespace opentxs;

namespace
{
class Test_ContactList : public ::testing::Test
{
public:
    using WidgetUpdateCounter = std::map<std::string, int>;

    const std::string fingerprint_{OT::App().API().Exec().Wallet_ImportSeed(
        "response seminar brave tip suit recall often sound stick owner "
        "lottery motion",
        "")};
    const OTIdentifier nym_id_{
        Identifier::Factory(OT::App().API().Exec().CreateNymHD(
            proto::CITEMTYPE_INDIVIDUAL,
            ALICE_NYM_NAME,
            fingerprint_,
            0))};
    std::string contact_widget_id_{""};
    WidgetUpdateCounter counter_;
    std::mutex counter_lock_;
    OTZMQListenCallback callback_{network::zeromq::ListenCallback::Factory(
        [=](const network::zeromq::Message& message) -> void {
            ASSERT_EQ(1, message.size());
            IncrementCounter(message.at(0));
        })};
    OTZMQSubscribeSocket subscriber_{setup_listener(callback_)};
    const ui::ContactList& contact_list_{OT::App().UI().ContactList(nym_id_)};
    std::thread loop_{&Test_ContactList::loop, this};
    std::atomic<bool> shutdown_{false};
    const OTPaymentCode bob_payment_code_{
        PaymentCode::Factory(BOB_PAYMENT_CODE)};
    const OTPaymentCode charly_payment_code_{
        PaymentCode::Factory(CHARLY_PAYMENT_CODE)};
    const OTPaymentCode dave_payment_code_{
        PaymentCode::Factory(DAVE_PAYMENT_CODE)};
    OTIdentifier bob_contact_id_{Identifier::Factory()};
    OTIdentifier charly_contact_id_{Identifier::Factory()};

    static OTZMQSubscribeSocket setup_listener(
        const network::zeromq::ListenCallback& callback)
    {
        auto output = OT::App().ZMQ().Context().SubscribeSocket(callback);
        output->Start(network::zeromq::Socket::WidgetUpdateEndpoint);

        return output;
    }

    void IncrementCounter(const std::string& widgetID)
    {
        Lock lock(counter_lock_);
        otErr << "Widget " << widgetID << " update counter set to "
              << ++counter_[widgetID] << std::endl;
    }

    int GetCounter(const std::string& widgetID)
    {
        Lock lock(counter_lock_);

        return counter_[widgetID];
    }

    int ListLength(const ui::ContactList& clist) {
        auto item = clist.First();
        int loops = 1;
      
        while (!item->Last())
        {
            item = clist.Next();
            loops++;
        }
        return loops;
    }

    void loop()
    {
        while (contact_widget_id_.empty()) {
            contact_widget_id_ = contact_list_.WidgetID()->str();
        }

        while (false == shutdown_.load()) {
            switch (GetCounter(contact_widget_id_)) {
                case 0:
                case 1: {
                    std::cout << "begin case 1\n";
                    const auto first = contact_list_.First();

                    //ASSERT_EQ(1, ListLength(contact_list_));
                    ASSERT_EQ(true, first.get().Valid());
                    ASSERT_EQ(true, first.get().Last());
                    ASSERT_EQ(
                        true,
                        (DEFAULT_ME_NAME == first.get().DisplayName()) ||
                            (ALICE_NYM_NAME == first.get().DisplayName()));

                    if (ALICE_NYM_NAME == first.get().DisplayName()) {
                        IncrementCounter(contact_widget_id_);
                    }

                    std::cout << "end case 1\n";
                } break;
                case 2: {
                    // contacts may be added during this
                    std::cout << "begin case 2\n";
                    const auto first = contact_list_.First();

                    ASSERT_EQ(true, first.get().Valid());
                    
                    ASSERT_EQ(first.get().DisplayName(), ALICE_NYM_NAME);
                    std::cout << "end case 2\n";
                } break;
                case 3: {
                    // a suscriber just bumped the counter because a contact was added
                    std::cout << "begin case 3\n";
                    const auto first = contact_list_.First();

                    const ui::ContactList& list_copy_{contact_list_};

                    const auto alice = contact_list_.First();
                    ASSERT_EQ(alice.get().DisplayName(), "Alice");
                    ASSERT_FALSE(alice.get().Last());
                    ASSERT_TRUE(alice.get().Valid());

                    const auto charly_ = contact_list_.Next();
                    ASSERT_EQ("Charly", charly_.get().DisplayName());
                    ASSERT_TRUE(charly_.get().Last());
                    ASSERT_TRUE(charly_.get().Valid());                    

                    // should not be callable (returns first)
                    const auto extra_ = contact_list_.Next();
                    ASSERT_EQ("Alice", extra_.get().DisplayName());
                    ASSERT_FALSE(extra_.get().Last()); //shoul be true
                    ASSERT_TRUE(extra_.get().Valid());

                    // shoul not be calable
                    const auto extra_2 = contact_list_.Next();
                    ASSERT_EQ("Charly", extra_2.get().DisplayName());
                    ASSERT_TRUE(extra_2.get().Last());
                    ASSERT_TRUE(extra_2.get().Valid());
                    
                    // ASSERT_EQ(contact_list_.Next().get().DisplayName(), "Alice");

                    const ui::ContactList& contact_list__{OT::App().UI().ContactList(nym_id_)};

                    ASSERT_STREQ(contact_list_.WidgetID()->str().c_str(),
                                 contact_list__.WidgetID()->str().c_str());
                    ASSERT_EQ(2, ListLength(contact_list_));
                    ASSERT_EQ(2, ListLength(contact_list__));
                    
                    ASSERT_EQ(true, first.get().Valid());
                    ASSERT_EQ(false, first.get().Last());

                    const auto charly = contact_list_.Next();

                    ASSERT_EQ(true, charly.get().Valid());
                    ASSERT_EQ(false, charly.get().Last());
                    ASSERT_EQ(first.get().DisplayName(), ALICE_NYM_NAME);
                    ASSERT_EQ(charly.get().DisplayName(), ALICE_NYM_NAME);

                    const auto bob = contact_list_.Next();

                    ASSERT_EQ(true, bob.get().Valid());
                    ASSERT_EQ(true, bob.get().Last());
                    EXPECT_EQ(bob.get().DisplayName(), CHARLY_NYM_NAME);
                    
                    otErr << "Test complete" << std::endl;
                    IncrementCounter(contact_widget_id_); // bump the counter to 4
                    std::cout << "end case 3\n";
                } break;
                case 4: {
                    // contacts may be added during this
                    std::cout << "begin case 4\n";
                    const auto first = contact_list_.First();

                    ASSERT_EQ(true, first.get().Valid());
                    
                    ASSERT_EQ(first.get().DisplayName(), ALICE_NYM_NAME);
                    std::cout << "end case 4\n";
                } break;
                case 5: {
                    std::cout << "begin case 5\n";
                    const auto first = contact_list_.First();

                    //const ui::ContactList& contact_list_{OT::App().UI().ContactList(nym_id_)};

                    const auto alice = contact_list_.First();
                    ASSERT_EQ(alice.get().DisplayName(), "Alice");
                    ASSERT_FALSE(alice.get().Last());
                    ASSERT_TRUE(alice.get().Valid());

                    const auto bob_ = contact_list_.Next();
                    ASSERT_EQ("Bob", bob_.get().DisplayName());
                    ASSERT_FALSE(bob_.get().Last());
                    ASSERT_TRUE(bob_.get().Valid());                    

                    const auto charly_ = contact_list_.Next();
                    ASSERT_EQ("Charly", charly_.get().DisplayName());
                    ASSERT_TRUE(charly_.get().Last());
                    ASSERT_TRUE(charly_.get().Valid());
                    
                    ASSERT_EQ(contact_list_.First().get().DisplayName(), "Alice");
                    ASSERT_EQ(contact_list_.Next().get().DisplayName(), "Bob");
                    ASSERT_EQ(contact_list_.Next().get().DisplayName(), "Charly");
                    ASSERT_EQ(contact_list_.Next().get().DisplayName(), "Alice");
                    ASSERT_EQ(3, ListLength(contact_list_));
                    
                    ASSERT_EQ(true, first.get().Valid());
                    
                    const auto bob = contact_list_.Next();

                    ASSERT_EQ(true, bob.get().Valid());
                    ASSERT_EQ(false, bob.get().Last());
                    EXPECT_EQ("Alice", bob.get().DisplayName());

                    const auto charly = contact_list_.Next();

                    ASSERT_EQ(true, charly.get().Valid());
                    ASSERT_EQ(false, charly.get().Last());
                    EXPECT_EQ(charly.get().DisplayName(), "Bob");

                    // shoul not be calable
                    const auto next_1 = contact_list_.Next();
                    
                    ASSERT_EQ("Charly", next_1.get().DisplayName());
                    ASSERT_TRUE(next_1.get().Last());
                    ASSERT_TRUE(next_1.get().Valid());
                    
                    otErr << "Test complete" << std::endl;
                    IncrementCounter(contact_widget_id_);
                    std::cout << "end case 5\n";
                } break;
                default: {
                    shutdown_.store(true);
                }
            }
        }
    }

    ~Test_ContactList() { loop_.join(); }
};

TEST_F(Test_ContactList, Contact_List)
{
    ASSERT_EQ(false, nym_id_->empty());
    ASSERT_EQ(nym_id_->str(), ALICE_NYM_ID);
    
    ASSERT_EQ(true, bob_payment_code_->VerifyInternally());
    ASSERT_EQ(true, charly_payment_code_->VerifyInternally());

    // wait for #2 
    while (GetCounter(contact_widget_id_) < 2) { ; }

    // add contact
    const auto charly = OT::App().Contact().NewContact(
        CHARLY_NYM_NAME, charly_payment_code_->ID(), charly_payment_code_);

    // expect increment to #3
    
    // wait for #3 to bump to 4 in loop
    while (GetCounter(contact_widget_id_) < 4) { ; }

    const auto bob = OT::App().Contact().NewContact(
        BOB_NYM_NAME, bob_payment_code_->ID(), bob_payment_code_);

    //const auto dave = OT::App().Contact().NewContact(
    //    DAVE_NYM_NAME, dave_payment_code_->ID(), dave_payment_code_);
    
    // expect increment to #4
    
    // run step 4
    ASSERT_EQ(true, bool(bob));
    ASSERT_EQ(true, bool(charly));

    bob_contact_id_ = Identifier::Factory(bob->ID());
    charly_contact_id_ = Identifier::Factory(charly->ID());

    ASSERT_EQ(false, bob_contact_id_->empty());
    ASSERT_EQ(false, charly_contact_id_->empty());
}

}  // namespace
