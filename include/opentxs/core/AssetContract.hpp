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

#ifndef OPENTXS_CORE_OTASSETCONTRACT_HPP
#define OPENTXS_CORE_OTASSETCONTRACT_HPP

#include "Contract.hpp"

namespace opentxs
{

class Account;
class AccountVisitor;
class Identifier;
class Nym;
class String;
class Tag;

class AssetContract : public Contract
{
public:
    EXPORT AssetContract();
    EXPORT AssetContract(const String& name, const String& foldername,
                         const String& filename, const String& strID);
    EXPORT virtual ~AssetContract();

    EXPORT virtual void CreateContents(); // Only used when first generating an
                                          // asset
    // or server contract. Meant for contracts
    // which never change after that point.
    // Otherwise does the same thing as
    // UpdateContents. (But meant for a different
    // purpose.)

    EXPORT bool IsShares() const
    {
        return m_bIsShares;
    }
    // Some instrument definitions keep a list of "user" accounts (the
    // complete set of
    // that type.)
    // This is called when the user creates a new asset account, in order to add
    // it to that list.
    // (Currently only operational for "shares", not "currencies", since it's
    // used exclusively
    // for the payment of dividends.)

    // adds the account to the list. (When account is created.)
    EXPORT bool AddAccountRecord(const Account& theAccount) const;

    // removes the account from the list. (When account is deleted.)
    EXPORT bool EraseAccountRecord(const Identifier& theAcctID) const;

    EXPORT bool VisitAccountRecords(AccountVisitor& visitor) const;

    EXPORT int32_t GetCurrencyFactor() const;
    EXPORT int32_t GetCurrencyDecimalPower() const;

    EXPORT static std::string formatLongAmount(
        int64_t lValue, int32_t nFactor = 100, int32_t nPower = 2,
        const char* szCurrencySymbol = "",
        const char* szThousandSeparator = ",",
        const char* szDecimalPoint = ".");
    EXPORT static bool ParseFormatted(int64_t& lResult,
                                      const std::string& str_input,
                                      int32_t nFactor = 100, int32_t nPower = 2,
                                      const char* szThousandSeparator = ",",
                                      const char* szDecimalPoint = ".");

    // deprecated
    EXPORT bool FormatAmount(int64_t amount, std::string& str_output) const;
    // deprecated
    EXPORT bool FormatAmountWithoutSymbol(int64_t amount,
                                          std::string& str_output) const;
    // deprecated
    EXPORT bool StringToAmount(int64_t& amount,
                               const std::string& str_input) const;

    EXPORT bool FormatAmountLocale(int64_t amount, std::string& str_output,
                                   const std::string& str_thousand,
                                   const std::string& str_decimal) const;
    EXPORT bool FormatAmountWithoutSymbolLocale(
        int64_t amount, std::string& str_output,
        const std::string& str_thousand, const std::string& str_decimal) const;

    EXPORT bool StringToAmountLocale(int64_t& amount,
                                     const std::string& str_input,
                                     const std::string& str_thousand,
                                     const std::string& str_decimal) const;

    EXPORT const String& GetBasketInfo() const
    {
        return m_strBasketInfo;
    }

    EXPORT const String& GetCurrencyName() const
    {
        return m_strCurrencyName;
    } // "dollars"  (for example)
    EXPORT const String& GetCurrencyFraction() const
    {
        return m_strCurrencyFraction;
    } // "cents"    (for example)
    EXPORT const String& GetCurrencySymbol() const
    {
        return m_strCurrencySymbol;
    } // "$"        (for example)
    EXPORT const String& GetCurrencyTLA() const
    {
        return m_strCurrencyTLA;
    } // "USD""     (for example)

    EXPORT virtual bool SaveContractWallet(Tag& parent) const;
    EXPORT virtual bool DisplayStatistics(String& strContents) const;

protected:
    // return -1 if error, 0 if nothing, and 1 if the node was processed.
    EXPORT virtual int32_t ProcessXMLNode(irr::io::IrrXMLReader*& xml);

protected:
    // baskets
    String m_strBasketInfo;

    // currencies and shares:
    String m_strIssueCompany;
    String m_strIssueEmail;
    String m_strIssueContractURL;
    String m_strIssueType; // A vs B. Voting / non-voting...

    // shares only:
    String m_strIssueDate;

    // currencies and shares:
    String m_strCurrencyName;   //  "dollars", not cents. The name used in
                                // normal conversation.
    String m_strCurrencyType;   //  "decimal" (Versus? Floating point? Int?)
    String m_strCurrencySymbol; //  "$"

    // currencies only:
    String m_strCurrencyTLA;    // ISO-4217. E.g., USD, AUG, PSE. Take as hint,
                                // not as contract.
    String m_strCurrencyFactor; // A dollar is 100 cents. Therefore factor ==
                                // 100.
    String m_strCurrencyDecimalPower; // If value is 103, decimal power of 0
                                      // displays 103 (actual value.) Whereas
                                      // decimal power of 2 displays 1.03 and
                                      // 4 displays .0103
    String m_strCurrencyFraction;     // "cents"

    bool m_bIsCurrency; // default: true.  (default.)
    bool m_bIsShares;   // default: false. (defaults to currency, not shares.)
};

} // namespace opentxs

#endif // OPENTXS_CORE_OTASSETCONTRACT_HPP
