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

#include "opentxs/stdafx.hpp"

#include "opentxs/api/crypto/implementation/Util.hpp"

#include "opentxs/core/crypto/OTPassword.hpp"

#include <iostream>

namespace opentxs::api::crypto::implementation
{

bool Util::GetPasswordFromConsole(OTPassword& theOutput, bool bRepeat) const
{
    std::int32_t nAttempts = 0;

    for (int i = 0; i < 5; i++) {
        theOutput.zeroMemory();

        if (get_password(theOutput, "(OT) passphrase: ")) {
            if (!bRepeat) {
                std::cout << std::endl;
                return true;
            }
        } else {
            std::cout << "Sorry." << std::endl;
            return false;
        }

        OTPassword tempPassword;

        if (!get_password(tempPassword, "(Verifying) passphrase again: ")) {
            std::cout << "Sorry." << std::endl;
            return false;
        }

        if (!tempPassword.Compare(theOutput)) {
            if (++nAttempts >= 3) break;

            std::cout << "(Mismatch, try again.)\n" << std::endl;
        } else {
            std::cout << std::endl;
            return true;
        }
    }

    std::cout << "Sorry." << std::endl;

    return false;
}
}  // namespace opentxs::api::crypto::implementation
