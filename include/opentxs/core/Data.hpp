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

#ifndef OPENTXS_CORE_DATA_HPP
#define OPENTXS_CORE_DATA_HPP

#include "opentxs/Forward.hpp"

#include <cstdint>
#include <string>
#include <vector>

#ifdef SWIG
// clang-format off
%ignore opentxs::Data::Concatenate;
%ignore opentxs::Data::GetPointer;
%ignore opentxs::Data::OTfread;
%ignore opentxs::Pimpl<opentxs::Data>::Pimpl(opentxs::Data const &);
%ignore opentxs::Pimpl<opentxs::Data>::operator opentxs::Data&;
%ignore opentxs::Pimpl<opentxs::Data>::operator const opentxs::Data &;
%ignore operator==(OTData& lhs, const Data& rhs);
%ignore operator!=(OTData& lhs, const Data& rhs);
%ignore operator+=(OTData& lhs, const OTData& rhs);
%rename(dataCompareEqual) opentxs::Data::operator==(const Data& rhs) const;
%rename(dataCompareNotEqual) opentxs::Data::operator!=(const Data& rhs) const;
%rename(dataPlusEqual) opentxs::Data::operator+=(const Data& rhs);
%rename(assign) operator=(const opentxs::Data&);
%template(OTData) opentxs::Pimpl<opentxs::Data>;
// clang-format on
#endif  // SWIG

namespace opentxs
{
bool operator==(OTData& lhs, const Data& rhs);
bool operator!=(OTData& lhs, const Data& rhs);
OTData& operator+=(OTData& lhs, const OTData& rhs);

class Data
{
public:
    EXPORT static Pimpl<opentxs::Data> Factory();
    EXPORT static Pimpl<opentxs::Data> Factory(const Data& rhs);
#ifndef SWIG
    EXPORT static Pimpl<opentxs::Data> Factory(
        const void* data,
        std::size_t size);
    EXPORT static OTData Factory(const OTASCIIArmor& source);
    EXPORT static OTData Factory(const std::vector<unsigned char>& source);
#endif
    EXPORT static Data fromHex(const std::string&);
    EXPORT virtual bool operator==(const Data& rhs) const = 0;
    EXPORT virtual bool operator!=(const Data& rhs) const = 0;
    EXPORT virtual std::string asHex() const = 0;
    EXPORT virtual bool empty() const = 0;
    EXPORT virtual const void* GetPointer() const = 0;
    EXPORT virtual std::size_t GetSize() const = 0;
#ifndef SWIG
    [[deprecated]] EXPORT virtual bool IsEmpty() const = 0;
#endif

    EXPORT virtual Data& operator+=(const Data& rhs) = 0;
    EXPORT virtual void Assign(const Data& source) = 0;
#ifndef SWIG
    EXPORT virtual void Assign(const void* data, const std::size_t& size) = 0;
#endif
    EXPORT virtual void Concatenate(
        const void* data,
        const std::size_t& size) = 0;
    EXPORT virtual std::size_t OTfread(
        std::uint8_t* data,
        const std::size_t& size) = 0;
    EXPORT virtual bool Randomize(const std::size_t& size) = 0;
    EXPORT virtual void Release() = 0;
    EXPORT virtual void reset() = 0;
    EXPORT virtual void SetSize(const std::size_t& size) = 0;
    EXPORT virtual void swap(Data&& rhs) = 0;
    EXPORT virtual void zeroMemory() = 0;

    EXPORT virtual ~Data() = default;

protected:
    Data() = default;

private:
    friend OTData;

    EXPORT virtual Data* clone() const = 0;

    Data(const Data& rhs) = delete;
    Data(Data&& rhs) = delete;
    Data& operator=(const Data& rhs) = delete;
    Data& operator=(Data&& rhs) = delete;
};
}  // namespace opentxs
#endif  // OPENTXS_CORE_DATA_HPP
