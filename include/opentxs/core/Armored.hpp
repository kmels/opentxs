// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OPENTXS_CORE_ARMORED_HPP
#define OPENTXS_CORE_ARMORED_HPP

#include "opentxs/Forward.hpp"

#include "opentxs/core/String.hpp"

#include <cstdint>
#include <iosfwd>
#include <map>
#include <string>

namespace opentxs
{
extern const char* OT_BEGIN_ARMORED;
extern const char* OT_END_ARMORED;

extern const char* OT_BEGIN_ARMORED_escaped;
extern const char* OT_END_ARMORED_escaped;

extern const char* OT_BEGIN_SIGNED;
extern const char* OT_BEGIN_SIGNED_escaped;

/** The natural state of Armored is in compressed and base64-encoded,
 string form.

 HOW TO USE THIS CLASS

 Methods that put data into Armored
   ...if the input is already encoded:
      Constructors that take Armored, OTEnvelope, char*
      Assignment operators that take Armored, char*
      Load methods

   ...if the data is *not* already encoded:
      Constructors that take String, Data
      Assignment operators that take String, Data
      Set methods

 Methods that take data out of Armored
   ...in encoded form:
      Write methods
      Save methods
      (inherited) String::Get() method

   ...in decoded form:
      Armored::GetString() and Armored::GetData() methods

      Note: if an Armored is provided to the constructor of String(),
      the resulting String will be in *decoded* form. */
class Armored : virtual public String
{
public:
    EXPORT static opentxs::Pimpl<opentxs::Armored> Factory();
    EXPORT static opentxs::Pimpl<opentxs::Armored> Factory(const char* in);
    EXPORT static opentxs::Pimpl<opentxs::Armored> Factory(const Data& in);
    EXPORT static opentxs::Pimpl<opentxs::Armored> Factory(const String& in);
    EXPORT static opentxs::Pimpl<opentxs::Armored> Factory(
        const OTEnvelope& in);

    /** Let's say you don't know if the input string is raw base64, or if it has
     * bookends on it like -----BEGIN BLAH BLAH ... And if it DOES have
     * Bookends, you don't know if they are escaped: - -----BEGIN ... Let's say
     * you just want an easy function that will figure that crap out, and load
     * the contents up properly into an Armored object. (That's what this
     * function will do.)
     *
     * str_bookend is a default. You could make it more specific like,
     * -----BEGIN ENCRYPTED KEY (or whatever.)
     */
    EXPORT static bool LoadFromString(
        Armored& ascArmor,
        const String& strInput,
        std::string str_bookend = "-----BEGIN");

    EXPORT virtual bool GetData(Data& theData, bool bLineBreaks = true)
        const = 0;
    EXPORT virtual bool GetString(String& theData, bool bLineBreaks = true)
        const = 0;
    // for "-----BEGIN OT LEDGER-----", str_type would contain "LEDGER" There's
    // no default, to force you to enter the right string.
    // for "-----BEGIN OT LEDGER-----", str_type would contain "LEDGER" There's
    // no default, to force you to enter the right string.
    EXPORT virtual bool WriteArmoredString(
        String& strOutput,
        const std::string str_type,
        bool bEscaped = false) const = 0;

    EXPORT virtual bool LoadFrom_ifstream(std::ifstream& fin) = 0;
    EXPORT virtual bool LoadFromExactPath(const std::string& filename) = 0;
    // This code reads up the string, discards the bookends, and saves only the
    // gibberish itself. the bEscaped option allows you to load a normal
    // ASCII-Armored file if off, and allows you to load an escaped
    // ASCII-armored  file (such as inside the contracts when the public keys
    // are escaped with a  "- " before the rest of the ------- starts.)
    //
    // str_override determines where the content starts, when loading.
    // "-----BEGIN" is the default "content start" substr.
    EXPORT virtual bool LoadFromString(
        String& theStr,
        bool bEscaped = false,
        const std::string str_override = "-----BEGIN") = 0;
    EXPORT virtual bool SaveTo_ofstream(std::ofstream& fout) = 0;
    EXPORT virtual bool SaveToExactPath(const std::string& filename) = 0;
    EXPORT virtual bool SetData(
        const Data& theData,
        bool bLineBreaks = true) = 0;
    EXPORT virtual bool SetString(
        const String& theData,
        bool bLineBreaks = true) = 0;

    EXPORT ~Armored() = default;

protected:
    friend OTArmored;

	//IClonable* CloneImpl(void) const override;
    //virtual Armored* clone() const = 0;

    Armored() = default;

private:
    Armored(const Armored&) = delete;
    Armored(Armored&&) = delete;
    Armored& operator=(const Armored&) = delete;
    Armored& operator=(Armored&&) = delete;
};
}  // namespace opentxs
#endif
