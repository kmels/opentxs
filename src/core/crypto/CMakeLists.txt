set(cxx-sources
  AsymmetricKeyEC.cpp
  AsymmetricKeyEd25519.cpp
  AsymmetricKeySecp256k1.cpp
  Bip32.cpp
  Bip39.cpp
  ChildKeyCredential.cpp
  ContactCredential.cpp
  Credential.cpp
  CredentialSet.cpp
  Crypto.cpp
  CryptoAsymmetric.cpp
  CryptoHash.cpp
  CryptoSymmetric.cpp
  Ecdsa.cpp
  KeyCredential.cpp
  Letter.cpp
  Libsecp256k1.cpp
  Libsodium.cpp
  LowLevelKeyGenerator.cpp
  MasterCredential.cpp
  NymParameters.cpp
  OTASCIIArmor.cpp
  OTAsymmetricKey.cpp
  OTAsymmetricKeyOpenSSL.cpp
  OTAsymmetricKeyOpenSSLPrivdp.cpp
  OTCachedKey.cpp
  OTCallback.cpp
  OTCaller.cpp
  OTEnvelope.cpp
  OTKeypair.cpp
  OTKeyring.cpp
  OTNymOrSymmetricKey.cpp
  OTPassword.cpp
  OTPasswordData.cpp
  OTSignatureMetadata.cpp
  OTSignedFile.cpp
  OTSymmetricKey.cpp
  OpenSSL.cpp
  PaymentCode.cpp
  SymmetricKey.cpp
  TrezorCrypto.cpp
  VerificationCredential.cpp
  mkcert.cpp
)

set(cxx-install-headers
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/AsymmetricKeyEC.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/AsymmetricKeyEd25519.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/AsymmetricKeySecp256k1.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/Bip32.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/Bip39.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/ChildKeyCredential.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/ContactCredential.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/Credential.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/CredentialSet.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/CryptoAsymmetric.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/CryptoEncoding.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/CryptoHash.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/Crypto.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/CryptoSymmetric.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/CryptoSymmetricNew.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/Ecdsa.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/KeyCredential.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/Letter.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/Libsecp256k1.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/Libsodium.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/LowLevelKeyGenerator.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/MasterCredential.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/mkcert.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/NymParameters.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/OpenSSL_BIO.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/OTASCIIArmor.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/OTAsymmetricKey.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/OTAsymmetricKeyOpenSSL.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/OTAsymmetricKey_OpenSSLPrivdp.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/OTCachedKey.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/OTCallback.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/OTCaller.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/OTEnvelope.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/OTKeypair.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/OTKeyring.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/OTNymOrSymmetricKey.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/OTPasswordData.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/OTPassword.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/OTSignature.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/OTSignatureMetadata.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/OTSignedFile.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/OTSymmetricKey.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/PaymentCode.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/SymmetricKey.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/VerificationCredential.hpp"
)

set(cxx-headers
  ${cxx-install-headers}
  PaymentCode.hpp
  TrezorCrypto.hpp
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include/opentxs/core/crypto/OpenSSL.hpp"
)

set(MODULE_NAME opentxs-core-crypto)

if(WIN32)
  # suppress warnings about exported internal symbols (global log stream objects)
  add_definitions(-DOTLOG_IMPORT)

  # suppress linker warnings about locallly defined imported symbols
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /ignore:4049 /ignore:4217")

  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/windll.rc.in
    ${CMAKE_CURRENT_BINARY_DIR}/module.rc
    @ONLY
  )

  # we have an extra Windows-specific file to compile
  add_library(${MODULE_NAME} OBJECT
    ${cxx-sources}
    ${cxx-headers}
    ${CMAKE_CURRENT_BINARY_DIR}/module.rc
  )
else()
  add_library(${MODULE_NAME} OBJECT
    ${cxx-sources}
    ${cxx-headers}
  )
endif()

install(FILES ${cxx-install-headers}
        DESTINATION include/opentxs/core/crypto
        COMPONENT dev)

set_property(TARGET ${MODULE_NAME} PROPERTY POSITION_INDEPENDENT_CODE 1)
set_lib_property(${MODULE_NAME})
