// Copyright (c) 2018 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#if OT_CRYPTO_USING_OPENSSL
#if OPENSSL_VERSION_NUMBER < 0x10100000L
extern "C" {
EVP_MD_CTX* EVP_MD_CTX_new();
void EVP_MD_CTX_free(EVP_MD_CTX* context);
}
#endif

namespace opentxs::crypto::implementation
{
class OpenSSL : virtual public crypto::OpenSSL
#if OT_CRYPTO_SUPPORTED_KEY_RSA
    ,
                public AsymmetricProvider
#endif
{
public:
    static std::mutex* s_arrayMutex;

    bool Digest(
        const proto::HashType hashType,
        const std::uint8_t* input,
        const size_t inputSize,
        std::uint8_t* output) const override;
    bool HMAC(
        const proto::HashType hashType,
        const std::uint8_t* input,
        const size_t inputSize,
        const std::uint8_t* key,
        const size_t keySize,
        std::uint8_t* output) const override;

#if OT_CRYPTO_SUPPORTED_ALGO_AES
    bool Decrypt(
        const OTPassword& theRawSymmetricKey,
        const char* szInput,
        std::uint32_t lInputLength,
        const Data& theIV,
        CryptoSymmetricDecryptOutput& theDecryptedOutput) const override;
    bool Decrypt(
        const LegacySymmetricProvider::Mode cipher,
        const OTPassword& key,
        const char* ciphertext,
        std::uint32_t ciphertextLength,
        CryptoSymmetricDecryptOutput& plaintext) const override;
    bool Decrypt(
        const LegacySymmetricProvider::Mode cipher,
        const OTPassword& key,
        const Data& iv,
        const char* ciphertext,
        std::uint32_t ciphertextLength,
        CryptoSymmetricDecryptOutput& plaintext) const override;
    bool Decrypt(
        const LegacySymmetricProvider::Mode cipher,
        const OTPassword& key,
        const Data& iv,
        const Data& tag,
        const char* ciphertext,
        const std::uint32_t ciphertextLength,
        CryptoSymmetricDecryptOutput& plaintext) const override;

    OTPassword* DeriveNewKey(
        const OTPassword& userPassword,
        const Data& dataSalt,
        std::uint32_t uIterations,
        Data& dataCheckHash) const override;
    bool Encrypt(
        const OTPassword& theRawSymmetricKey,
        const char* szInput,
        std::uint32_t lInputLength,
        const Data& theIV,
        Data& theEncryptedOutput) const override;
    bool Encrypt(
        const LegacySymmetricProvider::Mode cipher,
        const OTPassword& key,
        const char* plaintext,
        std::uint32_t plaintextLength,
        Data& ciphertext) const override;
    bool Encrypt(
        const LegacySymmetricProvider::Mode cipher,
        const OTPassword& key,
        const Data& iv,
        const char* plaintext,
        std::uint32_t plaintextLength,
        Data& ciphertext) const override;
    bool Encrypt(
        const LegacySymmetricProvider::Mode cipher,
        const OTPassword& key,
        const Data& iv,
        const char* plaintext,
        std::uint32_t plaintextLength,
        Data& ciphertext,
        Data& tag) const override;
    OTPassword* InstantiateBinarySecret() const override;
    BinarySecret InstantiateBinarySecretSP() const override;
#endif

#if OT_CRYPTO_SUPPORTED_KEY_RSA
    bool Sign(
        const Data& plaintext,
        const key::Asymmetric& theKey,
        const proto::HashType hashType,
        Data& signature,  // output
        const OTPasswordData* pPWData = nullptr,
        const OTPassword* exportPassword = nullptr) const override;
    bool Verify(
        const Data& plaintext,
        const key::Asymmetric& theKey,
        const Data& signature,
        const proto::HashType hashType,
        const OTPasswordData* pPWData = nullptr) const override;

    bool EncryptSessionKey(
        const mapOfAsymmetricKeys& RecipPubKeys,
        Data& plaintext,
        Data& dataOutput) const override;
    bool DecryptSessionKey(
        Data& dataInput,
        const Nym& theRecipient,
        Data& plaintext,
        const OTPasswordData* pPWData = nullptr) const override;
#endif  // OT_CRYPTO_SUPPORTED_KEY_RSA

    void Cleanup() override;
    void Init() override;

    ~OpenSSL() = default;

private:
    friend opentxs::Factory;
    class OpenSSLdp;

    class CipherContext
    {
    public:
        operator EVP_CIPHER_CTX*();

        CipherContext();
        ~CipherContext();

    private:
        EVP_CIPHER_CTX* context_{nullptr};

        CipherContext(const CipherContext&) = delete;
        CipherContext(CipherContext&&) = delete;
        CipherContext& operator=(const CipherContext&) = delete;
        CipherContext& operator=(CipherContext&&) = delete;
    };

    class DigestContext
    {
    public:
        operator EVP_MD_CTX*();

        DigestContext();
        ~DigestContext();

    private:
        EVP_MD_CTX* context_{nullptr};

        DigestContext(const DigestContext&) = delete;
        DigestContext(DigestContext&&) = delete;
        DigestContext& operator=(const DigestContext&) = delete;
        DigestContext& operator=(DigestContext&&) = delete;
    };

    const api::Crypto& crypto_;
    std::unique_ptr<OpenSSLdp> dp_;
    mutable std::mutex lock_;

    bool ArgumentCheck(
        const bool encrypt,
        const LegacySymmetricProvider::Mode cipher,
        const OTPassword& key,
        const Data& iv,
        const Data& tag,
        const char* input,
        const std::uint32_t inputLength,
        bool& AEAD,
        bool& ECB) const;
    void thread_setup() const;
    void thread_cleanup() const;

    OpenSSL(const api::Crypto& crypto);
    OpenSSL() = delete;
    OpenSSL(const OpenSSL&) = delete;
    OpenSSL(OpenSSL&&) = delete;
    OpenSSL& operator=(const OpenSSL&) = delete;
    OpenSSL& operator=(OpenSSL&&) = delete;
};
}  // namespace opentxs::crypto::implementation
#endif  // OT_CRYPTO_USING_OPENSSL
