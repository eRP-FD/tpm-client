#ifndef TPM_CLIENT_TYPES_H
#define TPM_CLIENT_TYPES_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <array>
#include <cstddef>
#include <string_view>
#include <vector>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace tpmclient
{
    /**
     * Owning buffer type - usually returned by the API
     */
    using Buffer = std::vector<unsigned char>;

    /**
     * Non-owning buffer type - usually passed to the API.
     * `std::span` would've been a nicer choice, but is only available from C++20.
     */
    using BufferView = std::basic_string_view<unsigned char>;

    /**
     * X509 certificate weak type.
     * Format: binary ASN1 DER
     */
    using Certificate = Buffer;

    /**
     * Elliptic curve public key weak type.
     * Format: binary TPMT_PUBLIC
     */
    using PublicKey = Buffer;

    /**
     * Elliptic curve digital signature weak type.
     * Format: binary TPMT_SIGNATURE
     */
    using Signature = Buffer;

    /**
     * Encrypted blob containing a keypair that the TPM can decrypt and load.
     * Format: binary raw
     */
    using KeyPairBlob = Buffer;

    /**
     * Public key name -- stack-based fixed-size buffer -- result of a SHA256 with two magic bytes prepended.
     * Format: binary raw
     */
    using PublicKeyName = std::array<unsigned char, 34>;

    /**
     * List of the PCR registers to be included in a quote.
     * Expected to be filled with unique integers ranging from 0 to 15 inclusively.
     */
    using PCRRegisterList = std::vector<std::size_t>;

    /**
     * Result of the getEK() API method.
     */
    struct EndorsementIdentity
    {
        Certificate certificate;
        PublicKeyName keyName;
    };

    /**
     * Result of the `getAK()` API method.
     */
    struct PublicKeyInfo
    {
        PublicKey key;
        PublicKeyName name;
    };

    /**
     * Result of the `getQuote` API method.
     */
    struct Quote
    {
        Buffer data;
        Signature signature;
    };

    /**
     * Result of the `makeCredential` API method;
     */
    struct MadeCredential
    {
        Buffer secret;
        Buffer credential;
        Buffer encryptedCredential;
    };

    /**
     * Returns a "view" of the given buffer. Obviously, the buffer must outlive the view.
     */
    BufferView GetBufferView(const Buffer& buffer);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
