/*
 * (C) Copyright IBM Deutschland GmbH 2021, 2023
 * (C) Copyright IBM Corp 2021, 2023
 *
 * non-exclusively licensed to gematik GmbH
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef TPM_CLIENT_CLIENT_H
#define TPM_CLIENT_CLIENT_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Types.h"

#include <cstddef>
#include <cstdint>
#include <memory>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace tpmclient
{

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class Session;
class StorageIndex;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 *
 */
class Client
{
public:
    friend class ClientUser;

    Client();

    explicit Client(std::shared_ptr<Session> session);

    /**
     * Sets a new session for this client.
     */
    void setSession(std::shared_ptr<Session> session);

    /**
     * Queries whether this client has a session set.
     */
    bool hasSession() const;

    /**
     * Returns the session of this client. Throws if the client does not have a session.
     */
    const Session& getSession() const;

    /**
     * Queries whether this client is valid and therefore ready to be used.
     */
    bool isValid() const;

    /**
     * Attempts to ping the TPM using this client. Throws if the client is not valid.
     */
    void ping() const;

    /**
     * Fetches the endorsement certificate and key from the TPM.
     */
    EndorsementIdentity getEk() const;

    /**
     * Creates an attestation key on the TPM and returns it as an encrypted blob.
     */
    KeyPairBlob createAk() const;

    /**
     * Given an encrypted attestation key blob (created earlier by createAk()),
     * this function passes it to the TPM, decrypts it and returns the public key.
     */
    PublicKeyInfo getAk(const KeyPairBlob& akBlob) const;

    /**
     * Generates a new credential at the TPM using the given attestation key.
     */
    MadeCredential makeCredential(const KeyPairBlob& akBlob) const;

    /**
     * Attempts to authenticate a credential using the given attestation key.
     */
    Buffer authenticateCredential(const BufferView& secret,
                                  const BufferView& encryptedCredential,
                                  const KeyPairBlob& akBlob) const;

    /**
     * Fetches a fresh quote from the TPM for the given registers using the given attestation key.
     */
    Quote getQuote(const BufferView& nonce, const PCRRegisterList& registerList, const KeyPairBlob& akBlob) const;

    /**
     * Verifies whether given quote and signature are correct using the given attestation key.
     */
    void verifyQuote(const Quote& quote, const KeyPairBlob& akBlob) const;

private:
    std::shared_ptr<Session> mSession;
    mutable std::uint32_t mPkHandle;
    mutable std::uint32_t mAkHandle;
    mutable std::uint32_t mEkHandle;
    mutable std::unique_ptr<std::size_t> mDataMtu;

    void ensureIsValid() const;

    void attemptToUse() const;

    void initialize() const;

    void updateMaximumTransmissionUnit() const;

    std::size_t queryDataSize(const StorageIndex& index) const;

    Buffer retrieveData(const StorageIndex& index) const;

    void createPk() const;

    void loadAk(const KeyPairBlob& akBlob) const;

    void createEk(bool withCertificate) const;

    void flushKeys() const;

    int startAuthSession() const;

    Buffer getRandom(std::size_t bytes) const;

    PublicKeyInfo retrievePublicKey(std::uint32_t handle) const;
};

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
