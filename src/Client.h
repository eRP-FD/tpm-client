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
 * TODO TSB
 */
class Client
{
public:
    friend class ClientUser;

    Client();

    explicit Client(std::shared_ptr<Session> session);

    /**
     * TODO TSB
     */
    void setSession(std::shared_ptr<Session> session);

    /**
     * TODO TSB
     */
    bool hasSession() const;

    /**
     * TODO TSB
     */
    const Session& getSession() const;

    /**
     * TODO TSB
     */
    bool isValid() const;

    /**
     * TODO TSB
     */
    void ping() const;

    /**
     * TODO TSB
     */
    EndorsementIdentity getEk() const;

    /**
     * TODO TSB
     */
    KeyPairBlob createAk() const;

    /**
     * TODO TSB
     */
    PublicKeyInfo getAk(const KeyPairBlob& akBlob) const;

    /**
     * TODO TSB
     */
    MadeCredential makeCredential(const KeyPairBlob& akBlob) const;

    /**
     * TODO TSB
     */
    Buffer authenticateCredential(const BufferView& secret,
                                  const BufferView& encryptedCredential,
                                  const KeyPairBlob& akBlob) const;

    /**
     * TODO TSB
     */
    Quote getQuote(const BufferView& nonce, const PCRRegisterList& registerList, const KeyPairBlob& akBlob) const;

    /**
     * TODO TSB
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
