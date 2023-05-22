/*
 * (C) Copyright IBM Deutschland GmbH 2021, 2023
 * (C) Copyright IBM Corp 2021, 2023
 *
 * non-exclusively licensed to gematik GmbH
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef TPM_CLIENT_SESSION_H
#define TPM_CLIENT_SESSION_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <memory>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct TSS_CONTEXT TSS_CONTEXT;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace tpmclient
{

/**
 * A tpmclient `Session` object represents a communication channel with a TPM device.
 */
class Session
{
private:
    using RawNativeType = TSS_CONTEXT;

public:
    /**
     * Native type of the underlying resource (dictated by underlying TSS library)
     */
    using NativeType = RawNativeType*;

    Session();

    /**
     * Attempts to open a new session with the TPM. Throws if already open.
     */
    void open();

    /**
     * Closes the session to the TPM. Throws if there is no open session.
     */
    void close();

    /**
     * Queries whether this session object is open for communication with the TPM.
     */
    bool isOpen() const;

    /**
     * Queries whether this session object is closed for communication with the TPM.
     */
    bool isClosed() const;

    /**
     * Returns the native underlying type of the session.
     */
    NativeType getNative() const;

    /**
     * Returns the native underlying type of the session.
     */
    NativeType operator*() const;

private:
    std::unique_ptr<RawNativeType, void (*)(NativeType)> mSession;
};

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
