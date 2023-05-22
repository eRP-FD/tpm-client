/*
 * (C) Copyright IBM Deutschland GmbH 2021, 2023
 * (C) Copyright IBM Corp 2021, 2023
 *
 * non-exclusively licensed to gematik GmbH
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef TPM_CLIENT_SCRATCHPAD_H
#define TPM_CLIENT_SCRATCHPAD_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Exception.h"
#include "Utils.h"

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include <iomanip>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>
#include <utility>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/Unmarshal_fp.h>

class Base64 {
public:

    static std::string Encode(const std::string data) {
        static constexpr char sEncodingTable[] = {
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                '4', '5', '6', '7', '8', '9', '+', '/'
        };

        size_t in_len = data.size();
        size_t out_len = 4 * ((in_len + 2) / 3);
        std::string ret(out_len, '\0');
        size_t i;
        char *p = const_cast<char*>(ret.c_str());

        for (i = 0; i < in_len - 2; i += 3) {
            *p++ = sEncodingTable[(data[i] >> 2) & 0x3F];
            *p++ = sEncodingTable[((data[i] & 0x3) << 4) | ((int) (data[i + 1] & 0xF0) >> 4)];
            *p++ = sEncodingTable[((data[i + 1] & 0xF) << 2) | ((int) (data[i + 2] & 0xC0) >> 6)];
            *p++ = sEncodingTable[data[i + 2] & 0x3F];
        }
        if (i < in_len) {
            *p++ = sEncodingTable[(data[i] >> 2) & 0x3F];
            if (i == (in_len - 1)) {
                *p++ = sEncodingTable[((data[i] & 0x3) << 4)];
                *p++ = '=';
            }
            else {
                *p++ = sEncodingTable[((data[i] & 0x3) << 4) | ((int) (data[i + 1] & 0xF0) >> 4)];
                *p++ = sEncodingTable[((data[i + 1] & 0xF) << 2)];
            }
            *p++ = '=';
        }

        return ret;
    }

    static std::string Decode(const std::string& input, std::string& out) {
        static constexpr unsigned char kDecodingTable[] = {
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
                52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
                64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
                15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
                64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
        };

        size_t in_len = input.size();
        if (in_len % 4 != 0) return "Input data size is not a multiple of 4";

        size_t out_len = in_len / 4 * 3;
        if (input[in_len - 1] == '=') out_len--;
        if (input[in_len - 2] == '=') out_len--;

        out.resize(out_len);

        for (size_t i = 0, j = 0; i < in_len;) {
            uint32_t a = input[i] == '=' ? 0 & i++ : kDecodingTable[static_cast<int>(input[i++])];
            uint32_t b = input[i] == '=' ? 0 & i++ : kDecodingTable[static_cast<int>(input[i++])];
            uint32_t c = input[i] == '=' ? 0 & i++ : kDecodingTable[static_cast<int>(input[i++])];
            uint32_t d = input[i] == '=' ? 0 & i++ : kDecodingTable[static_cast<int>(input[i++])];

            uint32_t triple = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);

            if (j < out_len) out[j++] = (triple >> 2 * 8) & 0xFF;
            if (j < out_len) out[j++] = (triple >> 1 * 8) & 0xFF;
            if (j < out_len) out[j++] = (triple >> 0 * 8) & 0xFF;
        }

        return "";
    }

};

const std::string& getBase64SelfSignedEKCert()
{
    static const std::string result{"-----BEGIN CERTIFICATE-----\n"
                                    "MIIB/jCCAaSgAwIBAgIUT+komv7PPUJq0FCRrKQ1cLpaL9QwCgYIKoZIzj0EAwIw\n"
                                    "VTEWMBQGA1UEAwwNVFBNIFNpbXVsYXRvcjELMAkGA1UEBhMCUk8xEjAQBgNVBAcM\n"
                                    "CUJ1Y2hhcmVzdDEMMAoGA1UECgwDSUJNMQwwCgYDVQQLDANFUlAwHhcNMjEwNDEy\n"
                                    "MjMyODI0WhcNMjIwNDEyMjMyODI0WjBVMRYwFAYDVQQDDA1UUE0gU2ltdWxhdG9y\n"
                                    "MQswCQYDVQQGEwJSTzESMBAGA1UEBwwJQnVjaGFyZXN0MQwwCgYDVQQKDANJQk0x\n"
                                    "DDAKBgNVBAsMA0VSUDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI4sIREiHNeZ\n"
                                    "8fXM5b9wQpWCgfJCS/0scWih/hn783en9eS5wXJAbZXohhvs0ZYsuxVdbZe/mFy+\n"
                                    "6m0pE6+VRgyjUjBQMB0GA1UdDgQWBBSHwgUqZvWmtpZAI2PRXixqM0DruDAfBgNV\n"
                                    "HSMEGDAWgBSXQzc82KH+4nyjh9SDUPDJ2m7x8DAOBgNVHQ8BAf8EBAMCAwgwCgYI\n"
                                    "KoZIzj0EAwIDSAAwRQIgPmyVWyvxqh7+8fOpVxQSJAIZ/IBnvSrQluheMQyQbEkC\n"
                                    "IQCTmI19fK8ZxNbwjrFjQFd7LzZtKiqhKvIe1LlkmjGWiQ==\n"
                                    "-----END CERTIFICATE-----"};
    return result;
}

const std::string& getBase64PrivateKeyToSignEKCert()
{
    static const std::string result{"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
                                    "MIHeMEkGCSqGSIb3DQEFDTA8MBsGCSqGSIb3DQEFDDAOBAiv+ODLOPcsbwICCAAw\n"
                                    "HQYJYIZIAWUDBAEqBBC/F0OaeoTz2ROpX89quSvWBIGQl4BxlX1Lvy31myw1vPN0\n"
                                    "w/1Wqozirz53nIsVN/q+jV4zgx4fu/KWqKMFYwtb+BkGWBueCh5jRJ9YvEqMpUl+\n"
                                    "LX4YgKGm7q4LQaf3DdRaWc5/99iIzMsdwGt/nbpZ0eyl1gwnwkU4+06RTE1156Li\n"
                                    "AnZcGYkwxCS8DKdy7qeU9n915io+A9hJucwXjvHOOo0S\n"
                                    "-----END ENCRYPTED PRIVATE KEY-----"};
    return result;
}

const std::string& getPrivateKeyToSignEKCertPassword()
{
    static const std::string result{"rrrr"};
    return result;
}

TPM_RC convertBin2Bn(BIGNUM **bn,			/* freed by caller */
                     const unsigned char *bin,
                     unsigned int bytes)
{
    TPM_RC rc = 0;

    /* BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);

       BN_bin2bn() converts the positive integer in big-endian form of length len at s into a BIGNUM
       and places it in ret. If ret is NULL, a new BIGNUM is created.

       BN_bin2bn() returns the BIGNUM, NULL on error.
    */
    if (rc == 0) {
        *bn = BN_bin2bn(bin, bytes, *bn);
        if (*bn == NULL) {
            printf("convertBin2Bn: Error in BN_bin2bn\n");
            rc = TSS_RC_BIGNUM;
        }
    }
    return rc;
}

static TPM_RC getEcNid(int		*nid,
                       TPMI_ECC_CURVE 	curveID)
{
    TPM_RC 		rc = 0;

    switch (curveID) {
        case TPM_ECC_NIST_P192:
            *nid = NID_X9_62_prime192v1;	/* untested guess */
            break;
        case TPM_ECC_NIST_P224:
            *nid = NID_secp224r1;		/* untested guess */
            break;
        case TPM_ECC_NIST_P256:		/* TCG standard */
            *nid = NID_X9_62_prime256v1;
            break;
        case TPM_ECC_NIST_P384:		/* TCG standard */
            *nid = NID_secp384r1;
            break;
        case TPM_ECC_NIST_P521:
            *nid = NID_secp521r1;		/* untested guess */
            break;
        case TPM_ECC_BN_P256:
        case TPM_ECC_BN_P638:
        case TPM_ECC_SM2_P256:
        case TPM_ECC_BP_P256_R1:
        case TPM_ECC_BP_P384_R1:
        case TPM_ECC_BP_P512_R1:
        case TPM_ECC_CURVE_25519:
        default:
            *nid = NID_undef;
            printf("getEcNid: Error, TCG curve %04x not supported \n", curveID);
            rc = TSS_RC_EC_KEY_CONVERT;
    }
    return rc;
}

TPM_RC convertEcTPMTPublicToEvpPubKey(EVP_PKEY **evpPubkey,		/* freed by caller */
                                      const TPMT_PUBLIC *tpmtPublic)
{
    TPM_RC 	rc = 0;
    int		irc;
    int		nid;
    EC_GROUP 	*ecGroup = NULL;
    EC_KEY 	*ecKey = NULL;
    BIGNUM 	*x = NULL;		/* freed @2 */
    BIGNUM 	*y = NULL;		/* freed @3 */

    if (rc == 0) {
        ecKey = EC_KEY_new();		/* freed @1 */
        if (ecKey == NULL) {
            printf("convertEcTPMTPublicToEvpPubKey: Error creating EC_KEY\n");
            rc = TSS_RC_OUT_OF_MEMORY;
        }
    }
    /* map from the TCG curve to the openssl nid */
    if (rc == 0) {
        rc = getEcNid(&nid, tpmtPublic->parameters.eccDetail.curveID);
    }
    if (rc == 0) {
        ecGroup = EC_GROUP_new_by_curve_name(nid);	/* freed @4 */
        if (ecGroup == NULL) {
            printf("convertEcTPMTPublicToEvpPubKey: Error in EC_GROUP_new_by_curve_name\n");
            rc = TSS_RC_OUT_OF_MEMORY;
        }
    }
    if (rc == 0) {
        /* returns void */
        EC_GROUP_set_asn1_flag(ecGroup, OPENSSL_EC_NAMED_CURVE);
    }
    /* assign curve to EC_KEY */
    if (rc == 0) {
        irc = EC_KEY_set_group(ecKey, ecGroup);
        if (irc != 1) {
            printf("convertEcTPMTPublicToEvpPubKey: Error in EC_KEY_set_group\n");
            rc = TSS_RC_EC_KEY_CONVERT;
        }
    }
    if (rc == 0) {
        rc = convertBin2Bn(&x,				/* freed @2 */
                           tpmtPublic->unique.ecc.x.t.buffer,
                           tpmtPublic->unique.ecc.x.t.size);
    }
    if (rc == 0) {
        rc = convertBin2Bn(&y,				/* freed @3 */
                           tpmtPublic->unique.ecc.y.t.buffer,
                           tpmtPublic->unique.ecc.y.t.size);
    }
    if (rc == 0) {
        irc = EC_KEY_set_public_key_affine_coordinates(ecKey, x, y);
        if (irc != 1) {
            printf("convertEcTPMTPublicToEvpPubKey: "
                   "Error converting public key from X Y to EC_KEY format\n");
            rc = TSS_RC_EC_KEY_CONVERT;
        }
    }
    if (rc == 0) {
        *evpPubkey = EVP_PKEY_new();		/* freed by caller */
        if (*evpPubkey == NULL) {
            printf("convertEcTPMTPublicToEvpPubKey: EVP_PKEY failed\n");
            rc = TSS_RC_OUT_OF_MEMORY;
        }
    }
    if (rc == 0) {
        irc = EVP_PKEY_set1_EC_KEY(*evpPubkey, ecKey);
        if (irc != 1) {
            printf("convertEcTPMTPublicToEvpPubKey: "
                   "Error converting public key from EC to EVP format\n");
            rc = TSS_RC_EC_KEY_CONVERT;
        }
    }
    if (ecGroup != NULL) {
        EC_GROUP_free(ecGroup);	/* @4 */
    }
    if (ecKey != NULL) {
        EC_KEY_free(ecKey);	/* @1 */
    }
    if (x != NULL) {
        BN_free(x);		/* @2 */
    }
    if (y != NULL) {
        BN_free(y);		/* @3 */
    }
    return rc;
}

std::string getOpenSSLError()
{
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf;
    size_t len = BIO_get_mem_data(bio, &buf);
    std::string ret(buf, len);
    BIO_free(bio);
    return ret;
}

EVP_PKEY* getPrivateKeyToSignEkWith()
{
    const auto keyData = getBase64PrivateKeyToSignEKCert();
    BIO* bio = BIO_new_mem_buf(keyData.data(), static_cast<int>(keyData.length()));

    const auto result = PEM_read_bio_PrivateKey(bio,
                                                nullptr,
                                                [](char* passwordBuffer, int passwordBufferSize, int, void*)
                                                {
                                                    const auto& password = getPrivateKeyToSignEKCertPassword();
                                                    const int passwordSize = password.size();
                                                    if (passwordBufferSize < passwordSize)
                                                    {
                                                        throw tpmclient::Exception{"Private key password too large"};
                                                    }

                                                    std::memcpy(passwordBuffer, password.c_str(), passwordSize);

                                                    return passwordSize;
                                                },
                                                nullptr);
    if (!result)
    {
        throw tpmclient::Exception("EVP_PKEY result is null: " + getOpenSSLError());
    }

    if (1 != BIO_free(bio))
    {
        throw tpmclient::Exception("fail to free EVP_PKEY pem bio");
    }

    return result;
}

X509* getOpensslSelfSignedEKCert()
{
    const auto certData = getBase64SelfSignedEKCert();
    BIO* bio = BIO_new_mem_buf(certData.data(), static_cast<int>(certData.length()));

    const auto result = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (!result)
    {
        throw tpmclient::Exception("x509 result is null: " + getOpenSSLError());
    }

    if (1 != BIO_free(bio))
    {
        throw tpmclient::Exception("fail to free x509 pem bio");
    }

    return result;
}

void tweakOpensslSelfSignedEKCert(X509*& cert, TPMT_PUBLIC* tpmtPublic)
{
    EVP_PKEY* evpPubkey{};

    if (0 != convertEcTPMTPublicToEvpPubKey(&evpPubkey, tpmtPublic))
    {
        throw tpmclient::Exception("fail to convertEcTPMTPublicToEvpPubKey");
    }

    if (1 != X509_set_pubkey(cert, evpPubkey))
    {
        throw tpmclient::Exception("fail to X509_set_pubkey");
    }

    auto* evpPrivateSignKey = getPrivateKeyToSignEkWith();
    const auto* digest = EVP_sha256();
    if (0 == X509_sign(cert, evpPrivateSignKey, digest))
    {
        throw tpmclient::Exception("fail to X509_sign");
    }

    if (1 != X509_verify(cert, evpPrivateSignKey))
    {
        throw tpmclient::Exception("fail to X509_verify");
    }

    if (evpPubkey)
    {
        EVP_PKEY_free(evpPubkey);
    }

    if (evpPrivateSignKey)
    {
        EVP_PKEY_free(evpPrivateSignKey);
    }
}

std::pair<std::vector<unsigned char>, std::string> ScratchPad_getFinalEKCert(TPMT_PUBLIC* tpmtPublic)
{
    auto* x509 = getOpensslSelfSignedEKCert();
    tweakOpensslSelfSignedEKCert(x509, tpmtPublic);

    unsigned char* derCert{};
    const auto derCertLen = i2d_X509(x509, &derCert);
    if (derCertLen < 0)
    {
        throw tpmclient::Exception("i2d_X509");
    }

    std::vector<unsigned char> derResult(derCert, derCert+derCertLen);

    OPENSSL_free(derCert);

    const auto certDataBase64 = Base64::Encode(std::string{derResult.cbegin(), derResult.cend()});

    X509_free(x509);

    return std::make_pair(derResult, certDataBase64);
}

TPM_RC ScratchPad_storeEkCertificate(TSS_CONTEXT *tssContext,
                          std::size_t dataMtu,
                          uint32_t certLength,
                          const unsigned char *certificate,
                          TPMI_RH_NV_INDEX nvIndex,
                          const char *platformPassword)
{
    TPM_RC 		rc = 0;
    NV_Write_In 	nvWriteIn;
    uint16_t 		bytesWritten;		/* bytes written so far */
    int			done = FALSE;

    if (rc == 0) {
        if (1) printf("storeEkCertificate: writing %u bytes to %08x\n",
                      certLength, nvIndex);
        nvWriteIn.authHandle = TPM_RH_PLATFORM;
        nvWriteIn.nvIndex = nvIndex;
        nvWriteIn.offset = 0;
        bytesWritten = 0;	/* bytes written so far */
    }
    while ((rc == 0) && !done) {
        uint16_t writeBytes;		/* bytes to write in this pass */
        if (rc == 0) {
            nvWriteIn.offset = bytesWritten;
            if ((uint32_t)(certLength - bytesWritten) < dataMtu) {
                writeBytes = certLength - bytesWritten;	/* last chunk */
            }
            else {
                writeBytes = dataMtu;	/* next chunk */
            }
            rc = TSS_TPM2B_Create(&nvWriteIn.data.b, const_cast<unsigned char*>(certificate + bytesWritten), writeBytes,
                                  sizeof(nvWriteIn.data.t.buffer));
        }
        if (rc == 0) {
            rc = TSS_Execute(tssContext,
                             NULL,
                             (COMMAND_PARAMETERS *)&nvWriteIn,
                             NULL,
                             TPM_CC_NV_Write,
                             TPM_RS_PW, platformPassword, 0,
                             TPM_RH_NULL, NULL, 0);
        }
        if (rc == 0) {
            bytesWritten += writeBytes;
            if (bytesWritten == certLength) {
                done = TRUE;
            }
        }
    }
    if (rc == 0) {
        if (1) printf("storeEkCertificate: success\n");
    }
    else {
        const char *msg;
        const char *submsg;
        const char *num;
        printf("storeEkCertificate: failed, rc %08x\n", rc);
        TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
        printf("%s%s%s\n", msg, submsg, num);
        if (rc == TSS_RC_FILE_OPEN) {
            printf("Possible cause: missing nvreadpublic before nvwrite\n");
        }
        rc = EXIT_FAILURE;
    }
    return rc;
}

TPM_RC ScratchPad_defineEKCertIndex(TSS_CONTEXT *tssContext,
                         uint32_t certLength,
                         TPMI_RH_NV_INDEX nvIndex,
                         const char *platformPassword)
{
    TPM_RC 		rc = 0;
    NV_ReadPublic_In 	nvReadPublicIn;
    NV_ReadPublic_Out	nvReadPublicOut;
    NV_DefineSpace_In 	nvDefineSpaceIn;

    /* read metadata to make sure the index is there, the size is sufficient, and get the Name */
    if (rc == 0) {
        nvReadPublicIn.nvIndex = nvIndex;
        rc = TSS_Execute(tssContext,
                         (RESPONSE_PARAMETERS *)&nvReadPublicOut,
                         (COMMAND_PARAMETERS *)&nvReadPublicIn,
                         NULL,
                         TPM_CC_NV_ReadPublic,
                         TPM_RH_NULL, NULL, 0);
    }
    /* if already defined, check the size */
    if (rc == 0) {
        if (nvReadPublicOut.nvPublic.nvPublic.dataSize < certLength) {
            printf("defineEKCertIndex: data size %u insufficient for certificate %u\n",
                   nvReadPublicOut.nvPublic.nvPublic.dataSize, certLength);
            rc = EXIT_FAILURE;
        }
    }
    else if ((rc & 0xff) == TPM_RC_HANDLE) {
        rc = 0;		/* not an error yet, define the index for the EK certificate */
        nvDefineSpaceIn.authHandle = TPM_RH_PLATFORM;
        nvDefineSpaceIn.auth.b.size = 0;					/* empty auth */
        nvDefineSpaceIn.publicInfo.nvPublic.authPolicy.t.size = 0;		/* empty policy */
        nvDefineSpaceIn.publicInfo.nvPublic.nvIndex = nvIndex;	/* handle of the data area */
        nvDefineSpaceIn.publicInfo.nvPublic.nameAlg = TPM_ALG_SHA256; 	/* name hash algorithm */
        nvDefineSpaceIn.publicInfo.nvPublic.attributes.val = 0;
        /* PC Client specification */
        nvDefineSpaceIn.publicInfo.nvPublic.attributes.val |= TPMA_NVA_ORDINARY;
        nvDefineSpaceIn.publicInfo.nvPublic.attributes.val |= TPMA_NVA_PLATFORMCREATE;
        nvDefineSpaceIn.publicInfo.nvPublic.attributes.val |= TPMA_NVA_AUTHREAD;
        nvDefineSpaceIn.publicInfo.nvPublic.attributes.val |= TPMA_NVA_NO_DA;
        nvDefineSpaceIn.publicInfo.nvPublic.attributes.val |= TPMA_NVA_PPWRITE;
        /* required for Microsoft Windows certification test */
        nvDefineSpaceIn.publicInfo.nvPublic.attributes.val |= TPMA_NVA_OWNERREAD;
        if (certLength < 1000) {
            nvDefineSpaceIn.publicInfo.nvPublic.dataSize = 1000;		/* minimum size */
        }
        else {
            nvDefineSpaceIn.publicInfo.nvPublic.dataSize = certLength;
        }
        /* call TSS to execute the command */
        if (rc == 0) {
            rc = TSS_Execute(tssContext,
                             NULL,
                             (COMMAND_PARAMETERS *)&nvDefineSpaceIn,
                             NULL,
                             TPM_CC_NV_DefineSpace,
                             TPM_RS_PW, platformPassword, 0,
                             TPM_RH_NULL, NULL, 0);
        }
    }
    if (rc != 0) {
        const char *msg;
        const char *submsg;
        const char *num;
        printf("defineEKCertIndex: failed, rc %08x\n", rc);
        TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
        printf("%s%s%s\n", msg, submsg, num);
        printf("ERROR: defineEKCertIndex: requires certificate min length %u at index %08x\n",
               certLength, nvIndex);
        rc = EXIT_FAILURE;
    }
    return rc;
}

void ScratchPad_setupDefaultEkInput(TPMT_PUBLIC& input)
{
    input.type = TPM_ALG_ECC;
    input.nameAlg = TPM_ALG_SHA256;
    input.objectAttributes.val = TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                 TPMA_OBJECT_ADMINWITHPOLICY |
                                 TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_DECRYPT;

    static constexpr const std::uint8_t policySha256[] =
            {
                    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
                    0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
            };

    input.authPolicy.t.size = sizeof(policySha256);
    std::memcpy(input.authPolicy.t.buffer, policySha256, sizeof(policySha256));
    input.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
    input.parameters.eccDetail.symmetric.keyBits.aes = 128;
    input.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
    input.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
    input.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
    input.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    input.unique.ecc.x.t.size = 32;
    input.unique.ecc.y.t.size = 32;
}

void ScratchPad_setupEkInput(TPMT_PUBLIC& input, const tpmclient::Buffer& ekTemplate, const tpmclient::Buffer& nonce)
{
    const auto ekTemplateData = ekTemplate.data();
    const auto ekTemplateSize = static_cast<std::uint32_t>(ekTemplate.size());

    const auto result = TSS_TPMT_PUBLIC_Unmarshalu(&input,
                                                   const_cast<std::uint8_t**>(&ekTemplateData),
                                                   const_cast<std::uint32_t*>(&ekTemplateSize),
                                                   YES);

    if (result)
    {
        throw tpmclient::Exception{"Unable to unmarshal EK: " + tpmclient::Utils::BuildErrorMessage(result)};
    }

    input.unique.ecc.x.t.size = 32;
    input.unique.ecc.y.t.size = 32;

    std::memcpy(input.unique.ecc.x.t.buffer, nonce.data(), nonce.size());
}

std::string BinaryToHex(const tpmclient::BufferView& buffer)
{
    std::ostringstream stream{};
    stream << std::hex << std::setfill('0');

    for (const auto byte : buffer)
    {
        stream << std::setw(2) << static_cast<int>(byte) << " ";
    }

    return stream.str();
}

std::array<unsigned char, SHA256_DIGEST_SIZE> computeSha256(const tpmclient::BufferView& buffer)
{
    SHA256_CTX context{};
    if (!SHA256_Init(&context))
    {
        throw tpmclient::Exception{"Unable to compute sha256: cannot initialise context"};
    }

    if (!SHA256_Update(&context, buffer.data(), buffer.size()))
    {
        throw tpmclient::Exception{"Unable to compute sha256: cannot update context with data"};
    }

    std::array<unsigned char, SHA256_DIGEST_SIZE> result{};
    if (!SHA256_Final(result.data(), &context))
    {
        throw tpmclient::Exception{"Unable to compute sha256: cannot write to result buffer"};
    }

    return result;
}

#endif
