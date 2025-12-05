/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.crypto.pqc.algorithms;

import org.hyperledger.besu.crypto.pqc.PQCPublicKey;
import org.hyperledger.besu.crypto.pqc.PQCSignature;
import org.hyperledger.besu.crypto.pqc.SignatureAlgorithmFactoryPQC;
import org.hyperledger.besu.crypto.pqc.SignatureAlgorithmPQC;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ML-DSA-44 implementation.
 */
public final class MLDSA44SignatureAlgorithm implements SignatureAlgorithmPQC {

    private static final Logger LOG = LoggerFactory.getLogger(MLDSA44SignatureAlgorithm.class);

    // cf FIPS 204 : pk=1312, sig=2420
    private static final int PUBLIC_KEY_LEN = 1312;
    private static final int SIGNATURE_LEN = 2420;

    public static final MLDSA44SignatureAlgorithm INSTANCE = new MLDSA44SignatureAlgorithm();

    private MLDSA44SignatureAlgorithm() {
    }

    @Override
    public byte algorithmId() {
        return SignatureAlgorithmFactoryPQC.ALG_ID_ML_DSA_44;
    }

    @Override
    public String name() {
        return "ML-DSA-44";
    }

    @Override
    public int publicKeyLength() {
        return PUBLIC_KEY_LEN;
    }

    @Override
    public int signatureLength() {
        return SIGNATURE_LEN;
    }

    @Override
    public PQCPublicKey createPublicKey(final Bytes encoded) {
        if (encoded.size() != PUBLIC_KEY_LEN) {
            throw new IllegalArgumentException(
                    "Invalid %s public key length: " + encoded.size());
        }
        return new PQCPublicKey(encoded);
    }

    @Override
    public PQCSignature createSignature(final Bytes encoded) {
        if (encoded.size() != SIGNATURE_LEN) {
            throw new IllegalArgumentException(
                    "Invalid ML-DSA-44 signature length: " + encoded.size());
        }
        return new PQCSignature(encoded);
    }

    @Override
    public boolean verify(
            final Bytes message, final PQCSignature signature, final PQCPublicKey publicKey) {
        try {
            MLDSAPublicKeyParameters params = new MLDSAPublicKeyParameters(
                    MLDSAParameters.ml_dsa_44, publicKey.getEncoded().toArray());
            MLDSASigner signer = new MLDSASigner();
            signer.init(false, params);
            byte[] msg = message.toArray();
            signer.update(msg, 0, msg.length);
            return signer.verifySignature(signature.getEncoded().toArray());
        } catch (Exception e) {
            LOG.error("PQC verification failed", e);
            return false;
        }
    }
}
