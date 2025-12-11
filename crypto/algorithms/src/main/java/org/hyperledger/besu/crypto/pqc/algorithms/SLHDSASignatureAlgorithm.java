/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.crypto.pqc.algorithms;

import org.hyperledger.besu.crypto.pqc.PQCPublicKey;
import org.hyperledger.besu.crypto.pqc.PQCSignature;
import org.hyperledger.besu.crypto.pqc.SignatureAlgorithmFactoryPQC;
import org.hyperledger.besu.crypto.pqc.SignatureAlgorithmPQC;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSASigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SLH-DSA-SHA2-128s implementation.
 */
public final class SLHDSASignatureAlgorithm implements SignatureAlgorithmPQC {

    private static final Logger LOG = LoggerFactory.getLogger(SLHDSASignatureAlgorithm.class);

    // SLH-DSA-SHA2-128s: pk=32, sig=7856
    private static final int PUBLIC_KEY_LEN = 32;
    private static final int SIGNATURE_LEN = 7856;

    public static final SLHDSASignatureAlgorithm INSTANCE = new SLHDSASignatureAlgorithm();

    private SLHDSASignatureAlgorithm() {
    }

    @Override
    public byte algorithmId() {
        return SignatureAlgorithmFactoryPQC.ALG_ID_SLH_DSA_SHA2_128S;
    }

    @Override
    public String name() {
        return "SLH_DSA_PURE_SHA2_128S";
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
                    "Invalid SLH-DSA public key length: " + encoded.size());
        }
        return new PQCPublicKey(encoded);
    }

    @Override
    public PQCSignature createSignature(final Bytes encoded) {
        if (encoded.size() != SIGNATURE_LEN) {
            throw new IllegalArgumentException(
                    "Invalid SLH-DSA signature length: " + encoded.size());
        }
        return new PQCSignature(encoded);
    }

    @Override
    public boolean verify(
            final Bytes message, final PQCSignature signature, final PQCPublicKey publicKey) {
        try {
            SLHDSAPublicKeyParameters params = new SLHDSAPublicKeyParameters(
                    SLHDSAParameters.sha2_128s, publicKey.getEncoded().toArray());
            SLHDSASigner signer = new SLHDSASigner();
            signer.init(false, params);
            byte[] msg = message.toArray();
            return signer.verifySignature(msg, signature.getEncoded().toArray());
        } catch (Exception e) {
            LOG.error("PQC verification failed (SLH-DSA)", e);
            return false;
        }
    }
}
