/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.crypto.pqc.algorithms;

import org.hyperledger.besu.crypto.pqc.PQCPublicKey;
import org.hyperledger.besu.crypto.pqc.PQCSignature;
import org.hyperledger.besu.crypto.pqc.SignatureAlgorithmFactoryPQC;
import org.hyperledger.besu.crypto.pqc.SignatureAlgorithmPQC;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Falcon-512 implementation (Padded).
 */
public final class FalconSignatureAlgorithm implements SignatureAlgorithmPQC {

    private static final Logger LOG = LoggerFactory.getLogger(FalconSignatureAlgorithm.class);

    // Falcon-512: pk=897 and 896 in BC, sig variable (cf liboqs, max 752 )
    // https://github.com/bcgit/bc-java/issues/2046
    private static final int PUBLIC_KEY_LEN = 896;
    private static final int MAX_SIGNATURE_LEN = 752;

    public static final FalconSignatureAlgorithm INSTANCE = new FalconSignatureAlgorithm();

    private FalconSignatureAlgorithm() {
    }

    @Override
    public byte algorithmId() {
        return SignatureAlgorithmFactoryPQC.ALG_ID_FALCON_512;
    }

    @Override
    public String name() {
        return "Falcon-512";
    }

    @Override
    public int publicKeyLength() {
        return PUBLIC_KEY_LEN;
    }

    @Override
    public int signatureLength() {
        return MAX_SIGNATURE_LEN;
    }

    @Override
    public boolean isSignatureLengthValid(final int length) {
        return length > 2 && length <= MAX_SIGNATURE_LEN;
    }

    @Override
    public PQCPublicKey createPublicKey(final Bytes encoded) {
        if (encoded.size() != PUBLIC_KEY_LEN) {
            throw new IllegalArgumentException(
                    "Invalid Falcon public key length: " + encoded.size());
        }
        return new PQCPublicKey(encoded);
    }

    @Override
    public PQCSignature createSignature(final Bytes encoded) {
        if (!isSignatureLengthValid(encoded.size())) {
            throw new IllegalArgumentException(
                    "Invalid Falcon signature length: " + encoded.size());
        }
        return new PQCSignature(encoded);
    }

    @Override
    public boolean verify(
            final Bytes message, final PQCSignature signature, final PQCPublicKey publicKey) {
        try {
            FalconPublicKeyParameters params = new FalconPublicKeyParameters(
                    FalconParameters.falcon_512, publicKey.getEncoded().toArray());
            FalconSigner signer = new FalconSigner();
            signer.init(false, params);
            byte[] msg = message.toArray();
            return signer.verifySignature(msg, signature.getEncoded().toArray());
        } catch (Exception e) {
            LOG.error("PQC verification failed (Falcon)", e);
            return false;
        }
    }
}
