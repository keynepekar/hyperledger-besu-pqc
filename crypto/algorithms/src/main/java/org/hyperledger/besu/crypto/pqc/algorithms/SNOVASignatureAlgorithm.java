/*
 * Copyright contributors to Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.crypto.pqc.algorithms;

import org.hyperledger.besu.crypto.pqc.PQCPublicKey;
import org.hyperledger.besu.crypto.pqc.PQCSignature;
import org.hyperledger.besu.crypto.pqc.SignatureAlgorithmFactoryPQC;
import org.hyperledger.besu.crypto.pqc.SignatureAlgorithmPQC;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.pqc.crypto.snova.SnovaParameters;
import org.bouncycastle.pqc.crypto.snova.SnovaPublicKeyParameters;
import org.bouncycastle.pqc.crypto.snova.SnovaSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** SNOVA implementation. */
public final class SNOVASignatureAlgorithm implements SignatureAlgorithmPQC {

  private static final Logger LOG = LoggerFactory.getLogger(SNOVASignatureAlgorithm.class);

  // SNOVA_24_5_4: pk=1016, sig=248
  private static final int PUBLIC_KEY_LEN = 1016;
  private static final int SIGNATURE_LEN = 248;

  public static final SNOVASignatureAlgorithm INSTANCE = new SNOVASignatureAlgorithm();

  private SNOVASignatureAlgorithm() {}

  @Override
  public byte algorithmId() {
    return SignatureAlgorithmFactoryPQC.ALG_ID_SNOVA;
  }

  @Override
  public String name() {
    return "SNOVA_24_5_4";
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
      throw new IllegalArgumentException("Invalid SNOVA public key length: " + encoded.size());
    }
    return new PQCPublicKey(encoded);
  }

  @Override
  public PQCSignature createSignature(final Bytes encoded) {
    if (encoded.size() != SIGNATURE_LEN) {
      throw new IllegalArgumentException("Invalid SNOVA signature length: " + encoded.size());
    }
    return new PQCSignature(encoded);
  }

  @Override
  public boolean verify(
      final Bytes message, final PQCSignature signature, final PQCPublicKey publicKey) {
    try {
      SnovaPublicKeyParameters params =
          new SnovaPublicKeyParameters(
              SnovaParameters.SNOVA_24_5_4_SSK, publicKey.getEncoded().toArray());
      SnovaSigner signer = new SnovaSigner();
      signer.init(false, params);
      byte[] msg = message.toArray();
      return signer.verifySignature(msg, signature.getEncoded().toArray());
    } catch (Exception e) {
      LOG.error("PQC verification failed (SNOVA)", e);
      return false;
    }
  }
}
