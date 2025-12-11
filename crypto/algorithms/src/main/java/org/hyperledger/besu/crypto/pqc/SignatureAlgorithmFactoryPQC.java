/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.crypto.pqc;

import org.hyperledger.besu.crypto.pqc.algorithms.FalconSignatureAlgorithm;
import org.hyperledger.besu.crypto.pqc.algorithms.MAYOSignatureAlgorithm;
import org.hyperledger.besu.crypto.pqc.algorithms.MLDSA44SignatureAlgorithm;
import org.hyperledger.besu.crypto.pqc.algorithms.SLHDSASignatureAlgorithm;
import org.hyperledger.besu.crypto.pqc.algorithms.SNOVASignatureAlgorithm;

/** The PQ Signature algorithm factory. */
public final class SignatureAlgorithmFactoryPQC {

  /**
   * 1 = ML-DSA-44
   */
  public static final byte ALG_ID_ML_DSA_44 = 0x01;
  public static final byte ALG_ID_FALCON_512 = 0x02;
  public static final byte ALG_ID_SLH_DSA_SHA2_128S = 0x03;
  public static final byte ALG_ID_SNOVA = 0x04;
  public static final byte ALG_ID_MAYO = 0x05;

  private SignatureAlgorithmFactoryPQC() {
  }

  /**
   * Returns the PQ implementation for a given algorithm
   *
   * @throws IllegalArgumentException if algId is unknown
   */
  public static SignatureAlgorithmPQC getInstance(final byte algId) {
    switch (algId) {
      case ALG_ID_ML_DSA_44:
        return MLDSA44SignatureAlgorithm.INSTANCE;
      case ALG_ID_FALCON_512:
        return FalconSignatureAlgorithm.INSTANCE;
      case ALG_ID_SLH_DSA_SHA2_128S:
        return SLHDSASignatureAlgorithm.INSTANCE;
      case ALG_ID_SNOVA:
        return SNOVASignatureAlgorithm.INSTANCE;
      case ALG_ID_MAYO:
        return MAYOSignatureAlgorithm.INSTANCE;
      default:
        throw new IllegalArgumentException(
            "Unknown PQ algorithm id: " + Byte.toUnsignedInt(algId));
    }
  }
}
