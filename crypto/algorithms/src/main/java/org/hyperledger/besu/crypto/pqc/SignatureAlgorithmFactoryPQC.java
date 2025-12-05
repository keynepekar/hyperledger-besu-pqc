/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.crypto.pqc;

import org.hyperledger.besu.crypto.pqc.algorithms.MLDSA44SignatureAlgorithm;

/** The PQ Signature algorithm factory. */
public final class SignatureAlgorithmFactoryPQC {

  /**
   * 1 = ML-DSA-44
   */
  public static final byte ALG_ID_ML_DSA_44 = 0x01;

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
      default:
        throw new IllegalArgumentException(
            "Unknown PQ algorithm id: " + Byte.toUnsignedInt(algId));
    }
  }
}
