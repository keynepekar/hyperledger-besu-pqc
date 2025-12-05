/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.crypto.pqc;

import org.apache.tuweni.bytes.Bytes;

/** The PQ signature. */
public final class PQCSignature {

  private final Bytes encoded;

  public PQCSignature(final Bytes encoded) {
    this.encoded = encoded;
  }

  /** Raw binary representation of the signature. */
  public Bytes getEncoded() {
    return encoded;
  }

  public int size() {
    return encoded.size();
  }

  @Override
  public String toString() {
    return "PQCSignature = " + encoded.toHexString();
  }
}
