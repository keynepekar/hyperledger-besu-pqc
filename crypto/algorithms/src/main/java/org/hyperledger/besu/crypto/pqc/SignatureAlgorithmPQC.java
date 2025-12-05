/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.crypto.pqc;

import org.apache.tuweni.bytes.Bytes;

/**
 * The interface for PQ Signature algorithms.
 * NB : only handles verification
 */
public interface SignatureAlgorithmPQC {

  /** Identifier (1st byte of payload) */
  byte algorithmId();

  /** Algorithm name */
  String name();

  /** Public key length (in bytes) */
  int publicKeyLength();

  /** Signature length (in bytes) */
  int signatureLength();

  /**
   * Create PQ public key.
   *
   * @param encoded the encoded
   * @return the PQ public key
   */
  PQCPublicKey createPublicKey(Bytes encoded);

  /**
   * Create PQ signature.
   *
   * @param encoded the encoded
   * @return the PQ signature
   */
  PQCSignature createSignature(Bytes encoded);

  /**
   * Verify given message digest data, signature and public key.
   *
   * @param data      the data
   * @param signature the signature
   * @param pub       the pub
   * @return the boolean
   */
  boolean verify(Bytes data, PQCSignature signature, PQCPublicKey pub);
}
