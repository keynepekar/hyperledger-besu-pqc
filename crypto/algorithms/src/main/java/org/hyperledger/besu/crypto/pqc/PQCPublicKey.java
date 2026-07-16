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
package org.hyperledger.besu.crypto.pqc;

import org.apache.tuweni.bytes.Bytes;

/** The PQ public key. */
public final class PQCPublicKey {

  private final Bytes encoded;

  public PQCPublicKey(final Bytes encoded) {
    this.encoded = encoded;
  }

  /** Raw binary representation of the public key. */
  public Bytes getEncoded() {
    return encoded;
  }

  public int size() {
    return encoded.size();
  }

  @Override
  public String toString() {
    return "PQCPublicKey = " + encoded.toHexString();
  }
}
