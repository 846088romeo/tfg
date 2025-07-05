/*

 AnBx Java Security Library

 Copyright 2011-2014 Paolo Modesti
 Copyright 2013-2014 School of Computing Science, Newcastle University
 Copyright 2011-2012 DAIS, Universita' Ca' Foscari Venezia
   
 This file is part of AnBx

 AnBx is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 any later version.

 AnBx is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with AnBx. If not, see <http://www.gnu.org/licenses/>.

 */

package anbxj;

import java.io.Serializable;

import javax.crypto.SecretKey;


/**
 * A class to store the result of an HMAC operation along with metadata about the used algorithm.
 * Moreover, it allows carrying information for AnBx private or public digests.
 */
public class Crypto_HmacPair implements Serializable {

	 /**
     * Unique identifier for serialisation.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Hash value resulting from the HMAC operation.
     */
    private Crypto_ByteArray hashValue;

    /**
     * Sealed Pair used in case of a secret random hash.
     */
    private Crypto_SealedPair k;

    /**
     * Secret Key used in case of a public random hash.
     */
    private SecretKey sk;

    /**
     * HMAC algorithm used.
     */
    private String HMacAlgorithm;

    /**
     * Constructs a Crypto_HmacPair with the specified parameters.
     *
     * @param hashValue      The hash value.
     * @param k              The sealed pair.
     * @param HMacAlgorithm  The HMAC algorithm.
     */
    public Crypto_HmacPair(Crypto_ByteArray hashValue, Crypto_SealedPair k, String HMacAlgorithm) {
        super();
        this.hashValue = hashValue;
        this.k = k;
        this.HMacAlgorithm = HMacAlgorithm;
    }

    /**
     * Constructs a Crypto_HmacPair with the specified parameters.
     *
     * @param hashValue      The hash value.
     * @param sk             The secret key.
     * @param HMacAlgorithm  The HMAC algorithm.
     */
    public Crypto_HmacPair(Crypto_ByteArray hashValue, SecretKey sk, String HMacAlgorithm) {
        super();
        this.hashValue = hashValue;
        this.sk = sk;
        this.HMacAlgorithm = HMacAlgorithm;
    }

    /**
     * Gets the hash value.
     *
     * @return The hash value.
     */
    public Crypto_ByteArray getHashValue() {
        return hashValue;
    }

    /**
     * Gets the sealed pair.
     *
     * @return The sealed pair.
     */
    public Crypto_SealedPair getK() {
        return k;
    }

    /**
     * Gets the secret key.
     *
     * @return The secret key.
     */
    public SecretKey getSK() {
        return sk;
    }

    /**
     * Gets the HMAC algorithm.
     *
     * @return The HMAC algorithm.
     */
    public String getAlgorithm() {
        return HMacAlgorithm;
    }

    /**
     * Anonymizes the HMAC pair by removing the public secret key.
     */
    public void anonymize() {
        // remove the public SK
        sk = null;
    }

    /**
     * Returns a string representation of the Crypto_HmacPair.
     */
    @Override
    public String toString() {
        return "Crypto_HmacPair [hashValue=" + hashValue + ", k=" + k + ", sk=" + sk + ", HMacAlgorithm=" + HMacAlgorithm + "]";
    }
}
