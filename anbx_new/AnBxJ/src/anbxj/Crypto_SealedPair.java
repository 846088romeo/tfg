/*

 AnBx Java Security Library

 Copyright 2011-2024 Paolo Modesti
 Copyright 2018-2024 SCM/SCDT/SCEDT, Teesside University
 Copyright 2016-2018 School of Computer Science, University of Sunderland
 Copyright 2013-2015 School of Computing Science, Newcastle University
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
import java.util.Objects;
import javax.crypto.SealedObject;

/**
 * Represents a sealed pair of objects (key, message) used for encryption.
 */
public class Crypto_SealedPair implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * The sealed key.
     * <p>
     * This field holds the sealed key, which is an instance of {@code SealedObject}.
     * </p>
     */
    private final SealedObject sealedKey;

    /**
     * The sealed message.
     * <p>
     * This field holds the sealed message, which is an instance of {@code SealedObject}.
     * </p>
     */
    private final SealedObject sealedMessage;

    /**
     * The cipher scheme used.
     * <p>
     * This field stores the cipher scheme used for encryption as a String.
     * </p>
     */
    private final String cipherScheme;

    /**
     * The cryptographic byte array digest.
     * <p>
     * This field represents a cryptographic byte array digest, possibly used for cryptographic operations.
     * </p>
     */
    private final Crypto_ByteArray digest;


    /**
     * Constructs a Crypto_SealedPair with the specified sealed key, message, and cipher scheme.
     *
     * @param sealedKey    The sealed key.
     * @param sealedMessage The sealed message.
     * @param cipherScheme The cipher scheme used for encryption.
     */
    public Crypto_SealedPair(SealedObject sealedKey, SealedObject sealedMessage, String cipherScheme) {
        this(sealedKey, sealedMessage, cipherScheme, null);
    }

    /**
     * Constructs a Crypto_SealedPair with the specified sealed key, message, cipher scheme, and digest.
     *
     * @param sealedKey    The sealed key.
     * @param sealedMessage The sealed message.
     * @param cipherScheme The cipher scheme used for encryption.
     * @param digest       The digest for checking equality of objects (for testing).
     */
    public Crypto_SealedPair(SealedObject sealedKey, SealedObject sealedMessage, String cipherScheme, Crypto_ByteArray digest) {
        this.sealedKey = sealedKey;
        this.sealedMessage = sealedMessage;
        this.cipherScheme = cipherScheme;
        this.digest = digest;
    }

    /**
     * Returns the cipher scheme used.
     * 
     * @return the cipher scheme as a String.
     */
    public String getCipherScheme() {
        return cipherScheme;
    }

    /**
     * Returns the sealed key.
     * <p>
     * This method provides the sealed key, which is an instance of {@code SealedObject}.
     * </p>
     * 
     * @return the sealed key.
     */
    public SealedObject getSealedKey() {
        return sealedKey;
    }

    /**
     * Returns the sealed message.
     * <p>
     * This method provides the sealed message, which is an instance of {@code SealedObject}.
     * </p>
     * 
     * @return the sealed message.
     */
    public SealedObject getSealedMessage() {
        return sealedMessage;
    }


    @Override
    public int hashCode() {
        return Objects.hash(cipherScheme, digest, sealedKey, sealedMessage);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        Crypto_SealedPair other = (Crypto_SealedPair) obj;
        return Objects.equals(cipherScheme, other.cipherScheme) &&
               Objects.equals(digest, other.digest) &&
               Objects.equals(sealedKey, other.sealedKey) &&
               Objects.equals(sealedMessage, other.sealedMessage);
    }

    @Override
    public String toString() {
        return "Crypto_SealedPair{" +
               "sealedKey=" + sealedKey +
               ", sealedMessage=" + sealedMessage +
               ", cipherScheme='" + cipherScheme + '\'' +
               '}';
    }
}
