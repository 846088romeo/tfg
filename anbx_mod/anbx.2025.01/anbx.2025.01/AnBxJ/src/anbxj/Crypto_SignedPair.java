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
import java.security.SignedObject;
import java.util.Objects;

/**
 * Represents a signed pair of objects (SignedObject, Object) used for digital signatures.
 */
public class Crypto_SignedPair implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * The signed object.
     * <p>
     * This field holds a signed object, which is an instance of {@code SignedObject}.
     * </p>
     */
    private final SignedObject signedObject;

    /**
     * The signed content.
     * <p>
     * This field holds the content that has been signed. The type of the content can vary depending on the context.
     * </p>
     */
    private final Object signedContent;

    /**
     * The signature scheme used.
     * <p>
     * This field stores the signature scheme used for signing as a String.
     * </p>
     */
    private final String signatureScheme;


    /**
     * Constructs a Crypto_SignedPair with the specified SignedObject, object, and signature scheme.
     *
     * @param signedObject    The SignedObject.
     * @param signedContent   The object.
     * @param signatureScheme The signature scheme used for digital signatures.
     */
    public Crypto_SignedPair(SignedObject signedObject, Object signedContent, String signatureScheme) {
        this.signedObject = signedObject;
        this.signedContent = signedContent;
        this.signatureScheme = signatureScheme;
    }

    /**
     * Gets the signed content in the signed pair.
     *
     * @return The signed content.
     */
    public Object getSignedContent() {
        return signedContent;
    }

    /**
     * Gets the signature scheme used for digital signatures.
     *
     * @return The signature scheme.
     */
    public String getSignatureScheme() {
        return signatureScheme;
    }

    /**
     * Gets the SignedObject in the signed pair.
     *
     * @return The SignedObject.
     */
    public SignedObject getSignedObject() {
        return signedObject;
    }

    @Override
    public int hashCode() {
        return Objects.hash(signedObject, signedContent, signatureScheme);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        Crypto_SignedPair other = (Crypto_SignedPair) obj;
        return Objects.equals(signedObject, other.signedObject) &&
               Objects.equals(signedContent, other.signedContent) &&
               Objects.equals(signatureScheme, other.signatureScheme);
    }

    @Override
    public String toString() {
        return "Crypto_SignedPair{" +
               "signedObject=" + signedObject +
               ", signedContent=" + signedContent +
               ", signatureScheme='" + signatureScheme + '\'' +
               '}';
    }
}

