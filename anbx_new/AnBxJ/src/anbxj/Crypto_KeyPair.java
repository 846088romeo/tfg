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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Represents a public/private key pair.
 */

public class Crypto_KeyPair {

    private KeyPair pair;

    /**
     * Constructs a Crypto_KeyPair with the specified key algorithm and size.
     *
     * @param keyAlgorithm The key algorithm.
     * @param keySize      The key size.
     */
    public Crypto_KeyPair(String keyAlgorithm, int keySize) {
        KeyPairGenerator keyGen = null;
        
        try {
            keyGen = KeyPairGenerator.getInstance(keyAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keyGen.initialize(keySize);
        pair = keyGen.generateKeyPair();
    }

    /**
     * Constructs a Crypto_KeyPair with the specified key algorithm, size and provider.
     *
     * @param keyAlgorithm The key algorithm.
     * @param keySize      The key size.
     * @param provider 	   The security provider.
     */
    public Crypto_KeyPair(String keyAlgorithm, int keySize, String provider) {
        KeyPairGenerator keyGen = null;
        
        try {
            keyGen = KeyPairGenerator.getInstance(keyAlgorithm, provider);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        keyGen.initialize(keySize);
        pair = keyGen.generateKeyPair();
    }    
    
    /**
     * Gets the public key in the key pair.
     *
     * @return The public key.
     */
    public PublicKey getPublicKey() {
        return pair.getPublic();
    }

    /**
     * Gets the private key in the key pair.
     *
     * @return The private key.
     */
    protected PrivateKey getPrivateKey() {
        return pair.getPrivate();
    }
}
