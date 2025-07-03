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

/**
 * Enumerates key stores for different key purposes in the cryptographic API.
 */
public enum Crypto_KeyStoreType {
    /**
     * KeyStore type TLS
     */
	
	tls, 
	
	/**
     * KeyStore type encryption
     */
	
	enc, 
	
	/**
     * KeyStore type signature
     */
	
	sig,
	
	/**
     * KeyStore type hmac
     */
	
	hmc;

    /**
     * Checks if the key store is for secret keys.
     *
     * @return true if the key store is for secret keys, false otherwise.
     */
    public boolean is_CryptoKeyStoreSK() {
        switch (this) {
            case sig:
                return true;
            default:
                return false;
        }
    }

    /**
     * Checks if the key store is for public keys.
     *
     * @return true if the key store is for public keys, false otherwise.
     */
    public boolean is_CryptoKeyStorePK() {
        switch (this) {
            case enc:
            case hmc:
                return true;
            default:
                return false;
        }
    }

    /**
     * Gets the key store type for public keys.
     *
     * @return The key store type for public keys.
     */
    public static Crypto_KeyStoreType pk() {
        return enc;
    }

    /**
     * Gets the key store type for secret keys.
     *
     * @return The key store type for secret keys.
     */
    public static Crypto_KeyStoreType sk() {
        return sig;
    }

    /**
     * Gets the key store type for hybrid keys.
     *
     * @return The key store type for hybrid keys.
     */
    public static Crypto_KeyStoreType hk() {
        return hmc;
    }

    /**
     * Gets the key store type for identity.
     *
     * @return The key store type for identity.
     */
    public static Crypto_KeyStoreType ident_ks() {
        return sk();
    }
}

