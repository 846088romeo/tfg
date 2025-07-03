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
 * Default values for cryptographic engine configuration.
 */
public class Crypto_Config_Default {

    /**
     * Cipher Algorithm Name/Cipher Algorithm Mode/Cipher Algorithm Padding (Symmetric Encryption)
     */
    public static String cipherScheme = "AES/CBC/PKCS5Padding";

    /**
     * Key length in bits for ciphers supporting different key lengths
     */
    public static int keySize = 256;

    /**
     * KeyGenerator Algorithm Name used for dynamic key generation (Symmetric Encryption)
     */
    public static String keyGenerationScheme = "AES";

    /**
     * Key length in bits for ciphers, used for dynamic key generation, supporting different key lengths
     */
    public static int keyGenerationSize = 256;

    /**
     * SecretKeyFactory Algorithm used for Password Based Encryption (PBE) dynamic key generation (Symmetric Encryption)
     */
    public static String keyGenerationSchemePBE = "PBKDF2WithHmacSHA512";

    /**
     * KeyPairGenerator Algorithm dynamic creation of Key Pairs (Asymmetric Encryption)
     */
    public static String keyPairGenerationScheme = "RSA";

    /**
     * KeyPairGenerator key length for dynamic creation of Key Pairs
     */
    public static int keyPairGenerationSize = 2048;

    /**
     * SecureRandom Number Generation Algorithm
     */
    public static String secureRandomAlgorithm = "DRBG";

    /**
     * KeyGenerator Algorithms for Hmac
     */
    public static String hmacAlgorithm = "HmacSHA1"; // default hmac algorithm

    /**
     * MessageDigest Algorithm (Hash)
     */
    public static String messageDigestAlgorithm = "SHA-256";

    /**
     * MessageDigest Signature Algorithm (Hash)
     * Corresponds to the "digest" part of "digest"with"encryption" of the Signature algorithm name 
     */
    public static String messageDigestSignatureAlgorithm = "SHA256";
    
    /**
     * KeyAgreement Algorithm
     */
    public static String keyAgreementAlgorithm = "DH";
    
    /**
     * KeyPairGeneration for KeyAgreement Algorithm
     */
    public static String keyAgreementKeyPairGenerationScheme = "DH";
    
    /**
     * Random Exponent length in bit for Diffie-Hellman key agreement
     */
    public static int dhRndExpSize = 2048;

    /**
     * Elliptic Curve.
     */
    public static String ecGenParameterSpec = "secp256r1";
        
    /**
     * Asymmetric encryption scheme block mode (experimental)
     */
    public static String asymCipherSchemeBlock = "RSA";

    /**
     * Length of the asymmetric encryption block for encryption
     */
    public static int asymBlockLengthEnc = 100;

    /**
     * Length of the asymmetric encryption block for decryption
     */
    public static int asymBlockLengthDec = 128;
    
    /**
     * SSL Context
     */
    public static String sslContext = "TLSv1.2";

    /**
     * The default security provider
     */
    public static String securityProvider = "default";
    
    
    /**
     * Default constructor
     */
    
	public Crypto_Config_Default() {
        super();
    }
    
} 	
