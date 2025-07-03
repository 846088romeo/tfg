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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignedObject;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.NamedParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Cryptographic engine
 */

public class Crypto_EncryptionEngine {
	
	
	private Crypto_KeyStoreBuilder_Map ksbd;

	// crypto config values -- see Crypto_Config and Crypto_Config_Default

	private Crypto_Config cryptoConfig = null; 

	private int asymBlockLengthEnc = Crypto_Config_Default.asymBlockLengthEnc;
	private int asymBlockLengthDec = Crypto_Config_Default.asymBlockLengthDec;

	private CertPath TSA_CertPath;

	void setCryptoConfig(Crypto_Config config) {
		
		this.cryptoConfig = config;

		// some sanity check can be done on parameters
	}

	static Map<String, String> specialSignatureCases = new HashMap<>();
	// https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html#signature-algorithms
    static {
    	specialSignatureCases.put("EdDSA", "EdDSA");
    	specialSignatureCases.put("Ed25519", "Ed25519");
    	specialSignatureCases.put("Ed448", "Ed448");
    	specialSignatureCases.put("HSS/LMS", "HSS/LMS");
    	specialSignatureCases.put("RSASSA-PSS", "RSASSA-PSS");
    	specialSignatureCases.put("NONEwithRSA", "NONEwithRSA");
    	specialSignatureCases.put("NONEwithDSA", "NONEwithDSA");
    	specialSignatureCases.put("NONEwithECDSA", "NONEwithECDSA");
        // Add more special cases as needed
    }
		
	private final static AnBx_Layers layer = AnBx_Layers.ENCRYPTION;

	private Crypto_TimeStampValidator seqNumValidator;

	    /**
     * Constructor for Crypto_EncryptionEngine.
     *
     * @param ksbd The Crypto_KeyStoreBuilder_Map.
     */
    
	public Crypto_EncryptionEngine(Crypto_KeyStoreBuilder_Map ksbd) {
		this.ksbd = ksbd;
		this.cryptoConfig = new Crypto_Config();
		// this.setTSA_CertPath();
		this.seqNumValidator = new Crypto_TimeStampValidator();
	}

    /**
     * Constructor for Crypto_EncryptionEngine.
     *
     * @param ksbd   The Crypto_KeyStoreBuilder_Map.
     * @param config The Crypto_Config.
     */
	
	public Crypto_EncryptionEngine(Crypto_KeyStoreBuilder_Map ksbd, Crypto_Config config) {
		this.ksbd = ksbd;
		// this.setTSA_CertPath();
		this.seqNumValidator = new Crypto_TimeStampValidator();
		this.setCryptoConfig(config);
	}

    /**
     * Gets the available cryptographic implementations for a service type.
     *
     * @param serviceType The service type.
     * @return An array of available cryptographic implementations.
     */
	@SuppressWarnings("unused")
	private static String[] getCryptoImpls(String serviceType) {
	    Set<String> result = new HashSet<>();

	    Provider[] providers = Security.getProviders();
	    for (Provider provider : providers) {
	        Set<Object> keys = provider.keySet();
	        for (Object keyObj : keys) {
	            String key = (String) keyObj;
	            if (key.startsWith(serviceType + ".") || key.startsWith("Alg.Alias." + serviceType + ".")) {
	                String implementation = key.split(" ")[0];
	                int startIndex = key.startsWith(serviceType + ".") ? serviceType.length() + 1 : serviceType.length() + 11;
	                result.add(implementation.substring(startIndex));
	            }
	        }
	    }

	    return result.toArray(new String[0]);
	}


    /**
     * Serializes an object into a byte array.
     *
     * @param obj The object to serialize.
     * @return The serialized byte array.
     */	
	
	private static byte[] serialize(Object obj) {
	    try (ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
	         ObjectOutputStream dataOut = new ObjectOutputStream(byteOut)) {
	        dataOut.writeObject(obj);
	        AnBx_Debug.out(layer, "makeBytes - " + obj.getClass().getName() + ".toString: " + obj);
	        AnBx_Debug.out(layer, "makeBytes - " + obj.getClass().getName() + ".hashCode: " + obj.hashCode());
	        AnBx_Debug.out(layer, "makeBytes - ByteArrayOutputStream.size: " + byteOut.size());
	        AnBx_Debug.out(layer, "makeBytes - ByteArrayOutputStream.toByteArray: " + byteOut.toByteArray());
	        return byteOut.toByteArray();
	    } catch (IOException e) {
	        return new byte[0];
	    }
	}


    /**
     * Deserializes a byte array into an object.
     *
     * @param data The byte array to deserialize.
     * @return The deserialized object.
     */	
	
	private static Object deserialize(byte[] data) {
	    AnBx_Debug.out(layer, "deserialize - data.length: " + data.length);
	    AnBx_Debug.out(layer, "deserialize - data.hashCode: " + data.hashCode());
	    try (ByteArrayInputStream in = new ByteArrayInputStream(data);
	         ObjectInputStream is = new ObjectInputStream(in)) {
	        Object obj = is.readObject();
	        AnBx_Debug.out(layer, "deserialize - obj: " + obj);
	        AnBx_Debug.out(layer, "deserialize - obj.hashCode: " + obj.hashCode());
	        return obj;
	    } catch (IOException | ClassNotFoundException e) {
	        e.printStackTrace();
	    }
	    return null;
	}


    /**
     * Writes an object to a file.
     *
     * @param obj      The object to write.
     * @param filename The filename to save the object.
     */
	
	public static void writeObject(Object obj, String filename) {
	    try (FileOutputStream fileOut = new FileOutputStream(filename);
	         ObjectOutputStream out = new ObjectOutputStream(fileOut)) {
	        out.writeObject(obj);
	        AnBx_Debug.out(layer, "saveObject - " + obj.getClass().getName() + ".toString: " + obj.toString());
	        AnBx_Debug.out(layer, "saveObject - " + obj.getClass().getName() + ".hashCode: " + obj.hashCode());
	        AnBx_Debug.out(layer, "saveObject - Serialized data is saved in " + filename);
	    } catch (IOException e) {
	        e.printStackTrace();
	    }
	}


    /**
     * Reads an object from a file.
     *
     * @param filename The filename to read the object from.
     * @return The read object.
     */
	
	public static Object readObject(String filename) {
	    Object obj = null;
	    try (FileInputStream fileIn = new FileInputStream(filename);
	         ObjectInputStream in = new ObjectInputStream(fileIn)) {
	        AnBx_Debug.out(layer, "readObject - Serialized data from " + filename);
	        obj = in.readObject();
	        AnBx_Debug.out(layer, "readObject - " + obj.getClass().getName() + ".toString: " + obj.toString());
	        AnBx_Debug.out(layer, "readObject - " + obj.getClass().getName() + ".hashCode: " + obj.hashCode());
	    } catch (IOException i) {
	        i.printStackTrace();
	        return obj;
	    } catch (ClassNotFoundException c) {
	        System.out.println("Class not found");
	        c.printStackTrace();
	        return null;
	    }
	    return obj;
	}


    /**
     * Generates a key pair.
     *
     * @return The generated key pair.
     */
	
	public Crypto_KeyPair getKeyPair() {
		
		if (Crypto_Config.testStr(cryptoConfig.keyPairGenerationSchemeProvider))
			return new Crypto_KeyPair(cryptoConfig.keyPairGenerationScheme, cryptoConfig.keyPairGenerationSize, cryptoConfig.keyGenerationSchemeProvider);
		else
			return new Crypto_KeyPair(cryptoConfig.keyPairGenerationScheme, cryptoConfig.keyPairGenerationSize);
	}
	
    /**
     * Gets the public key from a key pair.
     *
     * @param pair The key pair.
     * @return The public key.
     */

	public PublicKey getKeyPair_PublicKey(Crypto_KeyPair pair) {
		return pair.getPublicKey();
	}

    /**
     * Checks if a given digest matches the calculated digest of an object.
     *
     * @param obj    The object to check the digest.
     * @param digest The digest to compare.
     * @return True if the digests match, false otherwise.
     */
	
	public boolean checkDigest(Object obj, Crypto_ByteArray digest) {
	    return digest.equals(makeDigest(obj));
	}


    /**
     * Calculates the digest of an object.
     *
     * @param obj The object to calculate the digest.
     * @return The calculated digest.
     */
	
	public Crypto_ByteArray makeDigest(Object obj) {
	    // Log object details and algorithm
	    AnBx_Debug.out(layer, "Digest Generation - obj: " + obj.getClass().getName());
	    AnBx_Debug.out(layer, "Digest Generation - obj.hashCode: " + obj.hashCode());
	    AnBx_Debug.out(layer, "Digest Generation - obj.toString: " + obj.toString());
	    AnBx_Debug.out(layer, "Digest Generation - messageDigestAlgorithm: " + cryptoConfig.messageDigestAlgorithm);

	    try {
	        // Initialise MessageDigest with algorithm and provider
	        MessageDigest md = Crypto_Config.testStr(cryptoConfig.messageDigestProvider)
	        		? MessageDigest.getInstance(cryptoConfig.messageDigestAlgorithm, cryptoConfig.messageDigestProvider)
	        		: MessageDigest.getInstance(cryptoConfig.messageDigestAlgorithm);
	        
	        // Reset and update digest with serialised object
	        md.reset();
	        byte[] serializedObj = serialize(obj);

	        // Log serialised object details
	        AnBx_Debug.out(layer, "Digest Generation - serialize(obj).length: " + serializedObj.length);
	        md.update(serializedObj);

	        // Compute final digest
	        Crypto_ByteArray digest = new Crypto_ByteArray(md.digest());
	        AnBx_Debug.out(layer, "Digest Generation - algorithm: " + md.getAlgorithm() + " - length: " + md.getDigestLength());
	        AnBx_Debug.out(layer, "Digest Generation - digest: " + digest.toString());
	        AnBx_Debug.out(layer, "Digest Generation - hashCode: " + digest.hashCode());
	        return digest;

	    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
	        e.printStackTrace();
	        return null;
	    }
	}

    /**
     * Calculates the HMAC value of an object using a secret key.
     *
     * @param obj The object to calculate the HMAC value.
     * @param key The secret key for HMAC.
     * @return The calculated HMAC value.
     */
	
	public Crypto_ByteArray makeHmacValue(Object obj, SecretKey key) {
	    try {
	        // Create a MAC object using the configured algorithm and provider
	        Mac mac = Crypto_Config.testStr(cryptoConfig.hmacProvider) 
	                  ? Mac.getInstance(cryptoConfig.hmacAlgorithm, cryptoConfig.hmacProvider)
	                  : Mac.getInstance(cryptoConfig.hmacAlgorithm);

	        // Initialise the MAC with the provided key
	        mac.init(key);

	        // Compute the HMAC for the serialised object and return the result
	        byte[] digest = mac.doFinal(serialize(obj));
	        return new Crypto_ByteArray(digest);
	    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
	        e.printStackTrace();
	        return null;
	    }
	}


    /**
     * Creates an HMAC pair using a secret key as a randomiser.
     *
     * @param obj The object to generate the HMAC pair.
     * @param sk  The secret key for HMAC.
     * @return The generated HMAC pair.
     */
	
	public Crypto_HmacPair makeHmacRnd(Object obj, SecretKey sk) {
	    try {
	        // Initialise KeyGenerator with algorithm and provider
	        KeyGenerator keyGen = Crypto_Config.testStr(cryptoConfig.hmacProvider) 
	                             ? KeyGenerator.getInstance(cryptoConfig.hmacAlgorithm, cryptoConfig.hmacProvider) 
	                             : KeyGenerator.getInstance(cryptoConfig.hmacAlgorithm);

	        // Generate the SecretKey
	        SecretKey key = keyGen.generateKey();
	        printStatus("HMAC Key Generation", key, null, keyGen.getProvider());

	        // Create HMAC value
	        Crypto_ByteArray hashValue = makeHmacValue(obj, key);

	        // Encrypt the key
	        SealedObject so = encrypt(key, sk);
	        printStatus("HMAC Computed", key, so, keyGen.getProvider());

	        // Create Crypto_SealedPair
	        Crypto_SealedPair sp = new Crypto_SealedPair(so, so, sk.getAlgorithm());

	        // Return the Crypto_HmacPair
	        return new Crypto_HmacPair(hashValue, sp, key.getAlgorithm());

	    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
	        e.printStackTrace();
	        return null;
	    }
	}


    /**
     * Creates an HMAC pair using a specified alias.
     *
     * @param obj   The object to generate the HMAC pair.
     * @param alias The alias for key generation.
     * @return The generated HMAC pair.
     */
	
	public Crypto_HmacPair makeHmac(Object obj, String alias) {
	    try {
	        // Generate a key using the configured algorithm and provider
	        // Initialise KeyGenerator with algorithm and provider
	        KeyGenerator keyGen = Crypto_Config.testStr(cryptoConfig.hmacProvider) 
	                             ? KeyGenerator.getInstance(cryptoConfig.hmacAlgorithm, cryptoConfig.hmacProvider) 
	                             : KeyGenerator.getInstance(cryptoConfig.hmacAlgorithm);
	        
	        SecretKey key = keyGen.generateKey();

	        // Compute HMAC value
	        Crypto_ByteArray so = makeHmacValue(obj, key);

	        // Log key generation and HMAC computation
	        printStatus("HMAC Key Generation", key, null, keyGen.getProvider());
	        printStatus("HMAC Computed", key, so, keyGen.getProvider());

	        // Create Crypto_HmacPair based on whether alias is provided
	        if (alias != null) {
	            return new Crypto_HmacPair(so, encrypt(key, alias, Crypto_KeyStoreType.hk()), key.getAlgorithm());
	        } else {
	            return new Crypto_HmacPair(so, key, key.getAlgorithm());
	        }
	    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
	        e.printStackTrace();
	        return null;
	    }
	}


    /**
     * Verifies the integrity of an HMAC pair.
     *
     * @param obj  The object used to compute the original HMAC pair.
     * @param hmac The HMAC pair to verify.
     * @return True if verification is successful, false otherwise.
     */
	
	public boolean checkHmacPair(Object obj, Crypto_HmacPair hmac) {
	    try {
	        // Retrieve or use the provided secret key
	        SecretKey key = (hmac.getK() != null) 
	                        ? (SecretKey) decrypt(hmac.getK(), Crypto_KeyStoreType.hk()) 
	                        : hmac.getSK();

	        // Compute the HMAC value
	        Crypto_ByteArray hashValue = makeHmacValue(obj, key);
	        printStatus("HMAC Computed", key, hashValue, null);

	        // Log verification details
	        AnBx_Debug.out(layer, "HMAC Verification - " + hmac.getAlgorithm() + ": " + hashValue.toString());

	        // Verify and log the result
	        boolean verificationResult = hashValue.equals(hmac.getHashValue());
	        AnBx_Debug.out(layer, verificationResult ? "HMAC Verification OK" : "HMAC Verification FAILED");
	        return verificationResult;

	    } catch (Exception e) {
	        e.printStackTrace();
	        return false;
	    }
	}



    /**
     * Verifies the integrity of an HMAC pair using a secret key as a randomizer.
     *
     * @param obj The object used to compute the original HMAC pair.
     * @param hmac The HMAC pair to verify.
     * @param sk The secret key used for randomization.
     * @return True if verification is successful, false otherwise.
     */
	
	public boolean checkHmacPairRnd(Object obj, Crypto_HmacPair hmac, SecretKey sk) {
	    try {
	        // Recompute the HMAC using the provided object and secret key
	        Crypto_HmacPair hashValue = makeHmacRnd(obj, sk);
	        AnBx_Debug.out(layer, "HMAC Verification - " + hmac.getAlgorithm() + ": " + hashValue.toString());

	        // Verify the computed HMAC against the provided HMAC
	        boolean verificationResult = hashValue.getHashValue().equals(hmac.getHashValue());
	        AnBx_Debug.out(layer, verificationResult ? "HMAC Verification OK" : "HMAC Verification FAILED");
	        return verificationResult;

	    } catch (Exception e) {
	        e.printStackTrace();
	        return false;
	    }
	}


    /**
     * Verifies the integrity of an HMAC value.
     *
     * @param obj  The object used to compute the original HMAC.
     * @param hmac The HMAC value to verify.
     * @param sk   The secret key for HMAC.
     * @return True if verification is successful, false otherwise.
     */
	
	public boolean checkHmacValue(Object obj, Crypto_ByteArray hmac, SecretKey sk) {
	    try {
	        // Compute the HMAC for the provided object using the secret key
	        Crypto_ByteArray computedHashValue = makeHmacValue(obj, sk);

	        // Verify the computed HMAC against the provided HMAC
	        boolean isHmacValid = computedHashValue.equals(hmac);
	        AnBx_Debug.out(layer, isHmacValid ? "HMAC Verification OK" : "HMAC Verification FAILED");
	        
	        return isHmacValid;
	    } catch (Exception e) {
	        e.printStackTrace();
	        return false;
	    }
	}


    /**
     * Generates a symmetric key using a password and salt.
     *
     * @param password The password for key generation.
     * @param salt     The salt for key generation.
     * @return The generated symmetric key.
     */
	
	public SecretKey getSymmetricKeyPBE(String password, String salt) {
	    try {
	        // Initialise SecretKeyFactory with the configured algorithm and provider
	        SecretKeyFactory skf = Crypto_Config.testStr(cryptoConfig.keyGenerationSchemePBEProvider) 
	                               ? SecretKeyFactory.getInstance(cryptoConfig.keyGenerationSchemePBE, cryptoConfig.keyGenerationSchemePBEProvider) 
	                               : SecretKeyFactory.getInstance(cryptoConfig.keyGenerationSchemePBE);

	        // Specify PBE key specifications
	        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, cryptoConfig.keySize);

	        // Generate the PBE key and convert it to the desired format
	        SecretKey tmp = skf.generateSecret(spec);
	        SecretKey symmetricKey = new SecretKeySpec(tmp.getEncoded(), cryptoConfig.keyGenerationScheme);

	        // Log the status of the key generation
	        printStatus("PBE Key Generated [Sym]", symmetricKey, symmetricKey, skf.getProvider());
	        
	        return symmetricKey;
	    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
	        e.printStackTrace();
	        return null;
	    }
	}


    /**
     * Generates a symmetric key.
     *
     * @return The generated symmetric key.
     */
	
	public SecretKey getSymmetricKey() {
		return getSecretKey(cryptoConfig.keyGenerationScheme);
	}

	/**
	 * Generates a secret key based on the specified algorithm.
	 *
	 * @param algorithm The algorithm to use for key generation.
	 * @return The generated secret key.
	 */
	
	private SecretKey getSecretKey(String algorithm) {
	    try {
	        // Create a KeyGenerator instance with the specified algorithm and provider
	        KeyGenerator keyGenerator = Crypto_Config.testStr(cryptoConfig.keyGenerationSchemeProvider) 
	                                    ? KeyGenerator.getInstance(algorithm, cryptoConfig.keyGenerationSchemeProvider) 
	                                    : KeyGenerator.getInstance(algorithm);

	        // Initialise the KeyGenerator with the configured key size
	        keyGenerator.init(cryptoConfig.keySize);

	        // Generate the symmetric key
	        SecretKey symmetricKey = keyGenerator.generateKey();

	        // Log the key generation status
	        printStatus("Key Generated [Sym]", symmetricKey, symmetricKey, keyGenerator.getProvider());

	        return symmetricKey;
	    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
	        e.printStackTrace();
	        return null;
	    }
	}


    /**
     * Generates a secret key for HMAC.
     *
     * @return The generated HMAC key.
     */	
	
	public SecretKey getHmacKey() {
		return getSecretKey(cryptoConfig.hmacAlgorithm);
	}

	/**
	 * Decrypts a sealed pair using the provided key store type.
	 *
	 * @param sc The sealed pair to decrypt.
	 * @param pk The key store type to obtain the private key for decryption.
	 * @return The decrypted object.
	 */
	
	public Object decrypt(Crypto_SealedPair sc, Crypto_KeyStoreType pk) {
	    try {
	        // Decrypt the symmetric session key using asymmetric decryption
	        SecretKey k = new SecretKeySpec((byte[]) decryptAsym(sc.getSealedKey(), pk), sc.getCipherScheme());

	        // Decrypt the message using the decrypted symmetric key
	        return decrypt(sc.getSealedMessage(), k);
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}

	
	/**
	 * Decrypts a sealed pair using the provided key pair.
	 *
	 * @param sc   The sealed pair to decrypt.
	 * @param pair The key pair to obtain the private key for decryption.
	 * @return The decrypted object.
	 */

	public Object decrypt(Crypto_SealedPair sc, Crypto_KeyPair pair) {
	    try {
	        // Decrypt the symmetric session key using the private key from the key pair
	        SecretKey k = new SecretKeySpec((byte[]) decryptAsymPK(sc.getSealedKey(), pair.getPrivateKey()), sc.getCipherScheme());

	        // Decrypt the message using the decrypted symmetric key
	        return decrypt(sc.getSealedMessage(), k);
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}

	/**
	 * Decrypts a sealed object using the provided key store type.
	 *
	 * @param so The sealed object to decrypt.
	 * @param pk The key store type to obtain the private key for decryption.
	 * @return The decrypted object.
	 */
	
	private Object decryptAsym(SealedObject so, Crypto_KeyStoreType pk) {
	    try {
	        // Retrieve the private key from the key store builder
	        PrivateKey privateKey = ksbd.getKeyStoreBuilder(pk).getLocalPrivateKey();
	        // Decrypt the SealedObject using the private key
	        
	        Object decryptedObject = decryptAsymPK(so, privateKey);

	        return decryptedObject;
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}


	/**
	 * Decrypts a sealed object using the provided private key.
	 *
	 * @param so         The sealed object to decrypt.
	 * @param privateKey The private key to use for decryption.
	 * @return The decrypted object.
	 */
	
	public Object decryptAsymPK(SealedObject so, PrivateKey privateKey) {
	    try {
	        
	        Object obj = null;
	        // Extract/Decrypt the Object from the SealedObject using the private key

	        if (Crypto_Config.testStr(cryptoConfig.asymEncProvider)) {
	        	Provider provider = Security.getProvider(cryptoConfig.asymEncProvider);
	        	printStatus("Decrypting [Asym]", privateKey, null, provider);
	        	obj = so.getObject(privateKey, cryptoConfig.asymEncProvider);
	            printStatus("Decrypted [Asym]", privateKey, so, provider);
	        } else {
	        	printStatus("Decrypting [Asym]", privateKey, null, null);
	        	obj = so.getObject(privateKey);
	            printStatus("Decrypted [Asym]", privateKey, so, null);
	        }

	        return obj;
	    } catch (IOException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException e) {
	        e.printStackTrace();
	        return null;
	    }
	}

	/**
	 * Decrypts a sealed object using the provided symmetric key.
	 *
	 * @param so           The sealed object to decrypt.
	 * @param symmetricKey The symmetric key to use for decryption.
	 * @return The decrypted object.
	 */
	
	public Object decrypt(SealedObject so, SecretKey symmetricKey) {
	    try {
	        // Log the start of the decryption process
	        printStatus("Decrypting [Sym]", symmetricKey, so, null);

	        // Extract and decrypt the Object from the SealedObject
	        Object obj = so.getObject(symmetricKey);

	        // Log the successful decryption
	        printStatus("Decrypted [Sym]", symmetricKey, so, null);
	        return obj;
	    } catch (IOException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException e) {
	        e.printStackTrace();
	        return null;
	    }
	}
	
	/**
	 * Decrypts a symmetrically encrypted block using the provided symmetric key.
	 *
	 * @param so           The symmetrically encrypted block.
	 * @param symmetricKey The symmetric key to use for decryption.
	 * @return The decrypted object.
	 */

	private Object decryptSymBlock(Crypto_ByteArray so, Key symmetricKey) {
	    try {
	        // Get an instance of the Cipher for encryption/decryption
	        Cipher c = Crypto_Config.testStr(cryptoConfig.cipherSchemeProvider) 
                    ? Cipher.getInstance(cryptoConfig.cipherScheme, cryptoConfig.cipherSchemeProvider) 
                    : Cipher.getInstance(cryptoConfig.cipherScheme);

	        // Initialise the Cipher for decryption with the symmetric key
	        c.init(Cipher.DECRYPT_MODE, symmetricKey);

	        // Perform the decryption
	        byte[] plaintext = blockCipher(so.getByteArray(), Cipher.DECRYPT_MODE, c, c.getBlockSize());

	        // Deserialise the decrypted plaintext
	        return deserialize(plaintext);
	    } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException e) {
	        e.printStackTrace();
	        return null;
	    }
	}


	/**
	 * Encrypts an object with the specified alias and key store type.
	 *
	 * @param object The object to encrypt.
	 * @param alias  The alias to identify the public key.
	 * @param pk     The key store type to obtain the public key for encryption.
	 * @return The sealed pair containing the encrypted object and key.
	 */
	
	public Crypto_SealedPair encrypt(Object object, String alias, Crypto_KeyStoreType pk) {

		PublicKey publicKey = ksbd.getKeyStoreBuilder(pk).getRemotePublicKey(alias);
		return encrypt(object, publicKey);
	}

	/**
	 * Encrypts an object with the provided public key.
	 *
	 * @param object    The object to encrypt.
	 * @param publicKey The public key to use for encryption.
	 * @return The sealed pair containing the encrypted object and key.
	 */
	
	public Crypto_SealedPair encrypt(Object object, PublicKey publicKey) {
	    // Generate a symmetric session key
	    SecretKey symmetricKey = getSymmetricKey();

	    // Encrypt the object using the symmetric session key
	    SealedObject sealedObject = encrypt(object, symmetricKey);

	    // Encrypt the symmetric key with the recipient's public key
	    SealedObject sealedSymmetricKey = encryptAsymPK(symmetricKey.getEncoded(), publicKey);

	    // Create a Crypto_SealedPair object containing the encrypted symmetric key and object
	    Crypto_SealedPair sealedPair = new Crypto_SealedPair(sealedSymmetricKey, sealedObject, symmetricKey.getAlgorithm());

	    return sealedPair;
	}
	
	/**
	 * Encrypts an object with a symmetric key, and also computes a digest for comparison.
	 *
	 * @param object The object to encrypt.
	 * @param alias  The alias to identify the public key.
	 * @param pk     The key store type to obtain the public key for encryption.
	 * @return The sealed pair containing the encrypted object, key, and digest.
	 */

	public Crypto_SealedPair encryptCompare(Object object, String alias, Crypto_KeyStoreType pk) {
	    // Generate a symmetric session key
	    SecretKey symmetricKey = getSymmetricKey();

	    // Encrypt the object using the symmetric session key
	    SealedObject sealedObject = encrypt(object, symmetricKey);

	    // Encrypt the symmetric key with the recipient's public key
	    SealedObject sealedSymmetricKey = encryptAsym(symmetricKey.getEncoded(), alias, pk);

	    // Compute the digest of the object for comparison
	    Crypto_ByteArray digest = makeDigest(object);

	    // Create a Crypto_SealedPair object containing the encrypted symmetric key, object, cipher scheme, and digest
	    Crypto_SealedPair sealedPair = new Crypto_SealedPair(sealedSymmetricKey, sealedObject, cryptoConfig.cipherScheme, digest);

	    return sealedPair;
	}


	/**
	 * Encrypts an object with the provided public key and returns the sealed object.
	 *
	 * @param object    The object to encrypt.
	 * @param publicKey The public key to use for encryption.
	 * @return The sealed object.
	 */
	
	private SealedObject encryptAsymPK(Object object, PublicKey publicKey) {
	    try {
	        // Get an instance of the Cipher for encryption
	        Cipher c = Crypto_Config.testStr(cryptoConfig.asymEncProvider) 
	                        ? Cipher.getInstance(publicKey.getAlgorithm(), cryptoConfig.asymEncProvider) 
	                        : Cipher.getInstance(publicKey.getAlgorithm());

	        // Initialise the Cipher for encryption with the public key
	        c.init(Cipher.ENCRYPT_MODE, publicKey);

	        // Encrypt the object using the initialised Cipher and return the SealedObject
	        return new SealedObject((Serializable) object, c);
	    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IOException | IllegalBlockSizeException | NoSuchProviderException e) {
	        e.printStackTrace();
	        return null;
	    }
	}
	
	/**
	 * Encrypts an object with the specified alias and key store type, and prints debug information.
	 *
	 * @param object The object to encrypt.
	 * @param alias  The alias to identify the public key.
	 * @param pk     The key store type to obtain the public key for encryption.
	 * @return The sealed object.
	 */
	
	private SealedObject encryptAsym(Object object, String alias, Crypto_KeyStoreType pk) {
	    try {
	        // Get the remote public key using the provided alias and Crypto_KeyStoreType
	        PublicKey publicKey = ksbd.getKeyStoreBuilder(pk).getRemotePublicKey(alias);

	        // Encrypt the object using the obtained public key
	        SealedObject sealedObject = encryptAsymPK(object, publicKey);

	        // Print status after encryption
	        printStatus("Encrypted [Asym] for <" + alias + ">", publicKey, sealedObject, null);

	        return sealedObject;
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}

	/**
	 * Encrypts an object with the provided symmetric key and returns the sealed object.
	 *
	 * @param object       The object to encrypt.
	 * @param symmetricKey The symmetric key to use for encryption.
	 * @return The sealed object.
	 */
	
	public SealedObject encrypt(Object object, SecretKey symmetricKey) {
	    try {
	    	
	        Cipher c = Crypto_Config.testStr(cryptoConfig.cipherSchemeProvider) 
                    ? Cipher.getInstance(cryptoConfig.cipherScheme, cryptoConfig.cipherSchemeProvider) 
                    : Cipher.getInstance(cryptoConfig.cipherScheme);

	        c.init(Cipher.ENCRYPT_MODE, symmetricKey);

	        // Print the initialisation vector if automatically generated, otherwise null
	        printStatus("Encrypting [Sym] IV", symmetricKey, c.getIV(), c.getProvider());

	        SealedObject sealedObject = new SealedObject((Serializable) object, c);

	        // Print status after encryption
	        printStatus("Encrypted [Sym]", symmetricKey, sealedObject, c.getProvider());

	        return sealedObject;
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}

	
	/**
	 * Encrypts an object with the provided symmetric key using a block cipher and returns the encrypted block.
	 *
	 * @param object       The object to encrypt.
	 * @param symmetricKey The symmetric key to use for encryption.
	 * @return The encrypted block as a byte array.
	 */
	
	private Crypto_ByteArray encryptSymBlock(Object object, SecretKey symmetricKey) {
		try {
			
	        Cipher c = Crypto_Config.testStr(cryptoConfig.cipherSchemeProvider) 
                    ? Cipher.getInstance(cryptoConfig.cipherScheme, cryptoConfig.cipherSchemeProvider) 
                    : Cipher.getInstance(cryptoConfig.cipherScheme);
			
			printStatus("Encrypting [Sym]", symmetricKey, null, c.getProvider());
			c.init(Cipher.ENCRYPT_MODE, symmetricKey);
			byte[] so = serialize(object);
			return new Crypto_ByteArray(blockCipher(so, Cipher.ENCRYPT_MODE, c, c.getBlockSize()));
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;

	}

	// -----------------------------------------------

	// AN ATTEMPT

	/**
	 * Encrypts an object using asymmetric encryption with block cipher.
	 *
	 * @param object The object to encrypt.
	 * @param alias  The alias to identify the public key.
	 * @return A {@code Crypto_ByteArray} containing the encrypted bytes.
	 */
	
	
	private Crypto_ByteArray encryptAsymBlock(Object object, String alias) {
	    PublicKey publicKey = ksbd.getKeyStoreBuilder(Crypto_KeyStoreType.pk()).getRemotePublicKey(alias);

	    try {
	        // Get an instance of the Cipher encryption/decryption
	        
	        Cipher c = Crypto_Config.testStr(cryptoConfig.asymEncProvider) 
                    ? Cipher.getInstance(cryptoConfig.asymCipherSchemeBlock, cryptoConfig.asymEncProvider) 
                    : Cipher.getInstance(cryptoConfig.asymCipherSchemeBlock);

	        // Initiate the Cipher for encryption with the public key
	        c.init(Cipher.ENCRYPT_MODE, publicKey);

	        // Serialize the object
	        byte[] bytes = serialize(object);

	        // Encrypt the serialized bytes using block cipher
	        byte[] encrypted = blockCipher(bytes, Cipher.ENCRYPT_MODE, c, asymBlockLengthEnc);

	        return new Crypto_ByteArray(encrypted);
	    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | NoSuchProviderException e) {
	        e.printStackTrace();
	    }

	    return null;
	}


	/**
	 * Decrypts bytes using asymmetric decryption with block cipher.
	 *
	 * @param encrypted The encrypted bytes to decrypt.
	 * @return The decrypted object.
	 */
	
	private Object decryptAsymBlock(Crypto_ByteArray encrypted) {
	    PrivateKey privateKey = ksbd.getKeyStoreBuilder(Crypto_KeyStoreType.pk()).getLocalPrivateKey();

	    try {
	        // Get an instance of the Cipher encryption/decryption
	        Cipher c = Crypto_Config.testStr(cryptoConfig.asymEncProvider) 
                    ? Cipher.getInstance(cryptoConfig.asymCipherSchemeBlock, cryptoConfig.asymEncProvider) 
                    : Cipher.getInstance(cryptoConfig.asymCipherSchemeBlock);
	        
	        // Initiate the Cipher for decryption with the private key
	        c.init(Cipher.DECRYPT_MODE, privateKey);

	        // Decrypt the encrypted bytes using block cipher
	        byte[] decryptedBytes = blockCipher(encrypted.getByteArray(), Cipher.DECRYPT_MODE, c, asymBlockLengthDec);

	        // Deserialize the decrypted bytes
	        return deserialize(decryptedBytes);
	    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | NoSuchProviderException e) {
	        e.printStackTrace();
	    }

	    return null;
	}


	/**
	 * Applies block cipher operation on the input bytes.
	 *
	 * @param bytes The input bytes to be processed.
	 * @param mode  The cipher operation mode (Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE).
	 * @param c     The Cipher instance.
	 * @param length The block size for the block cipher operation.
	 * @return The processed bytes after block cipher operation.
	 */
	
	
	private byte[] blockCipher(byte[] bytes, int mode, Cipher c, int length) {
	    AnBx_Debug.out(layer, "blockCipher - mode: " + (mode == Cipher.ENCRYPT_MODE ? "ENCRYPT" : "DECRYPT"));
	    AnBx_Debug.out(layer, "blockCipher - bytes: " + bytes.toString());
	    AnBx_Debug.out(layer, "blockCipher - bytes.length: " + bytes.length);
	    AnBx_Debug.out(layer, "blockCipher - bytes.hashCode: " + bytes.hashCode());
	    AnBx_Debug.out(layer, "blockCipher - cipher - algorithm: " + c.getAlgorithm());
	    AnBx_Debug.out(layer, "blockCipher - cipher - blocksize: " + c.getBlockSize());
	    AnBx_Debug.out(layer, "blockCipher - cipher - parameters: " + c.getParameters());

	    List<byte[]> resultList = new ArrayList<>();
	    int offset = 0;

	    while (offset < bytes.length) {
	        int blockSize = Math.min(length, bytes.length - offset);
	        byte[] buffer = Arrays.copyOfRange(bytes, offset, offset + blockSize);
	        byte[] scrambled;

	        try {
	            scrambled = c.doFinal(buffer);
	        } catch (IllegalBlockSizeException | BadPaddingException e) {
	            e.printStackTrace();
	            return new byte[0];
	        }

	        resultList.add(scrambled);
	        offset += blockSize;
	    }

	    int totalLength = resultList.stream().mapToInt(arr -> arr.length).sum();
	    byte[] toReturn = new byte[totalLength];
	    int destPos = 0;

	    for (byte[] arr : resultList) {
	        System.arraycopy(arr, 0, toReturn, destPos, arr.length);
	        destPos += arr.length;
	    }

	    return toReturn;
	}

	/**
	 * Appends two byte arrays.
	 *
	 * @param prefix The first byte array.
	 * @param suffix The second byte array.
	 * @return The combined byte array.
	 */

	private byte[] append(byte[] prefix, byte[] suffix) {
	    byte[] toReturn = new byte[prefix.length + suffix.length];
	    System.arraycopy(prefix, 0, toReturn, 0, prefix.length);
	    System.arraycopy(suffix, 0, toReturn, prefix.length, suffix.length);
	    return toReturn;
	}


	// ------------------------------------------------

	/**
	 * Retrieves the key store settings map.
	 *
	 * @return The key store settings map.
	 */
	
	public Crypto_KeyStoreSettings_Map getKeyStoreSettings_Map() {
		return ksbd.getKeyStoreSettings_Map();
	}

	/**
	 * Retrieves the local certificate for a specified key store type.
	 *
	 * @param kst The key store type.
	 * @return The local certificate for the specified key store type.
	 */
	
	public Certificate getLocaleCertificate(Crypto_KeyStoreType kst) {
		return ksbd.getKeyStoreBuilder(kst).getLocaleCertificate();
	}

	/**
	 * Retrieves a map of local certificates for different key store types.
	 *
	 * @return A map containing local certificates for various key store types.
	 */
	
	public Map<Crypto_KeyStoreType, Certificate> getLocaleCertificates() {
		return ksbd.getLocaleCertificates();
	}

	
	/**
	 * Retrieves the alias associated with a key store type.
	 *
	 * @param kst The key store type.
	 * @return The alias associated with the specified key store type.
	 */
	public String getMyAlias(Crypto_KeyStoreType kst) {
		return ksbd.getKeyStoreBuilder(kst).getMyAlias();
	}

	/**
	 * Generates and retrieves a nonce (number used once).
	 *
	 * @return A {@code Crypto_ByteArray} containing the generated nonce.
	 */
	
	public Crypto_ByteArray getNonce() {
	    // Get keysize*8 random bits
	    byte[] nonce = new byte[cryptoConfig.keySize];
	    SecureRandom sr = null;
	    try {
	    	sr = Crypto_Config.testStr(cryptoConfig.secureRandomProvider) 
                ? SecureRandom.getInstance(cryptoConfig.secureRandomAlgorithm, cryptoConfig.cipherSchemeProvider) 
                : SecureRandom.getInstance(cryptoConfig.secureRandomAlgorithm);
	    	sr.nextBytes(nonce);
	        AnBx_Debug.out(layer, "Nonce - " + sr.getAlgorithm() + " - Value: " + Arrays.toString(nonce));
	    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
	        e.printStackTrace();
	    } finally {
	        if (sr != null) {
	            sr.nextBytes(new byte[nonce.length]); // Discard remaining bytes to improve security
	            sr = null; // Explicitly set to null for garbage collection
	        }
	    }
	    return new Crypto_ByteArray(nonce);
	}

	/**
	 * Retrieves the current timestamp as an Instant.
	 *
	 * @return The current timestamp.
	 */
	
	
	public Instant getTimeStamp() {
		return Instant.now();
	}

	/**
	 * Retrieves the remote certificate associated with a specified alias and key store type.
	 *
	 * @param alias The alias for the remote certificate.
	 * @param pk    The key store type.
	 * @return The remote certificate for the specified alias and key store type.
	 */
	
	public Certificate getRemoteCertificate(String alias, Crypto_KeyStoreType pk) {
		return ksbd.getKeyStoreBuilder(pk).getRemoteCertificate(alias);
	}

	/**
	 * Retrieves a map of remote certificates associated with a specified alias.
	 *
	 * @param alias The alias for which remote certificates are retrieved.
	 * @return A map containing remote certificates for various key store types.
	 */
	
	public Map<Crypto_KeyStoreType, Certificate> getRemoteCertificates(String alias) {
		return ksbd.getRemoteCertificates(alias);
	}
	
	/**
	 * Checks if the key store builder contains a specific alias.
	 *
	 * @param alias The alias to check for existence.
	 * @return {@code true} if the alias exists; otherwise, {@code false}.
	 */

	public boolean containsAlias(String alias) {
		return ksbd.containsAlias(alias);
	}

	  /**
     * Constructs the appropriate signature algorithm based on the given private key and digest algorithm.
     *
     * This method handles both the common pattern of <digest>with<encryption> and special cases that do not follow this pattern.
     *
     * @param privateKey       The private key used for the signature.
     * @param digestAlgorithm  The digest algorithm used for the signature.
     * @return                 The signature algorithm name. If the private key algorithm is a special case, it returns the corresponding algorithm name from the map.
     */
	
	private String key2SignatureAlgorithm(PrivateKey privateKey, String digestAlgorithm) {
		String privateKeyAlgorithm = privateKey.getAlgorithm();
		// Handle special cases
		if (specialSignatureCases.containsKey(privateKeyAlgorithm)) {
			return specialSignatureCases.get(privateKeyAlgorithm);
		}

		// Default to <digest>with<encryption> pattern
		String signatureAlgorithm = digestAlgorithm + "with" + privateKeyAlgorithm;
		return signatureAlgorithm;
	}
		
	  /**
     * Constructs the appropriate signature algorithm based on the given public key and digest algorithm.
     *
     * This method handles both the common pattern of <digest>with<encryption> and special cases that do not follow this pattern.
     *
     * @param publicKey        The public key used for the signature.
     * @param digestAlgorithm  The digest algorithm used for the signature.
     * @return                 The signature algorithm name. If the private key algorithm is a special case, it returns the corresponding algorithm name from the map.
     */
	
	private String key2SignatureAlgorithm(PublicKey publicKey, String digestAlgorithm) {
		String privateKeyAlgorithm = publicKey.getAlgorithm();
		// Handle special cases
		if (specialSignatureCases.containsKey(privateKeyAlgorithm)) {
			return specialSignatureCases.get(privateKeyAlgorithm);
		}

		// Default to <digest>with<encryption> pattern
		String signatureAlgorithm = digestAlgorithm + "with" + privateKeyAlgorithm;
		return signatureAlgorithm;
	}	
	
	/**
	 * Prints a list of names to the debug output.
	 *
	 * @param names The array of names to print.
	 */
	@SuppressWarnings("unused")
	private void printList(String[] names) {
		for (int i = 0; i < names.length; i++) {
			AnBx_Debug.out(layer, (names[i].toString()));
		}
	}

	/**
	 * Prints the status information, including key details, object details, and provider information.
	 *
	 * @param s The status message.
	 * @param k The key.
	 * @param o The object.
	 * @param p The provider.
	 */
	private void printStatus(String s, Key k, Object o, Provider p) {
	    StringBuilder msg = new StringBuilder(s);
	    
	    if (k != null) {
	        String format = k.getFormat() != null ? k.getFormat() : "Unknown";
	        int keyLength = k.getEncoded() != null ? k.getEncoded().length * 8 : 0;
	        msg.append(" [").append(k.getAlgorithm()).append("/").append(format).append("/").append(keyLength).append("]");
	    }
	    
	    if (o != null) msg.append(" ").append(o.toString());
	    if (p != null) msg.append(" - Provider: ").append(p.getName());
	    
	    AnBx_Debug.out(layer, msg.toString());
	    
	}

//	/**
//	 * @param secureRandomAlgorithm the secureRandomAlgorithm to set
//	 */
//	public void setSecureRandomAlgorithm(String secureRandomAlgorithm) {
//		cryptoConfig.secureRandomAlgorithm = secureRandomAlgorithm;
//	}

	/**
	 * Signs an object using the private key associated with the specified key store type.
	 *
	 * @param object The object to sign.
	 * @param sk     The key store type.
	 * @return The SignedObject containing the signed object.
	 */
	
	public SignedObject sign(Object object, Crypto_KeyStoreType sk) {
	    SignedObject so = null;
	    Signature sig = null;
	    
	    try {
	        PrivateKey privateKey = ksbd.getKeyStoreBuilder(sk).getLocalPrivateKey();
	        Serializable o = (Serializable) object;
	        
	        String signatureAlgorithm = key2SignatureAlgorithm(privateKey, cryptoConfig.messageDigestSignatureAlgorithm);
	        
	        // Initialise the Signature object
	    	sig = Crypto_Config.testStr(cryptoConfig.signatureProvider) 
                ? Signature.getInstance(signatureAlgorithm, cryptoConfig.signatureProvider) 
                : Signature.getInstance(signatureAlgorithm);
	        
	        // Create the SignedObject
	        so = new SignedObject(o, privateKey, sig);
	        printStatus("Signed", privateKey, so, sig.getProvider());
	        
	    } catch (NoSuchAlgorithmException | NoSuchProviderException | SignatureException | InvalidKeyException | IOException e) {
	        e.printStackTrace();
	    }
	    
	    return so;
	}


	/**
	 * Signs an object using the private key from the provided key pair.
	 *
	 * @param object The object to sign.
	 * @param kp     The key pair containing the private key.
	 * @return The SignedObject containing the signed object.
	 */
	
	public SignedObject sign(Object object, Crypto_KeyPair kp) {
		SignedObject so = null;
		try {
			PrivateKey privateKey = kp.getPrivateKey();
			Serializable o = (Serializable) object;
			Signature sig = null;
			String signatureAlgorithm = key2SignatureAlgorithm(privateKey, cryptoConfig.messageDigestSignatureAlgorithm);
			sig = Crypto_Config.testStr(cryptoConfig.signatureProvider) 
		    	? Signature.getInstance(signatureAlgorithm,cryptoConfig.signatureProvider)
		    	: Signature.getInstance(signatureAlgorithm);

			so = new SignedObject(o, privateKey, sig);
			printStatus("Signed", privateKey, so, sig.getProvider());
		} catch (NoSuchAlgorithmException | NoSuchProviderException | SignatureException | InvalidKeyException | IOException e) {
			e.printStackTrace();
		} 
		return so;
	}

	/**
	 * Retrieves the public key associated with the specified alias and key store type.
	 *
	 * @param alias The alias for the remote public key.
	 * @param pk    The key store type.
	 * @return The remote public key for the specified alias and key store type.
	 */
	
	public PublicKey getPublicKey(String alias, Crypto_KeyStoreType pk) {
		return ksbd.getKeyStoreBuilder(pk).getRemotePublicKey(alias);
	}

	/**
	 * Verifies a SignedObject using the public key associated with the specified alias and key store type.
	 *
	 * @param so    The SignedObject to verify.
	 * @param alias The alias for the remote public key.
	 * @param sk    The key store type.
	 * @return The verified object or null if verification fails.
	 */
	
	public Object verify(SignedObject so, String alias, Crypto_KeyStoreType sk) {
		return verify(so, alias, sk, Crypto_OutputMode.OBJECT);
	}

	/**
	 * Verifies a SignedObject using the provided public key.
	 *
	 * @param so         The SignedObject to verify.
	 * @param publicKey  The public key used for verification.
	 * @return The verified object or null if verification fails.
	 */
	
	public Object verify(SignedObject so, PublicKey publicKey) {
		return verify(so, publicKey, Crypto_OutputMode.OBJECT);
	}
	
	/**
	 * Verifies a SignedObject using the public key associated with the specified alias and key store type.
	 *
	 * @param so    The SignedObject to verify.
	 * @param alias The alias for the remote public key.
	 * @param sk    The key store type.
	 * @param om    The output mode for the verified object.
	 * @return The verified object or null if verification fails.
	 */
	
	private Object verify(SignedObject so, String alias, Crypto_KeyStoreType sk, Crypto_OutputMode om) {
	    if (alias == null) {
	        AnBx_Debug.out(layer, "NOT Verified - Alias is null");
	        return null;
	    }
	    
	    PublicKey publicKey = ksbd.getKeyStoreBuilder(sk).getRemotePublicKey(alias);
	    return verify(so, publicKey, om);
	}
	
	/**
	 * Verifies a SignedObject using the provided public key.
	 *
	 * @param so        The SignedObject to verify.
	 * @param publicKey The public key used for verification.
	 * @param om        The output mode for the verified object.
	 * @return The verified object or null if verification fails.
	 */

	private Object verify(SignedObject so, PublicKey publicKey, Crypto_OutputMode om) {
	    if (so == null) {
	        AnBx_Debug.out(layer, "NOT Verified - Signed object is null");
	        return null;
	    }

	    if (publicKey == null) {
	        AnBx_Debug.out(layer, "NOT Verified - PublicKey is null");
	        return null;
	    }

	    try {
	        // Determine the signature algorithm and provider
	        String signatureAlgorithm = key2SignatureAlgorithm(publicKey, cryptoConfig.messageDigestSignatureAlgorithm);
	        Signature sig = Crypto_Config.testStr(cryptoConfig.signatureProvider)
	                ? Signature.getInstance(signatureAlgorithm, cryptoConfig.signatureProvider)
	                : Signature.getInstance(signatureAlgorithm);

	        // Verify the signed object
	        if (so.verify(publicKey, sig)) {
	            printStatus("Signature Verification OK", publicKey, so, sig.getProvider());
	            return (om == Crypto_OutputMode.SIGNED_OBJECT)
	                    ? new Crypto_SignedPair(so, so.getObject(), sig.getAlgorithm())
	                    : so.getObject();
	        } else {
	            AnBx_Debug.out(layer, "Signature Verification FAILED");
	        }
	    } catch (NoSuchAlgorithmException | NoSuchProviderException | SignatureException | InvalidKeyException | ClassNotFoundException | IOException e) {
	        e.printStackTrace();
	    }

	    return null;
	}


	/**
	 * Generates Diffie-Hellman parameters dynamically based on the configured settings.
	 *
	 * @return A comma-separated string of three values: prime modulus P, base generator G, and bit size of the random exponent L.
	 */
	@SuppressWarnings("unused")
	private String genDhParamsDynamic() {
	    try {
	        AnBx_Debug.out(layer, "Generating " + cryptoConfig.keyAgreementAlgorithm + " parameters with " + cryptoConfig.keyAgreementAlgorithm);

	        // Create the parameter generator for DH key pair
	        AlgorithmParameterGenerator paramGen = Crypto_Config.testStr(cryptoConfig.keyAgreementProvider)
	                ? AlgorithmParameterGenerator.getInstance(cryptoConfig.keyAgreementAlgorithm, cryptoConfig.keyAgreementProvider)
	                : AlgorithmParameterGenerator.getInstance(cryptoConfig.keyAgreementAlgorithm);

	        paramGen.init(cryptoConfig.dhRndExpSize);

	        // Generate the parameters
	        AlgorithmParameters params = paramGen.generateParameters();
	        DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

	        // Return the three values in a string
	        return String.format("%s,%s,%s", dhSpec.getP(), dhSpec.getG(), dhSpec.getL());
	    } catch (NoSuchAlgorithmException | InvalidParameterSpecException | NoSuchProviderException e) {
	        e.printStackTrace();
	    }
	    return null;
	}


	
	/**
	 * Generates Diffie-Hellman parameters using predefined values based on the configured size.
	 *
	 * @return A comma-separated string of three values: prime modulus P, base generator G, and bit size of the random exponent L.
	 */
	
	private String genDhParams() {

		// Returns a comma-separated string of 3 values.
		// The first number is the prime modulus P.
		// The second number is the base generator G.
		// The third number is bit size of the random exponent L.
		// The Java Developers Almanac 1.4 e470
		// update to use 2048 bit size module see DH weak Logjam attack

		// https://tools.ietf.org/html/rfc3526

		final String modp1024 = ("FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1" + "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
				+ "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245" + "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
				+ "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381" + "FFFFFFFF FFFFFFFF").replaceAll("\\s", "");

		final String modp1536 = ("FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1" + "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
				+ "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245" + "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
				+ "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D" + "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
				+ "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D" + "670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF").replaceAll("\\s", "");

		final String modp2048 = ("FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1" + "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
				+ "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245" + "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
				+ "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D" + "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
				+ "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D" + "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
				+ "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9" + "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510" + "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF")
						.replaceAll("\\s", "");

		final String modp3072 = ("FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1" + "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
				+ "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245" + "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
				+ "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D" + "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
				+ "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D" + "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
				+ "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9" + "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
				+ "15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64" + "ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7"
				+ "ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B" + "F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C"
				+ "BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31" + "43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF").replaceAll("\\s", "");

		final String modp4096 = ("FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1" + "      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
				+ "      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245" + "      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
				+ "      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D" + "      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
				+ "      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D" + "      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
				+ "      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9" + "      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
				+ "      15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64" + "      ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7"
				+ "      ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B" + "      F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C"
				+ "      BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31" + "      43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7"
				+ "      88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA" + "      2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6"
				+ "      287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED" + "      1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9"
				+ "      93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199" + "      FFFFFFFF FFFFFFFF").replaceAll("\\s", "");

		final String maxMod = modp4096; // max size supported by Java 8
		final BigInteger Modulus;

		// select the modulus size
		if (cryptoConfig.dhRndExpSize <= 1024)
			Modulus = new BigInteger(modp1024, 16); // input string,radix
		else if (cryptoConfig.dhRndExpSize <= 1536)
			Modulus = new BigInteger(modp1536, 16);
		else if (cryptoConfig.dhRndExpSize <= 2048)
			Modulus = new BigInteger(modp2048, 16);
		else if (cryptoConfig.dhRndExpSize <= 3072)
			Modulus = new BigInteger(modp3072, 16);
		else if (cryptoConfig.dhRndExpSize <= 4096)
			Modulus = new BigInteger(modp4096, 16);
		else
			Modulus = new BigInteger(maxMod, 16); // max size supported by Java 8

		final BigInteger Base = BigInteger.valueOf(2L);
		
		DHParameterSpec dhSpec = new DHParameterSpec(Modulus, Base, cryptoConfig.dhRndExpSize);
		AnBx_Debug.out(layer, "Generating " + cryptoConfig.keyAgreementAlgorithm + " parameters");
		
		// Return the three values in a string
		return "" + dhSpec.getP() + "," + dhSpec.getG() + "," + dhSpec.getL();

	}
	
	/**
	 * Initialises Diffie-Hellman parameters for key generation.
	 *
	 * @return DHParameterSpec object containing prime modulus P, base generator G, and bit size of the random exponent L.
	 */
	
	private DHParameterSpec DH_init_KeyGen() {
		String valuesInStr = genDhParams();
		AnBx_Debug.out(layer, cryptoConfig.keyAgreementAlgorithm + " parameters: " + valuesInStr);

		String[] values = valuesInStr.split(",");
		BigInteger p = new BigInteger(values[0]);
		BigInteger g = new BigInteger(values[1]);
		int l = Integer.parseInt(values[2]);
		return new DHParameterSpec(p, g, l);

	}
	
	/**
	 * Initialises Elliptic Curve parameters for key generation.
	 *
	 * @return ECParameterSpec object containing elliptic curve parameters.
	 */
	
	private ECGenParameterSpec ECDH_init_KeyGen() {
	
		AnBx_Debug.out(layer, "Elliptic Curve: " + cryptoConfig.ecGenParameterSpec);
		return new ECGenParameterSpec(cryptoConfig.ecGenParameterSpec);
	}

	
	private NamedParameterSpec ECX_init_KeyGen(String parameterSpec) {
		
		return new NamedParameterSpec(parameterSpec);
	}
	
	/**
	 * Generates a key pair for key exchange based on the configured key agreement algorithm.
	 *
	 * @return KeyPair object containing public and private keys.
	 */

	public KeyPair getKeyEx_KeyPair() {
	    AnBx_Debug.out(layer, "----- Key Exchange KeyPair Generation  ----- Begin ---- ");
	    AnBx_Debug.out(layer, "keyAgreementAlgorithm: " + cryptoConfig.keyAgreementAlgorithm);
	    AnBx_Debug.out(layer, "keyAgreementKeyPairGenerationScheme: " + cryptoConfig.keyAgreementKeyPairGenerationScheme);
	    try {

	        // Initialise the KeyPairGenerator with the specified algorithm
			KeyPairGenerator keyGen = (Crypto_Config.testStr(cryptoConfig.keyAgreementProvider)) 
	        		? KeyPairGenerator.getInstance(cryptoConfig.keyAgreementKeyPairGenerationScheme, cryptoConfig.keyAgreementProvider)
	        	    : KeyPairGenerator.getInstance(cryptoConfig.keyAgreementKeyPairGenerationScheme);

	        // Initialise the KeyPairGenerator with specific parameters based on the algorithm
	        switch (cryptoConfig.keyAgreementAlgorithm) {
	            case "DH":
	                keyGen.initialize(DH_init_KeyGen());
	                break;
	            case "ECDH":
	                keyGen.initialize(ECDH_init_KeyGen());
	                break;
	            case "X25519":
	            case "X448":
	            	keyGen.initialize(ECX_init_KeyGen(cryptoConfig.keyAgreementAlgorithm));
	                break;
	            // unsupported at the moment    
	            case "XDH":
	            case "ECMQV":
	            default:
	                keyGen.initialize(null); 
	                break;
	        }

	        // Generate the KeyPair
	        KeyPair keyPair = keyGen.generateKeyPair();

	        AnBx_Debug.out(layer, "Key Exchange keyPair: " + keyPair.getPublic().getFormat() +
	                " - Algorithm: " + keyPair.getPublic().getAlgorithm() +
	                " - Size: " + (keyPair.getPublic().getEncoded().length * 8));
	        AnBx_Debug.out(layer, "----- Key Exchange KeyPair Generation  ----- OK ---- ");
	        return keyPair;
	    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
	        e.printStackTrace();
	    }

	    AnBx_Debug.out(layer, "----- Key Exchange KeyPair Generation  ----- FAILED! ---- ");
	    return null;
	}

	/**
	 * Retrieves the public key from a key pair generated for key exchange.
	 *
	 * @param keyPair The KeyPair containing public and private keys.
	 * @return PublicKey object representing the public key.
	 */
	
	public PublicKey getKeyEx_PublicKey(KeyPair keyPair) {
		AnBx_Debug.out(layer, "----- Key Exchange PublicKey Retrival  ----- Begin ---- ");
	    AnBx_Debug.out(layer, "keyAgreementAlgorithm: " + cryptoConfig.keyAgreementAlgorithm);
	    AnBx_Debug.out(layer, "keyAgreementKeyPairGenerationScheme: " + cryptoConfig.keyAgreementKeyPairGenerationScheme);
		try {
			PublicKey publicKey = keyPair.getPublic();
			AnBx_Debug.out(layer, "Key Exchange PublicKey: " + publicKey.getFormat() + " - Algorithm: " + publicKey.getAlgorithm() + " - Size: " + publicKey.getEncoded().length * 8);
			AnBx_Debug.out(layer, "----- Key Exchange PublicKey Retrival  ----- OK ---- ");
			return publicKey;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		AnBx_Debug.out(layer, "----- Key Exchange PublicKey Retrival  ----- FAILED! ---- ");
		return null;
	}

	/**
	 * Retrieves the secret key for key exchange based on the public and private keys.
	 *
	 * @param publicKey The PublicKey of the other party.
	 * @param keyPair   The KeyPair containing the private key.
	 * @return SecretKey object representing the shared secret key.
	 */
	
	public SecretKey getKeyEx_SecretKey(PublicKey publicKey, KeyPair keyPair) {

		// Retrieve the prime, base, and private value for generating the key pair.
		// If the values are encoded as in e470 Generating a Parameter Set for the Diffie-Hellman Key
		// Agreement Algorithm, the following code will extract the values.

		AnBx_Debug.out(layer, "----- Key Exchange SecretKey Retrival  ----- Begin ---- ");
	    AnBx_Debug.out(layer, "keyAgreementAlgorithm: " + cryptoConfig.keyAgreementAlgorithm);
	    AnBx_Debug.out(layer, "keyAgreementKeyPairGenerationScheme: " + cryptoConfig.keyAgreementKeyPairGenerationScheme);

		try {

			// Convert the public key bytes into a PublicKey object
			AnBx_Debug.out(layer, "Key Exchange PublicKey: " + publicKey.getFormat() + " - Algorithm: " + publicKey.getAlgorithm() + " - Size: " + publicKey.getEncoded().length * 8);
			AnBx_Debug.out(layer, "Key Exchange PrivateKey: " + keyPair.getPrivate().getFormat() + " - Algorithm: " + keyPair.getPrivate().getAlgorithm() + " - Size: " + keyPair.getPrivate().getEncoded().length * 8) ;

			// Prepare to generate the secret key with the private key and
			// public key of the other party
			KeyAgreement ka = KeyAgreement.getInstance(cryptoConfig.keyAgreementAlgorithm);

			ka.init(keyPair.getPrivate());
			ka.doPhase(publicKey, true);

			// Specify the type of key to generate;
			// see e458 Listing All Available Symmetric Key Generators
			// Generate the secret key
			final byte[] sharedSecret = ka.generateSecret();

			// generate the key according to the keyAgreementAlgorithm
			SecretKey secretKey = new SecretKeySpec(sharedSecret, 0, cryptoConfig.keyGenerationSize / 8, cryptoConfig.keyGenerationScheme);
			/* 
			switch (cryptoConfig.keyAgreementAlgorithm) {
		    case "DH":
		        // will generate a maximum length key keyGenerationSize/8 bits -> bytes
		        secretKey = new SecretKeySpec(sharedSecret, 0, cryptoConfig.keyGenerationSize / 8, cryptoConfig.keyGenerationScheme);
		        break;
            case "ECDH":
            	secretKey = new SecretKeySpec(sharedSecret, cryptoConfig.keyGenerationScheme);
		        break;
            case "X25519":
            case "X448":
            	secretKey = new SecretKeySpec(sharedSecret, 0, cryptoConfig.keyGenerationSize / 8, cryptoConfig.keyGenerationScheme);
		        break;
            case "XDH":
            case "ECMQV":
            default:
		        // not really another keyAgreementAlgorithm available
		        secretKey = new SecretKeySpec(sharedSecret, 0, cryptoConfig.keyGenerationSize / 8, cryptoConfig.keyGenerationScheme);
		        break;
			}
			*/

			AnBx_Debug.out(layer, "Key Exchange SecretKey: " + secretKey.getFormat() + " - Algorithm: " + secretKey.getAlgorithm() + " - Size: " + secretKey.getEncoded().length * 8);
			AnBx_Debug.out(layer, "----- Key Exchange SecretKey Retrival  ----- OK---- ");
			return secretKey;

		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		AnBx_Debug.out(layer, "----- Key Exchange SecretKey Retrival  ----- FAILED! ---- ");
		return null;
	}

	
	/**
	 * Gets the TSA CertPath.
	 *
	 * @return The CertPath representing the TSA CertPath.
	 */
	public CertPath getTSA_CertPath() {
		return TSA_CertPath;
	}
	
	
	/**
	 * Sets the TSA CertPath by retrieving it from the KeyStoreBuilder.
	 */
	
	public void setTSA_CertPath() {
		TSA_CertPath = this.ksbd.getKeyStoreBuilder(Crypto_KeyStoreType.pk()).getCertPath();
	}

	/**
	 * Sets the TSA CertPath.
	 *
	 * @param tSA_CertPath The CertPath to set as the TSA CertPath.
	 */
	
	public void setTSA_CertPath(CertPath tSA_CertPath) {
		TSA_CertPath = tSA_CertPath;
	}

	/**
	 * Displays information about available providers and algorithms.
	 */
	
	public static void getInfo() {

		AnBx_Debug.out(layer, "------ List of available providers  ------------ ");
		Crypto_ProviderInformation.listProviders();
		AnBx_Debug.out(layer, "-------------------------------------------------- ");
		AnBx_Debug.out(layer, "------ List of available algorithms ------------ ");
		Crypto_ProviderInformation.listAlgorithms();
		AnBx_Debug.out(layer, "-------------------------------------------------- ");
	}

	
	/**
	 * Performs bitwise XOR on two Crypto_ByteArrays and returns the result.
	 *
	 * @param x1 The first Crypto_ByteArray.
	 * @param x2 The second Crypto_ByteArray.
	 * @return A new Crypto_ByteArray representing the result of the XOR operation.
	 */
	
	public Crypto_ByteArray xor(Crypto_ByteArray x1, Crypto_ByteArray x2) {

		byte[] result = new byte[Math.min(x1.getLength(), x2.getLength())];
		byte[] cba1 = x1.getByteArray();
		byte[] cba2 = x2.getByteArray();
		for (int i = 0; i < result.length; i++) {
			result[i] = (byte) (((int) cba1[i]) ^ ((int) cba2[i]));
		}
		return new Crypto_ByteArray(result);
	}
}