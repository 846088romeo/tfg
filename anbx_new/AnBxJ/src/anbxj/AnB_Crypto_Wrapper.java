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
import java.security.PublicKey;
import java.security.SignedObject;
// import java.security.Timestamp;
import java.security.cert.Certificate;
import java.time.Instant;
import java.util.Map;
import java.util.function.Supplier;

import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

/**
 * Cryptographic API: implements a class supporting cryptographic operations (a
 * wrapper for the cryptographic engine)
 */


public class AnB_Crypto_Wrapper {
	

	/**
	 * AnB crypto wrapper class
	 * provide implementation of general crypto and channel methods
	 * 
	 */

	
	 /**
     * Field to enable or disable logging.
     * By default, logging is not enabled.
     */
    private static boolean loggingExecTimeEnabled = false;

    /**
     * Sets the logging state for performance measurements.
     *
     * @param enabled {@code true} to enable logging, {@code false} to disable logging.
     */
    public static void setLoggingExecTimeEnabled(boolean enabled) {
        loggingExecTimeEnabled = enabled;
    }

    /**
     * Checks whether logging is currently enabled.
     *
     * @return {@code true} if logging is enabled, {@code false} otherwise.
     */
    public static boolean isLoggingExecTimeEnabled() {
        return loggingExecTimeEnabled;
    }
	
	
	protected Crypto_EncryptionEngine ee;
	
	/**
	 * the identity of the agent
	*/
		
	protected AnBx_Agent me;
	
	/**
	 * the crypto store type
	*/
		
	final protected Crypto_KeyStoreType ident_ks = Crypto_KeyStoreType.ident_ks();

	private final static AnBx_Layers layer = AnBx_Layers.LANGUAGE;

	/**
	 * Create a AnB_Crypto_Wrapper for a specified cryptographic engine
	 * 
	 * @param ee the specified cryptographic engine
	 * @see AnB_Crypto_Wrapper
	 * @see Crypto_EncryptionEngine
	 */

	public AnB_Crypto_Wrapper(Crypto_EncryptionEngine ee) {
		super();
		this.ee = ee;
		setMyIdentity();
	}

	/**
	 * Create a AnB_Crypto_Wrapper for a specified key store setting map
	 * 
	 * @param kssd the specified key store setting map
	 * @see Crypto_KeyStoreSettings_Map
	 */

	public AnB_Crypto_Wrapper(Crypto_KeyStoreSettings_Map kssd) {
		super();
		Setup(kssd);
	}

	/**
	 * Create a AnB_Crypto_Wrapper for a specified key store setting map and
	 * cryptographic configuration
	 * 
	 * @param kssd the specified key store setting map
	 * @param config the specified cryptographic configuration
	 * @see Crypto_KeyStoreSettings_Map
	 * @see Crypto_Config
	 */

	public AnB_Crypto_Wrapper(Crypto_KeyStoreSettings_Map kssd, Crypto_Config config) {
		super();
		Setup(kssd, config);
	}

	// -------------------- crypto info ----------------

	/**
	 * Prints information about the cryptographic engine including supported
	 * algorithms
	 *
	 * @see Crypto_EncryptionEngine
	 */

	public static void getInfo() {
		logExecutionTime("getInfo", () -> Crypto_EncryptionEngine.getInfo());
	}

	// -------------------- crypto info ----------------

	// ----------------- setup -------------------

	/**
	 * Setup a AnB_Crypto_Wrapper for a specified key store setting map
	 * 
	 * @param kssd the specified key store setting map
	 */

	public void Setup(Crypto_KeyStoreSettings_Map kssd) {
		Crypto_KeyStoreBuilder_Map ksbd = new Crypto_KeyStoreBuilder_Map(kssd);
		ee = logExecutionTime("Setup", () -> new Crypto_EncryptionEngine(ksbd));
		setMyIdentity();
	}

	/**
	 * Setup a AnB_Crypto_Wrapper for a specified key store setting map and
	 * cryptographic configuration
	 * 
	 * @param kssd the specified key store setting map
	 * @param config the specified cryptographic configuration
	 * @see Crypto_KeyStoreSettings_Map
	 * @see Crypto_Config
	 */

	public void Setup(Crypto_KeyStoreSettings_Map kssd, Crypto_Config config) {
		Crypto_KeyStoreBuilder_Map ksbd = new Crypto_KeyStoreBuilder_Map(kssd);
		ee = logExecutionTime("Setup", () -> new Crypto_EncryptionEngine(ksbd, config));
		setMyIdentity();
	}

	/**
	 * Retrieve the default Crypto_KeyStoreSettings_Map for the current
	 * cryptographic engine
	 * 
	 * @return the Crypto_KeyStoreSettings_Map
	 * @see Crypto_KeyStoreSettings_Map
	 * 
	 */

	public Crypto_KeyStoreSettings_Map getKeyStoreSettings_Map() {
		return logExecutionTime("Crypto_KeyStoreSettings_Map", () -> ee.getKeyStoreSettings_Map());
	}

	// --------------------- setup -------------------

	// ---------------- cert/identities -----------------------

	/**
	 * Returns the agent name associated with this for the current
	 * AnB_Crypto_Wrapper
	 * 
	 * @return the agent's name
	 * 
	 */

	public String getName() {
		return me.getName();
	}

	/**
	 * Check is an agent's alias is stored in the key stores accessible to the
	 * cryptographic engine
	 * 
	 * @param alias the agent's alias
	 * @return true if the agent's alias exists
	 * 
	 */

	public boolean aliasExists(String alias) {
		return ee.containsAlias(alias);
	}

	/**
	 * Retrieve a public key associated to an agent's alias for a specified
	 * Crypto_KeyStoreType
	 * 
	 * @param alias the agent's alias
	 * @param kst the crypto key store type
	 * @return the public key
	 * 
	 */

	public PublicKey getPublicKey(String alias, Crypto_KeyStoreType kst) {
		return logExecutionTime("getPublicKey", () -> ee.getPublicKey(alias, kst));
	}

	/**
	 * Retrieve the certificate associated to an agent's alias for a specified
	 * Crypto_KeyStoreType
	 * 
	 * @param alias the agent's alias
	 * @param kst the crypto key store type
	 * @return the certificate
	 * 
	 */
	
	protected Certificate getRemoteCertificate(String alias, Crypto_KeyStoreType kst) {
		return logExecutionTime("getRemoteCertificate", () -> ee.getRemoteCertificate(alias, kst));
	}

	/**
	 * Retrieve the certificates associated to an agent's alias
	 * 
	 * @param alias the agent's alias
	 * @return the certificates
	 * 
	 */
	
	protected Map<Crypto_KeyStoreType, Certificate> getRemoteCertificates(String alias) {
		return logExecutionTime("getRemoteCertificate", () -> ee.getRemoteCertificates(alias));
	}

	/**
	 * Retrieve the identity of the current agent
	 * @return the identity
	 * 
	*/
	
	protected AnBx_Agent getMyIdentity() {
		return me;
	}

	/**
	 * Set the identity of the current agent
	 * 
	*/
	
	
	protected void setMyIdentity() {
		me = new AnBx_Agent(ee.getMyAlias(this.ident_ks), ee.getLocaleCertificates());
	}

	// ---------------- cert/identities -----------------------

	// ---------------- send/receive -----------------------

	
	/**
	 * Send an object over a channel
	 * @param obj the object
	 * @param c the channel abstraction
	 * 
	*/
	
	protected void Send(Object obj, Channel_Abstraction c) {
		AnBx_Debug.out(layer, "Send");
		logExecutionTime("Send", () -> c.Send(obj));
	}

	/**
	 * Receive an object from a channel
	 * @param c the channel abstraction
	 * @return the object
	 * 
	*/	
	
	protected Object Receive(Channel_Abstraction c) {
		AnBx_Debug.out(layer, "Receive");
		return logExecutionTime("Receive", () -> c.Receive());
	}

	/**
	 * Set the identity of the current agent
	 * 
	*/
	
	/**
	 * Send the identity of an agent over a channel
	 * @param id the agent id
	 * @param c the channel abstraction
	 * 
	*/
	
	
	protected void Send_Id(AnBx_Agent id, Channel_Abstraction c) {
		logExecutionTime("Send_Id", () -> Send(id, c));
	}
	
	/**
	 * Receive the identity of an agent from a channel
	 * @param c the channel abstraction
	 * @return the agent identity
	 * 
	*/
	
	protected AnBx_Agent Receive_RemoteId(Channel_Abstraction c) {
		return logExecutionTime("Receive_RemoteId", () -> (AnBx_Agent) Receive(c));
	}

	// ---------------- send/receive -----------------------

	// ---------------- encrypt/decrypt -----------------------

	// ASYMMETRIC -------------------

	// HYBRID

	/**
	 * Encrypts an object with a public key retrieved from the default key store
	 * associated to an user identified by an alias
	 *
	 * @param object the object to encrypt
	 * @param alias the identifier of the agent
	 * @return the encrypted object as Crypto_SealedPair
	 * @see Crypto_SealedPair
	 */

	public Crypto_SealedPair encrypt(Object object, String alias) {
		return logExecutionTime("encrypt", () -> ee.encrypt(object, alias, Crypto_KeyStoreType.pk()));
			
	}

	/**
	 * Encrypts an object with a public key retrieved from a specified key store
	 * associated to an user identified by an alias
	 *
	 * @param object the object to encrypt
	 * @param alias the identifier of the agent
	 * @param pk the specified key store
	 * @return the encrypted object as Crypto_SealedPair
	 * @see Crypto_SealedPair
	 * @see Crypto_KeyStoreType
	 */

	public Crypto_SealedPair encrypt(Object object, String alias, Crypto_KeyStoreType pk) {
		return logExecutionTime("encrypt", () ->  ee.encrypt(object, alias, pk));
	}

	/**
	 * Encrypts an object with the public key of a specified key pair
	 *
	 * @param object the object to encrypt
	 * @param kp the specified key pair
	 * @return the encrypted object as Crypto_SealedPair
	 * @see Crypto_SealedPair
	 */

	public Crypto_SealedPair encrypt(Object object, Crypto_KeyPair kp) {
		return logExecutionTime("encrypt", () -> ee.encrypt(object, kp.getPublicKey()));
	}

	/**
	 * Encrypts an object with a specified public key
	 *
	 * @param object the object to encrypt
	 * @param publicKey the specified public key
	 * @return the encrypted object as Crypto_SealedPair
	 * @see Crypto_SealedPair
	 */

	public Crypto_SealedPair encrypt(Object object, PublicKey publicKey) {
		return logExecutionTime("encrypt", () ->  ee.encrypt(object, publicKey));
	}

	/**
	 * Decrypts a Crypto_SealedPair with the private key from the default key
	 * store associated to current agent
	 *
	 * @param sc the Crypto_SealedPair to decrypt
	 * @return the decrypted object
	 * @see Crypto_SealedPair
	 */

	public Object decrypt(Crypto_SealedPair sc) {
		return logExecutionTime("decrypt", () ->  ee.decrypt(sc, Crypto_KeyStoreType.pk()));
	}

	/**
	 * Decrypts a Crypto_SealedPair with the private key from a specified key
	 * store associated to current agent
	 *
	 * @param sc the Crypto_SealedPair to decrypt
	 * @param pk the specified key store
	 * @return the decrypted object
	 * @see Crypto_SealedPair
	 * @see Crypto_KeyStoreType
	 */

	public Object decrypt(Crypto_SealedPair sc, Crypto_KeyStoreType pk) {
		return logExecutionTime("decrypt", () -> ee.decrypt(sc, pk));
	}

	/**
	 * Decrypts a Crypto_SealedPair with the private key from a specified key
	 * pair
	 *
	 * @param sc the Crypto_SealedPair to decrypt
	 * @param kp the specified key pair
	 * @return the decrypted object
	 * @see Crypto_KeyPair
	 */

	public Object decrypt(Crypto_SealedPair sc, Crypto_KeyPair kp) {
		return logExecutionTime("decrypt", () ->  ee.decrypt(sc, kp));
	}

	// SYMMETRIC ---------------------

	/**
	 * Encrypts an object with a specified symmetric key
	 *
	 * @param object the object to encrypt
	 * @param symmetricKey the specified symmetric key
	 * @return the encrypted object as SealedObject
	 */

	public SealedObject encrypt(Object object, SecretKey symmetricKey) {
		return logExecutionTime("encrypt", () -> ee.encrypt(object, symmetricKey));
	}

	/**
	 * Decrypts a SealedObject with a specified symmetric key
	 *
	 * @param so the SealedObject to encrypt
	 * @param symmetricKey the specified symmetric key
	 * @return the encrypted object as SealedObject
	 */

	public Object decrypt(SealedObject so, SecretKey symmetricKey) {
		return logExecutionTime("decrypt", () ->  ee.decrypt(so, symmetricKey));
	}

	// ---------------- encrypt/decrypt -----------------------

	// ---------------- sign/verify -----------------------

	/**
	 * Signs an object with the private key of the current agent retrieved from
	 * the default key store
	 *
	 * @param object the object to sign
	 * @return the signed object as SignedObject
	 */

	public SignedObject sign(Object object) {
		return logExecutionTime("sign", () ->  ee.sign(object, Crypto_KeyStoreType.sk()));
	}

	/**
	 * Signs an object with the private key of the current agent retrieved from
	 * a specified key store
	 *
	 * @param object the object to sign
	 * @param sk the specified key store
	 * @return the signed object as SignedObject
	 * @see Crypto_KeyStoreType
	 * 
	 */

	public SignedObject sign(Object object, Crypto_KeyStoreType sk) {
		return logExecutionTime("sign", () -> ee.sign(object, sk));
	}

	/**
	 * Signs an object with a private key retrieved from the specified key pair
	 *
	 * @param object the object to sign
	 * @param kp the specified key pair
	 * @return the signed object as SignedObject
	 * @see Crypto_KeyPair
	 * 
	 */

	public SignedObject sign(Object object, Crypto_KeyPair kp) {
		return logExecutionTime("sign", () -> ee.sign(object, kp));
	}

	/**
	 * Verifies a SignedObject with a private key retrieved from the default key
	 * store associated to an agent identified by an alias
	 *
	 * @param so the SignedObject to verify
	 * @param alias the identifier of the agent
	 * @return the verified object
	 * @see Crypto_KeyPair
	 * 
	 */

	public Object verify(SignedObject so, String alias) {
		return logExecutionTime("verify", () -> ee.verify(so, alias, Crypto_KeyStoreType.sk()));
	}

	/**
	 * Verifies a SignedObject with a private key retrieved from a specified key
	 * store associated to an agent identified by an alias
	 *
	 * @param so the SignedObject to verify
	 * @param alias the identifier of the agent
	 * @param sk the specified key store
	 * @return the verified object
	 * @see Crypto_KeyStoreType
	 * 
	 */

	public Object verify(SignedObject so, String alias, Crypto_KeyStoreType sk) {
		return logExecutionTime("verify", () -> ee.verify(so, alias, sk));
	}

	/**
	 * Verifies a SignedObject with a specified public key
	 *
	 * @param so the SignedObject to verify
	 * @param pk the specified public key
	 * @return the verified object
	 * 
	 */

	public Object verify(SignedObject so, PublicKey pk) {
		return logExecutionTime("verify", () ->  ee.verify(so, pk));
	}

	// ---------------- sign/verify -----------------------

	// ---------------- nonces, keys, seqnumbers -----------------------

	/**
	 * Generates a fresh nonce
	 *
	 * @return the fresh nonce
	 * 
	 */

	public Crypto_ByteArray getNonce() {
		return logExecutionTime("getNonce", () ->  ee.getNonce());
	}

	/**
	 * Generates a sequence number
	 *
	 * @return the sequence number
	 * 
	 */

	public Crypto_ByteArray getSeqNumber() {
		return logExecutionTime("getSeqNumber", () -> ee.getNonce());
	}

	/**
	 * Generates a symmetric key
	 *
	 * @return the symmetric key
	 * 
	 */

	public SecretKey getSymmetricKey() {
		return logExecutionTime("getSymmetricKey", () -> ee.getSymmetricKey());
	}

	/**
	 * Generates a HMAC secret key
	 *
	 * @return the HMAC secret key
	 * 
	 */

	public SecretKey getHmacKey() {
		return logExecutionTime("getHmacKey", () -> ee.getHmacKey());
	}

	/**
	 * Generates a time stamp
	 *
	 * @return the time stamp
	 * 
	 */

	public Instant getTimeStamp() {
		return logExecutionTime("getTimeStamp", () -> ee.getTimeStamp());
	}

	/**
	 * Generates a symmetric key for Password Based Encryption (PBE)
	 *
	 * @param password the password
	 * @param salt the salting argument
	 * @return the symmetric key
	 * 
	 */

	public SecretKey getSymmetricKeyPBE(String password, String salt) {
		return logExecutionTime("getSymmetricKeyPBE", () ->  ee.getSymmetricKeyPBE(password, salt));
	}

	// ---------------- nonces, keys, seqnumbers -----------------

	// ---------------- key exchange ----------------------

	/**
	 * Generates a key exchange key pair for the default key agreement algorithm
	 *
	 * @return the key exchange key pair
	 * 
	 */

	public KeyPair getKeyEx_KeyPair() {
		return logExecutionTime("getKeyEx_KeyPair", () -> ee.getKeyEx_KeyPair());
	}

	/**
	 * Retrieves the public key from a specified key exchange key pair
	 *
	 * @param keyPair the specified key pair
	 * @return the key pair
	 */

	public PublicKey getKeyEx_PublicKey(KeyPair keyPair) {
		return logExecutionTime("getKeyEx_PublicKey", () ->  ee.getKeyEx_PublicKey(keyPair));
	}

	/**
	 * Retrieves the secret key from a specified key exchange key pair and
	 * associated public key
	 *
	 * @param keyPair the specified key pair
	 * @param publicKey the associated public key
	 * @return the (symmetric) secret key
	 */

	public SecretKey getKeyEx_SecretKey(PublicKey publicKey, KeyPair keyPair) {
		return logExecutionTime("getKeyEx_SecretKey", () -> ee.getKeyEx_SecretKey(publicKey, keyPair));
	}

	// ---------------- key exchange ----------------------

	// ---------------- fresh key pair ------------------

	/**
	 * Generates a key pair for the default public key algorithm
	 *
	 * @return the key pair
	 * @see Crypto_KeyPair
	 * 
	 */

	public Crypto_KeyPair getKeyPair() {
		return logExecutionTime("getKeyPair", () -> ee.getKeyPair());
	}

	/**
	 * Retrieves the public key from a specified key pair
	 *
	 * @param pair the specified key pair
	 * @return the public key
	 * @see Crypto_KeyPair
	 */

	public PublicKey getPublicKey(Crypto_KeyPair pair) {
		return logExecutionTime("getPublicKey", () -> ee.getKeyPair_PublicKey(pair));
	}

	// ---------------- fresh key pair ------------------

	// ---------------- digest hash/hmac ------------------

	/**
	 * Computes the hash of a given object with the default hashing algorithm
	 * 
	 * @param object the given object
	 * @return the hash value as Crypto_ByteArray
	 */

	public Crypto_ByteArray makeDigest(Object object) {
		return logExecutionTime("makeDigest", () -> ee.makeDigest(object));
	}

	/**
	 * Computes the hmac of a given object with the default hashing algorithm
	 * and a specified secret key
	 * 
	 * @param object the given object
	 * @param sk the secret key
	 * @return the hmac value as Crypto_ByteArray
	 * @see Crypto_ByteArray
	 */

	public Crypto_ByteArray makeHmac(Object object, SecretKey sk) {
		return logExecutionTime("makeHmac", () -> ee.makeHmacValue(object, sk));
	}

	/**
	 * Check a hmac value of a given object computed with the default hashing
	 * algorithm and a specified secret key
	 * 
	 * @param object the given object
	 * @param hmac the hmac value
	 * @param sk the secret key
	 * @return the hmac value as Crypto_ByteArray
	 * @see Crypto_ByteArray
	 */

	public boolean checkHmac(Object object, Crypto_ByteArray hmac, SecretKey sk) {
		return logExecutionTime("checkHmac", () -> ee.checkHmacValue(object, hmac, sk));
	}

	// ---------------- digest hash/hmac ------------------

	// ------------------- xor -----------------

	/**
	 * Computes the xor of two Crypto_ByteArrays
	 * 
	 * @param x1 the first Crypto_ByteArray argument
	 * @param x2 the second Crypto_ByteArray argument
	 * @return the computed xor value
	 * @see Crypto_ByteArray
	 */

	public Crypto_ByteArray xor(Crypto_ByteArray x1, Crypto_ByteArray x2) {
		return logExecutionTime("xor", () -> ee.xor(x1, x2));
	}

	// ------------------- xor -----------------

	// ---------------- serialisation ------------------

	/**
	 * Writes a serialised object to the file system
	 * 
	 * @param object the given object
	 * @param filename the specified destination file
	 *
	 */

	public static void writeObject(Object object, String filename) {
		logExecutionTime("writeObject", () -> Crypto_EncryptionEngine.writeObject(object, filename));
	}

	/**
	 * Writes a serialised object from the file system
	 * 
	 * @param filename the specified source file
	 * @return the retrieved object
	 *
	 */

	public static Object readObject(String filename) {
		return logExecutionTime("readObject", () -> Crypto_EncryptionEngine.readObject(filename));
	}

	// ---------------- serialisation -----------------
	
	// ---------------- benchmarking -----------------

	
	/**
	 * Logs the execution time of a given action that returns a result.
	 *
	 * @param <T>        The type of the result returned by the action.
	 * @param methodName The name of the method being logged.
	 * @param action     A {@link Supplier} representing the action whose execution time will be measured.
	 * @return The result of the action.
	 */
	private static <T> T logExecutionTime(String methodName, Supplier<T> action) {
	    long start = System.nanoTime();
	    T result = action.get();
	    long end = System.nanoTime();
	    // Convert to milliseconds with floating-point precision
	    if (loggingExecTimeEnabled) {
		    // Convert to milliseconds with floating-point precision
		    double durationInMs = (end - start) / 1_000_000.0;
		    AnBx_Debug.out(layer, String.format("%s - Execution time was %.3f ms.", methodName, durationInMs));
	    	}
	    return result;
	    }

	/**
	 * Logs the execution time of a given action that does not return a result.
	 *
	 * @param methodName The name of the method being logged.
	 * @param action     A {@link Runnable} representing the action whose execution time will be measured.
	 */
	private static void logExecutionTime(String methodName, Runnable action) {
	    long start = System.nanoTime();
	    action.run();
	    long end = System.nanoTime();
	    if (loggingExecTimeEnabled) {
		    // Convert to milliseconds with floating-point precision
		    double durationInMs = (end - start) / 1_000_000.0;
		    AnBx_Debug.out(layer, String.format("%s - Execution time was %.3f ms.", methodName, durationInMs));
	    }
	}
	
	// ---------------- benchmarking -----------------
	
}
