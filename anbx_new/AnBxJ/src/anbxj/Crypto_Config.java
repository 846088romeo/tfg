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

import java.security.Provider;
import java.security.Security;
import java.util.Properties;

/**
 * An abstract class for encryption configuration.
 */

public class Crypto_Config {

    private final static AnBx_Layers layer = AnBx_Layers.ENCRYPTION;

    // Default values -- see Crypto_EncryptionEngine.java and CryptoConfig

    /**
     * The cipher scheme.
     */
    protected String cipherScheme = Crypto_Config_Default.cipherScheme;

    /**
     * The key size.
     */
    protected int keySize = Crypto_Config_Default.keySize;

    /**
     * The key generation scheme.
     */
    protected String keyGenerationScheme = Crypto_Config_Default.keyGenerationScheme;

    /**
     * The key generation size.
     */
    protected int keyGenerationSize = Crypto_Config_Default.keyGenerationSize;

    /**
     * The key generation scheme for password-based encryption (PBE).
     */
    protected String keyGenerationSchemePBE = Crypto_Config_Default.keyGenerationSchemePBE;

    /**
     * The key pair generation scheme.
     */
    protected String keyPairGenerationScheme = Crypto_Config_Default.keyPairGenerationScheme;

    /**
     * The key pair generation size.
     */
    protected int keyPairGenerationSize = Crypto_Config_Default.keyPairGenerationSize;

    /**
     * The secure random algorithm.
     */
    protected String secureRandomAlgorithm = Crypto_Config_Default.secureRandomAlgorithm;

    /**
     * The HMAC algorithm.
     */
    protected String hmacAlgorithm = Crypto_Config_Default.hmacAlgorithm;

    /**
     * The message digest algorithm.
     */
    protected String messageDigestAlgorithm = Crypto_Config_Default.messageDigestAlgorithm;

    /**
     * The message digest algorithm.
     */
    protected String messageDigestSignatureAlgorithm = Crypto_Config_Default.messageDigestSignatureAlgorithm;

    
    /**
     * The key agreement algorithm.
     */
    protected String keyAgreementAlgorithm = Crypto_Config_Default.keyAgreementAlgorithm;

    
    /**
     * The key pair generation for key agreement algorithm.
     */
    protected String keyAgreementKeyPairGenerationScheme = Crypto_Config_Default.keyAgreementKeyPairGenerationScheme;
    
    
    /**
     * The Diffie-Hellman random exponent size.
     */
    protected int dhRndExpSize = Crypto_Config_Default.dhRndExpSize;

    
    /**
     * The Elliptic Curve.
     */
    protected String ecGenParameterSpec = Crypto_Config_Default.ecGenParameterSpec; 
    
    
    /**
     * The asymmetric cipher scheme block.
     */
    protected String asymCipherSchemeBlock = Crypto_Config_Default.asymCipherSchemeBlock;
    
    /**
     * The SSL context.
     */
    protected String sslContext = Crypto_Config_Default.sslContext;
    

    /**
     * The global security provider.
     */
    protected String securityProvider = Crypto_Config_Default.securityProvider;

    /**
     * The provider for cipher scheme.
     */
    protected String cipherSchemeProvider = null;

    /**
     * The provider for key generation.
     */
    protected String keyGenerationSchemeProvider = null;

    /**
     * The provider for PBE key generation.
     */
    protected String keyGenerationSchemePBEProvider = null;
    
    /**
     * The provider for key pair generation.
     */
    protected String keyPairGenerationSchemeProvider = null;

    /**
     * The provider for secure random algorithm.
     */
    protected String secureRandomProvider = null;

    /**
     * The provider for HMAC algorithm.
     */
    protected String hmacProvider = null;

    /**
     * The provider for message digest algorithm.
     */
    protected String messageDigestProvider = null;


    /**
     * The provider for signature algorithm.
     */
    protected String signatureProvider = null;

    /**
     * The provider for signature algorithm.
     */
    protected String asymEncProvider = null;
    
    
    /**
     * The provider for key agreement algorithm.
     */
    protected String keyAgreementProvider = null;

    /**
     * The provider for ssl context.
     */
    private String sslContextProvider;
    
    
    // Private fields (optional, uncomment if needed)
    // private int symblocklength = Crypto_Config_Default.;
    // private int asymBlockLengthEnc = Crypto_Config_Default.asymblocklengthenc;
    // private int asymBlockLengthDec = Crypto_Config_Default.asymBlockLengthDec;

    // Constructors

    /**
     * Constructs a Crypto_Config object with default values.
     */
    public Crypto_Config() {
        super();
    }

    /**
     * Constructs a Crypto_Config object with a global provider.
     *
     * @param cipherScheme              The cipher scheme.
     * @param keySize                   The key size.
     * @param keyGenerationScheme       The key generation scheme.
     * @param keyGenerationSchemePBE    The key generation scheme for password-based encryption (PBE).
     * @param keyGenerationSize         The key generation size.
     * @param keyPairGenerationScheme   The key pair generation scheme.
     * @param keyPairGenerationSize     The key pair generation size.
     * @param secureRandomAlgorithm     The secure random algorithm.
     * @param hmacAlgorithm             The HMAC algorithm.
     * @param messageDigestAlgorithm    The message digest algorithm.
     * @param messageDigestSignatureAlgorithm The message digest algorithm for signature.
     * @param keyAgreementAlgorithm     The key agreement algorithm.
     * @param keyAgreementKeyPairGenerationScheme	The key pair generation scheme for key agreement algorithm 
     * @param dhRndExpSize              The Diffie-Hellman random exponent size.
     * @param ecGenParameterSpec		The elliptic curve
     * @param asymCipherSchemeBlock     The asymmetric cipher scheme block.
     * @param sslContext                The SSL context.
     * @param securityProvider          The security provider.
     */
	
    public Crypto_Config(String cipherScheme, int keySize, String keyGenerationScheme, String keyGenerationSchemePBE, int keyGenerationSize,
                         String keyPairGenerationScheme, int keyPairGenerationSize, String secureRandomAlgorithm, String hmacAlgorithm,
                         String messageDigestAlgorithm, String messageDigestSignatureAlgorithm, String keyAgreementAlgorithm, 
                         String keyAgreementKeyPairGenerationScheme, int dhRndExpSize, String ecGenParameterSpec, String asymCipherSchemeBlock, String sslContext, String securityProvider) {
		super();

		if (testStr(cipherScheme)) this.cipherScheme = cipherScheme;
		if (keySize > 0) this.keySize = keySize;
		if (testStr(keyGenerationScheme)) this.keyGenerationScheme = keyGenerationScheme;
		
		if (testStr(keyGenerationSchemePBE)) 
			this.keyGenerationSchemePBE = keyGenerationSchemePBE;
			// if keyGenerationScheme entry not provided uses cipherScheme
		else
			this.keyGenerationScheme = this.cipherScheme;
		
		if (keyGenerationSize > 0) 
			this.keyGenerationSize = keyGenerationSize;
			// if keyGenerationSize entry not provided uses keySize
		else
			this.keyGenerationSize = this.keySize;
		
		if (testStr(keyPairGenerationScheme)) this.keyPairGenerationScheme = keyPairGenerationScheme;
		if (keyPairGenerationSize > 0) this.keyPairGenerationSize = keyPairGenerationSize;
		if (testStr(secureRandomAlgorithm)) this.secureRandomAlgorithm = secureRandomAlgorithm;
		if (testStr(hmacAlgorithm)) this.hmacAlgorithm = hmacAlgorithm;
		if (testStr(messageDigestAlgorithm)) this.messageDigestAlgorithm = messageDigestAlgorithm;
		if (testStr(messageDigestSignatureAlgorithm)) this.messageDigestSignatureAlgorithm = messageDigestSignatureAlgorithm;
		if (testStr(keyAgreementAlgorithm)) this.keyAgreementAlgorithm = keyAgreementAlgorithm;
		if (testStr(keyAgreementKeyPairGenerationScheme)) this.keyAgreementKeyPairGenerationScheme = keyAgreementKeyPairGenerationScheme;
		if (dhRndExpSize > 0) this.dhRndExpSize = dhRndExpSize; 
		if (testStr(ecGenParameterSpec))	this.ecGenParameterSpec = ecGenParameterSpec;
		if (testStr(asymCipherSchemeBlock))	this.asymCipherSchemeBlock = asymCipherSchemeBlock;
		if (testStr(sslContext)) this.sslContext = sslContext;
        
        if (testStr(securityProvider))
        	{
        			if (securityProvider == null || securityProvider.equalsIgnoreCase(Crypto_Config_Default.securityProvider)) securityProvider = null;
        	
        			this.securityProvider = securityProvider;
        			// set the providers as the global security provider
        		    this.cipherSchemeProvider = securityProvider;
        		    this.keyGenerationSchemeProvider = securityProvider;
        		    this.keyGenerationSchemePBEProvider = securityProvider;
        		    this.keyPairGenerationSchemeProvider = securityProvider;
        		    this.secureRandomProvider = null;
        		    this.hmacProvider = securityProvider;
        		    this.messageDigestProvider = securityProvider;
        		    this.signatureProvider = securityProvider;
        		    this.asymEncProvider = securityProvider;
        		    this.keyAgreementProvider = securityProvider;
        		    this.sslContextProvider = securityProvider;
        		    
        	}		
    }

    /**
     * Constructs a Crypto_Config object with all the fine-grained providers.
     *
     * @param cipherScheme              The cipher scheme.
     * @param keySize                   The key size.
     * @param keyGenerationScheme       The key generation scheme.
     * @param keyGenerationSchemePBE    The key generation scheme for password-based encryption (PBE).
     * @param keyGenerationSize         The key generation size.
     * @param keyPairGenerationScheme   The key pair generation scheme.
     * @param keyPairGenerationSize     The key pair generation size.
     * @param secureRandomAlgorithm     The secure random algorithm.
     * @param hmacAlgorithm             The HMAC algorithm.
     * @param messageDigestAlgorithm    The message digest algorithm.
     * @param messageDigestSignatureAlgorithm    The message digest signature algorithm.
     * @param keyAgreementAlgorithm     The key agreement algorithm.
     * @param keyAgreementKeyPairGenerationScheme	The key pair generation scheme for key agreement algorithm 
     * @param dhRndExpSize              The Diffie-Hellman random exponent size.
     * @param ecGenParameterSpec		The elliptic curve
     * @param asymCipherSchemeBlock     The asymmetric cipher scheme block.
     * @param sslContext                The SSL context.
     * @param securityProvider          The global security provider.
     * @param cipherSchemeProvider      The provider for cipher scheme.
     * @param keyGenerationSchemeProvider     The provider for key generation.
     * @param keyGenerationSchemePBEProvider  The provider for PBE key generation.
     * @param keyPairGenerationSchemeProvider The provider for key pair generation.
     * @param secureRandomProvider      The provider for secure random algorithm.
     * @param hmacProvider              The provider for HMAC algorithm.
     * @param messageDigestProvider     The provider for message digest algorithm.
     * @param keyAgreementProvider      The provider for key agreement algorithm.
     * @param asymEncProvider      		The provider for asymmetric encryption.
     * @param sslContextProvider        The provider for SSL context.
     * @param signatureProvider		    The provider for Signature
     */
    
    public Crypto_Config(String cipherScheme, int keySize, String keyGenerationScheme, String keyGenerationSchemePBE, int keyGenerationSize,
                         String keyPairGenerationScheme, int keyPairGenerationSize, String secureRandomAlgorithm, String hmacAlgorithm,
                         String messageDigestAlgorithm, String messageDigestSignatureAlgorithm, String keyAgreementAlgorithm, String keyAgreementKeyPairGenerationScheme, 
                         int dhRndExpSize, String ecGenParameterSpec, String asymCipherSchemeBlock,
                         String sslContext, String securityProvider,
                         String cipherSchemeProvider, String keyGenerationSchemeProvider, String keyGenerationSchemePBEProvider, String keyPairGenerationSchemeProvider,
                         String secureRandomProvider, String hmacProvider, String messageDigestProvider, String signatureProvider, String asymEncProvider, String keyAgreementProvider,
                         String sslContextProvider) {
        this(cipherScheme, keySize, keyGenerationScheme, keyGenerationSchemePBE, keyGenerationSize,
             keyPairGenerationScheme, keyPairGenerationSize, secureRandomAlgorithm, hmacAlgorithm,
             messageDigestAlgorithm, messageDigestSignatureAlgorithm, keyAgreementAlgorithm, keyAgreementKeyPairGenerationScheme, 
             dhRndExpSize, ecGenParameterSpec, asymCipherSchemeBlock, sslContext, securityProvider);
        
        if (securityProvider == null || securityProvider.equalsIgnoreCase(Crypto_Config_Default.securityProvider)) securityProvider = null;
		
			// Assign providers using the helper method
			this.cipherSchemeProvider = getProvider(cipherSchemeProvider, securityProvider);
			this.keyGenerationSchemeProvider = getProvider(keyGenerationSchemeProvider, securityProvider);
			this.keyGenerationSchemePBEProvider = getProvider(keyGenerationSchemePBEProvider, securityProvider);
			this.keyPairGenerationSchemeProvider = getProvider(keyPairGenerationSchemeProvider, securityProvider);
			// ignore the specific SecureRandom provider as BC does not have one
			this.secureRandomProvider = getProvider(secureRandomProvider, null);
			this.hmacProvider = getProvider(hmacProvider, securityProvider);
			this.messageDigestProvider = getProvider(messageDigestProvider, securityProvider);
			this.signatureProvider = getProvider(signatureProvider, securityProvider);
			this.asymEncProvider = getProvider(asymEncProvider, securityProvider);
			this.keyAgreementProvider = getProvider(keyAgreementProvider, securityProvider);
			this.sslContextProvider = getProvider(sslContextProvider, securityProvider);

    }    
    
    /**
	 * Constructs a Crypto_Config object from the properties specified in the given configuration file.
	 *
	 * @param configFile The properties configuration file.
	 */

	public Crypto_Config(Properties configFile) {
        this(
            getTrimmedProperty(configFile, "cipherScheme", Crypto_Config_Default.cipherScheme),
            parseIntProperty(configFile, "keySize", Crypto_Config_Default.keySize),
            getTrimmedProperty(configFile, "keyGenerationScheme", Crypto_Config_Default.keyGenerationSchemePBE),
            getTrimmedProperty(configFile, "keyGenerationSchemePBE", Crypto_Config_Default.keyGenerationSchemePBE),
            parseIntProperty(configFile, "keyGenerationSize", Crypto_Config_Default.keyGenerationSize),
            getTrimmedProperty(configFile, "keyPairGenerationScheme", Crypto_Config_Default.keyPairGenerationScheme),
            parseIntProperty(configFile, "keyPairGenerationSize", Crypto_Config_Default.keyPairGenerationSize),
            getTrimmedProperty(configFile, "secureRandomAlgorithm", Crypto_Config_Default.secureRandomAlgorithm),
            getTrimmedProperty(configFile, "hMacAlgorithm", Crypto_Config_Default.hmacAlgorithm),
            getTrimmedProperty(configFile, "messageDigestAlgorithm", Crypto_Config_Default.messageDigestAlgorithm),
            getTrimmedProperty(configFile, "messageDigestSignatureAlgorithm", Crypto_Config_Default.messageDigestSignatureAlgorithm),
            getTrimmedProperty(configFile, "keyAgreementAlgorithm", Crypto_Config_Default.keyAgreementAlgorithm),
            getTrimmedProperty(configFile, "keyAgreementKeyPairGenerationScheme", Crypto_Config_Default.keyAgreementKeyPairGenerationScheme),
            parseIntProperty(configFile, "dhRndExpSize", Crypto_Config_Default.dhRndExpSize),
            getTrimmedProperty(configFile, "ecGenParameterSpec", Crypto_Config_Default.ecGenParameterSpec),
            getTrimmedProperty(configFile, "asymCipherSchemeBlock", Crypto_Config_Default.asymCipherSchemeBlock),
            getTrimmedProperty(configFile, "sslContext", Crypto_Config_Default.sslContext),
            getTrimmedProperty(configFile, "securityProvider", Crypto_Config_Default.securityProvider),
            getOptionalTrimmedProperty(configFile, "cipherSchemeProvider"),
            getOptionalTrimmedProperty(configFile, "keyGenerationSchemeProvider"),
            getOptionalTrimmedProperty(configFile, "keyGenerationSchemePBEProvider"),
            getOptionalTrimmedProperty(configFile, "keyPairGenerationSchemeProvider"),
            getOptionalTrimmedProperty(configFile, "secureRandomProvider"),
            getOptionalTrimmedProperty(configFile, "hmacProvider"),
            getOptionalTrimmedProperty(configFile, "messageDigestProvider"),
            getOptionalTrimmedProperty(configFile, "signatureProvider"),
            getOptionalTrimmedProperty(configFile, "asymEncProvider"),
            getOptionalTrimmedProperty(configFile, "keyAgreementProvider"),
            getOptionalTrimmedProperty(configFile, "sslContextProvider")
        );
		getInfo();
    }
    
    /**
     * Returns the appropriate provider based on the availability of global and specific security providers.
     *
     * This method checks if the specific provider is non-null and not empty. If it is, the specific provider
     * is returned. If the specific provider is null or empty, it then checks if the global provider is
     * non-null and not empty. If the global provider is available, it is returned. If neither the specific
     * nor the global provider is available, the method returns null.
     *
     * @param specificProvider the specific provider to check.
     * @param securityProvider the global provider to use as a fallback if the specific provider is not available.
     * @return the specific provider if available, otherwise the global provider if available, or null if neither are available.
     */
	
	
	private String getProvider(String specificProvider, String securityProvider) {
	    String givenProvider = testStr(specificProvider) ? specificProvider : securityProvider;

	    if (givenProvider == null) return null;
	    if (givenProvider.equalsIgnoreCase(Crypto_Config_Default.securityProvider)) return null;
	    if (isProviderAvailable(givenProvider)) return givenProvider;
	    logAndTerminate(givenProvider, securityProvider);
	    
	    return null; // Unreachable, but required for compilation
	}

	/**
	 * Logs an error message and terminates the program.
	 *
	 * @param givenProvider the provider that was attempted to be used and could not be found.
	 * @param securityProvider the global security provider used as a fallback, which is also logged.
	 */
	private void logAndTerminate(String givenProvider, String securityProvider) {
	    AnBx_Debug.out(AnBx_Layers.ALWAYS, "The program will now terminate!");
	    AnBx_Debug.out(AnBx_Layers.ALWAYS, "The provider: " + givenProvider + " cannot be found.");
	    AnBx_Debug.out(AnBx_Layers.ALWAYS, "Global security provider: " + securityProvider);
	    printAvailableProviders();
	    System.exit(1);
	}
   
    /**
     * Prints the available security providers
    */ 
        
    private void printAvailableProviders() {
        AnBx_Debug.out(AnBx_Layers.ALWAYS, "Available providers:");
        Crypto_ProviderInformation.listProviders(AnBx_Layers.ALWAYS);
    }
    
    /**
     * Checks if a cryptographic provider is available in the current Java runtime environment.
     *
     * @param providerName The name of the provider to check.
     *                     It should be a non-null, non-empty string representing the name of the cryptographic provider.
     * @return {@code true} if the specified provider is available, {@code false} otherwise.
     */
    private boolean isProviderAvailable(String providerName) {
        if (providerName == null || providerName.isEmpty()) {
            return false;
        }

        for (Provider provider : Security.getProviders()) {
            if (provider.getName().equalsIgnoreCase(providerName)) {
                return true;
            }
        }

        return false;
    }
    
    /**
     * Retrieves a property value from the configuration file, trims it, and returns it.
     * If the property is not found, the provided default value is returned.
     *
     * @param configFile The properties configuration file.
     * @param key The property key to be retrieved.
     * @param defaultValue The default value to return if the property is not found.
     * @return The trimmed property value or the default value if the property is not found.
     */
    private static String getTrimmedProperty(Properties configFile, String key, String defaultValue) {
        String value = configFile.getProperty(key, defaultValue);
        return value != null ? value.trim() : defaultValue;
    }

    /**
     * Retrieves a property value from the configuration file and trims it.
     * If the property is not found, returns null.
     *
     * @param configFile The properties configuration file.
     * @param key The property key to be retrieved.
     * @return The trimmed property value or null if the property is not found.
     */
    private static String getOptionalTrimmedProperty(Properties configFile, String key) {
        String value = configFile.getProperty(key);
        return value != null ? value.trim() : null;
    }

    /**
     * Retrieves a property value from the configuration file, trims it, and parses it as an integer.
     * If the property is not found or if parsing fails, the provided default value is returned.
     *
     * @param configFile The properties configuration file.
     * @param key The property key to be retrieved.
     * @param defaultValue The default value to return if the property is not found or if parsing fails.
     * @return The parsed integer value of the property or the default value if the property is not found or parsing fails.
	 */

    private static int parseIntProperty(Properties configFile, String key, int defaultValue) {
        String value = configFile.getProperty(key);
        try {
            return value != null ? Integer.parseInt(value.trim()) : defaultValue;
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
	
	/**
	 * Checks if a string is not null and not empty.
	 *
	 * @param str The string to test.
	 * @return {@code true} if the string is not null and not empty; {@code false} otherwise.
	 */
	
	public static boolean testStr(String str) {
		return str != null && !str.isEmpty();
	}
	
	/**
	 * Prints debug information about the crypto configuration.
	 */

	public void getInfo() {

		AnBx_Debug.out(layer, "-------------------- crypto config --------------------");
		AnBx_Debug.out(layer, "cipherScheme = " + this.cipherScheme);
		AnBx_Debug.out(layer, "keySize = " + this.keySize);
		AnBx_Debug.out(layer, "keyGenerationScheme = " + this.keyGenerationScheme);
		AnBx_Debug.out(layer, "keyGenerationSize = " + this.keyGenerationSize);
		AnBx_Debug.out(layer, "keyGenerationSchemePBE = " + this.keyGenerationSchemePBE);
		AnBx_Debug.out(layer, "keyPairGenerationScheme = " + this.keyPairGenerationScheme);
		AnBx_Debug.out(layer, "keyPairGenerationSize = " + this.keyPairGenerationSize);
		AnBx_Debug.out(layer, "secureRandomAlgorithm = " + this.secureRandomAlgorithm);
		AnBx_Debug.out(layer, "hmacAlgorithm = " + this.hmacAlgorithm);
		AnBx_Debug.out(layer, "messageDigestAlgorithm = " + this.messageDigestAlgorithm);
		AnBx_Debug.out(layer, "messageDigestSignatureAlgorithm = " + this.messageDigestSignatureAlgorithm);
		AnBx_Debug.out(layer, "keyAgreementAlgorithm = " + this.keyAgreementAlgorithm);
		AnBx_Debug.out(layer, "keyAgreementKeyPairGenerationScheme = " + this.keyAgreementKeyPairGenerationScheme);
		AnBx_Debug.out(layer, "dhRndExpSize = " + this.dhRndExpSize);
		AnBx_Debug.out(layer, "ecGenParameterSpec = " + this.ecGenParameterSpec);
		AnBx_Debug.out(layer, "asymCipherSchemeBlock = " + this.asymCipherSchemeBlock);
		AnBx_Debug.out(layer, "sslContext = " + this.sslContext);
		// optional provider fields 
		printProvider ("securityProvider",this.securityProvider);
		// optional provider fields 
		printProvider("cipherSchemeProvider",this.cipherSchemeProvider);
		printProvider("keyGenerationSchemeProvider", this.keyGenerationSchemeProvider);
		printProvider("keyGenerationSchemePBEProvider", this.keyGenerationSchemePBEProvider);
		printProvider("keyPairGenerationSchemeProvider", this.keyPairGenerationSchemeProvider);
		printProvider("secureRandomProvider", this.secureRandomProvider);
		printProvider("hmacProvider", this.hmacProvider);
		printProvider("messageDigestProvider", this.messageDigestProvider);
		printProvider("signatureProvider", this.signatureProvider);
		printProvider("asymEncProvider", this.asymEncProvider);
		printProvider("keyAgreementProvider", this.keyAgreementProvider);
		printProvider("sslContextProvider", this.sslContextProvider);
		AnBx_Debug.out(layer, "-------------------- crypto config --------------------");
	}

	
	void printProvider (String label, String value) {
	   String value2print = testStr(value)
			   				? value
			   				: Crypto_Config_Default.securityProvider;
		
		AnBx_Debug.out(layer, label + " = " + value2print); 
	}
	
	
	/**
	 * Returns the cipher scheme.
	 *
	 * @return The cipher scheme.
	 */
	public String getCipherScheme() {
	    return cipherScheme;
	}

	/**
	 * Returns the key size.
	 *
	 * @return The key size.
	 */
	public int getKeySize() {
	    return keySize;
	}

	/**
	 * Returns the key generation scheme.
	 *
	 * @return The key generation scheme.
	 */
	public String getKeyGenerationScheme() {
	    return keyGenerationScheme;
	}

	/**
	 * Returns the key generation size.
	 *
	 * @return The key generation size.
	 */
	public int getKeyGenerationSize() {
	    return keyGenerationSize;
	}

	/**
	 * Returns the key pair generation scheme.
	 *
	 * @return The key pair generation scheme.
	 */
	public String getKeyPairGenerationScheme() {
	    return keyPairGenerationScheme;
	}

	/**
	 * Returns the key pair generation size.
	 *
	 * @return The key pair generation size.
	 */
	public int getKeyPairGenerationSize() {
	    return keyPairGenerationSize;
	}

	/**
	 * Returns the secure random algorithm.
	 *
	 * @return The secure random algorithm.
	 */
	public String getSecureRandomAlgorithm() {
	    return secureRandomAlgorithm;
	}

	/**
	 * Returns the HMAC algorithm.
	 *
	 * @return The HMAC algorithm.
	 */
	public String getHmacAlgorithm() {
	    return hmacAlgorithm;
	}

	/**
	 * Returns the message digest algorithm.
	 *
	 * @return The message digest algorithm.
	 */
	public String getMessageDigestAlgorithm() {
	    return messageDigestAlgorithm;
	}

	/**
	 * Returns the message digest signature algorithm.
	 *
	 * @return The message digest signature algorithm.
	 */
	public String getMessageDigestSignatureAlgorithm() {
	    return messageDigestSignatureAlgorithm;
	}
	
	/**
	 * Returns the key agreement algorithm.
	 *
	 * @return The key agreement algorithm.
	 */
	public String getKeyAgreementAlgorithm() {
	    return keyAgreementAlgorithm;
	}
	
	/**
	 * Returns the key pair generation scheme for key agreement algorithm.
	 *
	 * @return The key pair generation scheme for key agreement algorithm.
	 */
	public String getKeyAgreementKeyPairGenerationScheme() {
	    return keyAgreementKeyPairGenerationScheme;
	}

	/**
	 * Returns the Diffie-Hellman random exponent size.
	 *
	 * @return The Diffie-Hellman random exponent size.
	 */
	public int getDhRndExpSize() {
	    return dhRndExpSize;
	}

	/**
	 * Returns the Elliptic Curve.
	 *
	 * @return The Elliptic Curve
	 */
	public String getEcGenParameterSpec() {
	    return ecGenParameterSpec;
	}
	
	/**
	 * Returns the asymmetric cipher scheme block.
	 *
	 * @return The asymmetric cipher scheme block.
	 */
	public String getasymCipherSchemeBlock() {
	    return asymCipherSchemeBlock;
	}

	/**
	 * Returns the SSL context.
	 *
	 * @return The SSL context.
	 */
	public String getSslContext() {
	    return sslContext;
	}

	/**
	 * Returns the global security provider.
	 *
	 * @return The global security provider.
	 */
	public String getSecurityProvider() {
	    return securityProvider;
	}

	/**
	 * Returns the provider for the cipher scheme.
	 *
	 * @return The provider for the cipher scheme.
	 */
	public String getCipherSchemeProvider() {
	    return cipherSchemeProvider;
	}

	/**
	 * Returns the provider for key generation.
	 *
	 * @return The provider for key generation.
	 */
	public String getkeyGenerationSchemeProvider() {
	    return keyGenerationSchemeProvider;
	}

	/**
	 * Returns the provider for PBE key generation.
	 *
	 * @return The provider for PBE key generation.
	 */
	public String getkeyGenerationSchemePBEProvider() {
	    return keyGenerationSchemeProvider;
	}

	/**
	 * Returns the provider for key pair generation.
	 *
	 * @return The provider for key pair generation.
	 */
	public String getKeyPairGenerationProvider() {
	    return keyPairGenerationSchemeProvider;
	}

	/**
	 * Returns the provider for secure random algorithm.
	 *
	 * @return The provider for secure random algorithm.
	 */
	public String getSecureRandomProvider() {
	    return secureRandomProvider;
	}

	/**
	 * Returns the provider for HMAC algorithm.
	 *
	 * @return The provider for HMAC algorithm.
	 */
	public String getHmacProvider() {
	    return hmacProvider;
	}

	/**
	 * Returns the provider for message digest algorithm.
	 *
	 * @return The provider for message digest algorithm.
	 */
	public String getMessageDigestProvider() {
	    return messageDigestProvider;
	}
	
	/**
	 * Returns the provider for signature algorithm.
	 *
	 * @return The provider for signature algorithm.
	 */
	public String getSignatureProvider() {
	    return signatureProvider;
	}
	
	/**
	 * Returns the provider for asymmetric encryption algorithm.
	 *
	 * @return The provider for asymmetric encryption algorithm.
	 */
	public String getasymEncProvider() {
	    return asymEncProvider;
	}
	
	/**
	 * Returns the provider for key agreement algorithm.
	 *
	 * @return The provider for key agreement algorithm.
	 */
	public String getKeyAgreementProvider() {
	    return keyAgreementProvider;
	}

	/**
	 * Returns the provider for SSL context.
	 *
	 * @return The provider for SSL context.
	 */
	public String getSslContextProvider() {
	    return sslContextProvider;
	}
	
}
