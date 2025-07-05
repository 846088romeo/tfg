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

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

/**
 * Keystore builder
 */

public class Crypto_KeyStoreBuilder {

	private final static AnBx_Layers layer = AnBx_Layers.ENCRYPTION;

	/**
	 * A local copy of channel properties
	 */
	
	protected Crypto_KeyStoreSettings kss; 
	
	/**
	 * KeyStore for storing our public/private key pair
	 * 
	 */
		
	protected KeyStore localKeyStore; 
	
	/**
	 * // KeyStore for storing the other public keys
	 */
	
	protected KeyStore remoteKeyStore; 

	
    /**
     * Handles the failure of the keystore setup by printing an error message and exiting.
     *
     * @param e the exception that caused the failure
     */
	
	private void KeyStoreFail(Exception e) {
		// unrecoverable error
		e.printStackTrace();
		AnBx_Debug.out(AnBx_Layers.ALWAYS, "Unrecoverable error: keystore was tampered with, or password was incorrect");
		System.exit(1);
	}

	
	 /**
     * Constructs a Crypto_KeyStoreBuilder with the given Crypto_KeyStoreSettings.
     *
     * @param kss the Crypto_KeyStoreSettings
     */
	
	public Crypto_KeyStoreBuilder(Crypto_KeyStoreSettings kss) {
		super();
		this.kss = kss;
		try {
			setupLocalKeyStore();
			setupRemoteKeyStore();

		} catch (GeneralSecurityException e) {
			KeyStoreFail(e);
		} catch (IOException e) {
			KeyStoreFail(e);
		}
	}

    /**
     * Gets the Crypto_KeyStoreSettings.
     *
     * @return the Crypto_KeyStoreSettings
     */
	
	public Crypto_KeyStoreSettings getKss() {
		return kss;
	}

    /**
     * Gets the local certificate.
     *
     * @return the local certificate
     */
	
	public Certificate getLocaleCertificate() {
		try {
			// Get private key
			Key key = localKeyStore.getKey(getMyAlias(), kss.getPassphrasePrivateKeyLocalKeyStore().toCharArray());
			if (key instanceof PrivateKey) {
				// Get certificate of public key
				Certificate cert = localKeyStore.getCertificate(getMyAlias());
				AnBx_Debug.out(layer, "Certificate retrieved: <" + getMyAlias() + ">");
				// Return a certificate
				return cert;
			}
		} catch (UnrecoverableKeyException e) {
			KeyStoreFail(e);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			KeyStoreFail(e);
		}
		return null;

	}

    /**
     * Gets the local private key.
     *
     * @return the local private key
     */	
	
	public PrivateKey getLocalPrivateKey() {
		try {
			// Get private key
			Key key = localKeyStore.getKey(getMyAlias(), kss.getPassphrasePrivateKeyLocalKeyStore().toCharArray());
			if (key instanceof PrivateKey) {
				AnBx_Debug.out(layer, "PrivateKey retrieved: <" + getMyAlias() + ">");
				return (PrivateKey) key;
			}
		} catch (UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException e) {
			KeyStoreFail(e);
		}
		return null;
	}

    /**
     * Gets the alias of the key.
     *
     * @return the alias of the key
     */
	
	public String getMyAlias() {
		return kss.getMyAlias();
	}

	 /**
     * Gets the remote certificate with the specified alias.
     *
     * @param alias the alias of the certificate
     * @return the remote certificate
     */	
	
	public Certificate getRemoteCertificate(String alias) {
		Certificate cert = null;
		try {
			cert = remoteKeyStore.getCertificate(alias);
		} catch (KeyStoreException e) {
			KeyStoreFail(e);
		}
		AnBx_Debug.out(layer, "Certificate found: <" + alias + ">");
		// Return public Certificate
		return cert;
	}

	 /**
     * Gets the remote public key with the specified alias.
     *
     * @param alias the alias of the public key
     * @return the remote public key
     */
	
	public PublicKey getRemotePublicKey(String alias) {

		Certificate cert = null;
		PublicKey publicKey = null;
		try {
			cert = remoteKeyStore.getCertificate(alias);
			AnBx_Debug.out(layer, "PublicKey found: <" + alias + ">");
		} catch (KeyStoreException e) {
			KeyStoreFail(e);
		}
		try {
			if (isSelfSigned(cert)) {
				publicKey = verifySelfSignedCertificate(alias, cert);
				// Return public key
				return publicKey;
			} else {

				Certificate certArray[] = { remoteKeyStore.getCertificate(kss.getRootCA()), remoteKeyStore.getCertificate(alias) };
				Certificate certRoot = null;
				try {
					certRoot = remoteKeyStore.getCertificate(kss.getRootCA());
					AnBx_Debug.out(layer, "Root Certificate found: <" + kss.getRootCA() + ">");
				} catch (KeyStoreException e) {
					KeyStoreFail(e);
				}
				try {
					publicKey = verifyCertificate((X509Certificate) certRoot, certArray, ((X509Certificate) remoteKeyStore.getCertificate(alias)).getSubjectX500Principal().getName());
				} catch (KeyStoreException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					return null;
				}
				return publicKey;
			}
		} catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException | KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}
    
	/**
     * Verifies a self-signed certificate and returns the public key.
     *
     * @param alias the alias of the certificate
     * @param cert  the self-signed certificate
     * @return the public key
     */
	
	private PublicKey verifySelfSignedCertificate(String alias, Certificate cert) {
		// Verify the key's certificate (no check of validity)
		PublicKey publicKey = cert.getPublicKey();
		try {
			cert.verify(publicKey);
		} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
			// TODO Auto-generated catch block
			AnBx_Debug.out(layer, "Invalid PublicKey: <" + alias + ">");
			e.printStackTrace();
			return null;
		}

		AnBx_Debug.out(layer, "PublicKey certificate is verified: <" + alias + ">");

		// check validity of the certificate
		if (cert instanceof X509Certificate) {
			certificateDebug((X509Certificate) cert);
			try {
				((X509Certificate) cert).checkValidity();
			} catch (CertificateExpiredException | CertificateNotYetValidException e) {
				AnBx_Debug.out(layer, "Certificate invalid date: " + ((X509Certificate) cert).getSubjectX500Principal().getName());
				e.printStackTrace();
				return null;
			}
		} else {
			AnBx_Debug.out(layer, "Unable to check validity of non-X509 certificates: <" + alias + ">");
			return null;
		}
		return publicKey;
	}

	/**
	 * Verifies a certificate chain and returns the public key of the subject.
	 *
	 * @param x509certificateRoot the root certificate in the chain
	 * @param arx509certificate   the certificate chain
	 * @param stringTarget        the target subject
	 * @return the public key of the subject if verification is successful, otherwise null
	 */
	
	private PublicKey verifyCertificate(X509Certificate x509certificateRoot, Certificate[] arx509certificate, String stringTarget) {

		PublicKey publicKeySubject = null;
		int nSize = arx509certificate.length;

		// int nSize = collectionX509CertificateChain.size();
		// X509Certificate [] arx509certificate = new X509Certificate [nSize];
		// collectionX509CertificateChain.toArray(arx509certificate);

		// Working down the chain, for every certificate in the chain,
		// verify that the subject of the certificate is the issuer of the
		// next certificate in the chain.

		Principal principalLast = null;
		for (int i = 0; i < nSize; i++) {
			AnBx_Debug.out(layer, "Certificate #" + i);
			X509Certificate x509certificate = (X509Certificate) arx509certificate[i];
			Principal principalSubject = x509certificate.getSubjectX500Principal();
			Principal principalIssuer = x509certificate.getIssuerX500Principal();
			certificateDebug(x509certificate);
			if (principalLast != null) {
				if (principalIssuer.equals(principalLast)) {
					try {
						PublicKey publickey = arx509certificate[i - 1].getPublicKey();
						arx509certificate[i].verify(publickey);
					} catch (GeneralSecurityException generalsecurityexception) {
						AnBx_Debug.out(layer, "Signature verification failed: <" + principalLast.getName() + ">");
						return null;
					}
				} else {
					AnBx_Debug.out(layer, "Subject/issuer verification failed: <" + principalLast.getName() + ">");
					return null;
				}
			}
			principalLast = principalSubject;
		}

		// Verify that the the first certificate in the chain was issued
		// by a third-party that the client trusts.

		try {
			PublicKey publickey = x509certificateRoot.getPublicKey();
			arx509certificate[0].verify(publickey);
			AnBx_Debug.out(layer, "Root Certificate");
			certificateDebug(x509certificateRoot);
		} catch (GeneralSecurityException generalsecurityexception) {
			AnBx_Debug.out(layer, "Signature verification failed");
			return null;
		}

		// Verify that the last certificate in the chain corresponds to
		// the server we desire to authenticate.

		Principal principalSubject = ((X509Certificate) arx509certificate[nSize - 1]).getSubjectX500Principal();
		if (!stringTarget.equals(principalSubject.getName())) {
			AnBx_Debug.out(layer, "StringTarget: " + stringTarget.toString());
			AnBx_Debug.out(layer, "PrincipalSubject: " + principalSubject.getName());
			AnBx_Debug.out(layer, "Target verification failed");
			return null;
		}

		// For every certificate in the chain, verify that the certificate
		// is valid at the current time.
		Date date = new Date();
		for (int i = 0; i < nSize; i++) {
			try {
				((X509Certificate) arx509certificate[i]).checkValidity(date);
			} catch (GeneralSecurityException generalsecurityexception) {
				AnBx_Debug.out(layer, "Certificate invalid date: " + ((X509Certificate) arx509certificate[i]).getSubjectX500Principal().toString());
				return null;
			}
		}

		publicKeySubject = ((X509Certificate) arx509certificate[nSize - 1]).getPublicKey();
		return publicKeySubject;
	}

	/**
	 * Outputs debug information for a certificate.
	 *
	 * @param cert the certificate
	 */
	
	private static void certificateDebug(X509Certificate cert) {
		AnBx_Debug.out(layer, "Subject: " + cert.getSubjectX500Principal().getName());
		AnBx_Debug.out(layer, "Issuer: " + cert.getIssuerX500Principal().getName());
		AnBx_Debug.out(layer, "Validity: from " + cert.getNotBefore() + " to " + cert.getNotAfter());
		AnBx_Debug.out(layer, "Version: " + cert.getVersion());
		AnBx_Debug.out(layer, "Serial Number: " + cert.getSerialNumber());
		AnBx_Debug.out(layer, "Signature Algorithm Name: " + cert.getSigAlgName());
	}

	/**
	 * Lists the aliases in the given keystore.
	 *
	 * @param keystore      the keystore
	 * @param keyStoreFile  the file name of the keystore
	 * @throws KeyStoreException if an error occurs while listing aliases
	 */
	
	public void listAliases(KeyStore keystore, String keyStoreFile) throws KeyStoreException {
		// List the aliases
		AnBx_Debug.out(layer, "List Aliases in " + keyStoreFile + " - size: " + keystore.size());
		Enumeration<String> aliases = keystore.aliases();
		for (; aliases.hasMoreElements();) {
			String alias = aliases.nextElement();
			AnBx_Debug.out(layer, "Alias: <" + alias + ">");
		}
	}

	/**
	 * Checks if the given alias exists in the remote keystore.
	 *
	 * @param alias the alias to check
	 * @return true if the alias exists, false otherwise
	 */
	
	public boolean containsAlias(String alias) {
		// returns true if the alias exists
		try {
			return remoteKeyStore.containsAlias(alias);
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}
	
	/**
	 * Sets up the local keystore.
	 *
	 * @throws GeneralSecurityException if a security-related error occurs
	 * @throws IOException              if an I/O error occurs
	 */

	private void setupLocalKeyStore() throws GeneralSecurityException, IOException {

		// Create a KeyStore instance

		AnBx_Debug.out(layer, "Loading KeyStore: " + kss.getLocalKeyStore() + " - Type: " + kss.getKeyStoreType());

		localKeyStore = KeyStore.getInstance(kss.getKeyStoreType());
		localKeyStore.load(new FileInputStream(kss.getLocalKeyStore()), kss.getPassphraseLocalKeyStore().toCharArray());

		// listAliases(localKeyStore, kss.getLocalKeyStore());
		// AnBx_Debug.out(layer, "Loaded KeyStore: " + kss.getLocalKeyStore() +
		// " - Type: " + kss.getKeyStoreType());
	}
	
	/**
	 * Sets up the remote keystore.
	 *
	 * @throws GeneralSecurityException if a security-related error occurs
	 * @throws IOException              if an I/O error occurs
	 */
	
	private void setupRemoteKeyStore() throws GeneralSecurityException, IOException {

		// Create a KeyStore instance

		AnBx_Debug.out(layer, "Loading KeyStore: " + kss.getRemoteKeyStore() + " - Type: " + kss.getKeyStoreType());

		remoteKeyStore = KeyStore.getInstance(kss.getKeyStoreType());
		remoteKeyStore.load(new FileInputStream(kss.getRemoteKeyStore()), kss.getPassphraseRemoteKeyStore().toCharArray());

		// listAliases(remoteKeyStore, kss.getRemoteKeyStore());
		// AnBx_Debug.out(layer, "Loaded KeyStore: " + kss.getRemoteKeyStore() +
		// " - Type: " + kss.getKeyStoreType());
	}

	/**
	 * Retrieves the certificate path from the local keystore.
	 *
	 * @return the certificate path
	 */
	
	public CertPath getCertPath() {
		//
		Certificate[] certArray = null;
		try {
			certArray = this.localKeyStore.getCertificateChain(this.getMyAlias());
			// convert chain to a List
			List<Certificate> certList = Arrays.asList(certArray);
			// instantiate a CertificateFactory for X.509
			CertificateFactory cf = null;
			cf = CertificateFactory.getInstance(this.getKss().getCertificateType());
			// extract the certification path from the List of Certificates
			return cf.generateCertPath(certList);
		} catch (CertificateException e) {
			KeyStoreFail(e);
		} catch (KeyStoreException e) {
			KeyStoreFail(e);
		}
		return null;
	}

	/**
	 * Checks if a certificate is self-signed.
	 *
	 * @param cert the certificate to check
	 * @return true if the certificate is self-signed, false otherwise
	 * @throws CertificateException      if a certificate error occurs
	 * @throws NoSuchAlgorithmException   if the specified algorithm is not available
	 * @throws NoSuchProviderException    if the specified security provider is not available
	 */
	
	private boolean isSelfSigned(Certificate cert) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
		try {
			// Try to verify certificate signature with its own public key
			PublicKey publicKey = cert.getPublicKey();
			cert.verify(publicKey);
			return true;
		} catch (SignatureException sigEx) {
			// Invalid signature --> not self-signed
			return false;
		} catch (InvalidKeyException keyEx) {
			// Invalid key --> not self-signed
			return false;
		}
	}

}