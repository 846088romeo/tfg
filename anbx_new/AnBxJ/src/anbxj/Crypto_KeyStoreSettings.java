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
import java.io.InputStream;
import java.util.Properties;

/**
 * Keystore Settings
 */

public class Crypto_KeyStoreSettings implements java.io.Serializable {

    /**
     * Unique identifier for serialization.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Default layer for Crypto KeyStore Settings.
     */
    private final static AnBx_Layers layer = AnBx_Layers.ENCRYPTION;

    /**
     * Default certificate type.
     */
    private String certificateType = "SunX509";

    /**
     * Type of the KeyStore.
     */
    private String keyStoreType;

    /**
     * Passphrase for local KeyStore.
     */
    private String passphraseLocalKeyStore;

    /**
     * Passphrase for remote KeyStore.
     */
    private String passphraseRemoteKeyStore;

    /**
     * Path to the local KeyStore containing private keys.
     */
    private String localKeyStore;

    /**
     * Path to the remote KeyStore containing public keys.
     */
    private String remoteKeyStore;

    /**
     * Passphrase for the private key in local KeyStore.
     */
    private String passphrasePrivateKeyLocalKeyStore;

    /**
     * Alias for the KeyStore.
     */
    private String myAlias;

    /**
     * Root Certificate Authority.
     */
    private String rootCA = "root";
	
	/**
	 * Constructs a Crypto_KeyStoreSettings object with specified parameters.
	 *
	 * @param localKeyStore The path to the local keystore file.
	 * @param passphraseLocalKeyStore The passphrase for the local keystore.
	 * @param remoteKeyStore The path to the remote keystore file.
	 * @param passphraseRemoteKeyStore The passphrase for the remote keystore.
	 * @param passphrasePrivateKeyLocalKeyStore The passphrase for the private key in the local keystore.
	 * @param keyStoreType The type of the keystore.
	 * @param myAlias The alias used in the keystore.
	 * @param rootCA The root certificate authority (can be null).
	 */

	public Crypto_KeyStoreSettings(String localKeyStore, String passphraseLocalKeyStore, String remoteKeyStore, String passphraseRemoteKeyStore,
			String passphrasePrivateKeyLocalKeyStore, String keyStoreType, String myAlias, String rootCA) {
		super();
		this.passphraseLocalKeyStore = passphraseLocalKeyStore;
		this.passphraseRemoteKeyStore = passphraseRemoteKeyStore;
		this.localKeyStore = localKeyStore;
		this.remoteKeyStore = remoteKeyStore;
		this.passphrasePrivateKeyLocalKeyStore = passphrasePrivateKeyLocalKeyStore;
		this.keyStoreType = keyStoreType;
		this.myAlias = myAlias;
		if (rootCA != null) {
			this.rootCA = rootCA;
		}

	}
	
	/**
	 * Constructs a Crypto_KeyStoreSettings object.
	 *
	 * @param path The path where the configuration file is located.
	 * @param myAlias The alias used in the keystore.
	 * @param enc The encryption identifier.
	 */

	public Crypto_KeyStoreSettings(String path, String myAlias, String enc) {

		final String sep = "_";
		final String pub = ".public";
		final String priv = ".private";
		final String kss_pwd_suffix = ".pwd";
		final String configFileName = myAlias + kss_pwd_suffix;
		final String cfgRootCA = "CA";

		Properties configFile = new Properties(); // where store passwords are kept

		String kss_enc_filename_local = myAlias + sep + enc + priv;
		String kss_enc_filename_remote = myAlias + sep + enc + pub;
		String kss_enc_keyStoreTypeEntry = myAlias + sep + enc + ".type";

		InputStream propertiesStream = null;

		this.myAlias = myAlias;

		try {
			AnBx_Debug.out(layer, "Reading config file (KSS): " + path + configFileName);
			propertiesStream = new FileInputStream(path + configFileName);

			// load a properties file
			configFile.load(propertiesStream);

			// keystore private key pwd
			this.passphrasePrivateKeyLocalKeyStore = configFile.getProperty(myAlias + sep + enc + kss_pwd_suffix);

			// keystore pwd
			this.passphraseLocalKeyStore = configFile.getProperty(kss_enc_filename_local);
			this.passphraseRemoteKeyStore = configFile.getProperty(kss_enc_filename_remote);

			this.keyStoreType = configFile.getProperty(kss_enc_keyStoreTypeEntry);

			this.localKeyStore = path + kss_enc_filename_local;
			this.remoteKeyStore = path + kss_enc_filename_remote;
			if (configFile.getProperty(cfgRootCA) != null) {
				this.rootCA = configFile.getProperty(cfgRootCA);
			}
			AnBx_Debug.out(layer, enc + " - KeyStoreType: " + keyStoreType);
			AnBx_Debug.out(layer, enc + " - LocalKeyStore: " + localKeyStore);
			// AnBx_Debug.out(layer, enc + " - LocalKeyStore pwd: " +
			// passphraseLocalKeyStore);
			// AnBx_Debug.out(layer, enc + " - PrivateKeyLocalKeyStore pwd: " +
			// passphrasePrivateKeyLocalKeyStore);
			AnBx_Debug.out(layer, enc + " - RemotelKeyStore: " + remoteKeyStore);
			// AnBx_Debug.out(layer, enc + " - RemoteKeyStore pwd: " +
			// passphraseRemoteKeyStore);

			AnBx_Debug.out(layer, "My Alias: " + myAlias);
			AnBx_Debug.out(layer, "RootCA: " + rootCA);

		} catch (IOException ex) {
			// Properties file not found!
			AnBx_Debug.out(AnBx_Layers.ALWAYS, "Key store file not found: " + path + configFileName);
			// ex.printStackTrace();
			System.exit(1);
		} finally {
			if (propertiesStream != null) {
				try {
					propertiesStream.close();
				} catch (IOException e) {
					e.printStackTrace();

				}
			}
		}
	}

	/**
	 * Gets the certificate type.
	 *
	 * @return the certificateType
	 */
	public String getCertificateType() {
	    return certificateType;
	}

	/**
	 * Gets the key store type.
	 *
	 * @return the keyStoreType
	 */
	public String getKeyStoreType() {
	    return keyStoreType;
	}

	/**
	 * Gets the local key store path.
	 *
	 * @return the localKeyStore
	 */
	public String getLocalKeyStore() {
	    return localKeyStore;
	}

	/**
	 * Gets the alias used in the keystore.
	 *
	 * @return the myAlias
	 */
	public String getMyAlias() {
	    return myAlias;
	}

	/**
	 * Gets the passphrase for the local keystore.
	 *
	 * @return the passphraseLocalKeyStore
	 */
	public String getPassphraseLocalKeyStore() {
	    return passphraseLocalKeyStore;
	}

	/**
	 * Gets the passphrase for the remote keystore.
	 *
	 * @return the passphraseRemoteKeyStore
	 */
	public String getPassphraseRemoteKeyStore() {
	    return passphraseRemoteKeyStore;
	}

	/**
	 * Gets the path of the remote keystore.
	 *
	 * @return the remoteKeyStore
	 */
	public String getRemoteKeyStore() {
	    return remoteKeyStore;
	}

	/**
	 * Sets the certificate type.
	 *
	 * @param certificateType the certificateType to set
	 */
	public void setCertificateType(String certificateType) {
	    this.certificateType = certificateType;
	}

	/**
	 * Sets the key store type.
	 *
	 * @param keyStoreType the keyStoreType to set
	 */
	public void setKeyStoreType(String keyStoreType) {
	    this.keyStoreType = keyStoreType;
	}

	/**
	 * Gets the passphrase for the private key in the local keystore.
	 *
	 * @return the passphrasePrivateKeyLocalKeyStore
	 */
	public String getPassphrasePrivateKeyLocalKeyStore() {
	    return passphrasePrivateKeyLocalKeyStore;
	}

	/**
	 * Gets the root CA path.
	 *
	 * @return the rootCA
	 */
	public String getRootCA() {
	    return rootCA;
	}

	/**
	 * Sets the root CA path.
	 *
	 * @param rootCA the rootCA to set
	 */
	public void setRootCA(String rootCA) {
	    this.rootCA = rootCA;
	}


}
