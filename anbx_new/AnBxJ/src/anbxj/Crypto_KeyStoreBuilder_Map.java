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

import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.Map;

/**
 * Keystore builder mapping key stores and their type/purpose
 */

public class Crypto_KeyStoreBuilder_Map {

	private Map<Crypto_KeyStoreType, Crypto_KeyStoreBuilder> ksb;

    /**
     * Constructs a Crypto_KeyStoreBuilder_Map with the given map of key stores.
     *
     * @param ksb the map of key stores
     */
	
	public Crypto_KeyStoreBuilder_Map(Map<Crypto_KeyStoreType, Crypto_KeyStoreBuilder> ksb) {
		super();
		this.ksb = ksb;
	}

    /**
     * Constructs a Crypto_KeyStoreBuilder_Map with the given key store settings map.
     *
     * @param kss the key store settings map
     */
	
	public Crypto_KeyStoreBuilder_Map(Crypto_KeyStoreSettings_Map kss) {
		super();
		ksb = new HashMap<Crypto_KeyStoreType, Crypto_KeyStoreBuilder>();
		for (Crypto_KeyStoreType kst : Crypto_KeyStoreType.values()) {
			AnBx_Debug.out(AnBx_Layers.ENCRYPTION, "Building KeyStore: " + kst.toString() + " #" + kst.ordinal());
			this.ksb.put(kst, new Crypto_KeyStoreBuilder(kss.getKeyStoreSettings(kst)));
		}
	}


    /**
     * Gets the Keystore builder for the specified Keystore type.
     *
     * @param kst the Keystore type
     * @return the Keystore builder
     */
	
	public Crypto_KeyStoreBuilder getKeyStoreBuilder(Crypto_KeyStoreType kst) {
		return ksb.get(kst);
	}

    /**
     * Checks if the given alias exists in any of the Keystores.
     *
     * @param alias the alias to check
     * @return true if the alias exists in any Keystore, false otherwise
     */
	
	public boolean containsAlias(String alias) {
		boolean found = false;
		for (Crypto_KeyStoreType kst : Crypto_KeyStoreType.values()) {
			found = ksb.get(kst).containsAlias(alias);
			if (!found) {
				AnBx_Debug.out(AnBx_Layers.ENCRYPTION, "Alias <" + alias + "> NOT found in keystore <" + kst.toString() + ">");
				break;
			} else
				AnBx_Debug.out(AnBx_Layers.ENCRYPTION, "Alias <" + alias + "> found in keystore <" + kst.toString() + ">");
		}
		return found;
	}
	
    /**
     * Gets the key store settings map.
     *
     * @return the key store settings map
     */

	public Crypto_KeyStoreSettings_Map getKeyStoreSettings_Map() {
		Map<Crypto_KeyStoreType, Crypto_KeyStoreSettings> kss = new HashMap<Crypto_KeyStoreType, Crypto_KeyStoreSettings>();
		for (Crypto_KeyStoreType kst : Crypto_KeyStoreType.values()) {
			kss.put(kst, ksb.get(kst).getKss());
		}
		return new Crypto_KeyStoreSettings_Map(kss);
	}
	
    /**
     * Gets the local certificates from all Keystores.
     *
     * @return a map containing Keystore types and their corresponding local certificates
     */

	public Map<Crypto_KeyStoreType, Certificate> getLocaleCertificates() {
		Map<Crypto_KeyStoreType, Certificate> cert = new HashMap<Crypto_KeyStoreType, Certificate>();
		for (Crypto_KeyStoreType kst : Crypto_KeyStoreType.values()) {
			cert.put(kst, ksb.get(kst).getLocaleCertificate());
		}
		return cert;

	}
	
    /**
     * Gets the remote certificates for the given alias from all Keystores.
     *
     * @param alias the alias to get remote certificates for
     * @return a map containing Keystore types and their corresponding remote certificates
     */

	public Map<Crypto_KeyStoreType, Certificate> getRemoteCertificates(String alias) {
		Map<Crypto_KeyStoreType, Certificate> cert = new HashMap<Crypto_KeyStoreType, Certificate>();
		for (Crypto_KeyStoreType kst : Crypto_KeyStoreType.values()) {
			cert.put(kst, ksb.get(kst).getRemoteCertificate(alias));
		}
		return cert;
	}
}
