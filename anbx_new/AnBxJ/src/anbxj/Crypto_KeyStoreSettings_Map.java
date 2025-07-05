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

import java.util.HashMap;
import java.util.Map;

/**
 * A class mapping key stores and their type/purpose.
 */
public class Crypto_KeyStoreSettings_Map {

    private Map<Crypto_KeyStoreType, Crypto_KeyStoreSettings> kss;

    /**
     * Constructs a Crypto_KeyStoreSettings_Map with the specified map of keystore settings.
     *
     * @param kss The map of keystore settings.
     */
    public Crypto_KeyStoreSettings_Map(Map<Crypto_KeyStoreType, Crypto_KeyStoreSettings> kss) {
        super();
        this.kss = kss;
    }

    /**
     * Constructs a Crypto_KeyStoreSettings_Map with the specified path and alias for keystore settings.
     *
     * @param path The path to the keystore.
     * @param myAlias The alias for the keystore.
     */
    public Crypto_KeyStoreSettings_Map(String path, String myAlias) {
        kss = new HashMap<Crypto_KeyStoreType, Crypto_KeyStoreSettings>();
        for (Crypto_KeyStoreType kst : Crypto_KeyStoreType.values()) {
            AnBx_Debug.out(AnBx_Layers.ENCRYPTION, "Loading KeyStore: " + kst.toString() + " #" + kst.ordinal());
            this.kss.put(kst, new Crypto_KeyStoreSettings(path, myAlias, kst.toString()));
        }
    }

    /**
     * Get the keystore settings for the specified keystore type.
     *
     * @param kst Keystore type.
     * @return The keystore settings.
     */
    public Crypto_KeyStoreSettings getKeyStoreSettings(Crypto_KeyStoreType kst) {
        return kss.get(kst);
    }

    /**
     * Get the map of keystore settings.
     *
     * @return The map of keystore settings.
     */
    public Map<Crypto_KeyStoreType, Crypto_KeyStoreSettings> getKeyStoreSettings_Map() {
        return kss;
    }
}
