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
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

/**
 * AnB Principal: A concrete principal for AnB/AnBx protocols.
 * <p>
 * This abstract class serves as a concrete implementation of a principal for AnB/AnBx protocols.
 * It initialises AnB sessions based on provided key store settings, channel settings, aliases, and configuration.
 * It also provides methods to run AnB protocols using the initialised sessions.
 */
public abstract class AnB_Principal {

    // private final static AnBx_Layers layer = AnBx_Layers.APPLICATION;

    /**
     * Flag to automatically exchange identities during session if set to true
    */
	
	protected boolean exchange_identities = false;
    
    /**
     * Mapping agent identities and sessions
    */
    protected Map<String, AnB_Session> lbs;
    
    /**
     * Mapping agent aliases
    */
        
    protected Map<String, String> aliases;

    /**
     * Constructor for AnB_Principal with specified key store settings, channel settings, aliases, and configuration.
     *
     * @param kssd    Crypto key store settings map.
     * @param cs      Map of channel settings.
     * @param aliases Map of aliases.
     * @param config  Crypto configuration.
     */
    
    public AnB_Principal(Crypto_KeyStoreSettings_Map kssd, Map<String, Channel_Settings> cs, Map<String, String> aliases, Crypto_Config config) {
        super();
        this.aliases = aliases;
        init(kssd, cs, config);
    }

    /**
     * Constructor for AnB_Principal with specified alias, path, channel settings, aliases, and configuration.
     *
     * @param myAlias Alias of the principal.
     * @param path    Path for key store settings.
     * @param cs      Map of channel settings.
     * @param aliases Map of aliases.
     * @param config  Crypto configuration.
     */
    public AnB_Principal(String myAlias, String path, Map<String, Channel_Settings> cs, Map<String, String> aliases, Crypto_Config config) {
        super();
        this.aliases = aliases;
        Crypto_KeyStoreSettings_Map kssd = new Crypto_KeyStoreSettings_Map(path, myAlias);
        init(kssd, cs, config);
    }

    /**
     * Constructor for AnB_Principal with specified key store settings, channel settings, and aliases.
     *
     * @param kssd    Crypto key store settings map.
     * @param cs      Map of channel settings.
     * @param aliases Map of aliases.
     */
    public AnB_Principal(Crypto_KeyStoreSettings_Map kssd, Map<String, Channel_Settings> cs, Map<String, String> aliases) {
        super();
        this.aliases = aliases;
        init(kssd, cs, new Crypto_Config());
    }

    /**
     * Constructor for AnB_Principal with specified alias, path, channel settings, and aliases.
     *
     * @param myAlias Alias of the principal.
     * @param path    Path for key store settings.
     * @param cs      Map of channel settings.
     * @param aliases Map of aliases.
     */
    public AnB_Principal(String myAlias, String path, Map<String, Channel_Settings> cs, Map<String, String> aliases) {
        super();
        this.aliases = aliases;
        Crypto_KeyStoreSettings_Map kssd = new Crypto_KeyStoreSettings_Map(path, myAlias);
        init(kssd, cs, new Crypto_Config());
    }

    /**
     * Initializes AnB sessions based on provided key store settings, channel settings, and configuration.
     *
     * @param kssd   Crypto key store settings map.
     * @param cs     Map of channel settings.
     * @param config Crypto configuration.
     */
    protected void init(Crypto_KeyStoreSettings_Map kssd, Map<String, Channel_Settings> cs, Crypto_Config config) {
        lbs = new HashMap<String, AnB_Session>();

        for (Iterator<Entry<String, Channel_Settings>> it = cs.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry<String, Channel_Settings> entry = it.next();
            String key = entry.getKey();
            Channel_Settings value = entry.getValue();

            if (!aliases.containsKey(key)) {
                lbs.put(key, new AnB_Session(kssd, value, exchange_identities, config));
            } else {
                lbs.put(key, new AnB_Session(kssd, value, aliases.get(key), config));
            }
        }
    }

    /**
     * Runs the specified AnB protocol with a specified number of sessions.
     *
     * @param prot     AnB protocol to run.
     * @param sessions Number of sessions to run.
     * @param <S>      Enum representing the protocol's steps.
     * @param <R>      Enum representing the protocol's roles.
     */
    public <S extends Enum<?>, R extends Enum<?>> void run(AnB_Protocol<S, R> prot, long sessions) {
        prot.run(lbs, aliases, sessions);
    }

    /**
     * Runs the specified AnB protocol.
     *
     * @param prot AnB protocol to run.
     * @param <S>  Enum representing the protocol's steps.
     * @param <R>  Enum representing the protocol's roles.
     */
    public <S extends Enum<?>, R extends Enum<?>> void run(AnB_Protocol<S, R> prot) {
        prot.run(lbs, aliases);
    }
}