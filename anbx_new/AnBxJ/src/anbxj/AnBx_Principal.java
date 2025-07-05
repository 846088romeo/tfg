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

import java.util.Map;

/**
 * AnBx Principal: an abstract agent for AnBx protocols
 * 
 * This abstract class represents a principal agent in the AnBx protocols
 * It extends the AnB_Principal class and serves as a foundation for
 * specific AnBx protocol implementations
 */
public abstract class AnBx_Principal extends AnB_Principal {

    /**
     * Constructor for AnBx Principal.
     *
     * @param kssd    Crypto KeyStoreSettings Map for the principal
     * @param cs      Map of Channel Settings for the principal
     * @param aliases Map of aliases
     * @param config  Crypto configuration for the principal
     */
    public AnBx_Principal(Crypto_KeyStoreSettings_Map kssd, Map<String, Channel_Settings> cs, Map<String, String> aliases, Crypto_Config config) {
        super(kssd, cs, aliases, config);
    }

    /**
     * Constructor for AnBx Principal with specified alias and path
     *
     * @param myAlias Alias for the principal
     * @param path    Path for crypto store
     * @param cs      Map of Channel Settings for the principal
     * @param aliases Map of aliases
     * @param config  Crypto configuration for the principal
     */
    public AnBx_Principal(String myAlias, String path, Map<String, Channel_Settings> cs, Map<String, String> aliases, Crypto_Config config) {
        super(myAlias, path, cs, aliases, config);
    }
}
