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
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * This class allows printing information about supported cryptographic
 * providers and algorithms for the installed JRE/JDK.
 */
public final class Crypto_ProviderInformation {

    private static final AnBx_Layers layer = AnBx_Layers.ENCRYPTION;

    /**
     * Default constructor.
     */
    public Crypto_ProviderInformation() {
        super();
    }

    /**
     * Prints the list of all supported providers.
     */
    public static void listProviders() {
        listProviders(false, layer);
    }

    /**
     * Prints the list of all supported providers, with a specific log debug layer
     * @param layer The specified layer @AnBx_Layers
     */
    public static void listProviders(AnBx_Layers layer) {
        listProviders(false, layer);
    }

    /**
     * Prints the list of all supported providers with optional details.
     * 
     * @param detail verbose if this parameter is true.
     * @param layer The specified layer @AnBx_Layers
     */
    public static void listProviders(boolean detail, AnBx_Layers layer) {
        for (Provider provider : Security.getProviders()) {
            AnBx_Debug.out(layer, "Provider (version): " + provider.getName() + " (" + provider.getVersionStr() + ") - " + provider.getInfo());
            if (detail) {
                provider.stringPropertyNames().forEach(key ->
                    AnBx_Debug.out(layer, "\t" + key + "\t" + provider.getProperty(key))
                );
            }
        }
    }

    /**
     * Prints the list of supported algorithms.
     */
    public static void listAlgorithms() {
        Map<String, Set<String>> categoryMap = new TreeMap<>();
        categoryMap.put("AlgorithmParameterGenerator", new TreeSet<>());
        categoryMap.put("AlgorithmParameters", new TreeSet<>());
        categoryMap.put("CertPathBuilder", new TreeSet<>());
        categoryMap.put("CertPathValidator", new TreeSet<>());
        categoryMap.put("Cipher", new TreeSet<>());
        categoryMap.put("KEM", new TreeSet<>());
        categoryMap.put("KeyAgreement", new TreeSet<>());
        categoryMap.put("KeyFactory", new TreeSet<>());
        categoryMap.put("KeyGenerator", new TreeSet<>());
        categoryMap.put("KeyManagerFactory", new TreeSet<>());
        categoryMap.put("KeyPairGenerator", new TreeSet<>());
        categoryMap.put("Mac", new TreeSet<>());
        categoryMap.put("MessageDigest", new TreeSet<>());
        categoryMap.put("SecretKeyFactory", new TreeSet<>());
        categoryMap.put("SecureRandom", new TreeSet<>());
        categoryMap.put("Signature", new TreeSet<>());
        categoryMap.put("SSLContext", new TreeSet<>());
        categoryMap.put("TrustManagerFactory", new TreeSet<>());

        for (Provider provider : Security.getProviders()) {
            for (Provider.Service service : provider.getServices()) {
                categorizeAlgorithm(service, categoryMap);
            }
        }

        categoryMap.forEach((type, algorithms) -> printSet(type, algorithms));
    }

    private static void categorizeAlgorithm(Provider.Service service, Map<String, Set<String>> categoryMap) {
        String type = service.getType();
        String algorithm = service.getAlgorithm();

        if (categoryMap.containsKey(type)) {
            categoryMap.get(type).add(algorithm);
        }
    }

    private static void printSet(String setName, Set<String> algorithms) {
        final String spacing = "   ";
        AnBx_Debug.out(layer, setName + ":");
        if (algorithms.isEmpty()) {
            AnBx_Debug.out(layer, spacing + "None available.");
        } else {
            algorithms.forEach(name -> AnBx_Debug.out(layer, spacing + name));
        }
    }
}

