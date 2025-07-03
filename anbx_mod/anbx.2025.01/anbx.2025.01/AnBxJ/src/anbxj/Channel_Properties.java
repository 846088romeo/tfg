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

/**
 * Channel Properties: Represents the properties of a communication channel.
 * 
 * This class encapsulates settings related to a communication channel, including
 * channel type, role, host, port, cipher suites, and key store settings.
 */
public class Channel_Properties {

    private Channel_Settings cs;
    private Crypto_KeyStoreSettings kss;

    /**
     * Default constructor for Channel_Properties.
     */
    public Channel_Properties() {
        super();
    }

    /**
     * Constructor for Channel_Properties with specified channel settings and key store settings map.
     *
     * @param cs  Channel settings for the communication channel.
     * @param kss Crypto key store settings map.
     */
    public Channel_Properties(Channel_Settings cs, Crypto_KeyStoreSettings_Map kss) {
        super();
        this.cs = cs;
        this.kss = kss.getKeyStoreSettings(Crypto_KeyStoreType.tls);
    }

    /**
     * Constructor for Channel_Properties with specified channel settings and key store settings.
     *
     * @param cs  Channel settings for the communication channel.
     * @param kss Crypto key store settings.
     */
    public Channel_Properties(Channel_Settings cs, Crypto_KeyStoreSettings kss) {
        super();
        this.cs = cs;
        this.kss = kss;
    }

    /**
     * Constructor for Channel_Properties with specified channel settings.
     *
     * @param cs Channel settings for the communication channel.
     */
    public Channel_Properties(Channel_Settings cs) {
        super();
        this.cs = cs;
        this.kss = null;
    }

    /**
     * Get the role of the communication channel.
     *
     * @return Channel role.
     */
    public Channel_Roles getChannelRole() {
        return cs.getChannelRole();
    }

    /**
     * Get the channel settings for the communication channel.
     *
     * @return Channel settings.
     */
    public Channel_Settings getChannelSettings() {
        return cs;
    }

    /**
     * Get the channel type for the communication channel.
     *
     * @return Channel type.
     */
    public Channel_SSLChannelType getChannelType() {
        return cs.getChannelType();
    }

    /**
     * Get the enabled cipher suites for the communication channel.
     *
     * @param enabled Array of enabled cipher suites.
     * @return Enabled cipher suites.
     */
    public String[] getEnabledCipherSuites(String[] enabled) {
        return cs.getEnabledCipherSuites(enabled);
    }

    /**
     * Get the host of the communication channel.
     *
     * @return Host name or IP address.
     */
    public String getHost() {
        return cs.getHost();
    }

    /**
     * Get the key store settings for the communication channel.
     *
     * @return Crypto key store settings.
     */
    public Crypto_KeyStoreSettings getKeyStoreSettings() {
        return kss;
    }

    /**
     * Get the port of the communication channel.
     *
     * @return Port number.
     */
    public int getPort() {
        return cs.getPort();
    }
    
    
    /**
     * Get channel SSL context.
     *
     * @return SSL context
     */
    public String getSSLContextAlgorithm() {
        return cs.getSSLContextAlgorithm();
    }

    /**
     * Check if the communication channel is an authenticated channel.
     *
     * @return True if the channel is authenticated, false otherwise.
     */
    public Boolean isAuthenticatedChannel() {
        return cs.isAuthenticatedChannel();
    }

    /**
     * Check if the communication channel is a secret channel.
     *
     * @return True if the channel is a secret channel, false otherwise.
     */
    public Boolean isSecretChannel() {
        return cs.isSecretChannel();
    }
}