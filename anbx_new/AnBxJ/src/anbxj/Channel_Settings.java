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
 * Represents settings for a communication channel.
 * Implements java.io.Serializable to support serialization.
 */
public class Channel_Settings implements java.io.Serializable {

    /**
     * Enum for cipher suite operators.
     */
    private enum CipherSuiteOperator {
        ENABLE, DISABLE
    }

    /**
     * Serial version UID for serialization/deserialization.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Type of SSL channel.
     */
    private Channel_SSLChannelType ct = Channel_SSLChannelType.SSL_NONE;

    
    /**
     * Type of SSL context.
     */
    private String ctx = Crypto_Config_Default.sslContext;
    
    
    /**
     * Roles of the channel.
     */
    private Channel_Roles cr;

    /**
     * Hostname or IP address of the channel.
     */
    private String host;

    /**
     * Port number for the channel.
     */
    private int port;

    /**
     * Flag indicating whether the channel requires authentication.
     */
    private Boolean AuthenticatedChannel = false;

    /**
     * Flag indicating whether the channel requires secrecy.
     */
    private Boolean SecretChannel = false;

    /**
     * The layer associated with the channel settings.
     */
    private final static AnBx_Layers layer = AnBx_Layers.NETWORK;

	/**
	 * Channel_Settings Constructor
	 * 
	 * @param ct channel type: SSL or not
	 * @param cr channel role (client or server)
	 * @param host IP address of the remote server (if role is client)
	 * @param port port (both client an server)
	 * @param sslContext the sslContext parameter (e.g. TLSv1.2, TLSv1.3)
	 */

	public Channel_Settings(Channel_SSLChannelType ct, Channel_Roles cr, String host, int port, String sslContext) {
		super();
		this.ct = ct;
		this.cr = cr;
		this.ctx = sslContext;

		if (cr == Channel_Roles.SERVER)
			host = "localhost";
		else
			this.host = host;
		this.port = port;

		switch (ct) {
		// not authenticated channels
		case SSL_NONE:
		case SSL_PLAIN:
			AuthenticatedChannel = false;
			SecretChannel = false;
			break;
		case SSL_SECRET:
			AuthenticatedChannel = false;
			SecretChannel = true;
			break;
		// authenticated channels
		case SSL_AUTH:
			AuthenticatedChannel = true;
			SecretChannel = false;
			break;
		case SSL_SECURE:
			AuthenticatedChannel = true;
			SecretChannel = true;
			break;
		}
		AnBx_Debug.out(AnBx_Layers.APPLICATION, "Host: " + host + " - Port: " + port);
		AnBx_Debug.out(AnBx_Layers.APPLICATION, "Channel Type: " + ct.toString() + " - Role: " + cr.toString());
	}

	/**
	 * PLAIN channel settings
	 * 
	 * @param cr channel role (client or server)
	 * @param host IP address of the remote server (if role is client)
	 * @param port port (both client an server)
	 */

	public Channel_Settings(Channel_Roles cr, String host, int port) {
		this(Channel_SSLChannelType.SSL_NONE, cr, host, port, Crypto_Config_Default.sslContext);
	}

	/**
	 * Standard channel settings, without SSL context specification
	 * 
	 * @param ct channel type: SSL or not
	 * @param cr channel role (client or server)
	 * @param host IP address of the remote server (if role is client)
	 * @param port port (both client an server)
	 */
	
	public Channel_Settings(Channel_SSLChannelType ct, Channel_Roles cr, String host, int port) {
			this(ct, cr, host, port, Crypto_Config_Default.sslContext);
		}	
	
    /**
     * Gets the role of the channel.
     *
     * @return The role of the channel.
     */
	
	public Channel_Roles getChannelRole() {
		return cr;
	}


    /**
     * Gets the type of the channel.
     *
     * @return The type of the channel.
     */

	public Channel_SSLChannelType getChannelType() {
		return ct;
	}

    /**
     * Gets the type of the channel.
     *
     * @return The type of the channel.
     */

	public String getSSLContextAlgorithm() {
		return ctx;
	}
	
	
    /**
     * Gets the enabled cipher suites based on the channel type.
     *
     * @param enabled The array of enabled cipher suites.
     * @return The modified array of enabled cipher suites.
     */
	
	public String[] getEnabledCipherSuites(String[] enabled) {
		// Enable cipher suite override if necessary

		AnBx_Debug.out(layer, "--- SupportedCipherSuites ---");
		for (int i = 0; i < enabled.length; i++) {
			AnBx_Debug.out(layer, enabled[i]);
		}
		AnBx_Debug.out(layer, "---------------------------");

		switch (ct) {
		case SSL_SECRET:
			// use anonymous suites
			enabled = opCipherSuites(enabled, "_anon_", CipherSuiteOperator.ENABLE);
			break;
		case SSL_AUTH:
			// use authenticated not encrypted suites
			enabled = opCipherSuites(enabled, "_WITH_NULL_", CipherSuiteOperator.ENABLE);
			break;
		case SSL_NONE: // never called! - no suite enabled
		case SSL_PLAIN: // never called! - no suite enabled
			enabled = new String[] {};
		case SSL_SECURE: // use default settings - remove anonymous and not
			// encrypted suites
			enabled = opCipherSuites(enabled, "_anon_", CipherSuiteOperator.DISABLE);
			enabled = opCipherSuites(enabled, "_WITH_NULL_", CipherSuiteOperator.DISABLE);
			break;
		}
		AnBx_Debug.out(layer, "--- EnabledCipherSuites ---");
		if (enabled.length <= 0) {
			// AnBx_Debug.out(layer, "No Cipher Suites available");
			System.err.println(
					"No Cipher Suites are Enabled. _anon_ and _WITH_NULL may have been disabled.\nPlease check the jdk.tls.disabledAlgorithms entry in your java.security file");
		} else {
			for (int i = 0; i < enabled.length; i++) {
				AnBx_Debug.out(layer, enabled[i]);
			}
		}
		AnBx_Debug.out(layer, "---------------------------");

		return enabled;
	}

    /**
     * Gets the host of the channel.
     *
     * @return The host of the channel.
     */
	
	public String getHost() {
		return host;
	}

    /**
     * Gets the port of the channel.
     *
     * @return The port of the channel.
     */
	
	public int getPort() {
		return port;
	}

	   /**
     * Checks if the channel is authenticated.
     *
     * @return True if the channel is authenticated, false otherwise.
     */
	
	public Boolean isAuthenticatedChannel() {
		return AuthenticatedChannel;
	}

    /**
     * Checks if the channel is secret.
     *
     * @return True if the channel is secret, false otherwise.
     */
	
	public Boolean isSecretChannel() {
		return SecretChannel;
	}

    /**
     * Checks the condition for the operator.
     *
     * @param i  The first operand.
     * @param op The operator.
     * @param j  The second operand.
     * @return True if the condition is satisfied, false otherwise.
     */
	
	private boolean opCheck(int i, CipherSuiteOperator op, int j) {
		switch (op) {
		case ENABLE:
			return (i > j);
		case DISABLE:
			return (i < j);
		}
		return false;
	}

    /**
     * Modifies the array of cipher suites based on the specified pattern and operator.
     *
     * @param enabled The array of cipher suites to be modified.
     * @param pattern The pattern used for modification.
     * @param op      The operator used for modification.
     * @return The modified array of cipher suites.
     */
	
	private String[] opCipherSuites(String[] enabled, String pattern, CipherSuiteOperator op) {

		int i;
		int j;

		for (i = 0, j = 0; i < enabled.length; i++) {
			if (opCheck(enabled[i].indexOf(pattern), op, 0)) {
				j++;
			}
		}

		String[] tempArray = new String[j];
		for (i = 0, j = 0; i < enabled.length; i++) {
			if (opCheck(enabled[i].indexOf(pattern), op, 0)) {
				tempArray[j] = enabled[i];
				j++;
			}
		}

		return tempArray;
	}

    /**
     * Generates a string representation of the channel settings.
     *
     * @return A string representation of the channel settings.
     */
    	
	@Override
	public String toString() {
		String s;
		s = "Channel Settings - Port: " + getPort() + " - Role: " + getChannelRole() + " - Type: " + getChannelType();
		return s;

	}

}
