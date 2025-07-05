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
 * SSL channel type enumerator
 */

/**
 * Enumeration representing different types of SSL channels.
 */
public enum Channel_SSLChannelType {
    /**
     * No SSL channel.
     */
    SSL_NONE,

    /**
     * Plain SSL channel.
     */
    SSL_PLAIN,

    /**
     * SSL channel with authentication.
     */
    SSL_AUTH,

    /**
     * SSL channel with secret features.
     */
    SSL_SECRET,

    /**
     * Secure SSL channel.
     */
    SSL_SECURE;
    /**
     * Returns the corresponding SSL channel type given a string The string should
     * be a valid SSL channel type name
     *
     * @param cts the specified string
     * @return a Channel_SSLChannelType
     */

	public static Channel_SSLChannelType String2ChannelType(String cts) {
		if (cts.equalsIgnoreCase("SSL_PLAIN"))
			return SSL_PLAIN;
		else if (cts.equalsIgnoreCase("SSL_AUTH"))
			return SSL_AUTH;
		else if (cts.equalsIgnoreCase("SSL_SECRET"))
			return SSL_SECRET;
		else if (cts.equalsIgnoreCase("SSL_SECURE"))
			return SSL_SECURE;
		else
			return SSL_NONE;
	}
	
    /**
     * Returns information about SSL Channel Types.
     *
     * @return a string containing information about SSL Channel Types
     */

	public static String getInfo() {
		String info = "SSL Channel Types: " + SSL_PLAIN.toString() + ", " + SSL_AUTH.toString() + ", " + SSL_SECRET.toString() + ", " + SSL_SECURE.toString();
		return info;
	}
	}

