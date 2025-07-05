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

import java.security.cert.X509Certificate;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLPeerUnverifiedException;

class Channel_HandshakeListener implements HandshakeCompletedListener

// Source: http://www.ibm.com/developerworks/java/library/j-customssl/
// Listing 2
{
	private String ident;
	private final static AnBx_Layers layer = AnBx_Layers.NETWORK;

	/**
	 * Constructs a HandshakeListener with the given identifier.
	 * 
	 * @param ident Used to identify output from this Listener.
	 */
	public Channel_HandshakeListener(String ident) {
		this.ident = ident;
	}

	/** Invoked upon SSL handshake completion. */
	@Override
	public void handshakeCompleted(HandshakeCompletedEvent event) {
		// Display the peer specified in the certificate.
		try {
			X509Certificate cert = (X509Certificate) event.getPeerCertificates()[0];
			String peer = cert.getSubjectX500Principal().getName();
			AnBx_Debug.out(layer, ident + ": Request from " + peer);
			// System.out.println(ident + " certificate information:");
			// System.out.println("- Subject DN: " + cert.getSubjectX500Principal().getName());
			// System.out.println("- Issuer DN: " + cert.getIssuerX500Principal().getName());
			// System.out.println("- Serial number: " + cert.getSerialNumber());
		} catch (SSLPeerUnverifiedException pue) {
			AnBx_Debug.out(layer, ident + ": Peer unverified");
		}
	}
}