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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * A class used to build an SSLContext for creating SocketFactory.
 */
public class Channel_SSLContextBuilder extends Crypto_KeyStoreBuilder {

    /**
     * The layer associated with this channel.
     */
    private final static AnBx_Layers layer = AnBx_Layers.NETWORK;
	
	private SSLContext sslContext;

    /**
     * Constructs a Channel_SSLContextBuilder with the given Crypto_KeyStoreSettings.
     *
     * @param kss the Crypto_KeyStoreSettings
     * @param sslContextParameter the SSL context
     */
    public Channel_SSLContextBuilder(Crypto_KeyStoreSettings kss, String sslContextParameter) {
        super(kss);
        try {
            setupSSLContext(sslContextParameter);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Gets the SSLContext.
     *
     * @return the SSLContext
     */
    public SSLContext getSSLContext() {
        return sslContext;
    }
    
    /**
     * Sets up the SSLContext with configured KeyManagerFactory, TrustManagerFactory, and secure random.
     *
     * @throws GeneralSecurityException if a security error occurs
     * @throws IOException              if an I/O error occurs
     */

    private void setupSSLContext(String sslContextParameter) throws GeneralSecurityException, IOException {

        // Create a TrustManagerFactory implementing the X.509 key management
        // algorithm.
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(kss.getCertificateType());
        tmf.init(remoteKeyStore);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(kss.getCertificateType());
        kmf.init(localKeyStore, kss.getPassphraseLocalKeyStore().toCharArray());

        // A source of secure random numbers
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextInt();

        // Create an SSLContext instance implementing the TLS protocol.
        sslContext = SSLContext.getInstance(sslContextParameter);
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), secureRandom);
        AnBx_Debug.out(layer, "SSLContext Algorithm: " + sslContext.getProtocol());
        
    }
}

