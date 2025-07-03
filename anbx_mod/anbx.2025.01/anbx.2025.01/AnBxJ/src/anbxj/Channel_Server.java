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
import java.net.ServerSocket;
import java.net.Socket;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Server Channel
 */

public class Channel_Server extends Channel_Abstraction {

	 /**
     * The server socket used for communication.
     */
    protected ServerSocket server;

    /**
     * The client socket used for communication.
     */
    protected Socket client;

    /**
     * The layer associated with the network.
     */
    protected final static AnBx_Layers layer = AnBx_Layers.NETWORK;


    /**
     * Constructor for Channel_Server.
     *
     * @param cp The Channel_Properties.
     */
	
	public Channel_Server(Channel_Properties cp) {
		super(cp);
	}

    /**
     * Handles IOException with a specific message and exits the system.
     *
     * @param message The error message.
     * @param e       The IOException.
     */
	
	private void handleIOException(String message, IOException e) {
		AnBx_Debug.out(AnBx_Layers.ALWAYS, message + "\n" + e);
		System.exit(1);
	}
	
    /**
     * Opens the server socket on the specified port.
     *
     * @param port The port to open the server socket.
     */
	
	protected void openServerSocket(int port) {
		AnBx_Debug.out(layer, "Starting server on port " + port + " ...");

		try {
			server = new ServerSocket(cp.getPort());
		} catch (IOException e) {
			handleIOException("There is already a Server running on port " + port, e);
		}

		AnBx_Debug.out(AnBx_Layers.ALWAYS, "Server started on port " + port);
		AnBx_Debug.out(layer, "Waiting for clients ...");

	}
	
    /**
     * Accepts a client connection and opens the stream.
     *
     * @param port The port to open the client connection.
     */
	
	protected void openClient(int port) {
		try {
			client = server.accept();
		} catch (IOException ioe) {
			handleIOException("Unable to accept connection from Client\n", ioe);
		}
		openStream(port);

	}

	
    /**
     * Opens the stream based on the channel type.
     *
     * @param port The port to open the stream.
     */
	
	protected void openStream(int port) {

		switch (cp.getChannelType()) {
		// plain channels
		case SSL_NONE:
		case SSL_PLAIN:
			AnBx_Debug.out(layer, "Request from Client received ...");
			super.OpenStreams(client);
			break;
		// secret channels
		case SSL_AUTH:
		case SSL_SECRET:
		case SSL_SECURE:

			// adapted from
			// Enterprise Java Security: Building Secure J2EE Applications
			// Marco Pistoia, Nataraj Nagaratnam, Larry Koved, Anthony Nadalin
			// Addison-Wesley Professional, 2004

			SSLContext sslContext = new Channel_SSLContextBuilder(cp.getKeyStoreSettings(),cp.getSSLContextAlgorithm()).getSSLContext();
			SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

			// Try to start the sslServer. At this point, problems may arise if
			// another process is already listening on
			// the selected port.

			SSLSocket sslClient;
			try {
				sslClient = (SSLSocket) sslSocketFactory.createSocket(client, client.getInetAddress().getHostAddress(), port, false);
				// authenticated channel
				if (cp.isAuthenticatedChannel())
					sslClient.setNeedClientAuth(true);
				sslClient.setEnabledCipherSuites(cp.getEnabledCipherSuites(sslSocketFactory.getSupportedCipherSuites()));
				sslClient.setUseClientMode(false);

				// We add in a HandshakeCompletedListener, which allows us to
				// peek at the certificate provided by the
				// Client_1st.
				HandshakeCompletedListener hcl = new Channel_HandshakeListener("Client");
				sslClient.addHandshakeCompletedListener(hcl);

				sslClient.startHandshake();
				client = sslClient;
				AnBx_Debug.out(layer, "Using cipher suite: " + (sslClient.getSession()).getCipherSuite());

			} catch (IOException e) {
				handleIOException("There is already a Server running on port " + port, e);
			}

			AnBx_Debug.out(layer, "Request from Client received ...");
			OpenStreams(client);

		}
	}

    /**
     * Closes the client socket.
     */
	private void closeClient() {
		try {
			client.close();
		} catch (IOException e) {
			handleIOException("Unable to close the Client", e);
		}
	}

    /**
     * Closes the server socket.
     */
	private void closeServer() {
		try {
			server.close();
		} catch (IOException e) {
			handleIOException("Unable to close the Server", e);
		}
	}

    /**
     * Opens the server channel.
     */
	@Override
	public void Open() {

		this.checkPort();
		int port = cp.getPort();
		this.openServerSocket(port);
		this.openClient(port);
	}

    /**
     * Closes the server channel.
     */
	@Override
	public void Close() {
		super.Close();
		this.closeClient();
		this.closeServer();

		AnBx_Debug.out(layer, "Connection closed");
	}

}