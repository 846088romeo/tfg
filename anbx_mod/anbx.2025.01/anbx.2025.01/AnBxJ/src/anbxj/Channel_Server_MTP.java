/*

 AnBx Java Security Library

 Copyright 2011-2014 Paolo Modesti
 Copyright 2013-2014 School of Computing Science, Newcastle University
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

public class Channel_Server_MTP extends Channel_Abstraction implements Runnable {
	// A multithreaded version of Channel_Server (just experimenting)

	protected boolean isStopped = false;
	protected Thread runningThread = null;

	private ServerSocket server = null;
	private Socket client = null;
	private final static AnBx_Layers layer = AnBx_Layers.NETWORK;

	public Channel_Server_MTP(Channel_Properties cp) {
		super(cp);
	}

	@Override
	public void Open() {

		super.Open();

		AnBx_Debug.out(AnBx_Layers.ALWAYS, "Starting server...");
		int port = cp.getPort();
		try {
			server = new ServerSocket(port);
		} catch (IOException e) {
			AnBx_Debug.out(AnBx_Layers.ALWAYS, "There is already a Server running on port " + port + "\n" + e);
			System.exit(1);
		}

		AnBx_Debug.out(layer, "Server started on port " + port);
		AnBx_Debug.out(layer, "Waiting for clients...");

	}

	public void waitforClient() {
		try {

			client = server.accept();

			switch (cp.getChannelType()) {
			// plain channels
			case SSL_NONE:
			case SSL_PLAIN:
				AnBx_Debug.out(layer, "Request from Client received...");
				super.OpenStreams(client);
				break;
			// secret channels
			case SSL_AUTH:
			case SSL_SECRET:
			case SSL_SECURE:

				// adapted from
				// Enterprise Java Security: Building Secure J2EE Applications
				// Marco Pistoia, Nataraj Nagaratnam, Larry Koved, Anthony
				// Nadalin
				// Addison-Wesley Professional, 2004

				SSLContext sslContext = new Channel_SSLContextBuilder(cp.getKeyStoreSettings(),cp.getSSLContextAlgorithm()).getSSLContext();
				SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

				// Try to start the sslServer. At this point, problems may arise
				// if another process is already listening
				// on the selected port.

				SSLSocket sslClient;
				try {
					sslClient = (SSLSocket) sslSocketFactory.createSocket(client, client.getInetAddress().getHostAddress(), cp.getPort(), false);
					// authenticated channel
					if (cp.isAuthenticatedChannel())
						sslClient.setNeedClientAuth(true);
					sslClient.setEnabledCipherSuites(cp.getEnabledCipherSuites(sslSocketFactory.getSupportedCipherSuites()));
					sslClient.setUseClientMode(false);

					// We add in a HandshakeCompletedListener, which allows us
					// to peek at the certificate provided by
					// the Client.
					HandshakeCompletedListener hcl = new Channel_HandshakeListener("Client");
					sslClient.addHandshakeCompletedListener(hcl);
					sslClient.startHandshake();
					client = sslClient;
					AnBx_Debug.out(layer, "Using cipher suite: " + (sslClient.getSession()).getCipherSuite());
					AnBx_Debug.out(layer, "Request from Client received...");
					super.OpenStreams(client);
				} catch (IOException ioe) {
					AnBx_Debug.out(AnBx_Layers.ALWAYS, "Unable to accept connection from Client\n" + ioe);
					System.exit(1);
				}
			}

		} catch (IOException ioe) {
			AnBx_Debug.out(AnBx_Layers.ALWAYS, "Unable to accept connection from Client\n" + ioe);
			System.exit(1);
		}
	}

	@Override
	public void Close() {
		this.isStopped = true;
		super.Close();

		// close sslClient
		try {
			client.close();
		} catch (IOException e) {
			AnBx_Debug.out(AnBx_Layers.ALWAYS, "Unable to close the Client\n" + e);
			System.exit(1);
		}
		// close sslServer
		try {
			server.close();
		} catch (IOException e) {
			AnBx_Debug.out(AnBx_Layers.ALWAYS, "Unable to close the Server\n" + e);
			System.exit(1);
		}
		AnBx_Debug.out(layer, "Connection closed");
	}

	@Override
	public void run() {
		synchronized (this) {
			this.runningThread = Thread.currentThread();
		}
		openServerSocket();

		while (!isStopped()) {
			waitforClient();
			try {
				new Thread(new Channel_Server_Runnable(client, "Multithreaded Server")).start();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	protected void processClientRequest() throws IOException {
		Send("Generic processClientRequest");
	}

	private synchronized boolean isStopped() {
		return this.isStopped;
	}

	public synchronized void stop() {
		Close();
	}

	private void openServerSocket() {
		Open();
	}

}
