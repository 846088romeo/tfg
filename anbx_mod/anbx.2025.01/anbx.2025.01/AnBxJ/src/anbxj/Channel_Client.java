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
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Client Channel
 */

public class Channel_Client extends Channel_Abstraction {
	private Socket client;
	private final static AnBx_Layers layer = AnBx_Layers.NETWORK;
	private static int timeoutMs = 5000; 	 // timeout for connection in milliseconds
	
	// Retry parameters
	private static int maxRetries = 10; 	 // Maximum number of retries
	private static int retryDelayMs = 500; 	 // Delay between retries in milliseconds

	
	/**
	 * create a channel client
	 * @param cp  the channel properties
	 */
	
	public Channel_Client(Channel_Properties cp) {
		super(cp);
	}

	// handle connection errors
	private void handleConnectionError(IOException e, String destination, String msg) {
		if (e instanceof UnknownHostException) {
			AnBx_Debug.out(AnBx_Layers.ALWAYS, "Host Unknown" + msg);
		} else if (e instanceof SocketTimeoutException) {
			AnBx_Debug.out(AnBx_Layers.ALWAYS, "Timeout" + msg);
		} else {
			AnBx_Debug.out(AnBx_Layers.ALWAYS, "IOException" + msg);
		}
	}
	
	// handle connection errors
	private void handleConnectionErrorWithRetries(IOException e, String destination, int retries) {
		String msg = " - Unable to connect: " + destination + " - Attempt: " + retries + "/" + maxRetries;
		if (retries < maxRetries)
				msg = msg + " - Trying again in " + retryDelayMs + "ms";
		handleConnectionError(e, destination, msg);
	}

	@Override
	public void Close() {
		super.Close();
		// close Client
		try {
			client.close();
		} catch (IOException e) {
			AnBx_Debug.out(AnBx_Layers.ALWAYS, "Unable to close the connection\n" + e);
			System.exit(1);
		}
		AnBx_Debug.out(layer, "Connection closed");
	}

	@Override
	public void Open() {

		String destination = cp.getHost() + ":" + cp.getPort();

		super.Open();
		AnBx_Debug.out(layer, "Starting Client for " + destination);
		
		int retries = 0;
		boolean connected = false;

		while (!connected && retries < maxRetries) {
		    try {
		        // Create an unbound socket
		        client = new Socket();

		        // Connect to the server
		        client.connect(new InetSocketAddress(cp.getHost(), cp.getPort()), timeoutMs);
		        
		        // If connection succeeds, set connected to true to exit the loop
		        connected = true;
		    } catch (IOException e) {
		        // Increment retry count
		        retries++;
		        // Handle connection error
		        handleConnectionErrorWithRetries(e, destination, retries);
		        // If not last retry, delay before next retry
		        if (retries < maxRetries) {
		            try {
		                Thread.sleep(retryDelayMs);
		            } catch (InterruptedException ex) {
		                Thread.currentThread().interrupt();
		            }
		        }
		    }
		}

		// If still not connected after all retries, terminate
		if (!connected) {
			AnBx_Debug.out(AnBx_Layers.ALWAYS, "Unable to connect to: " + destination + " after " + retries + " attempts");
			Close();
			System.exit(1);
		}
		
/*				
		// Create a socket with a timeout
		try {
			// Create an unbound socket
			client = new Socket();

			// some specific properties, just for test, do not use it for release
			// client.setKeepAlive(true); 		// Will monitor the TCP connection is valid
			// client.setTcpNoDelay(true); 	    // Socket buffer whether closed, to ensure timely delivery of data
			// client.setSoLinger(true, 0); 	// Control calls close () method, the underlying socket is closed immediately
			// This method will block no more than timeoutMs. If the timeout occurs, SocketTimeoutException is thrown.
			client.connect(new InetSocketAddress(cp.getHost(), cp.getPort()), timeoutMs);
		} catch (IOException e) {
			handleConnectionError(e, destination);
		}
*/

		AnBx_Debug.out(AnBx_Layers.ALWAYS, "Connected to Server " + destination + " - ChannelType: " + cp.getChannelType().toString());
		
		switch (cp.getChannelType()) {
		case SSL_NONE:
		case SSL_PLAIN:
			super.OpenStreams(client);
			break;
		case SSL_AUTH:
		case SSL_SECRET:
		case SSL_SECURE:
			SSLContext sslContext = new Channel_SSLContextBuilder(cp.getKeyStoreSettings(),cp.getSSLContextAlgorithm()).getSSLContext();
			SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
			SSLSocket sslClient;

			try {
				// Open socket connection with the external Server
				sslClient = (SSLSocket) sslSocketFactory.createSocket(client, client.getInetAddress().getHostAddress(), cp.getPort(), false);
				sslClient.setEnabledCipherSuites(cp.getEnabledCipherSuites(sslSocketFactory.getSupportedCipherSuites()));
				sslClient.setUseClientMode(true);

				// We add in a HandshakeCompletedListener, which allows us to
				// peek at the certificate provided by the Client
				HandshakeCompletedListener hcl = new Channel_HandshakeListener("Server");
				sslClient.addHandshakeCompletedListener(hcl);

				sslClient.startHandshake();
				client = sslClient;
				AnBx_Debug.out(layer, "Using cipher suite: " + (sslClient.getSession()).getCipherSuite());

			} catch (IOException e) {
				handleConnectionError(e, destination, " - " + cp.getChannelType().toString());
				System.exit(1);
			}
			super.OpenStreams(client);
			AnBx_Debug.out(AnBx_Layers.ALWAYS, "Established TLS/SSL connection with " + destination + " - ChannelType: " + cp.getChannelType().toString());
			break;
		default:
			break;
		}
	}

	/**
	 * Set the channel timeout
	 * 
	 * @param timeoutMs the timeout in milliseconds
	 */
	public static void setTimeoutMs(int timeoutMs) {
		if (timeoutMs > 500)
			Channel_Client.timeoutMs = timeoutMs;
	}

	/**
	 * set the max number of attempts if the client is unable to connect to the server
	 * @param maxRetries  the number of attemps
	 */
	protected static void setMaxRetries(int maxRetries) {
		if (maxRetries > 0)
		Channel_Client.maxRetries = maxRetries;
	}

	/** 
	 * set the time interval between connection attempts
	 * @param retryDelayMs the the time interval in milliseconds
	 */
	protected static void setRetryDelayMs(int retryDelayMs) {
		if (retryDelayMs > 50)
			Channel_Client.retryDelayMs = retryDelayMs;
	}


}