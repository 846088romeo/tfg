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

public class Channel_Server_MT extends Channel_Server implements Runnable {
	// A multi-threaded version of Channel_Server (just experimenting)

	protected boolean isStopped = false;
	protected Thread runningThread = null;

	public Channel_Server_MT(Channel_Properties cp) {
		super(cp);
	}

	@Override
	public void Close() {
		this.isStopped = true;
		super.Close();
	}

	@Override
	public void run() {
		synchronized (this) {
			this.runningThread = Thread.currentThread();
		}
		openServerSocket(cp.getPort());

		while (!isStopped()) {

			try {
				processClientRequest();
			} catch (IOException e) {
				// log exception and go on to next request.
			}
		}

		AnBx_Debug.out(AnBx_Layers.ALWAYS, "Server stopped");
	}

	protected void processClientRequest() throws IOException {
		Send("Generic processClientRequest");
	}

	protected synchronized boolean isStopped() {
		return this.isStopped;
	}

	public synchronized void stop() {
		Close();
	}

	// protected void openServerSocket() {
	// Open();
	// }

	@Override
	public void Open() {
		checkPort();
		int port = cp.getPort();
		this.openServerSocket(port);
		this.openClient(port);
	}

}
