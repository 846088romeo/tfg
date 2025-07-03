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

public class Channel_Server_MTC extends Channel_Server_MT {

	// A multi-threaded version of Channel_Server (just experimenting)

	public Channel_Server_MTC(Channel_Properties cp) {
		super(cp);
	}

	@Override
	public void run() {
		int port = cp.getPort();
		synchronized (this) {
			this.runningThread = Thread.currentThread();
		}
		this.openStream(port);

		while (!isStopped()) {
			this.openClient(cp.getPort());
			try {
				new Thread(new Channel_Server_Runnable(client, "Multithreaded Server")).start();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

}
