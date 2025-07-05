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

abstract class Channel_Factory {

	// use "ABSTRACT FACTORY" design pattern

	public static Channel_Factory getFactory(Channel_Properties cp) {
		switch (cp.getChannelRole()) {
		case SERVER:
			return new ServerFactory();
		case CLIENT:
			return new ClientFactory();
		}
		return null;
	}

	public abstract Channel_Abstraction createChannel(Channel_Properties cp);
}

class ClientFactory extends Channel_Factory {
	@Override
	public Channel_Abstraction createChannel(Channel_Properties cp) {
		return new Channel_Client(cp);
	}
}

class ServerFactory extends Channel_Factory {
	@Override
	public Channel_Abstraction createChannel(Channel_Properties cp) {
		return new Channel_Server(cp);
		// return new Channel_Server_MTC(cp);
		// return new Channel_Server_MT(cp);
		// return new Channel_Server_MTP(cp);
	}
}
