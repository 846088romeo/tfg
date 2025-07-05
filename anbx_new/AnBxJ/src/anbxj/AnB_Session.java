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
 * AnB Session: implements a protocol session supporting cryptographic
 * operations
 */

public class AnB_Session extends AnB_Crypto_Wrapper {

	private final static AnBx_Layers layer = AnBx_Layers.SESSION;

	private Channel_Abstraction c;
	private AnBx_Agent id_Remote = null;
	private boolean exchange_id = false; // allow agents to exchange their aliases
	
	/**
	 * Constructs a new AnB_Session with the specified parameters.
	 *
	 * @param kssd          The Crypto_KeyStoreSettings_Map to be used.
	 * @param cs            The Channel_Settings for initialising channels.
	 * @param exchange_id   A boolean indicating whether to exchange ID.
	 * @param config        The Crypto_Config to be used.
	 */

	public AnB_Session(Crypto_KeyStoreSettings_Map kssd, Channel_Settings cs, boolean exchange_id, Crypto_Config config) {
		super(kssd, config);
		initChannels(cs);
		this.exchange_id = exchange_id;
	}

	/**
	 * Constructs a new AnB_Session with the specified parameters.
	 *
	 * @param kssd      The Crypto_KeyStoreSettings_Map to be used.
	 * @param cs        The Channel_Settings for initialising channels.
	 * @param id_Remote The AnBx_Agent representing the remote ID.
	 * @param config    The Crypto_Config to be used.
	 */
	
	public AnB_Session(Crypto_KeyStoreSettings_Map kssd, Channel_Settings cs, AnBx_Agent id_Remote, Crypto_Config config) {
		super(kssd, config);
		initChannels(cs);
		this.id_Remote = id_Remote;
	}
	
	/**
	 * Constructs a new AnB_Session with the specified parameters.
	 *
	 * @param kssd            The Crypto_KeyStoreSettings_Map to be used.
	 * @param cs              The Channel_Settings for initialising channels.
	 * @param id_Remote_alias The alias for the remote ID.
	 * @param config          The Crypto_Config to be used.
	 */

	public AnB_Session(Crypto_KeyStoreSettings_Map kssd, Channel_Settings cs, String id_Remote_alias, Crypto_Config config) {
		super(kssd, config);
		initChannels(cs);
		this.id_Remote = new AnBx_Agent(id_Remote_alias, this);
	}

	/**
	 * Initializes the channels based on the provided Channel_Settings.
	 *
	 * @param cs The Channel_Settings for initialising channels.
	 */
	
	void initChannels(Channel_Settings cs) {
		AnBx_Debug.out(layer, "Initializing channel - cs: " + cs.toString());
		AnBx_Debug.out(layer, "Initializing channel - keystore: " + ee.getKeyStoreSettings_Map().getKeyStoreSettings(super.ident_ks).toString());
		Channel_Properties cp = new Channel_Properties(cs, ee.getKeyStoreSettings_Map().getKeyStoreSettings(super.ident_ks));
		c = Channel.setup(cp);
	}

	/**
	 * Opens the session by initiating the channel, exchanging IDs if required.
	 */
	public void Open() {
	    AnBx_Debug.out(layer, "Opening session");
	    c.Open();
	    if (exchange_id) {
	        switch (c.getChannelRole()) {
	            case CLIENT:
	                Send_Id();
	                id_Remote = Receive_RemoteId();
	                break;
	            case SERVER:
	                id_Remote = Receive_RemoteId();
	                Send_Id();
	                break;
	        }
	    }
	}

	/**
	 * Closes the session by closing the channel and logging the closure.
	 */
	public void Close() {
	    if (c != null) c.Close();
	    AnBx_Debug.out(layer, "Session closed");
	}

	/**
	 * Receives an object using the current channel.
	 *
	 * @return The received object.
	 */
	public Object Receive() {
	    return Receive(c);
	}

	/**
	 * Sends an object using the current channel.
	 *
	 * @param obj The object to be sent.
	 */
	public void Send(Object obj) {
	    Send(obj, c);
	}

	/**
	 * Receives the remote identity (AnBx_Agent) using the current channel.
	 *
	 * @return The received AnBx_Agent representing the remote identity.
	 */
	public AnBx_Agent Receive_RemoteId() {
	    AnBx_Agent id;
	    id = (AnBx_Agent) Receive(c);
	    AnBx_Debug.out(layer, "Received id_Client: <" + id.getName() + ">");
	    return id;
	}

	/**
	 * Sends the local identity (me) using the current channel.
	 */
	public void Send_Id() {
	    Send(me, c);
	    AnBx_Debug.out(layer, "Sending My Identity <" + me.getName() + ">");
	}

	/**
	 * Gets the current channel.
	 *
	 * @return The current channel.
	 */
	public Channel_Abstraction getChannel() {
	    return c;
	}

	/**
	 * Gets the remote identity (AnBx_Agent).
	 *
	 * @return The remote identity.
	 */
	public AnBx_Agent getId_Remote() {
	    return id_Remote;
	}

	/**
	 * Sets the current channel.
	 *
	 * @param c The channel to be set.
	 */
	public void setChannel(Channel_Abstraction c) {
	    this.c = c;
	}

	/**
	 * Sets the remote identity (AnBx_Agent).
	 *
	 * @param id_Remote The remote identity to be set.
	 */
	public void setId_Remote(AnBx_Agent id_Remote) {
	    this.id_Remote = id_Remote;
	}
}