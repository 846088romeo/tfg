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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.StreamCorruptedException;
import java.net.Socket;
import java.util.List;

	/**
	 * Channel Abstraction: a class abstracting TCP/IP channel
	 */

public abstract class Channel_Abstraction {

    /**
     * The layer associated with this channel.
     */
    private final static AnBx_Layers layer = AnBx_Layers.NETWORK;

    /**
     * Properties specific to the channel.
     */
    protected Channel_Properties cp;

    /**
     * Output stream for sending objects over the channel.
     */
    private ObjectOutputStream out;

    /**
     * Input stream for receiving objects over the channel.
     */
    private ObjectInputStream in;

    /**
     * Minimum TCP port in the allowed range.
     */
    private final static int minport = 1025;

    /**
     * Maximum TCP port in the allowed range.
     */
    private final static int maxport = 65536;

    /**
     * Constructor for Channel Abstraction.
     *
     * @param cp Channel properties for the abstraction.
     */
	
	public Channel_Abstraction(Channel_Properties cp) {
		super();
		this.cp = cp;
	}

	/**
	 * Close channel streams
	 */
	
	public void Close() {
		this.CloseStreams();
	}


    /**
     * Closes the channel by closing associated streams.
     */
	
	private void CloseStreams() {

		// close streams
		try {
			if (in != null)
				in.close();
			if (out != null)
				out.close();
		} catch (IOException e) {
			AnBx_Debug.out(AnBx_Layers.EXCEPTION, e);
		}
	}
	
	 /**
     * Gets the role of the channel.
     *
     * @return Channel role.
     */

	public Channel_Roles getChannelRole() {
		return cp.getChannelRole();
	}

    /**
     * Checks if the provided port is within the valid range.
     */
	
	protected void checkPort()

	{
		int port = cp.getPort();

		if (port < minport || port > maxport) {
			AnBx_Debug.out(AnBx_Layers.ALWAYS, "<port> must be an integer in the range " + minport + "-" + maxport);
			System.exit(0);
		}

	}
	
    /**
     * Opens the channel, by invoking the checkPort method.
     */

	public void Open() {
		this.checkPort();
	}

    /**
     * Opens input and output streams for the specified socket.
     *
     * @param s Socket for which to open streams.
     */
	
	protected void OpenStreams(Socket s) {
		// Open the I/O streams
		try {
			out = new ObjectOutputStream(s.getOutputStream());
			in = new ObjectInputStream(s.getInputStream());

		} catch (IOException e) {
			AnBx_Debug.out(AnBx_Layers.EXCEPTION, e);
		}
	}

    /**
     * Receives an object from the input stream.
     *
     * @return Received object.
     */
	
	public Object Receive() {
		Object obj = null;
		AnBx_Debug.out(layer, "---------- RECEIVE -------------");
		try {
			// readLine = in.readObject() .readLine();
			obj = in.readObject();
			if (obj != null) {
				AnBx_Debug.out(layer, "Received <- " + obj.toString());
			}
		} catch (StreamCorruptedException e) {
			AnBx_Debug.out(AnBx_Layers.EXCEPTION, e);
		} catch (IOException e) {
			AnBx_Debug.out(AnBx_Layers.EXCEPTION, e);
		} catch (NullPointerException e) {
			AnBx_Debug.out(AnBx_Layers.EXCEPTION, e);
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}

		return obj;
	}
	
    /**
     * Receives an object of a specified type with additional safety checks.
     *
     * @param type         Class representing the object type expected to be returned.
     * @param safeClasses  List of Classes allowed in the serialized object being read.
     * @param maxObjects   Maximum number of objects allowed inside the serialized object being read.
     * @param maxBytes     Maximum number of bytes allowed to be read from the InputStream.
     * @param <T>          Parametric type.
     * @return Received object of the specified type.
     */

	public <T> T Receive(Class<?> type, List<Class<?>> safeClasses, long maxObjects, long maxBytes) {
		T obj = null;
		AnBx_Debug.out(layer, "---------- RECEIVE -------------");
		try {
			obj = safeReadObject(type, safeClasses, maxObjects, maxBytes, in);
			if (obj != null) {
				AnBx_Debug.out(layer, "Received <- " + obj.toString());
			}
		} catch (IOException e) {
			AnBx_Debug.out(AnBx_Layers.EXCEPTION, e);
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}

		return obj;
	}

	// https://www.contrastsecurity.com/security-influencers/java-serialization-vulnerability-threatens-millions-of-applications
	// Copyright 2015 Jeff Williams

	/**
	 * A method to replace the unsafe ObjectInputStream.readObject() method
	 * built into Java. This method checks to be sure the classes referenced are
	 * safe, the number of objects is limited to something sane, and the number
	 * of bytes is limited to a reasonable number. The returned Object is also
	 * cast to the specified type.
	 * 
	 * @param <T> Parametric type
	 * @param type Class representing the object type expected to be returned
	 * @param safeClasses List of Classes allowed in serialized object being
	 * read
	 * @param maxObjects long representing the maximum number of objects allowed
	 * inside the serialized object being read
	 * @param maxBytes long representing the maximum number of bytes allowed to
	 * be read from the InputStream
	 * @param in InputStream containing an untrusted serialized object
	 * @return Object read from the stream (cast to the Class of the type
	 * parameter)
	 * @throws IOException I/O error exception
	 * @throws ClassNotFoundException Class not found exception
	 */
	@SuppressWarnings("unchecked")
	public static <T> T safeReadObject(Class<?> type, List<Class<?>> safeClasses, long maxObjects, long maxBytes, InputStream in) throws IOException, ClassNotFoundException {
		// create an input stream limited to a certain number of bytes
		InputStream lis = new FilterInputStream(in) {
			private long len = 0;

			@Override
			public int read() throws IOException {
				int val = super.read();
				if (val != -1) {
					len++;
					checkLength();
				}
				return val;
			}

			@Override
			public int read(byte[] b, int off, int len) throws IOException {
				int val = super.read(b, off, len);
				if (val > 0) {
					len += val;
					checkLength();
				}
				return val;
			}

			private void checkLength() throws IOException {
				if (len > maxBytes) {
					throw new SecurityException("Security violation: attempt to deserialize too many bytes from stream. Limit is " + maxBytes);
				}
			}
		};
		// create an object input stream that checks classes and limits the
		// number of objects to read
		ObjectInputStream ois = new ObjectInputStream(lis) {
			private int objCount = 0;

			// boolean b = enableResolveObject(true);

			@Override
			protected Object resolveObject(Object obj) throws IOException {
				if (objCount++ > maxObjects)
					throw new SecurityException("Security violation: attempt to deserialize too many objects from stream. Limit is " + maxObjects);
				Object object = super.resolveObject(obj);
				return object;
			}

			@Override
			protected Class<?> resolveClass(ObjectStreamClass osc) throws IOException, ClassNotFoundException {
				Class<?> clazz = super.resolveClass(osc);
				if (clazz.isArray() || clazz.equals(type) || clazz.equals(String.class) || Number.class.isAssignableFrom(clazz) || safeClasses.contains(clazz))
					return clazz;
				throw new SecurityException("Security violation: attempt to deserialize unauthorized " + clazz);
			}
		};
		// use the protected ObjectInputStream to read object safely and cast to
		// T
		return (T) ois.readObject();
	}
	
    /**
     * Sends an object through the output stream.
     *
     * @param obj Object to be sent.
     */

	public void Send(Object obj) {
		AnBx_Debug.out(layer, "---------- SEND -----------");
		if (obj != null) {
			AnBx_Debug.out(layer, "Sending -> " + obj.toString());
		}
		try {
			out.writeObject(obj);
			if (obj != null) {
				AnBx_Debug.out(layer, "Sent -> " + obj.toString());
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
