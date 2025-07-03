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

import java.io.Serializable;
import java.util.Arrays;

/**
 * Byte Array: a custom implementation of a byte array, used to store the result
 * of various cryptographic functions
 */

public class Crypto_ByteArray implements Serializable {

	private final static AnBx_Layers layer = AnBx_Layers.ENCRYPTION;
	/**
	 * 
	 */
	
    /**
     * Serial Version UID
     */
	private static final long serialVersionUID = 1L;
	
    /**
     * The byte array
     */
	
	private byte[] bytearray;

	
    /**
     * Gets the byte array.
     *
     * @return the byte array
     */
	
	public byte[] getByteArray() {
		return bytearray;
	}

	 /**
     * Gets the length of the byte array.
     *
     * @return the length of the byte array
     */
	
	public int getLength() {
		return bytearray.length;
	}
    /**
     * Constructs a Crypto_ByteArray with the given byte array.
     *
     * @param digest the byte array
     */
	
	public Crypto_ByteArray(byte[] digest) {
		super();
		this.bytearray = digest.clone();
	}
	
    /**
     * Constructs a Crypto_ByteArray with the given byte array and comment.
     *
     * @param digest  the byte array
     * @param comment a comment (unused in the current implementation)
     */

	public Crypto_ByteArray(byte[] digest, String comment) {
		super();
		this.bytearray = digest.clone();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(bytearray);
		return result;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		AnBx_Debug.out(layer, "Crypto_ByteArray check");
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof Crypto_ByteArray)) {
			AnBx_Debug.out(layer, "Crypto_ByteArray check - not a Crypto_ByteArray");
			return false;
		}
		Crypto_ByteArray other = (Crypto_ByteArray) obj;
		if (bytearray.length != other.getLength()) {
			AnBx_Debug.out(layer, "Crypto_ByteArray check - error in bytearray length: " + bytearray.length + " != " + other.getLength());
			return false;
		}
		return Arrays.equals(this.bytearray, other.getByteArray());

		// see http://codahale.com/a-lesson-in-timing-attacks/

//		int result = 0;
//		for (int i = 0; i < other.bytearray.length; i++) {
//			result |= bytearray[i] ^ other.bytearray[i];
//		}
//		if (result != 0) {
//			AnBx_Debug.out(layer, "Crypto_ByteArray check - error in bytearray comparison");
//			AnBx_Debug.out(layer, "Crypto_ByteArray check obj.toString - error " + this.toString() + " != " + other.toString());
//			AnBx_Debug.out(layer, "Crypto_ByteArray check obj.hashCode - error " + this.hashCode() + " != " + other.hashCode());
//		}
//		return result == 0;

	}
	

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "Crypto_ByteArray [bytearray=" + Arrays.toString(bytearray) + "]";
	}
}
