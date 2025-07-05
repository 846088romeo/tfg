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
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

/**
 * A class for time stamp validation
 */

// inspired by http://oauth.googlecode.com/svn/code/java/core/provider/src/main/java/net/oauth/SimpleOAuthValidator.java

/*
 * Copyright 2008 Google, Inc., Licensed under the Apache License, Version 2.0
 * (the "License");
 */

public class Crypto_TimeStampValidator {

	/** The default maximum age of time stamps is 15 minutes. */
	public static final long DEFAULT_MAX_TIMESTAMP_AGE = 15 * 60 * 1000L;
	
	/** The default time stamp window */
	
	public static final long DEFAULT_TIMESTAMP_WINDOW = DEFAULT_MAX_TIMESTAMP_AGE;

	/** Tha maximum timestamp age in ms */
	
	protected final long maxTimestampAgeMsec;
	
	/** A set of used nonces */
		
	private final Set<UsedNonce> usedNonces = new TreeSet<UsedNonce>();
	
	/**
	 * Construct a validator that rejects messages more than five minutes old
	 */
	public Crypto_TimeStampValidator() {
		this(DEFAULT_TIMESTAMP_WINDOW);
	}

	/**
	 * Public constructor.
	 * 
	 * @param maxTimestampAgeMsec the range of valid timestamps, in milliseconds
	 * into the past or future. So the total range of valid timestamps is twice
	 * this value, rounded to the nearest second.
	 */

	public Crypto_TimeStampValidator(long maxTimestampAgeMsec) {
		this.maxTimestampAgeMsec = maxTimestampAgeMsec;
	}

	/**
	 * Allow objects that are no longer useful to become garbage.
	 * 
	 * @return the earliest point in time at which another call will release
	 * some garbage, or null to indicate there's nothing currently stored that
	 * will become garbage in future. This value may change, each time
	 * releaseGarbage or validateNonce is called.
	 */

	public Date releaseGarbage() {
		return removeOldNonces(currentTimeMsec());
	}

	/**
	 * Remove usedNonces with timestamps that are too old to be valid.
	 */
	private Date removeOldNonces(long currentTimeMsec) {
		UsedNonce next = null;
		UsedNonce min = new UsedNonce(null, (currentTimeMsec - maxTimestampAgeMsec + 500) / 1000L);
		synchronized (usedNonces) {
			// Because usedNonces is a TreeSet, its iterator produces
			// elements from oldest to newest (their natural order).
			for (Iterator<UsedNonce> iter = usedNonces.iterator(); iter.hasNext();) {
				UsedNonce used = iter.next();
				if (min.compareTo(used) <= 0) {
					next = used;
					break; // all the rest are also new enough
				}
				iter.remove(); // too old
			}
		}
		if (next == null)
			return null;
		return new Date((next.getTimestamp() * 1000L) + maxTimestampAgeMsec + 500);
	}

	/**
	 * Throw an exception if the nonce has been validated previously.
	 * 
	 * @param nx the nonce to be validated
	 * @param timestamp the timestamp *
	 * @return the earliest point in time at which a call to releaseGarbage will
	 * actually release some garbage, or null to indicate there's nothing
	 * currently stored that will become garbage in future.
	 * 
	 * @throws Crypto_TimeStampException for non validated nonces
	 * @throws IOException if an IO error is detected
	 * 
	 * @see Crypto_TimeStampException
	 * @see java.io.IOException
	 */
	protected Date validateNonce(byte[] nx, long timestamp) throws IOException, Crypto_TimeStampException {
		UsedNonce nonce = new UsedNonce(nx, timestamp);
		boolean valid = false;
		synchronized (usedNonces) {
			valid = usedNonces.add(nonce);
		}
		if (!valid) {
			throw new Crypto_TimeStampException();
		}
		return removeOldNonces(this.currentTimeMsec());
	}

	/**
	 * Get the number of milliseconds since midnight, January 1, 1970 UTC.
	 * 
	 * @return number of milliseconds since midnight, January 1, 1970
	 * 
	 */
	protected long currentTimeMsec() {
		return System.currentTimeMillis();
	}

	@Override
	public boolean equals(Object that) {
		if (that == null)
			return false;
		if (that == this)
			return true;
		if (that.getClass() != getClass())
			return false;
		return equals((that));
	}

	private static class UsedNonce implements Comparable<UsedNonce> {

		private byte[] nonce;
		private long timestamp;

		public UsedNonce(byte[] nonce, long timestamp) {
			super();
			this.nonce = nonce;
			this.timestamp = timestamp;
		}

		@Override
		public int compareTo(UsedNonce o) {

			return ((nonce.equals(o.nonce)) ? 1 : 0);
		}

		/**
		 * @return the timestamp
		 */
		public long getTimestamp() {
			return timestamp;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.lang.Object#hashCode()
		 */
		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + Arrays.hashCode(nonce);
			result = prime * result + (int) (timestamp ^ (timestamp >>> 32));
			return result;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.lang.Object#equals(java.lang.Object)
		 */
		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			UsedNonce other = (UsedNonce) obj;
			if (!Arrays.equals(nonce, other.nonce))
				return false;
			// compare only the nonce
			// if (timestamp != other.timestamp)
			// return false;
			return true;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.lang.Object#toString()
		 */
		@Override
		public String toString() {
			return "UsedNonce [nonce=" + Arrays.toString(nonce) + ", timestamp=" + timestamp + "]";
		}

	}

}
