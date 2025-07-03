/*

 AnBx Java Security Library

 Copyright 2011-2024 Paolo Modesti
 Copyright 2022 Remi Garcia
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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashSet;
import java.util.Map;
import java.security.SignedObject;
import java.util.Arrays;

import javax.crypto.SealedObject;

/**
 * AnB Protocol: an abstract class for defining AnB protocols
 * @param <R> roles class
 * @param <S> class steps
 */

public abstract class AnB_Protocol<S extends Enum<?>, R extends Enum<?>> {

	 /**
     * The layer for debugging purposes.
     */
    protected final static AnBx_Layers layer = AnBx_Layers.PROTOCOL;

    /**
     * The name of the protocol.
     */
    protected String name = null;

    /**
     * The path for sharing data in the protocol.
     */
    protected String sharepath = null;

    /**
     * The role of the protocol.
     */
    protected R role;

    /**
     * Mapping of aliases for protocol roles.
     */
    protected Map<String, String> aliases;

    /**
     * Mapping of session names to session instances.
     */
    protected Map<String, AnB_Session> lbs;

    /**
     * Number of sessions for the protocol.
     */
    protected static long sessions = 1;

    
	/**
     * Flag indicating whether to abort on a check failure.
     */
	
	private boolean abortOnFail = false;
	
    /**
     * Flag indicating whether to check anyway, even if the comparison types are different.
     */
	private boolean checkAnyway = false;
	
    /**
     * Enum to represent different types of checks.
     */
	
	private enum CheckType {
		EQ, INV, WFF, NOTEQ, SEEN;
	};

    /**
     * A byte array of zeros used in the protocol.
     */
	
	protected Crypto_ByteArray zero = new Crypto_ByteArray(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });

	
	
    /**
     * Default constructor
     */
    
	public AnB_Protocol() {
        super();
    }
	
	
	/**
	 * Runs the protocol with the given maps of sessions and aliases.
	 *
	 * @param lbs     Mapping of session names to session instances.
	 * @param aliases Mapping of aliases for protocol roles.
	 */
	
	public void run(Map<String, AnB_Session> lbs, Map<String, String> aliases) {
		run(lbs,aliases, 1);
	}
		
	/**
	 * Abstract method to run the AnB protocol.
	 * 
	 * @param lbs      The map of session IDs to AnB sessions.
	 * @param aliases  The map of role names to their corresponding aliases.
	 * @param sessions The number of sessions for the protocol.
	 */
	
	abstract public void run(Map<String, AnB_Session> lbs, Map<String, String> aliases, long sessions);
	// specifies if the protocol should loop or number of sessions

	/**
	 * Abstract method to execute a step in the AnB protocol.
	 * 
	 * @param lbs  The AnB session for the role.
	 * @param step The step to execute.
	 */
	
	abstract protected void executeStep(AnB_Session lbs, S step);
	// abstract protected void executeStep(AnB_Session lbs1, AnB_Session lbs2, S
	// step);

	/**
	 * Abstract method to initialise the AnB protocol.
	 */
	
	abstract protected void init();


	/**
	 * Get the value of abortOnFail.
	 * 
	 * @return true if the protocol should abort on failure, false otherwise.
	 */
	
	protected boolean isAbortOnFail() {
		return abortOnFail;
	}

	/**
	 * Set the value of abortOnFail.
	 * 
	 * @param abortOnFail The value to set for abortOnFail.
	 */
	protected void setAbortOnFail(boolean abortOnFail) {
		this.abortOnFail = abortOnFail;
	}
	
	/**
	 * Return the value of checkAnyway
	 * @return the checkAnyway
	 */
	protected boolean isCheckAnyway() {
		return checkAnyway;
	}

	/**
	 * Set the value of checkAnyway.
	 * 
	 * @param checkAnyway The value to set for checkAnyway.
	 */
	
	protected void setCheckAnyway(boolean checkAnyway) {
		this.checkAnyway = checkAnyway;
	}
	
	/**
	 * Abort the protocol with a specified error message
	 * 
	 * @param msg       The error message.
	 */

	protected void abort(String msg) {
		abort(msg, null,1);
	}
	

	/**
	 * Abort the protocol with a specified error message, exception, and session ID.
	 * 
	 * @param msg       The error message.
	 * @param e         The exception (can be null).
	 * @param sessionID The session ID.
	 */

	protected void abort(String msg, Exception e, long sessionID) {
		AnBx_Debug.out(AnBx_Layers.ALWAYS, " ----------------- Protocol Error ------------------- ");
		AnBx_Debug.out(AnBx_Layers.ALWAYS, "Protocol: " + name);
		AnBx_Debug.out(AnBx_Layers.ALWAYS, "Session: " + sessionID + "/" + sessions);
		AnBx_Debug.out(AnBx_Layers.ALWAYS, "Error: " + msg);
		if (e != null) {
			AnBx_Debug.out(AnBx_Layers.ALWAYS, "Error description: " + e.toString());
			e.printStackTrace();
		}
		if (abortOnFail || sessionID >= sessions) { 
				AnBx_Debug.out(AnBx_Layers.ALWAYS, "The program will now terminate!");
				AnBx_Debug.out(AnBx_Layers.ALWAYS, " ----------------- Protocol Error ------------------- ");
				System.exit(1);
		} else {
			AnBx_Debug.out(AnBx_Layers.ALWAYS, " ----------------- Protocol Error ------------------- ");
			AnBx_Debug.out(AnBx_Layers.ALWAYS, "The program will now restart!");
			for (AnB_Session s : lbs.values()) {
			s.Close();
			}
		if (!abortOnFail) run(lbs, aliases, sessions);		// restart another session
		}
	}
	
	/**
	 * Get the alias for the current role.
	 * 
	 * @return The alias for the current role.
	 */
	
	protected String getAlias() {
		return aliases.get(role.toString()).toString();
	}
	// -------------------------- INV CHECK ---------------------------

	// w label

	/**
	 * Perform an inverse check with a label for two objects.
	 * 
	 * @param label The label for the check.
	 * @param obj1  The first object.
	 * @param obj2  The second object.
	 * @return True if the check is successful, false otherwise.
	 */
	
	protected boolean invCheck(String label, Object obj1, Object obj2) {
		statusLabel(label);
		return invCheck(obj1, obj2);
	}

	/**
	 * Perform an inverse check with a label for an object and a class.
	 * 
	 * @param label The label for the check.
	 * @param obj   The object.
	 * @param cls   The class to check against.
	 * @return True if the check is successful, false otherwise.
	 */
	
	protected boolean invCheck(String label, Object obj, Class<?> cls) {
		statusLabel(label);
		return invCheck(obj, cls);
	}

	
	/**
	 * Perform an inverse check with a label for a single object.
	 * 
	 * @param label The label for the check.
	 * @param obj   The object.
	 * @return True if the check is successful, false otherwise.
	 */
	
	protected boolean invCheck(String label, Object obj) {
		statusLabel(label);
		return invCheck(obj);
	}

	// w/o label
	
	
	/**
	 * Perform an inverse check without a label for two objects.
	 * 
	 * @param obj1 The first object.
	 * @param obj2 The second object.
	 * @return True if the check is successful, false otherwise.
	 */
	
	protected boolean invCheck(Object obj1, Object obj2) {

		String t1 = obj1.getClass().getName().toString();
		String t2 = obj2.getClass().getName().toString();
		AnBx_Debug.out(layer, CheckType.INV.toString() + " check NOT PERFORMED on obj1: " + t1 + " - obj2: " + t2);
		// checkFailed(obj1, obj2, CheckType.INV);

		// TO DO !!!
		// inv(obj1,obj2) -> dec(enc(<obj1,obj2>,obj1),obj2)
		return true;

	}
	
	/**
	 * Perform an inverse check without a label for an object and a class.
	 * 
	 * @param obj The object.
	 * @param cls The class to check against.
	 * @return True if the check is successful, false otherwise.
	 */

	protected boolean invCheck(Object obj, Class<?> cls) {
		String t1 = obj.getClass().getName().toString();
		AnBx_Debug.out(layer, CheckType.INV.toString() + " check PERFORMED on " + t1);
		if (cls.isInstance(obj)) {
			checkOK(obj, CheckType.INV);
			return true;
		} else {
			checkFailed(obj, CheckType.INV);
			return false;
		}
	}
	
	/**
	 * Perform an inverse check without a label for a single object.
	 * 
	 * @param obj The object.
	 * @return True if the check is successful, false otherwise.
	 */

	protected boolean invCheck(Object obj) {
		// OK if can be computed w/o errors
		try {
			String t = obj.getClass().getName().toString();
			AnBx_Debug.out(layer, CheckType.INV.toString() + " check PERFORMED on " + t);
			checkOK(obj, CheckType.INV);
			return true;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			checkFailed(obj, CheckType.INV);
			e.printStackTrace();
			return false;
		}
	}

	// -------------------------- WFF CHECK ---------------------------

	// w label

	/**
	 * Checks if the given object is a well-formed formula (WFF) with a specified label.
	 *
	 * @param label the label for the check
	 * @param obj the object to be checked
	 * @return true if the object is a well-formed formula, false otherwise
	 */
	protected boolean wffCheck(String label, Object obj) {
	    statusLabel(label);
	    return wffCheck(obj);
	}

	/**
	 * Checks if the given object is a well-formed formula (WFF) with a specified label and class type.
	 *
	 * @param label the label for the check
	 * @param obj the object to be checked
	 * @param cls the expected class type for the object
	 * @return true if the object is a well-formed formula, false otherwise
	 */
	protected boolean wffCheck(String label, Object obj, Class<?> cls) {
	    statusLabel(label);
	    return wffCheck(obj, cls);
	}

	// w/o label
	
	/**
	 * Checks if the given object is a well-formed formula (WFF) without a specific label.
	 *
	 * @param obj the object to be checked
	 * @return true if the object is a well-formed formula, false otherwise
	 */
	protected boolean wffCheck(Object obj) {
	    return invCheck(obj); // well-formed => can be computed w/o errors
	}

	/**
	 * Checks if the given object is a well-formed formula (WFF) with a specified class type.
	 *
	 * @param obj the object to be checked
	 * @param cls the expected class type for the object
	 * @return true if the object is a well-formed formula, false otherwise
	 */
	protected boolean wffCheck(Object obj, Class<?> cls) {
	    return invCheck(obj, cls); // well-formed => can be computed w/o errors
	}


	// -------------------------- WFF CHECK ---------------------------

	// -------------------------- NOTEQ CHECK ---------------------------

	/**
	 * Checks if two objects are not equal with a specified label.
	 *
	 * @param label the label for the check
	 * @param obj1 the first object to be compared
	 * @param obj2 the second object to be compared
	 * @return true if the objects are not equal, false otherwise
	 */
	protected boolean noteqCheck(String label, Object obj1, Object obj2) {
	    statusLabel(label);
	    return noteqCheck(obj1, obj2);
	}

	/**
	 * Checks if two objects are not equal without a specific label.
	 *
	 * @param obj1 the first object to be compared
	 * @param obj2 the second object to be compared
	 * @return true if the objects are not equal, false otherwise
	 */
	protected boolean noteqCheck(Object obj1, Object obj2) {
	    // String t1 = obj1.getClass().getName().toString();
	    // String t2 = obj2.getClass().getName().toString();
	    // AnBx_Debug.out(layer, CheckType.NOTEQ.toString() + " check NOT
	    // PERFORMED on obj1: " + t1 + " - obj2: " + t2);
	    if ((obj2).equals(obj1)) {
	        checkFailed(obj1, obj2, CheckType.NOTEQ);
	        return true;
	    } else {
	        checkOK(obj1, obj2, CheckType.NOTEQ);
	        return false;
	    }
	}

	// -------------------------- NOTEQ CHECK ---------------------------

	// -------------------------- EQ CHECK ---------------------------

	// w label

	
	/**
	 * Checks if two objects are equal with a specified label.
	 *
	 * @param label the label for the check
	 * @param obj1 the first object to be compared
	 * @param obj2 the second object to be compared
	 * @return true if the objects are equal, false otherwise
	 */
	
	protected boolean eqCheck(String label, Object obj1, Object obj2) {
		statusLabel(label);
		return eqCheck(obj1, obj2);
	}
	
	/**
	 * Checks if two objects are equal with a specified label and a flag indicating possible failure.
	 *
	 * @param label the label for the check
	 * @param obj1 the first object to be compared
	 * @param obj2 the second object to be compared
	 * @param mayfail flag indicating whether the check may fail
	 * @return true if the objects are equal, false otherwise
	 */

	protected boolean eqCheck(String label, Object obj1, Object obj2, boolean mayfail) {
		statusLabel(label);
		return eqCheck(obj1, obj2, mayfail);
	}

	// w/o label
	
	/**
	 * Checks if two objects are equal without a specific label.
	 *
	 * @param obj1 the first object to be compared
	 * @param obj2 the second object to be compared
	 * @return true if the objects are equal, false otherwise
	 */

	protected boolean eqCheck(Object obj1, Object obj2) {
		String t1 = obj1.getClass().getName().toString();
		String t2 = obj2.getClass().getName().toString();

		if (t1 != t2) {
			// types are different!
			checkFailed(obj1, obj2, CheckType.EQ);
			return false;
		} else if (obj1 instanceof SignedObject && obj2 instanceof SignedObject) {
			SignedObject sobj1 = (SignedObject) obj1;
			SignedObject sobj2 = (SignedObject) obj2;
			boolean check = true;
			try {
				check = sobj1.getAlgorithm().equals(sobj2.getAlgorithm()) && Arrays.equals(sobj1.getSignature(), sobj2.getSignature())
						&& eqCheck(sobj1.getObject(), sobj2.getObject());
			} catch (ClassNotFoundException | IOException e) {
				e.printStackTrace();
			}
			AnBx_Debug.out(layer, CheckType.EQ.toString() + " check PERFORMED on " + t1);
			if (check)
				checkOK(obj1, obj2, CheckType.EQ);
			else
				checkFailed(obj1, obj2, CheckType.EQ);
			return check;
		} else if (obj1 instanceof Crypto_SealedPair && obj2 instanceof Crypto_SealedPair) {
			// Crypto_SealedPair cannot be compared due to the key randomiser
			AnBx_Debug.out(layer, CheckType.EQ.toString() + " check NOT PERFORMED - cannot compare object of type " + t1 + " - " + obj1.toString() + " ?= " + obj2.toString());
			if (checkAnyway) {
				AnBx_Debug.out(layer, "EQ check -  attempting check anyway on " + t1);
				return eqCheckTest(obj1, obj2);
			} else
				return false;
		} else if (obj1 instanceof SealedObject && obj2 instanceof SealedObject) {
			// SealedObject cannot be compared due to the key randomiser
			AnBx_Debug.out(layer, CheckType.EQ.toString() + " check NOT PERFORMED - cannot compare object of type " + t1 + " - " + obj1.toString() + " ?= " + obj2.toString());
			if (checkAnyway) {
				AnBx_Debug.out(layer, "EQ check -  attempting check anyway on " + t1);
				return eqCheckTest(obj1, obj2);
			} else
				return false;
		} else if (obj1 instanceof AnBx_Params && obj2 instanceof AnBx_Params) {
			// AnBx_Params eqCheck
			AnBx_Params vobj1 = (AnBx_Params) obj1;
			AnBx_Params vobj2 = (AnBx_Params) obj2;
			if (vobj1.size() == vobj1.size()) {
				int i;
				boolean check = true;
				for (i = 0; i < vobj1.size(); i++) {
					AnBx_Debug.out(layer, CheckType.EQ.toString() + " check - checking component [" + i + "]");
					if (!eqCheck(vobj1.getValue(i), vobj1.getValue(i)))
						check = false;
				}
				AnBx_Debug.out(layer, CheckType.EQ.toString() + " check - end components check");
				if (check)
					checkOK(obj1, obj2, CheckType.EQ);
				else
					checkFailed(obj1, obj2, CheckType.EQ);
				return check;
			} else {
				AnBx_Debug.out(layer, CheckType.EQ.toString() + " check FAILED! - arity is different obj1: " + vobj1.size() + " != obj2: + " + vobj2.size());
				checkFailed(obj1, obj2, CheckType.EQ);
				return false;
			}
		} else {
			// default check
			AnBx_Debug.out(layer, CheckType.EQ.toString() + " check PERFORMED on " + t1);
			return eqCheckTest(obj1, obj2);
		}
	}


	/**
	 * Checks if two objects are equal with a flag indicating possible failure.
	 *
	 * @param obj1 the first object to be compared
	 * @param obj2 the second object to be compared
	 * @param mayfail flag indicating whether the check may fail
	 * @return true if the objects are equal, false otherwise
	 */
	
	protected boolean eqCheck(Object obj1, Object obj2, boolean mayfail) {
		String t1 = obj1.getClass().getName().toString();
		String t2 = obj2.getClass().getName().toString();
		if (t1 == t2 && mayfail)
			AnBx_Debug.out(layer, CheckType.EQ.toString() + " check MAY FAIL comparing objects of type " + t1);
		return eqCheck(obj1, obj2);
	}
	
	/**
	 * Internal method for testing equality between two objects.
	 *
	 * @param obj1 the first object to be compared
	 * @param obj2 the second object to be compared
	 * @return true if the objects are equal, false otherwise
	 */
	
	private boolean eqCheckTest(Object obj1, Object obj2) {
		if ((obj2).equals(obj1)) {
			checkOK(obj1, obj2, CheckType.EQ);
			return true;
		} else {
			checkFailed(obj1, obj2, CheckType.EQ);
			return false;
		}
	}

	// -------------------------- EQ CHECK ---------------------------

	// -------------------------- EQ SEEN ---------------------------

	/**
	 * Performs a "seen" check on the specified object.
	 *
	 * @param obj the object to be checked
	 * @return true if the object has been seen before, false otherwise
	 */
	
	@SuppressWarnings("unchecked")
	private boolean seenCheck(Object obj) {

		final String filename = "SeqNumbers_" + getAlias() + ".ser";
		HashSet<Object> seqnumbers = null;

		File f = new File(filename);
		if (f.exists() && !f.isDirectory()) {
			ObjectInputStream ois;
			AnBx_Debug.out(layer, filename + " exists");
			try {
				AnBx_Debug.out(layer, "Extract sequence numbers from " + filename);
				ois = new ObjectInputStream(new FileInputStream(filename));
				seqnumbers = (HashSet<Object>) ois.readObject();
			} catch (IOException | ClassNotFoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		} else {
			AnBx_Debug.out(layer, filename + " does not exist");
			seqnumbers = new HashSet<Object>();
			AnBx_Debug.out(layer, "New sequence number HashSet - " + seqnumbers.toString());
		}

		if (seqnumbers.contains(obj)) {
			AnBx_Debug.out(layer, "obj: " + obj.toString());
			AnBx_Debug.out(layer, "seqnumers: " + seqnumbers.toString());
			return true;
		} else {
			seqnumbers.add(obj);
			// save serialised set
			ObjectOutputStream oos = null;
			try {
				oos = new ObjectOutputStream(new FileOutputStream(filename));
				oos.writeObject(seqnumbers);
				oos.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return false;
			}
		}
		return false;
	}
	
	/**
	 * Checks if the specified object has been seen with a given label.
	 *
	 * @param label the label for the check
	 * @param obj the object to be checked
	 * @return true if the object has been seen before, false otherwise
	 */

	protected boolean seen(String label, Object obj) {
		statusLabel(label);
		return seen(obj);
	}

	/**
	 * Checks if the specified object has been seen.
	 *
	 * @param obj the object to be checked
	 * @return true if the object has been seen before, false otherwise
	 */	
	
	protected boolean seen(Object obj) {

		String t = obj.getClass().getName().toString();
		AnBx_Debug.out(layer, CheckType.SEEN.toString() + " check PERFORMED on " + t);
		if (seenCheck(obj)) {
			checkFailed(obj, CheckType.SEEN);
			return false;
		} else {
			checkOK(obj, CheckType.SEEN);
			return true;
		}
	}

	// -------------------------- EQ SEEN ---------------------------

	// -------------------------- COMMON CHECK METHODS
	// ---------------------------

	/**
	 * Handles the case when a check fails between two objects of different types.
	 *
	 * @param obj1 the first object for comparison
	 * @param obj2 the second object for comparison
	 * @param ck   the type of check that failed
	 */
	
	private void checkFailed(Object obj1, Object obj2, CheckType ck) {
		if (abortOnFail) {
			abort(ck.toString() + " check failed: " + obj1.toString() + " != " + obj2.toString());
		} else {
			AnBx_Debug.out(layer, ck.toString() + " check FAILED! - " + obj1.getClass().getName().toString() + ".toString - " + obj1.toString() + " != " + obj2.toString());
			AnBx_Debug.out(layer, ck.toString() + " check FAILED! - " + obj1.getClass().getName().toString() + ".hashCode - " + obj1.hashCode() + " != " + obj2.hashCode());
		}
	}
	
	/**
	 * Handles the case when a check fails for a single object.
	 *
	 * @param obj the object for which the check failed
	 * @param ck  the type of check that failed
	 */
	
	private void checkFailed(Object obj, CheckType ck) {
		if (abortOnFail) {
			abort(ck.toString() + " check failed: " + obj.toString());
		} else {
			String msg = ck.toString() + " check FAILED!";
			AnBx_Debug.out(layer, msg + " - " + obj.getClass().getName().toString() + ".toString - " + obj.toString());
			AnBx_Debug.out(layer, msg + " - " + obj.getClass().getName().toString() + ".hashCode - " + obj.hashCode());
		}
	}

	
	/**
	 * Handles the case when a check is successful for a single object.
	 *
	 * @param obj the object for which the check is successful
	 * @param ck  the type of check that is successful
	 */
	
	private void checkOK(Object obj, CheckType ck) {
		AnBx_Debug.out(layer, ck.toString() + " check OK - " + obj.getClass().getName().toString() + ".toString - " + obj.toString());
		AnBx_Debug.out(layer, ck.toString() + " check OK - " + obj.getClass().getName().toString() + ".hashCode - " + obj.hashCode());
	}


	/**
	 * Handles the case when a check is successful between two objects.
	 *
	 * @param obj1 the first object for comparison
	 * @param obj2 the second object for comparison
	 * @param ck   the type of check that is successful
	 */

	private void checkOK(Object obj1, Object obj2, CheckType ck) {
		String compStr;
		if (ck == CheckType.NOTEQ)
			compStr = " != ";
		else
			compStr = " = ";
		AnBx_Debug.out(layer, ck.toString() + " check OK - " + obj1.getClass().getName().toString() + ".toString - " + obj1.toString() + compStr + obj2.toString());
		AnBx_Debug.out(layer, ck.toString() + " check OK - " + obj1.getClass().getName().toString() + ".hashCode - " + obj1.hashCode() + compStr + obj2.hashCode());
	}
	
	/**
	 * Outputs the status of the protocol with a specific step.
	 *
	 * @param step the step in the protocol
	 */

	protected void status(S step) {
		AnBx_Debug.out(layer, name + " - " + role.toString() + " - " + step.toString());
		AnBx_Debug.out(layer, this.toString());
	}

	/**
	 * Outputs the status label for a check with a given label.
	 *
	 * @param label the label for the check
	 */
	
	protected void statusLabel(String label) {
		AnBx_Debug.out(layer, "CHECK # " + label);
	}

	/**
	 * Outputs the status of the protocol with a specific step and payload.
	 *
	 * @param step    the step in the protocol
	 * @param payload the payload associated with the step
	 */
	
	protected void status(S step, Object payload) {
		status(step);
		if (payload != null) {
			AnBx_Debug.out(layer, "Payload: " + payload.toString());
		}
	}

}