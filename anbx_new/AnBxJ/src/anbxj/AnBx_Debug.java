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
 * AnBx Debug/Logging utility
 */

public class AnBx_Debug {

	static String appname = "appname";
	static boolean NETWORK = false;
	static boolean ENCRYPTION = false;
	static boolean LANGUAGE = false;
	static boolean SESSION = false;
	static boolean PROTOCOL = false;
	static boolean BUSINESS_LOGIC = false;
	static boolean APPLICATION = false;
	static boolean ALWAYS = true;
	static boolean EXCEPTION = false;

	
	/**
	 * Default constructor
	 */

	
	public AnBx_Debug ()
			{
				super();
			}
	
	/**
	 * Print a debug message related to an object based on the debug level set and the current layer
	 * @param layer the current layer
	 * @param obj the object
	 */
	
	public static void out(AnBx_Layers layer, Object obj) {
		boolean toPrint = false;

		switch (layer) {
		case NETWORK:
			if (NETWORK)
				toPrint = true;
			break;
		case ENCRYPTION:
			if (ENCRYPTION)
				toPrint = true;
			break;
		case LANGUAGE:
			if (LANGUAGE)
				toPrint = true;
			break;
		case SESSION:
			if (SESSION)
				toPrint = true;
			break;
		case PROTOCOL:
			if (PROTOCOL)
				toPrint = true;
			break;
		case BUSINESS_LOGIC:
			if (BUSINESS_LOGIC)
				toPrint = true;
			break;
		case APPLICATION:
			if (APPLICATION)
				toPrint = true;
			break;
		case EXCEPTION:
			if (EXCEPTION)
				toPrint = true;
			break;
		case ALWAYS:
			if (ALWAYS)
				toPrint = true;
			break;
		}

		if (toPrint) {
			System.out.println("Debug [" + appname + "-" + layer.toString() + "] - " + obj.toString());
		}
	}
	
	/**
	 * Enable/disable all debug levels
	 * @param value (true/false)
	 */
	
	public static void setALL(boolean value) {
		NETWORK = value;
		ENCRYPTION = value;
		LANGUAGE = value;
		SESSION = value;
		PROTOCOL = value;
		BUSINESS_LOGIC = value;
		APPLICATION = value;
		ALWAYS = true;			// ALWAYS is not affected by this setting
		EXCEPTION = value;
	}
	
	/**
	 * Enable/disable individual debug level 
	 * @param application the APPLICATION to set (true/false) 
	 * @param business_logic the BUSINESS_LOGIC to set (true/false) 
	 * @param encryption the ENCRYPTION to set (true/false)
	 * @param exception the EXCEPTION to set (true/false)
	 * @param language the LANGUAGE to set (true/false)
	 * @param protocol the PROTOCOL to set (true/false)
	 * @param session the SESSION to set (true/false)
	 * @param network the NETWORK to set (true/false)
	 * @param always the ALWAYS to set (true/false)

	 */
	

	public static void setDebug(boolean network, boolean encryption, boolean language, boolean session, boolean protocol, boolean business_logic, boolean application,
			boolean always, boolean exception) {
		NETWORK = network;
		ENCRYPTION = encryption;
		LANGUAGE = language;
		SESSION = session;
		PROTOCOL = protocol;
		BUSINESS_LOGIC = business_logic;
		APPLICATION = application;
		ALWAYS = always;
		EXCEPTION = exception;
	}

	/**
	 * Enable/disable the APPLICATION  debug level
	 * @param application the APPLICATION to set (true/false) 
	 */

	public static void setAPPLICATION(boolean application) {
		APPLICATION = application;
	}

	/**
	 * Enable/disable the BUSINESS_LOGIC  debug level
	 * @param business_logic the BUSINESS_LOGIC to set (true/false) 
	 */
	public static void setBUSINESS_LOGIC(boolean business_logic) {
		BUSINESS_LOGIC = business_logic;
	}
	
	/**
	 * Enable/disable the ENCRYPTION debug level 
	 * @param encryption the ENCRYPTION to set (true/false)
	 */
	public static void setENCRYPTION(boolean encryption) {
		ENCRYPTION = encryption;
	}

	/**
	 * Enable/disable the EXCEPTION debug level
	 * @param exception the EXCEPTION to set (true/false)
	 */
	public static void setEXCEPTION(boolean exception) {
		EXCEPTION = exception;
	}

	/**
	 * set the LANGUAGE debug level
	 * @param language the LANGUAGE to set (true/false)
	 */
	public static void setLANGUAGE(boolean language) {
		LANGUAGE = language;
	}

	/**
	 * Enable/disable the NETWORK debug level
	 * @param network the NETWORK to set (true/false)
	 */
	public static void setNETWORK(boolean network) {
		NETWORK = network;
	}

	/**
	 * Enable/disable the PROTOCOL debug level
	 * @param protocol the PROTOCOL to set (true/false)
	 */
	public static void setPROTOCOL(boolean protocol) {
		PROTOCOL = protocol;
	}

	/**
	 * Enable/disable the SESSION debug level
	 * @param session the SESSION to set (true/false)
	 */
	public static void setSESSION(boolean session) {
		SESSION = session;
	}

	/**
	 * Retrieve the application name
	 * @return the appname
	 */
	public static String getAppname() {
		return appname;
	}

	/**
	 * Set the application name
	 * @param appname the appname to set
	 */
	public static void setAppname(String appname) {
		AnBx_Debug.appname = appname;
	}
}
