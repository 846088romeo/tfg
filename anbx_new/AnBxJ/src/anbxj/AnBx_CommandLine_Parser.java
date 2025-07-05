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
import java.io.InputStream;
import java.util.Map;
import java.util.Properties;

/**
 * An abstract class for parsing command line arguments.
 *
 * @param <R> The type of role enumeration.
 * @param <C> The type of channels enumerators.
 */
public abstract class AnBx_CommandLine_Parser<R extends Enum<?>, C extends Enum<?>> {

    /**
     * Default SSL channel type, overridden by command line parameters.
     */
    protected static Channel_SSLChannelType ct = Channel_SSLChannelType.SSL_NONE;

    /**
     * The layer for the application.
     */
    protected AnBx_Layers layer = AnBx_Layers.APPLICATION;

    /**
     * Path to the key file, set via command line parameters.
     */
    protected static String keypath = null;

    /**
     * Path to the shared resources, set via command line parameters.
     */
    protected static String sharepath = null;

    /**
     * Alias for identification, set via command line parameters.
     */
    protected static String myAlias = null;

    /**
     * Configuration for cryptography, set via command line parameters.
     */
    protected static Crypto_Config crypto_config = null;

    /**
     * Role enumeration, set via command line parameters.
     */
    protected R role = null;

    /**
     * Configuration file, set via command line parameters.
     */
    protected static Properties configFile = null;

    /**
     * Name of the configuration file.
     */
    private static String configFileName = "";

    /**
     * Name of the protocol, set via command line parameters.
     */
    protected static String protname = "";

    /**
     * Flag indicating whether to parse full arguments (true for standard program, false for setup program).
     */
    private static boolean parseFullArgs = true;

    /**
     * Number of sessions for the protocol run, set via command line parameters.
     */
    protected static long sessions = 1;

    /**
     * Verbose flag, set via command line parameters.
     */
    protected static boolean vflag = true;

    /**
     * Error message for the number of sessions.
     */
    private static String errNumSessions = "jsessions number must be an integer > 0; use -1 to loop forever";

	/**
	 * Create a AnBx_CommandLine_Parser
	 * 
	 * @param args the command line arguments
	 * @param roles the protocol roles enumerator
	 * @param prot the protocol name
	 * @param configName the name of the config file
	 * @param vflag true = verbose mode, false = silent mode
	 */

	public AnBx_CommandLine_Parser(String[] args, String prot, String configName, Class<R> roles, boolean vflag) {
		this(args, prot, configName, roles, vflag, parseFullArgs);
	}

	/**
	 * Create a AnBx_CommandLine_Parser
	 * 
	 * @param args the command line arguments
	 * @param prot the protocol name
	 * @param configName the name of the config file
	 * @param roles the protocol roles enumerator
	 * @param vflag true = verbose mode, false = silent mode
	 * @param parseFullArgs true = parsing a standard application (all arguments
	 * accepted), false = parsing a setup application (fewer arguments accepted)
	 */

	public AnBx_CommandLine_Parser(String[] args, String prot, String configName, Class<R> roles, boolean vflag, boolean parseFullArgs) {

		// initial verbose mode, can be overridden by command line parameters
		AnBx_CommandLine_Parser.vflag = vflag;
		AnBx_CommandLine_Parser.parseFullArgs = parseFullArgs;
		protname = prot;
		configFileName = configName + ".properties";
		
		AnBx_Debug.setAppname(protname);
		AnBx_Debug.out(layer, "Parsing command line arguments");

		ParseArgs(args, roles);
		// as soon as the role is set use it as appname
		if (role != null) AnBx_Debug.setAppname(role.toString());
		
		AnBx_Debug.setALL(AnBx_CommandLine_Parser.vflag); // set default verbose mode
		configFile = getConfigFile();
	}

	/**
	 * Set the debug level
	 * 
	 * @param layer the debugging layer
	 * @see AnBx_Layers
	 */

	protected void setLayer(AnBx_Layers layer) {
		this.layer = layer;
	}

	/**
	 * Computes the usage string for the given protocol
	 * 
	 * @return the usage string
	 * 
	 */

	public static String usage() {

		String usageMsgbase = "java " + protname.toLowerCase() + "." + protname;
		String usageWord = "USAGE: ";

		String usageMsg = usageWord + usageMsgbase;
		if (parseFullArgs)
			usageMsg = usageMsg + " -r <ROLE_x> [-jsessions <NUM>]";
		usageMsg = usageMsg + " [-verbose] [-silent] [-f configfilename]";
		usageMsg = usageMsg + "\n       " + usageMsgbase + " -info";

		return usageMsg;
	}

	/**
	 * Parses the arguments
	 * 
	 * @param args the command line arguments
	 * @roles the protocol roles enumerator
	 * 
	 */

	private void ParseArgs(String[] args, Class<R> roles) {

		int i = 0;
		int validArgs = 0;
		String arg = null;

		while (i < args.length && args[i].startsWith("-")) {
			arg = args[i++];

			// check for "wordy" arguments

			if (arg.equals("-info")) {
				if (args.length == 1) {
					// if info about provider and algorithms are requested
					// ignores all other parameters, displays the info and
					// terminates
					AnBx_Debug.setALL(true);
					Crypto_EncryptionEngine.getInfo();
					System.exit(0);
				} else
					terminate("-info can be used only as a single parameter");

			}

			if (arg.equals("-verbose")) {
				AnBx_CommandLine_Parser.vflag = true;
				validArgs++; 
			}
			if (arg.equals("-silent")) {
				AnBx_CommandLine_Parser.vflag = false;
				validArgs++;
			}
			// check for arguments that require parameters
			if (arg.equals("-f")) {
				validArgs++;
				if (i < args.length) {
					configFileName = new String(args[i]);
					i++;
					validArgs++;
				} else
					terminate("config file not specified");
			}
			if (parseFullArgs) { // applicable to full programs, not setup
									// programs

				if (arg.equals("-jsessions")) {
					validArgs++;
					if (i < args.length) {
						try {
							sessions = Long.parseLong(args[i]);
							if (sessions == 0 || sessions < -1)
								terminate(errNumSessions);
						} catch (NumberFormatException e) {
							terminate(errNumSessions);
						}
						i++;
						validArgs++;
					} else
						terminate(errNumSessions);
				}

				if (arg.equals("-r")) {
					validArgs++;
					if (i < args.length) {
						for (R peer : roles.getEnumConstants()) {
							if (args[i].equalsIgnoreCase(peer.toString()))
								{
								role = peer;
								validArgs++;
								}
						}
						i++;
					}
				}
				// role is a mandatory parameter when running full arguments
				if (role == null)
					terminate("no or incorrect role specified");
			}
		}
		// System.out.println("i: " + i);
		// System.out.println("validArgs: " + validArgs);
		// System.out.println("args: " + args.length);
		// there is at least an unprocessed parameter
		if (validArgs != args.length)
			terminate("there is at least one unrecognised parameter",args);
		if (vflag)
			AnBx_Debug.out(AnBx_Layers.ALWAYS, "Verbose mode on");
		else
			AnBx_Debug.out(AnBx_Layers.ALWAYS, "Silent mode on");
	}

	/**
	 * Initialise the protocol
	 * 
	 */

	protected abstract void initProtocol();

	/**
	 * Terminates the protocol after an error occurs and prints a message
	 * 
	 * @param msg the error message to be printed
	 * 
	 */

	protected static void terminate(String msg) {
		System.err.println(protname + ": " + msg);
		System.err.println(usage());
		System.err.println("\n");
		System.exit(0);
	}
	
	/**
	 * Terminates the protocol after an error occurs and prints a message along with the arguments passed.
	 *
	 * @param msg  The error message to be printed.
	 * @param args The array of arguments to be included in the error message.
	 */
	
	
	protected static void terminate(String msg, String[] args) {
        String argsStr = " in args: ";
		for (String arg : args) {
			argsStr += arg + " ";
	  }
		terminate(msg + argsStr);
	}
	

	/**
	 * Get the role name
	 * 
	 * @return the role name
	 * 
	 */

	public String getRole() {
		if (role != null)
			return role.toString();
		else
			return null;
	}

	/**
	 * Get the sender role in a channel
	 * 
	 * @param channel the specified channel
	 * @param role the specified role
	 *
	 * @return true if R is the first role in channel C
	 * 
	 */

	protected boolean isFirstRole(C channel, R role) {
		final String CHANNEL_SUFFIX = "_channel_";

		String chName = channel.toString();
		String roleName = role.toString();
		String firstRole = chName.split(CHANNEL_SUFFIX)[0].trim();

		return firstRole.equals(roleName);

	}

	/**
	 * Gets the role used to share information during the protocol setup
	 * 
	 * @param roles the protocol roles enumerator
	 * 
	 * @return the role used to share information prior protocol run
	 * 
	 */

	protected R getRoleShare(Class<R> roles) {
		R role = null;
		String roleshare = configFile.getProperty("ROLESHARE");
		for (R peer : roles.getEnumConstants()) {
			if (peer.toString().equals(roleshare)) {
				role = peer;
				AnBx_Debug.out(layer, "RoleShare: " + role.toString());
			}
		}
		return role;
	}

	/**
	 * Loads the properties from the config file
	 * 
	 * @return the properties object read from the config file
	 * 
	 */

	protected Properties getConfigFile() {

		// Read properties file
		AnBx_Debug.out(layer, "Reading config file: " + configFileName.toString());

		InputStream propertiesStream = null;
		propertiesStream = this.getClass().getResourceAsStream(configFileName);

		if (propertiesStream != null) {
			try {
				configFile = new Properties();
				configFile.load(propertiesStream);
				crypto_config = new Crypto_Config(configFile);
				propertiesStream.close();
			} catch (IOException e) {
				terminate("Error reading config file: " + configFileName);
			}
		} else {
			// Properties file not found!
			terminate("Config file not found: " + configFileName);
		}
		return configFile;
	}

	/**
	 * Reads the properties from the config file
	 * 
	 * @param aliases mapping channel names to channel settings
	 * @param roles the protocol roles enumerator
	 * @param role the protocol role
	 *
	 */

	protected void readConfigFile(Map<String, String> aliases, Class<R> roles, R role) {

		keypath = configFile.getProperty("keypath");
		sharepath = configFile.getProperty("sharepath");

		if (configFile.getProperty(role.toString()) == null)
			terminate("Cannot find entry for: " + role.toString());
		else {
			AnBx_Debug.out(layer, "Loading aliases");

			String keys = configFile.getProperty(role.toString());
			String[] aliasesArray = keys.split(",");
			if (aliasesArray.length == roles.getEnumConstants().length) {
				for (R peer : roles.getEnumConstants()) {
					aliases.put(peer.toString(), aliasesArray[peer.ordinal()]);
					AnBx_Debug.out(layer, "Role: " + peer.toString() + " - Alias: " + aliasesArray[peer.ordinal()]);
					if (peer.toString().equals(role.toString())) {
						myAlias = aliasesArray[peer.ordinal()];
						AnBx_Debug.out(layer, "myAlias: " + myAlias);
					}
				}
			} else {
				terminate("Incongruent roles/aliases number. Roles expected: " + roles.getEnumConstants().length + " Aliases found: " + aliasesArray.length);

			}
		}
	}

	/**
	 * Initialise the role
	 * 
	 * @param ct the channel type
	 * @param role the protocol role
	 * @param cs mapping channel names to channel settings
	 * @param aliases mapping role names with aliases (identifies)
	 * @param roles the protocol roles enumerator
	 * @param channels the protocol channels enumerator
	 * 
	 */

	protected void initRole(Channel_SSLChannelType ct, R role, Map<String, Channel_Settings> cs, Map<String, String> aliases, Class<R> roles, Class<C> channels) {

		final String HOST_SUFFIX = "_host";
		final String ROLE_SUFFIX = "_role";
		final String PORT_SUFFIX = "_port";
		final String TYPE_SUFFIX = "_type";
		
		final String SSL_CONTEXT_KEY = "sslContext";

		readConfigFile(aliases, roles, role);

		String ch = new String();

		for (R peer : roles.getEnumConstants()) {
			for (C channel : channels.getEnumConstants()) {

				if (peer.equals(role) && isFirstRole(channel, role)) {
					ch = channel.toString();
					String host = configFile.getProperty(ch + HOST_SUFFIX);
					if (host != null) {
						int port = 0;
						try {
							port = Integer.parseInt(configFile.getProperty(ch + PORT_SUFFIX));
						} catch (NumberFormatException e) {
							terminate("NumberFormatException at " + ch + PORT_SUFFIX + ":" + configFile.getProperty(ch + PORT_SUFFIX));
						}
						if (configFile.getProperty(ch + TYPE_SUFFIX) != null) {
							ct = Channel_SSLChannelType.String2ChannelType(configFile.getProperty(ch + TYPE_SUFFIX));
							if (ct == Channel_SSLChannelType.SSL_NONE)
								terminate(ch + TYPE_SUFFIX + ": wrong channel mode specified" + "\n" + Channel_SSLChannelType.getInfo());
						} else
							terminate(ch + TYPE_SUFFIX + ": channel mode not specified");

						Channel_Settings chs;

						if (configFile.getProperty(ch + ROLE_SUFFIX).equalsIgnoreCase(Channel_Roles.CLIENT.toString())) {
							chs = new Channel_Settings(ct, Channel_Roles.CLIENT, host, port, configFile.getProperty(SSL_CONTEXT_KEY));
							cs.put(ch, chs);
							AnBx_Debug.out(layer, "Channel: " + ch);
						} else if (configFile.getProperty(ch + ROLE_SUFFIX).equalsIgnoreCase(Channel_Roles.SERVER.toString())) {
							chs = new Channel_Settings(ct, Channel_Roles.SERVER, host, port, configFile.getProperty(SSL_CONTEXT_KEY));
							cs.put(ch, chs);
							AnBx_Debug.out(layer, "Channel: " + ch);
						} else
							terminate("Incorrect channel role specified for " + ch + ROLE_SUFFIX + "\n" + "Possible channel roles are " + Channel_Roles.CLIENT.toString() + " or "
									+ Channel_Roles.SERVER.toString());
					}
				}
			}
		}

	}
}
