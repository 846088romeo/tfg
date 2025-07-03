--------------------------------
AnBx Compiler and Code Generator
--------------------------------
Lead author: Paolo Modesti
Contributor: Rémi Garcia
--------------------------------

This document contains a summary of the instructions required 
for building and running the AnBx Compiler and Code Generator
Full details are available at https://www.dais.unive.it/~modesti/anbx/

An Eclipse-based IDE for AnBx is available at 
https://www.dais.unive.it/~modesti/anbx/ide/

The software is distributed under the GNU GPLv3 licence

For any questions/comments, or to be notified 
of new releases, write to: p.modesti (at) tees.ac.uk

Have fun!

## Outline the distribution package
-----------------------------------

Contents - Sources and binaries:
- \AnBx2 -> AnBx compiler src, binary file, config-file
- \AnBxJ -> AnBxJ security library and src + Bouncy Castle .jar
- \casestudies -> AnB and AnBx protocols
- \ext-tools -> External tools (OFMC, ProVerif binaries)
- \genAnBx\src -> Generated Java source code
- \genAnBx\keystore -> Keystores (cryptographic keys)

## Basic usage
--------------

To generate the JAVA implementation

anbxc <filename> -out:Java

To generate the typed ProVerif specification
anbxc <filename> -out:PVT

for the untyped ProVerif use
anbxc <filename> -out:PV

N.B if the config file anbxc.cfg is in the same folder of executable,
there is no need to use the option -cfg: <configfilename>

## Requirements
---------------

Building the tools: GHC 9.4.8+ (See: https://www.haskell.org/)
Running the tools: JRE 11+ (e.g. adoptium.net / Temurin). JDK required to compile Java files.

The optional Bouncy Castle Library is required to support more ciphers and algorithms than the standard JDK supported ones.

## Permissions on Linux or Mac
---------------------------
On Mac and Linux you will likely need to set execution permissions to the three binary files: anbxc, ofmc and proverif.
This can be done with the command chmod u+x filename or with the OS GUI. 
On Mac, you may also need to authorise the execution of the binary files in System Preferences -> Security and Privacy, go to General tab and click Allow.

The bash script setexecpermissions.sh can simplify the process of setting such permissions.

## Running ProVerif on Linux 
---------------------------
If trying to run Proverif under Linux and you experience an error similar to this one:

proverif: /lib/x86_64-linux-gnu/libm.so.6: version `GLIBC_2.38' not found (required by proverif)

you may need to install the missing library. Run this command: sudo apt install libc6

The following document may be useful:
https://www.cyberithub.com/how-do-i-install-the-linux-library-libc-so-6-in-5-easy-steps/

## Java (Docker)
---------------------------
Executing generated Java code in a Docker distributed system requires Docker to be installed, and Docker Engine running.
Installing Docker Desktop is the simplest option:
https://docs.docker.com/get-docker/

On Linux systems, if "docker compose" command is not available, you may need to install the "docker-compose-plugin"
https://docs.docker.com/compose/install/linux/"

## Upgrade from a previous version
----------------------------------
It is recommended to rename the folder containing the old version and extract the new files on the same folder as the old one.
However, if the config file (anbxc.cfg) has been customised, some care is required.
In fact, new versions can introduce new fields as specified below. For the meaning of the fields see the comments in the anbxc.cfg file.
Moreover, the fields with customise values should be edited in the new config file to match the old configuration.
Make sure all files are up to date, including the library (AnBxJ.jar) and the template files (*.st).
Finally, if you use JavaDocker, it is advisable to rebuild the images, as the Dockerfile(s) may have been updated.

In particular:

From version 2024.05, new fields are introduced in  the config file (anbxc.cfg)

Docker Settings:
- dockerdyinterval

Cryptographic Engine Settings:
- keyagreementkeypairgenerationscheme
- ecgenparameterspec
- sslcontext
- securityprovider

From version 2023.10, new fields are introduced in the config file (anbxc.cfg)
to support distributed execution using Docker. 
If you want to preserve you old config file, copy the entries of section:
# -----------------------------
# Docker Settings
# -----------------------------
from the config file provided with the distribution package for this version.

From version 2023.05, a new field is introduced in the config file (anbxc.cfg) 

- pathofmcstdeqtheory

this entry should point to the OFMC standard theory (std.thy) or any other OFMC theory that the user wants to include in the 
custom generated theory file, which can be generated with the AnBxC target option -out:AnBEqTheory

From version 2022.10, two new fields are supported in the config file (anbxc.cfg)

- keyPairGenerationScheme
- keyPairGenerationSize 

They are used to specify the Asymmetric Encryption used for key pair dynamic generation (previously was "RSA",2048 hardcoded).
Moreover, comments are added to the config file to explain the meaning of all cryptography fields.
It is therefore, recommended to update the current config file with these fields and comments which are below these lines.
# -----------------------------
# Cryptographic Engine settings
# -----------------------------

In order to work, make sure you are using the AnBxJ.jar file distributed in AnBx 2022.10 or later.

From version 2022.09, the way identities are associated with roles in the .properties file in the generated Java code
has changed. It now shows the identities from the role perspective.

# Aliases for agents A,B,s from the point of view of ROLE_x
ROLE_A = alice,bob,charlie
ROLE_B = alice,bob,charlie
ROLE_s = alice,bob,charlie

In order to work, make sure you are using the AnBxJ.jar file distributed in AnBx 2022.09 or later.

From version 2022.07, a few new fields are supported in the config file (anbxc.cfg)

In particular, due to issues about running processes on the localhost IP address (127.0.0.1), introduced by recent JRE versions,
it is advisable to explicitly specify the IP address or the network interface used to run the generated Java code.
For networked machines, enabling interface=eth (for win/linux) interface=en (for mac) should solve the issue.
See below for further details.

# Optional network parameters
# interface name prefix for automatic detection of IP address
# common values "eth" / "wi-fi" for win/linux, "en" for mac
# ip address has priority over interface
interface=eth
# Default IP address for code generation
# ipaddress=192.168.0.31
# Default starting port for code generation
# startingport=55555

## Notes 
--------
In Java, AnB bullet channels (e.g. *->*) are implemented using TLSv1.2 or TLSv1.3

In order to enable the Java implementation of AnB bullet channel *-> and ->*
it is necessary to remove "anon, NULL" from 
the jdk.tls.disabledAlgorithms entry in the java.security file. e.g.

jdk.tls.disabledAlgorithms=SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5withRSA, \
    DH keySize < 1024, EC keySize < 224, 3DES_EDE_CBC, anon, NULL, \
    include jdk.disabled.namedCurves

See: https://bugs.java.com/bugdatabase/view_bug.do?bug_id=JDK-8211883

For more information on Java Cryptography configuration, visit: https://www.java.com/en/configure_crypto.html

-----------------------------------------------------------------------------------------------------------------------
AnBx Compiler and Code Generator - Version 2025.01
Support website: https://www.dais.unive.it/~modesti/anbx/
Usage:
anbxc <AnBxFileName> [options]

anbxc -v # Print the product name and version
anbxc -help | ? # Print the help screen with the complete list of options

------ Options: ------
-impl:AANB|CIF|CIF2|CIF3 # implementation of AnBx channels

	CIF: Default implementation  (freshness: Sequence Numbers, encryption: PKI)
	CIF2: Alternative implementation (freshness: Challenge/Response, encryption: PKI)
	CIF3: Another alternative implementation (freshness: DH, encryption: PKI)
	AANB: Annotated AnB implementation (freshness: Sequence Numbers, encryption: PKI)

-debug:None|AnBx|AnB|AnB2AnBx|AnBEqTheory|Java|AnBIntrGoal|SpyerPN|Defs|Execnarr|NExecnarr|OptExecnarr|KnowExecnarr|PV|PVT|PVTAnB|PVTJava|PVTCBAB|VDM
-out:AnB|Java|JavaNoOpt|JavaDocker|SpyerPN|Execnarr|OptExecnarr|TypedOptExecnarr|TypedOptExecnarrDocker|KnowExecnarr|PV|PVT|PVTAnB|PVTJava|PVTCBAB|VDM
        |AnBxIntr|AnBIntr|AnBEqTheory|AnBIF|AnBStats|AnBStatsCSV|AnBx

	AnB: Generate AnB code
	Java: Generate Java code
	JavaNoOpt: Generate Java code without cryptographic optimisation
	JavaDocker: Generate Java code for distributed Docker containers
	SpyerPN: Generate Spyer code (legacy)
	Execnarr|OptExecnarr|TypedOptExecnarr|TypedOptExecnarrDocker: Generate intermediate formats for code generation
	KnowExecnarr: Generate agents' knowledge at the end of the protocol run
	PV: Generate an untyped ProVerif model
	PVT: Generate a typed ProVerif model
	PVTAnB: Generate a typed ProVerif model mapping types as in AnB
	PVTJava: Generate a typed ProVerif model mapping types as in Java
	PVTCBAB: Generate a typed ProVerif model mapping "ByteArray" types to "bitstring"
	VDM: Generate VDM code (experimental)
	AnBxIntr|AnBIntr: Generate AnBx|AnB code with explicit intruder/MITM (default: intr)
	   The name can be specified with -mitm, e.g., -mitm Intruder
	   Optionally, use -pubmitmknow to publish the initial knowledge of the MITM agent
	AnBEqTheory: Generate an OFMC theory file (.thy) if the protocol declares equational theories
	AnBIF: Generate IF code (experimental)
	AnBStats: Generate statistics about the AnB protocol
	AnBStatsCSV: Generate statistics about the AnB protocol in CSV format
	AnBxLatex|AnBLatex: Generate AnBx|AnB sequence diagram Latex code

-cfg <ConfigFileName> # Specify the config file - default: anbxc.cfg
-silent # Suppress display of generated files and config file messages
-nocfgmsg # Suppress display of config file messages only
-silentcode # Suppress log messages in the generated code
-omitverdatetime # Omit displaying version and date time in generated code
-nogoals # Ignore goals in code generation in all targets except AnB
-noprivatekeygoals # Skip creation of secrecy goals for private keys used in the protocol
-outprotsuffix <String> # Specify a suffix for the generated protocol name and filename (without spaces)
-ofmctrace # Specify the OFMC attack trace file for reconstruction to an AnBx protocol
-passiveintruder # Introduce a passive intruder in the code generation (similar to -out:AnBxIntr)
-replicate <Int> # Replicate the actions n times and save the protocol as <filename>_xn.AnBx (n > 1, AnBx target only)
-objcheck # Allow the passive intruder to check reconstructed serialised messages stored as .ser files
            Expected FileName: $prot$_STEP_#.ser

------ OFMC/AnB options: ------
-if2cif # AnB only, to be used in combination with OFMC switch --IF2CIF
-ifsessions <Int> # Specify the number of sessions for the generated IF code (n > 0, AnBIF only) (default: 2)
-noAnBTypeCheck # Disable type checking of AnB protocols
-noAnBExecCheck # Disable executability checking of AnB protocols
-noAnBKnowCheck # Disable checking that all agents have a declared initial knowledge in AnB protocols
-expandbullets # Expand bullet channels to AnBx channels, e.g., A*->*B: M => A->B,(A|B|B): M
-guessprivatefunctions # Guess private functions/mappings in AnB protocols (experimental)
-noshareguess # Disable automatic guessing of pre-shared information from knowledge in AnB protocols
                Note: Private functions can be declared as Function [T1,...,Tn ->* T] f

------ Single/Group goal generation options: ------
-singlegoals # Generate AnB/ProVerif files with a single goal each
-goalindex <Int> # Generate an AnB/ProVerif file with the <Int>-th goal
-groupgoals # Generate AnB/ProVerif files grouping goals of the same type (Auth,WAuth,ChGoal,Conf)

------ Code Generation & Optimisation (Java|ProVerif|(Typed)OptExecnarr) options: ------
-probenc:XX # where X=0|1 (False|True)
              Assume probabilistic encryption for (Asym Enc, Sym Enc) -> 11
              Default value automatically selected based on the target (-out:)
-checktype:all|opt|optfail|eq|none # Find vars in all checks (default: opt)
           all and optfail set -probenc:00, otherwise -probenc:11
-checkoptlevel <Int> # 0=none ... 4=full (default: 4)
-basicopt # Do not prune EQchecks that depend on previously successful EQchecks on variables
            Applied only if optimisation on OptExecnarr is done
-filterfailingchecks # Filter failing checks (Only for (Typed)OptExecnarr, applied by default to Java)
-maxMethodSize <Int> # Maximum number of actions in a Java method (default: 50)
-maxActionsOpt <Int> # Maximum number of actions for Execnarr optimisation (default: 100000)
-agent <String> # Generate only the common files and the specified agent code. <String> is the agent's name
-jfr # Enable Java Flight Recording
-jfrlabel <String> # Specify a label that can be added to the filename saved in JFR
-jfrsettings default|profile|<FilePath> # Specify the JFR settings file, default|profile|<FilePath>
-jdockerpcap # Enable packet capture (PCAP) - JavaDocker output only
-jdockercpuquota <Int> # CPU quota for Docker containers. Use units like '200000' for 200,000 CPU shares. Set to 0 for no CPU limit
-jdockermemlimit <Int><unit> # Memory limit for Docker containers. Unit: b|k|m|g for bytes|kb|Mb|Gb. Set to 0 for no memory limit
-jsessions <Int> # Specify the number of runs of the protocol in Java
-jabortonfail # Specify if an agent should abort the run of the protocol in Java if an error occurs
-jexectime # Display execution time for cryptographic methods

------ ProVerif options: ------
-pvprobenc # Assume probabilistic encryption for both symmetric and asymmetric primitives
-pvreachevents # Generate a reachability event at the end of each agent's process (e.g. event endX)
-pvpreciseactions # Set preciseActions = true in the generated code, to increase the precision of the solving procedure
-pvverbosegoalreacheable # Set verboseGoalReacheable = true in the generated code, to displays each derivable clause that satisfies the query
-pvverbosestatistics # Set verboseStatistics = true in the generated code, displays more statistics during the verification process
-pvtagfuntt # Tag the protocol to help prove some queries
              where some declared functions have the same argument and return type
-pvnomutual # Do not parallelise the main process by permutating free agents' names. Help to avoid loops,
              and find some attacks more quickly, but may miss others (mutual auth in particular)
-pvxor:none|basic|simple|ass|comm|full # Declare a different xor theory in ProVerif
	none: Only declare the xor function, no equations
	basic: Basic erasure xor(xor(x, y), y) = x
	simple: (default) basic erasure + zero
	ass: Associativity only
	comm: Commutativity only
	full: Full theory, not supported by ProVerif, at least up to version 2.05

Examples:
anbxc <AnBxFileName> -out:PVT -nogoals -pvreachevents # Verify reachability events only; all should
                                                        be "false" or at least "cannot be proved"
anbxc <AnBxFileName> -out:PVT -pvnomutual # Help to avoid loops, and find some attacks more quickly,
                                            but may miss others (mutual auth goals in particular)
anbxc <AnBxFileName> -out:PVT # Standard verification of the typed model

------ VDM (experimental) options: ------
Usage: anbxc <VDMFolder> options

-vdmtest:SG|WF # Generate VDM test file; the main argument <VDMFolder> should be a folder with vdmsl files
                 Test Types: SG (Security Goals), WF (Well-Formedness)
-vdmtestmodulename <ModuleName> # Specify the module name for the test file, otherwise these defaults are used
                                  SG: AnB_trace_satisfy_goals, WF: AnB_trace_wf

------ Cryptographic configuration options: ------
-cipherScheme <String> # Specify symmetric encryption cipher scheme
-keySize <Int> # Specify the key size for the symmetric encryption cipher scheme
-keyGenerationScheme <String> # Specify the key generation scheme
-keyGenerationSchemePBE <String> # Specify the PBE key generation scheme
-keyGenerationSize <Int> # Specify the size of the generated keys
-keyPairGenerationScheme <String> # Specify the key pair generation scheme
-keyPairGenerationSize <Int> # Specify the key pair generation size
-secureRandomAlgorithm <String> # Specify the secure random algorithm
-hMacAlgorithm <String> # Specify the HMAC algorithm
-messageDigestAlgorithm <String> # Specify the message digest algorithm
-keyAgreementAlgorithm <String> # Specify the key agreement algorithm
-keyAgreementKeyPairGenerationScheme <String> # Specify the key pair generation scheme for key agreement algorithm
-dhRndExpSize <Int> # Specify the Diffie-Hellman random exponent size
-ecGenParameterSpec <String> # Specify the elliptic curve used in ECDH key agreement
-asymcipherSchemeBlock <String> # Specify the asymmetric cipher scheme block (experimental)
-sslContext <String> # Specify the SSL context algorithm (e.g. TLSv1.3)
-securityProvider <String> # Specify the security provider (overrides java.security settings)
----------------------------------------------------
 
Credit: almost all of the following examples are adapted from the AnB models distributed with OFMC by Sebastian Mödersheim 
        available at http://www2.imm.dtu.dk/~samo/ under BSD licence 
 
Amended_NSCK.AnBx
AndrewSecureRPC.AnBx
AndrewSecureRPCSecrecy.AnBx
Basic_Kerberos.AnBx
Bilateral_Key_Exchange.AnBx
Carlsen.AnBx
DenningSacco.AnBx
DenningSaccoCorr.AnBx
EPMO.AnBx
IKEv2DS.AnBx
ISO4pass.AnBx
ISO5pass.AnBx
ISOCCFOnePassUnilateralAuthProt.AnBx
ISOCCFThreePassMutual.AnBx
ISOCCFTwoPassMutualAuthProtCorr.AnBx
ISOCCFTwoPassUnilateralAuthProt.AnBx
ISOpubKeyOnePassUnilateralAuthProt.AnBx
ISOpubKeyTwoPassMutualAuthProt.AnBx
ISOpubKeyTwoPassMutualAuthProtCorr.AnBx
ISOpubKeyTwoPassUnilateralAuthProt.AnBx
ISOsymKeyOnePassUnilateralAuthProt.AnBx
ISOsymKeyThreePassMutual.AnBx
ISOsymKeyTwoPassMutualAuthProtCorr.AnBx
ISOsymKeyTwoPassUnilateralAuthProt.AnBx
Kerberos_PKINIT.AnBx
KeyEx1.AnBx
KeyEx2.AnBx
KeyEx3.AnBx
KeyEx3b.AnBx
KeyEx4.AnBx
KeyEx4b.AnBx
KeyEx5.AnBx
KeyEx5b.AnBx
KeyEx5c.AnBx
KeyEx6.AnBx
NonReversible.AnBx
NSCK.AnBx
NSL.AnBx
NSL_KeyServer.AnBx
NSPK.AnBx
NSPK_KeyServer.AnBx
Otway_Rees.AnBx
SSO.AnBx
TLS.AnBx
TLS_noClientAuth.AnBx
TLS_pw.AnBx
WL92.AnBx
WMF.AnBx
WooLam.AnBx
WooLam1.AnBx
WooLam1Test.AnBx
WooLam2.AnBx
WooLam3.AnBx
WooLam4.AnBx
WooLamF.AnBx
WooLamMutual.AnBx
Yahalom.AnBx
-----------------------------------------------------------------------------------------------------------------------

Bouncy Castle Java Library (optional)
-------------------------------------

The following version is included in this AnBx distribution package: bcprov-jdk18on-1.80.jar 
Newer versions can be downloaded from: https://www.bouncycastle.org/latest_releases.html 
Installation: https://www.bouncycastle.org/wiki/display/JA1/Provider+Installation
Bouncy Castle is released under MIT License: http://opensource.org/licenses/MIT
Copyright (c) 2000 - 2025 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 

