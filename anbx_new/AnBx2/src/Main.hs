{-

 AnBx Compiler and Code Generator

 Copyright 2011-2025 Paolo Modesti
 Copyright 2021-2025 Rémi Garcia
 Copyright 2018-2025 SCM/SCDT/SCEDT, Teesside University
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

-}

import AnB2NExecnarr
import AnBShow
import AnBxShow
import AnBxAst
import AnBxDefinitions
import AnBxIntr (buildAnBxIntr)
import AnBxLexer
import AnBxMain ( trAnB2AnBx, mkAnB, getProtName, renameProtocol, getExt,trAnB,replicateAnBx )
import AnBxMsgCommon
import AnBxMsg
import AnBxOnP
import AnB2IF_Common (defaultAnBOpts,numSess,eqnoexec, AnBOnP (noowngoal))
import AnBxParser
import AnBAst
import JavaAst
import JavaCodeGen
import Main_Common
import Data.Char ( isSpace, toLower )
import Data.ConfigFile
import Data.Either
import Data.Either.Utils
import Data.Maybe
import Data.Time
import System.Directory
import System.Environment
import System.CPUTime
import System.FilePath
import System.IO
import Text.Printf
import Vdm
import VdmTest
-- import Debug.Trace
import AnB2PVT (printPvtOfExecnarr)
import Data.List (sort,isPrefixOf)
import Network.Info
import Net.IPv4
import Spyer_Execnarr (protAttackTraceGoals)
import AnB2IF_Translator (mkIF)
import AnB2Latex
import OFMCTraceUtils
import Text.Read (readMaybe)
import System.Info (os)
import Data.Containers.ListUtils (nubOrd)

supportWebsite :: String
supportWebsite = "Support website: https://www.dais.unive.it/~modesti/anbx/"

basicUsage :: String
basicUsage =       fullProductName ++ "\n" ++ supportWebsite ++ "\n" ++ "Usage:\n"
                ++ shortProductName ++ " <AnBxFileName> [options]\n" ++ "\n" -- extra new line to improve readability
                ++ shortProductName ++ " " ++ cmdVersion ++ " # Print the product name and version\n"
                ++ shortProductName ++ " " ++ cmdHelp ++ " | " ++ cmdHelp2 ++ " # Print the help screen with the complete list of options"

usage :: String
usage = basicUsage ++ "\n\n"
                ++ "------ Options: ------"
                ++ "\n"
--                ++ "-impl:AANB|CIF|CIF2|CIF3|CCM|CCM2|CCM3|CCM4|APP\n\n"
                ++ cmdAnBxImplType ++ "AANB|CIF|CIF2|CIF3 # implementation of AnBx channels\n"
--                ++ "CCM is the standard CCM-Cryptographic Channel Model implementation (fresheness: Sequence Numbers, encryption: PKI))\n"
--                ++ "CCM2 is another CCM implementation (freshness: Challenge/Response, encryption: PKI))\n"
--                ++ "CCM3 is another CCM implementation (freshness: Sequence Numbers, encryption: hybrid)\n"
--                ++ "CCM4 is another CCM implementation (freshness: Challenge/Response, encryption: DH/PKI)\n"
--                ++ "APP is an engineering implementation (freshness: Challenge/Response, encryption: DH+hybrid)\n"
                ++ "\n\t" ++ "CIF: Default implementation  (freshness: Sequence Numbers, encryption: PKI)"
                ++ "\n\t" ++ "CIF2: Alternative implementation (freshness: Challenge/Response, encryption: PKI)"
                ++ "\n\t" ++ "CIF3: Another alternative implementation (freshness: DH, encryption: PKI)"
                ++ "\n\t" ++ "AANB: Annotated AnB implementation (freshness: Sequence Numbers, encryption: PKI)"
                ++ "\n\n"
                ++ cmdAnBxDebugType ++ "None|AnBx|AnB|AnB2AnBx|AnBEqTheory|Java|AnBIntrGoal|SpyerPN|Defs|Execnarr|NExecnarr|OptExecnarr|KnowExecnarr|PV|PVT|PVTAnB|PVTJava|PVTCBAB|VDM\n"
                ++ cmdAnBxOutType ++ "AnB|Java|JavaNoOpt|JavaDocker|SpyerPN|Execnarr|OptExecnarr|TypedOptExecnarr|TypedOptExecnarrDocker|KnowExecnarr|PV|PVT|PVTAnB|PVTJava|PVTCBAB|VDM\n"
                ++ justifyRight cmdAnBxOutType 3 "|AnBxIntr|AnBIntr|AnBEqTheory|AnBIF|AnBStats|AnBStatsCSV|AnBx\n"
                ++ "\n\t" ++ "AnB: Generate AnB code"
                ++ "\n\t" ++ "Java: Generate Java code"
                ++ "\n\t" ++ "JavaNoOpt: Generate Java code without cryptographic optimisation"
                ++ "\n\t" ++ "JavaDocker: Generate Java code for distributed Docker containers"
                ++ "\n\t" ++ "SpyerPN: Generate Spyer code (legacy)"
                ++ "\n\t" ++ "Execnarr|OptExecnarr|TypedOptExecnarr|TypedOptExecnarrDocker: Generate intermediate formats for code generation"
                ++ "\n\t" ++ "KnowExecnarr: Generate agents' knowledge at the end of the protocol run"
                ++ "\n\t" ++ "PV: Generate an untyped ProVerif model"
                ++ "\n\t" ++ "PVT: Generate a typed ProVerif model"
                ++ "\n\t" ++ "PVTAnB: Generate a typed ProVerif model mapping types as in AnB"
                ++ "\n\t" ++ "PVTJava: Generate a typed ProVerif model mapping types as in Java"
                ++ "\n\t" ++ "PVTCBAB: Generate a typed ProVerif model mapping \"ByteArray\" types to \"bitstring\""
                ++ "\n\t" ++ "VDM: Generate VDM code (experimental)"
                ++ "\n\t" ++ "AnBxIntr|AnBIntr: Generate AnBx|AnB code with explicit intruder/MITM (default: " ++anbxMitmDefault ++ ")"
                ++ "\n\t" ++ "   The name can be specified with " ++ cmdAnBxMitm ++ ", e.g., " ++ cmdAnBxMitm ++ " " ++ "Intruder"
                ++ "\n\t" ++ "   Optionally, use " ++ cmdAnBxMitmpubknowledge ++ " to publish the initial knowledge of the MITM agent"
                ++ "\n\t" ++ "AnBEqTheory: Generate an OFMC theory file (." ++ getExt AnBEqTheory ++  ") if the protocol declares equational theories"
                ++ "\n\t" ++ "AnBIF: Generate IF code (experimental)"
                ++ "\n\t" ++ "AnBStats: Generate statistics about the AnB protocol"
                ++ "\n\t" ++ "AnBStatsCSV: Generate statistics about the AnB protocol in CSV format"
                ++ "\n\t" ++ "AnBxLatex|AnBLatex: Generate AnBx|AnB sequence diagram Latex code"
                ++ "\n\n"
                ++ cmdAnBxCfgFile ++ " <ConfigFileName> # Specify the config file - default: " ++ cfgFileDefault ++ "\n"
                ++ cmdSilent ++ " # Suppress display of generated files and config file messages" ++ "\n"
                ++ cmdNoCfgMsg ++ " # Suppress display of config file messages only" ++ "\n"
                ++ cmdSilentCode ++ " # Suppress log messages in the generated code" ++ "\n"
                ++ cmdOmitVerDateTime ++ " # Omit displaying version and date time in generated code" ++ "\n"
                ++ cmdNoGoals ++ " # Ignore goals in code generation in all targets except AnB" ++ "\n"
                ++ cmdNoPrivateKeyGoals ++ " # Skip creation of secrecy goals for private keys used in the protocol" ++ "\n"
                ++ cmdOutProtSuffix ++ " <String> # Specify a suffix for the generated protocol name and filename (without spaces)" ++ "\n"
                ++ cmdOfmcTrace ++ " # Specify the OFMC attack trace file for reconstruction to an AnBx protocol" ++ "\n"
                ++ cmdPassiveIntruder ++ " # Introduce a passive intruder in the code generation (similar to -out:AnBxIntr)" ++ "\n"
                ++ cmdAnBxReplicate ++ " <Int> # Replicate the actions n times and save the protocol as <filename>_xn.AnBx (n > " ++ show minAnBxReplicate ++ ", AnBx target only)" ++ "\n"
                ++ cmdObjCheck ++ " # Allow the passive intruder to check reconstructed serialised messages stored as .ser files" ++ "\n"
                ++ justifyRight cmdObjCheck 3 "Expected FileName: $prot$_STEP_#.ser" ++ "\n"
                ++ "\n"
                ++ "------ OFMC/AnB options: ------" ++ "\n"
                ++ cmdAnBxIfCif ++ " # AnB only, to be used in combination with OFMC switch --IF2CIF" ++ "\n"
                ++ cmdIFSessions ++ " <Int> # Specify the number of sessions for the generated IF code (n > " ++ show minIFSessions ++  ", AnBIF only) (default: " ++ show defaultIFSessions ++ ")" ++ "\n"
                ++ cmdAnBTypeCheck ++ " # Disable type checking of AnB protocols" ++ "\n"
                ++ cmdAnBExecCheck ++ " # Disable executability checking of AnB protocols" ++ "\n"
                ++ cmdAnBKnowCheck ++ " # Disable checking that all agents have a declared initial knowledge in AnB protocols" ++ "\n"
                ++ cmdAnBxExpandBullets ++ " # Expand bullet channels to AnBx channels, e.g., A*->*B: M => A->B,(A|B|B): M" ++ "\n"
                ++ cmdGuessPrivateFunctions ++ " # Guess private functions/mappings in AnB protocols (experimental)" ++ "\n"
                ++ cmdNoShareGuess ++ " # Disable automatic guessing of pre-shared information from knowledge in AnB protocols" ++ "\n"
                ++ justifyRight cmdNoShareGuess 3 "Note: Private functions can be declared as Function [T1,...,Tn ->* T] f" ++ "\n"
                ++ "\n"
                ++ "------ Single/Group goal generation options: ------" ++ "\n"
                ++ cmdSingleGoals ++ " # Generate AnB/ProVerif files with a single goal each" ++ "\n"
                ++ cmdGoalIndex ++ " <Int> # Generate an AnB/ProVerif file with the <Int>-th goal" ++ "\n"
                ++ cmdGroupGoals ++ " # Generate AnB/ProVerif files grouping goals of the same type (Auth,WAuth,ChGoal,Conf)"++ "\n"
                ++ "\n"
                ++ "------ Code Generation & Optimisation (Java|ProVerif|(Typed)OptExecnarr) options: ------" ++ "\n"
                ++ cmdSynthesisTypeEnc ++ "XX # where X=0|1 (False|True)" ++ "\n"
                ++ justifyRight cmdSynthesisTypeEnc 5 "Assume probabilistic encryption for (Asym Enc, Sym Enc) -> 11" ++ "\n"
                ++ justifyRight cmdSynthesisTypeEnc 5 "Default value automatically selected based on the target (" ++ cmdAnBxOutType ++ ")" ++ "\n"
                ++ cmdCheckType ++ listOfCheckTypes ++ " # Find vars in all checks (default: " ++ show defCheckType ++ ")" ++ "\n"
                ++ justifyRight cmdCheckType 0 (show CheckAll) ++ " and " ++ show CheckOptFail ++ " set " ++ cmdSynthesisTypeEnc ++ "00, otherwise " ++ cmdSynthesisTypeEnc ++ "11" ++ "\n"
                ++ cmdCheckOptLevel ++ " <Int> # " ++ show CheckOptLevel0 ++ "=none ... " ++ show CheckOptLevel4 ++ "=full" ++ " (default: " ++ show defCheckOptLevel ++ ")" ++ "\n"
                ++ cmdBasicOpt ++ " # Do not prune EQchecks that depend on previously successful EQchecks on variables" ++ "\n"
                ++ justifyRight cmdBasicOpt 3 "Applied only if optimisation on OptExecnarr is done" ++ "\n"
                ++ cmdFilterFailingChecks ++ " # Filter failing checks (Only for (Typed)OptExecnarr, applied by default to Java)" ++ "\n"
                ++ cmdMaxMethodSize ++ " <Int> # Maximum number of actions in a Java method (default: " ++ show defmaxMethodSize ++ ")" ++ "\n"
                ++ cmdMaxActionsOpt ++ " <Int> # Maximum number of actions for Execnarr optimisation (default: " ++ show defmaxActionsOpt ++ ")" ++ "\n"
                ++ cmdAgent ++ " <String> # Generate only the common files and the specified agent code. <String> is the agent's name" ++ "\n"
                ++ cmdJfr ++ " # Enable Java Flight Recording" ++ "\n"
                ++ cmdJfrLabel ++ " <String> # Specify a label that can be added to the filename saved in JFR" ++ "\n"
                ++ cmdJfrSettings ++ " default|profile|<FilePath> # Specify the JFR settings file, default|profile|<FilePath>" ++ "\n"
                ++ cmdJDockerPCAP ++ " # Enable packet capture (PCAP) - JavaDocker output only" ++ "\n"
                ++ cmdJDockerCPUQuota ++ " <Int> # CPU quota for Docker containers. Use units like '200000' for 200,000 CPU shares. Set to 0 for no CPU limit" ++ "\n"
                ++ cmdJDockerMEMLimit ++ " <Int><unit> # Memory limit for Docker containers. Unit: b|k|m|g for bytes|kb|Mb|Gb. Set to 0 for no memory limit" ++ "\n"
                ++ cmdJSessions ++ " <Int> # Specify the number of runs of the protocol in Java" ++ "\n"
                ++ cmdJAbortOnFail ++ " # Specify if an agent should abort the run of the protocol in Java if an error occurs" ++ "\n"
                ++ cmdJExecTime ++ " # Display execution time for cryptographic methods" ++ "\n"
                ++ "\n"
                ++ "------ ProVerif options: ------" ++ "\n"
                ++ cmdPvProbEnc ++ " # Assume probabilistic encryption for both symmetric and asymmetric primitives" ++ "\n"
                ++ cmdPvReachEvents ++ " # Generate a reachability event at the end of each agent's process (e.g. event endX)" ++ "\n"
                ++ cmdPvPreciseActions ++ " # Set preciseActions = true in the generated code, to increase the precision of the solving procedure" ++ "\n"
                ++ cmdPvVerboseGoalReacheable ++ " # Set verboseGoalReacheable = true in the generated code, to displays each derivable clause that satisfies the query" ++ "\n"
                ++ cmdPvVerboseStatistics ++ " # Set verboseStatistics = true in the generated code, displays more statistics during the verification process" ++ "\n"
                ++ cmdPvTagFunTT ++ " # Tag the protocol to help prove some queries" ++ "\n"
                ++ justifyRight cmdPvTagFunTT 3 "where some declared functions have the same argument and return type" ++ "\n"
                ++ cmdPvNoMutual ++ " # Do not parallelise the main process by permutating free agents' names. Help to avoid loops," ++ "\n"
                ++ justifyRight cmdPvNoMutual 3 "and find some attacks more quickly, but may miss others (mutual auth in particular)" ++ "\n"
                ++ cmdPvXorTheory ++ "none|basic|simple|ass|comm|full # Declare a different xor theory in ProVerif"
                ++ "\n\t" ++ "none: Only declare the xor function, no equations"
                ++ "\n\t" ++ "basic: Basic erasure xor(xor(x, y), y) = x"
                ++ "\n\t" ++ "simple: (default) basic erasure + zero"
                ++ "\n\t" ++ "ass: Associativity only"
                ++ "\n\t" ++ "comm: Commutativity only"
                ++ "\n\t" ++ "full: Full theory, not supported by ProVerif, at least up to version 2.05" ++ "\n"
                ++ "\n"
                ++ "Examples:" ++ "\n"
                ++ exPV1 ++ " # Verify reachability events only; all should" ++ "\n"
                ++ justifyRight exPV1 3 "be \"false\" or at least \"cannot be proved\"" ++ "\n"
                ++ exPV2 ++ " # Help to avoid loops, and find some attacks more quickly," ++ "\n"
                ++ justifyRight exPV2 3 "but may miss others (mutual auth goals in particular)" ++ "\n"
                ++ exPV3 ++ " # Standard verification of the typed model" ++ "\n"
                ++ "\n"
                ++ "------ VDM (experimental) options: ------" ++ "\n"
                ++ "Usage: " ++ shortProductName ++ " <VDMFolder> options\n" ++ "\n"
                ++ cmdVdmTest ++ "SG|WF # Generate VDM test file; the main argument <VDMFolder> should be a folder with vdmsl files" ++ "\n"
                ++ justifyRight cmdVdmTest 8 "Test Types: SG (Security Goals), WF (Well-Formedness)" ++ "\n"
                ++ cmdVdmTestModuleName ++ " <ModuleName> # Specify the module name for the test file, otherwise these defaults are used" ++ "\n"
                ++ justifyRight cmdVdmTestModuleName 16 "SG: " ++ vdmTestModuleNameDefault VDMTestSG ++ ", WF: " ++ vdmTestModuleNameDefault VDMTestWF ++ "\n"
                ++ "\n"
                ++ "------ Cryptographic configuration options: ------" ++ "\n"
                ++ cmdSwitchSymbol ++ cmdCipherScheme ++ " <String> # Specify symmetric encryption cipher scheme" ++ "\n"
                ++ cmdSwitchSymbol ++ cmdKeySize ++ " <Int> # Specify the key size for the symmetric encryption cipher scheme" ++ "\n"
                ++ cmdSwitchSymbol ++ cmdKeyGenerationScheme ++ " <String> # Specify the key generation scheme" ++ "\n"
                ++ cmdSwitchSymbol ++ cmdKeyGenerationSchemePBE ++ " <String> # Specify the PBE key generation scheme" ++ "\n"
                ++ cmdSwitchSymbol ++ cmdKeyGenerationSize ++ " <Int> # Specify the size of the generated keys" ++ "\n"
                ++ cmdSwitchSymbol ++ cmdKeyPairGenerationScheme ++ " <String> # Specify the key pair generation scheme" ++ "\n"
                ++ cmdSwitchSymbol ++ cmdKeyPairGenerationSize ++ " <Int> # Specify the key pair generation size" ++ "\n"
                ++ cmdSwitchSymbol ++ cmdSecureRandomAlgorithm ++ " <String> # Specify the secure random algorithm" ++ "\n"
                ++ cmdSwitchSymbol ++ cmdHMacAlgorithm ++ " <String> # Specify the HMAC algorithm" ++ "\n"
                ++ cmdSwitchSymbol ++ cmdMessageDigestAlgorithm ++ " <String> # Specify the message digest algorithm" ++ "\n"
                ++ cmdSwitchSymbol ++ cmdKeyAgreementAlgorithm ++ " <String> # Specify the key agreement algorithm" ++ "\n"
                ++ cmdSwitchSymbol ++ cmdKeyAgreementKeyPairGenerationScheme ++ " <String> # Specify the key pair generation scheme for key agreement algorithm" ++ "\n"
                ++ cmdSwitchSymbol ++ cmdDHRndExpSize ++ " <Int> # Specify the Diffie-Hellman random exponent size" ++ "\n"
                ++ cmdSwitchSymbol ++ cmdECGenParameterSpec ++ " <String> # Specify the elliptic curve used in ECDH key agreement" ++ "\n"
                ++ cmdSwitchSymbol ++ cmdAsymCipherSchemeBlock ++ " <String> # Specify the asymmetric cipher scheme block (experimental)" ++ "\n"
                ++ cmdSwitchSymbol ++ cmdSSLContext ++ " <String> # Specify the SSL context algorithm (e.g. TLSv1.3)" ++ "\n"
                ++ cmdSwitchSymbol ++ cmdSecurityProvider ++ " <String> # Specify the security provider (overrides java.security settings)" ++ "\n"
                ++ "----------------------------------------------------"

exPV1 :: String
exPV1 = shortProductName ++ " <AnBxFileName> -out:PVT " ++ cmdNoGoals ++ " " ++ cmdPvReachEvents

exPV2 :: String
exPV2 = shortProductName ++ " <AnBxFileName> -out:PVT " ++ cmdPvNoMutual

exPV3 :: String
exPV3 = shortProductName ++ " <AnBxFileName> -out:PVT"

justifyRight :: String -> Int -> String -> String
justifyRight s n c = replicate (length s + n) ' ' ++ c

parseArgs :: [String] -> AnBxOnP
parseArgs [] = defaultAnBxOnP { outmessage = Just ("No input file specified.\n" ++ basicUsage ++ "\n") }
parseArgs [x] | x == cmdVersion = (defaultAnBxOnP { outmessage = Just fullProductName })
              | x == cmdHelp || x == cmdHelp2 = (defaultAnBxOnP { outmessage = Just usage })
              | otherwise = (defaultAnBxOnP { anbxfilename = x })
parseArgs (x:xs) = processMitmArgs (parseArgs0 xs (defaultAnBxOnP { anbxfilename = x }))     -- first parameter is the input protocol

processMitmArgs :: AnBxOnP -> AnBxOnP
processMitmArgs anbxonp = anbxonp {anbxmitm = if anbxmitm anbxonp == anbxMitmDefault        -- if default value
                                                 then anbxMitmDefaultFun (anbxouttype anbxonp) (ofmctracefilename anbxonp)  -- use default value per target and trace
                                                    else anbxmitm anbxonp } -- use the value specified by the user

parseArgs0 :: [String] -> AnBxOnP -> AnBxOnP
parseArgs0 [] anbxonp = anbxonp
parseArgs0 (x:xs) anbxonp
    -- AnBx general parameters
    | x == cmdVersion = (anbxonp { outmessage = Just fullProductName })
    | x == cmdHelp || x == cmdHelp2 = (anbxonp { outmessage = Just usage })
    | x == cmdAnBxCfgFile = case xs of
                                    [] -> (anbxonp { outmessage = Just (parsingErrorMissing x) })
                                    _ -> parseArgs0 (tail xs) (anbxonp { anbxcfgfile=head xs })
    | x == cmdNoCfgMsg = parseArgs0 xs (anbxonp { nocfgmsg=True })
    | x == cmdAnBxIfCif = parseArgs0 xs (anbxonp { anbxif2cif=False })
    | x == cmdAnBTypeCheck = parseArgs0 xs (anbxonp { anbtypecheck=False })
    | x == cmdAnBExecCheck = parseArgs0 xs (anbxonp { anbexeccheck=False })
    | x == cmdAnBKnowCheck = parseArgs0 xs (anbxonp { anbknowcheck=False })
    | x == cmdIFSessions = case xs of
                    [] -> (anbxonp { outmessage = Just (parsingErrorMissing x) })
                    (arg:rest) -> case readMaybe arg of
                        Just i | i > minIFSessions    -> parseArgs0 rest (anbxonp { ifsessions = i })
                             | otherwise -> anbxonp { outmessage = Just (parsingErrorInvalidDec cmdIFSessions  ++ (": it must be greater than " ++ show minIFSessions ++ ", but got " ++ show i))}
                        Nothing -> anbxonp { outmessage = Just (parsingErrorInvalidDec cmdIFSessions) }
    | x == cmdIFStrictWhere = parseArgs0 xs (anbxonp { ifstrictwhere=True })
    | x == cmdAnBxExpandBullets = parseArgs0 xs (anbxonp { anbxexpandbullets=True })
    | x == cmdAnBxExpandAgree = parseArgs0 xs (anbxonp { anbxexpandagree=True })
    | x == cmdGuessPrivateFunctions = parseArgs0 xs (anbxonp { guessprivatefunctions=True })
    | x == cmdNoShareGuess = parseArgs0 xs (anbxonp { noshareguess=True })
    | x == cmdAnBxUseTags = parseArgs0 xs (anbxonp { anbxusetags=True })
    | x == cmdDigestType =  parseArgs0 xs (anbxonp { digesttype=DTAbstract })
    | x == cmdAnBxReplicate = case xs of
                                    [] -> (anbxonp { outmessage = Just (parsingErrorMissing x) })
                                    (arg:rest) -> case readMaybe arg of
                                        Just i | i > minAnBxReplicate -> parseArgs0 rest (anbxonp { anbxreplicate = i })
                                               | otherwise -> anbxonp { outmessage = Just (parsingErrorInvalidDec cmdAnBxReplicate ++ (": it must be greater than " ++ show minIFSessions ++ ", but got " ++ show i))}
                                        Nothing -> anbxonp { outmessage = Just (parsingErrorInvalidDec cmdAnBxReplicate) }
    | x == cmdAnBxMitm = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) ->
            if null arg
            then anbxonp { outmessage = Just (parsingErrorInvalidDec cmdAnBxMitm) }
            else parseArgs0 rest (anbxonp { anbxmitm = arg })
    | x == cmdAnBxMitmpubknowledge = parseArgs0 xs (anbxonp { anbxmitmpubknowledge=True })
    | x == cmdPassiveIntruder = parseArgs0 xs (anbxonp { passiveIntruder=True })
    | x == cmdObjCheck = parseArgs0 xs (anbxonp { objcheck=True, passiveIntruder=True })
    | x == cmdOutProtSuffix = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) ->
            if null arg
            then anbxonp { outmessage = Just (parsingErrorInvalidDec cmdOutProtSuffix) }
            else parseArgs0 rest (anbxonp { outprotsuffix = Just arg })

    | x == cmdAgent = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) ->
            if null arg
            then anbxonp { outmessage = Just (parsingErrorInvalidDec cmdAgent) }
            else parseArgs0 rest (anbxonp { agent = Just arg })

    | x == cmdSilentCode = parseArgs0 xs (anbxonp { silentCode=True })
    | x == cmdSilent = parseArgs0 xs (anbxonp { silentStdOut=True, nocfgmsg = True }) -- silent output including config msg
    | x == cmdJfr = parseArgs0 xs (anbxonp { jfr=True })
    | x == cmdJDockerPCAP = parseArgs0 xs (anbxonp { jdockerpcap=True })
    | x == cmdJfrLabel = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) ->
            if null arg
            then anbxonp { outmessage = Just (parsingErrorInvalidDec cmdJfrLabel) }
            else parseArgs0 rest (anbxonp { jfrlabel = arg })
    | x == cmdJfrSettings = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) ->
            let parsedSetting = case arg of
                    "default" -> Just JFRSettingsDefault
                    "profile" -> Just JFRSettingsProfile
                    _         -> Nothing
            in case parsedSetting of
                Just setting -> parseArgs0 rest (anbxonp { jfrsettings = setting })
                Nothing ->
                    if isValid arg
                        then parseArgs0 rest (anbxonp { jfrsettings = JFRFilePath arg })
                        else anbxonp { outmessage = Just (parsingErrorInvalidDec cmdJfrSettings ++ "\nInvalid file path: " ++ arg) }

    | x == cmdJDockerCPUQuota = case xs of
                                    [] -> (anbxonp { outmessage = Just (parsingErrorMissing x) })
                                    (arg:rest) -> case readMaybe arg of
                                        Just i  -> parseArgs0 rest (anbxonp { jdockerCPUQuota = i })
                                        Nothing -> anbxonp { outmessage = Just (parsingErrorInvalidDec cmdJDockerCPUQuota) }
    | x == cmdJDockerMEMLimit = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) ->
            if null arg
            then anbxonp { outmessage = Just (parsingErrorInvalidDec cmdJDockerMEMLimit) }
            else parseArgs0 rest (anbxonp { jdockerMEMLimit = Just arg })
    | x == cmdJSessions = case xs of
                                    [] -> (anbxonp { outmessage = Just (parsingErrorMissing x) })
                                    (arg:rest) -> case readMaybe arg of
                                        Just i  -> parseArgs0 rest (anbxonp { jsessions = i })
                                        Nothing -> anbxonp { outmessage = Just (parsingErrorInvalidDec cmdJSessions) }
    | x == cmdJAbortOnFail = parseArgs0 xs (anbxonp { jabortonfail=True })
    | x == cmdJExecTime = parseArgs0 xs (anbxonp { jexectime=True })
    | x == cmdOmitVerDateTime = parseArgs0 xs (anbxonp { omitverdatetime=True })
    -- crypto config 
    | x == cmdSwitchSymbol ++ cmdCipherScheme = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) ->
            if null arg
            then anbxonp { outmessage = Just (parsingErrorInvalidDec cmdCipherScheme) }
            else parseArgs0 rest (anbxonp { cryptoCipherScheme = Just arg })

    | x == cmdSwitchSymbol ++ cmdKeySize = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) -> case readMaybe arg of
            Just i  -> parseArgs0 rest (anbxonp { cryptoKeySize = Just i })
            Nothing -> anbxonp { outmessage = Just (parsingErrorInvalidDecHyphen cmdKeySize) }

    | x == cmdSwitchSymbol ++ cmdKeyGenerationScheme = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) ->
            if null arg
            then anbxonp { outmessage = Just (parsingErrorInvalidDec cmdKeyGenerationScheme) }
            else parseArgs0 rest (anbxonp { cryptoKeyGenerationScheme = Just arg })

    | x == cmdSwitchSymbol ++ cmdKeyGenerationSchemePBE = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) ->
            if null arg
            then anbxonp { outmessage = Just (parsingErrorInvalidDec cmdKeyGenerationSchemePBE) }
            else parseArgs0 rest (anbxonp { cryptoKeyGenerationSchemePBE = Just arg })

    | x == cmdSwitchSymbol ++ cmdKeyGenerationSize = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) -> case readMaybe arg of
            Just i  -> parseArgs0 rest (anbxonp { cryptoKeyGenerationSize = Just i })
            Nothing -> anbxonp { outmessage = Just (parsingErrorInvalidDecHyphen cmdKeyGenerationSize) }

    | x == cmdSwitchSymbol ++ cmdKeyPairGenerationScheme = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) ->
            if null arg
            then anbxonp { outmessage = Just (parsingErrorInvalidDec cmdKeyPairGenerationScheme) }
            else parseArgs0 rest (anbxonp { cryptoKeyPairGenerationScheme = Just arg })

    | x == cmdSwitchSymbol ++ cmdKeyPairGenerationSize = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) -> case readMaybe arg of
            Just i  -> parseArgs0 rest (anbxonp { cryptoKeyPairGenerationSize = Just i })
            Nothing -> anbxonp { outmessage = Just (parsingErrorInvalidDecHyphen cmdKeyPairGenerationSize) }

    | x == cmdSwitchSymbol ++ cmdSecureRandomAlgorithm = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) ->
            if null arg
            then anbxonp { outmessage = Just (parsingErrorInvalidDec cmdSecureRandomAlgorithm) }
            else parseArgs0 rest (anbxonp { cryptoSecureRandomAlgorithm = Just arg })

    | x == cmdSwitchSymbol ++ cmdHMacAlgorithm = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) ->
            if null arg
            then anbxonp { outmessage = Just (parsingErrorInvalidDec cmdHMacAlgorithm) }
            else parseArgs0 rest (anbxonp { cryptoHMacAlgorithm = Just arg })

    | x == cmdSwitchSymbol ++ cmdMessageDigestAlgorithm = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) ->
            if null arg
            then anbxonp { outmessage = Just (parsingErrorInvalidDec cmdMessageDigestAlgorithm) }
            else parseArgs0 rest (anbxonp { cryptoMessageDigestAlgorithm = Just arg })

    | x == cmdSwitchSymbol ++ cmdKeyAgreementAlgorithm = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) ->
            if null arg
            then anbxonp { outmessage = Just (parsingErrorInvalidDec cmdKeyAgreementAlgorithm) }
            else parseArgs0 rest (anbxonp { cryptoKeyAgreementAlgorithm = Just arg })

     | x == cmdSwitchSymbol ++ cmdKeyAgreementKeyPairGenerationScheme = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) ->
            if null arg
            then anbxonp { outmessage = Just (parsingErrorInvalidDec cmdKeyAgreementKeyPairGenerationScheme) }
            else parseArgs0 rest (anbxonp { cryptoKeyAgreementKeyPairGenerationScheme = Just arg })

    | x == cmdSwitchSymbol ++ cmdDHRndExpSize = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) -> case readMaybe arg of
            Just i  -> parseArgs0 rest (anbxonp { cryptoDHRndExpSize = Just i })
            Nothing -> anbxonp { outmessage = Just (parsingErrorInvalidDecHyphen cmdDHRndExpSize) }

    | x == cmdSwitchSymbol ++ cmdECGenParameterSpec = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) ->
            if null arg
            then anbxonp { outmessage = Just (parsingErrorInvalidDec cmdECGenParameterSpec) }
            else parseArgs0 rest (anbxonp { cryptoECGenParameterSpec = Just arg })

    | x == cmdSwitchSymbol ++ cmdAsymCipherSchemeBlock = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) ->
            if null arg
            then anbxonp { outmessage = Just (parsingErrorInvalidDec cmdAsymCipherSchemeBlock) }
            else parseArgs0 rest (anbxonp { cryptoAsymCipherSchemeBlock = Just arg })

    | x == cmdSwitchSymbol ++ cmdSSLContext = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) ->
            if null arg
            then anbxonp { outmessage = Just (parsingErrorInvalidDec cmdSSLContext) }
            else parseArgs0 rest (anbxonp { cryptoSSLContext = Just arg })

    | x == cmdSwitchSymbol ++ cmdSecurityProvider = case xs of
        [] -> anbxonp { outmessage = Just (parsingErrorMissing x) }
        (arg:rest) ->
            if null arg
            then anbxonp { outmessage = Just (parsingErrorInvalidDec cmdSecurityProvider) }
            else parseArgs0 rest (anbxonp { cryptoSecurityProvider = Just arg })

    -- AnBx implementation type

    | x == cmdAnBxImplType ++ "CCM" = parseArgs0 xs (anbxonp { anbximpltype=CCM })
    | x == cmdAnBxImplType ++ "CCM2" = parseArgs0 xs (anbxonp { anbximpltype=CCM2 })
    | x == cmdAnBxImplType ++ "CCM3" = parseArgs0 xs (anbxonp { anbximpltype=CCM3 })
    | x == cmdAnBxImplType ++ "CCM4" = parseArgs0 xs (anbxonp { anbximpltype=CCM4 })
    | x == cmdAnBxImplType ++ "APP" = parseArgs0 xs (anbxonp { anbximpltype=APP })
    | x == cmdAnBxImplType ++ "CIF" = parseArgs0 xs (anbxonp { anbximpltype=CIF })
    | x == cmdAnBxImplType ++ "CIF2" = parseArgs0 xs (anbxonp { anbximpltype=CIF2 })
    | x == cmdAnBxImplType ++ "CIF3" = parseArgs0 xs (anbxonp { anbximpltype=CIF3 })
    | x == cmdAnBxImplType ++ "AANB" = parseArgs0 xs (anbxonp { anbximpltype=AANB })
    -- AnBx debug output type
    | x == cmdAnBxDebugType ++ "None" = parseArgs0 xs (anbxonp { anbxdebugtype=DNone })
    | x == cmdAnBxDebugType ++ "AnB" = parseArgs0 xs (anbxonp { anbxdebugtype=DAnB })
    | x == cmdAnBxDebugType ++ "AnB2AnBx" = parseArgs0 xs (anbxonp { anbxdebugtype=DAnB2AnBx })
    | x == cmdAnBxDebugType ++ "AnBEqTheory" = parseArgs0 xs (anbxonp { anbxdebugtype=DAnBEqTheory })
    | x == cmdAnBxDebugType ++ "AnBIntrGoal" = parseArgs0 xs (anbxonp { anbxdebugtype=DAnBIntrGoal, nogoals=True })
    | x == cmdAnBxDebugType ++ "AnBx" = parseArgs0 xs (anbxonp { anbxdebugtype=DAnBx })
    | x == cmdAnBxDebugType ++ "Java" = parseArgs0 xs (anbxonp { anbxdebugtype=DJava, optimize=True, synthesistypeenc=(SynthesisTypeEnc {enc=True,encS=True})})            -- Java by default uses probabilistic encryption
    | x == cmdAnBxDebugType ++ "JavaNoOpt" = parseArgs0 xs (anbxonp { anbxdebugtype=DJavaNoOpt, optimize=False, synthesistypeenc=(SynthesisTypeEnc {enc=True,encS=True})})
    | x == cmdAnBxDebugType ++ "JavaCode" = parseArgs0 xs (anbxonp { anbxdebugtype=DJavaCode, optimize=True })
    | x == cmdAnBxDebugType ++ "SpyerPN" = parseArgs0 xs (anbxonp { anbxdebugtype=DSpyer })
    | x == cmdAnBxDebugType ++ "Defs" = parseArgs0 xs (anbxonp { anbxdebugtype=DDefs })
    | x == cmdAnBxDebugType ++ "Execnarr" = parseArgs0 xs (anbxonp { anbxdebugtype=DExecnarr })
    | x == cmdAnBxDebugType ++ "NExecnarr" = parseArgs0 xs (anbxonp { anbxdebugtype=DNExecnarr, optimize=False })
    | x == cmdAnBxDebugType ++ "OptExecnarr" = parseArgs0 xs (anbxonp { anbxdebugtype=DOptExecnarr, optimize=True })
    | x == cmdAnBxDebugType ++ "KnowExecnarr" = parseArgs0 xs (anbxonp { anbxdebugtype=DKnowExecnarr })
    | x == cmdAnBxDebugType ++ "SPI" = parseArgs0 xs (anbxonp { anbxdebugtype=DSPI })
    | x == cmdAnBxDebugType ++ "VDM" = parseArgs0 xs (anbxonp { anbxdebugtype=DVDM })
    | x == cmdAnBxDebugType ++ "PV" = parseArgs0 xs (anbxonp { anbxdebugtype=DPV })
    | x == cmdAnBxDebugType ++ "PVT" = parseArgs0 xs (anbxonp { anbxdebugtype=DPVT })
    | x == cmdAnBxDebugType ++ "PVTAnB" = parseArgs0 xs (anbxonp { anbxdebugtype=DPVTAnB })
    | x == cmdAnBxDebugType ++ "PVTCBAB" = parseArgs0 xs (anbxonp { anbxdebugtype=DPVTCBAB })
    | x == cmdAnBxDebugType ++ "PVTJava" = parseArgs0 xs (anbxonp { anbxdebugtype=DPVTJava })
    -- AnBx output type
    | x == cmdAnBxOutType ++ "None" = parseArgs0 xs (anbxonp { anbxouttype=None })
    | x == cmdAnBxOutType ++ "ProtName" = parseArgs0 xs (anbxonp { anbxouttype=ProtName })
    | x == cmdAnBxOutType ++ "AnB" = parseArgs0 xs (anbxonp { anbxouttype=AnB })
    | x == cmdAnBxOutType ++ "AnBx" = parseArgs0 xs (anbxonp { anbxouttype=AnBx })
    | x == cmdAnBxOutType ++ "AnBEqTheory" = parseArgs0 xs (anbxonp { anbxouttype=AnBEqTheory })
    | x == cmdAnBxOutType ++ "AnBStats" = parseArgs0 xs (anbxonp { anbxouttype=AnBStats })
    | x == cmdAnBxOutType ++ "AnBStatsCSV" = parseArgs0 xs (anbxonp { anbxouttype=AnBStatsCSV })
    | x == cmdAnBxOutType ++ "AnBIF" = parseArgs0 xs (anbxonp { anbxouttype=AnBIF })
    | x == cmdAnBxOutType ++ "AnBIntr" = parseArgs0 xs (anbxonp { anbxouttype=AnBIntr })
    | x == cmdAnBxOutType ++ "AnBxIntr" = parseArgs0 xs (anbxonp { anbxouttype=AnBxIntr })
    | x == cmdAnBxOutType ++ "AnBLatex" = parseArgs0 xs (anbxonp { anbxouttype=AnBLatex })
    | x == cmdAnBxOutType ++ "AnBxLatex" = parseArgs0 xs (anbxonp { anbxouttype=AnBxLatex })
    | x == cmdAnBxOutType ++ "Java" = parseArgs0 xs (anbxonp { anbxouttype=Java, optimize=True, synthesistypeenc=(SynthesisTypeEnc {enc=True,encS=True})})
    | x == cmdAnBxOutType ++ "JavaNoOpt" = parseArgs0 xs (anbxonp { anbxouttype=JavaNoOpt, optimize=False, synthesistypeenc=(SynthesisTypeEnc {enc=True,encS=True})})
    | x == cmdAnBxOutType ++ "JavaDocker" = parseArgs0 xs (anbxonp { anbxouttype=JavaDocker, optimize=True, synthesistypeenc=(SynthesisTypeEnc {enc=True,encS=True})})
    | x == cmdAnBxOutType ++ "SpyerPN" = parseArgs0 xs (anbxonp { anbxouttype=Spyer })
    | x == cmdAnBxOutType ++ "Execnarr" = parseArgs0 xs (anbxonp { anbxouttype=Execnarr })
    | x == cmdAnBxOutType ++ "OptExecnarr" = parseArgs0 xs (anbxonp { anbxouttype=OptExecnarr, optimize=True })
    | x == cmdAnBxOutType ++ "TypedOptExecnarr" = parseArgs0 xs (anbxonp { anbxouttype=TypedOptExecnarr, optimize=True })
    | x == cmdAnBxOutType ++ "TypedOptExecnarrDocker" = parseArgs0 xs (anbxonp { anbxouttype=TypedOptExecnarrDocker, optimize=True })
    | x == cmdAnBxOutType ++ "KnowExecnarr" = parseArgs0 xs (anbxonp { anbxouttype=KnowExecnarr })
    | x == cmdAnBxOutType ++ "SPI" = parseArgs0 xs (anbxonp { anbxouttype=SPI })
    | x == cmdAnBxOutType ++ "VDM" = parseArgs0 xs (anbxonp { anbxouttype=VDM })
    | x == cmdAnBxOutType ++ "PV" = parseArgs0 xs (anbxonp { anbxouttype=PV })
    | x == cmdAnBxOutType ++ "PVT" = parseArgs0 xs (anbxonp { anbxouttype=PVT })
    | x == cmdAnBxOutType ++ "PVT_AnB" = parseArgs0 xs (anbxonp { anbxouttype=PVTAnB })
    | x == cmdAnBxOutType ++ "PVT_CBAB" = parseArgs0 xs (anbxonp { anbxouttype=PVTCBAB })
    | x == cmdAnBxOutType ++ "PVT_Java" = parseArgs0 xs (anbxonp { anbxouttype=PVTJava })
    -- ProVerif parameters 
    | x == cmdPvProbEnc = parseArgs0 xs (anbxonp { pvProbEnc=True, synthesistypeenc=(SynthesisTypeEnc {enc=True,encS=True}) }) -- if probabilistic encryption is used, set also SynthesisTypeEnc
    | x == cmdPvReachEvents = parseArgs0 xs (anbxonp { pvReachEvents=True })
    | x == cmdPvNoMutual = parseArgs0 xs (anbxonp { pvNoMutual=True })
    | x == cmdPvPreciseActions = parseArgs0 xs (anbxonp { pvPreciseActions=True })
    | x == cmdPvVerboseGoalReacheable = parseArgs0 xs (anbxonp { pvVerboseGoalReacheable=True })
    | x == cmdPvVerboseStatistics = parseArgs0 xs (anbxonp { pvVerboseStatistics=True })
    | x == cmdPvTagFunTT = parseArgs0 xs (anbxonp { pvTagFunTT=True })
    -- ProVerif Xor theories 
    | x == cmdPvXorTheory ++ "none" = parseArgs0 xs (anbxonp { pvXorTheory = PVXorNone })
    | x == cmdPvXorTheory ++ "basic" = parseArgs0 xs (anbxonp { pvXorTheory = PVXorBasic })
    | x == cmdPvXorTheory ++ "simple" = parseArgs0 xs (anbxonp { pvXorTheory = PVXorSimple })
    | x == cmdPvXorTheory ++ "ass" = parseArgs0 xs (anbxonp { pvXorTheory = PVXorAss })
    | x == cmdPvXorTheory ++ "comm" = parseArgs0 xs (anbxonp { pvXorTheory = PVXorComm })
    | x == cmdPvXorTheory ++ "full" = parseArgs0 xs (anbxonp { pvXorTheory = PVXorFull })
    -- VDM parameters     
    | x == cmdVdmTest ++ "SG" = parseArgs0 xs (anbxonp { anbxouttype=VDMTest, vdmtesttype=VDMTestSG})
    | x == cmdVdmTest ++ "WF" = parseArgs0 xs (anbxonp { anbxouttype=VDMTest, vdmtesttype=VDMTestWF})
    | x == cmdVdmTestModuleName = case xs of
                                [] -> (anbxonp { outmessage = Just (parsingErrorMissing x) })
                                _ -> parseArgs0 (tail xs) (anbxonp { vdmtestmodulename= Just (head xs) })
    -- Optimisation parameters
    | x == cmdBasicOpt = parseArgs0 xs (anbxonp { basicopt=True })
    | x == cmdFilterFailingChecks = parseArgs0 xs (anbxonp { filterFailingChecks=True })
    | x == cmdCheckType ++ "none" = parseArgs0 xs (anbxonp { checkType=CheckNone, synthesistypeenc=(SynthesisTypeEnc {enc=True,encS=True}) })
    | x == cmdCheckType ++ "eq" = parseArgs0 xs (anbxonp { checkType=CheckEq, synthesistypeenc=(SynthesisTypeEnc {enc=True,encS=True}) })
    | x == cmdCheckType ++ "opt" = parseArgs0 xs (anbxonp { checkType=CheckOpt, synthesistypeenc=(SynthesisTypeEnc {enc=True,encS=True}) })
    | x == cmdCheckType ++ "optfail" = parseArgs0 xs (anbxonp { checkType=CheckOptFail , synthesistypeenc=(SynthesisTypeEnc {enc=False,encS=False}) })
    | x == cmdCheckType ++ "all" = parseArgs0 xs (anbxonp { checkType=CheckAll, synthesistypeenc=(SynthesisTypeEnc {enc=False,encS=False}) })      -- enc are different!

    | x == cmdSynthesisTypeEnc ++ "00" = parseArgs0 xs (anbxonp { synthesistypeenc=(SynthesisTypeEnc {enc=False,encS=False}) })
    | x == cmdSynthesisTypeEnc ++ "01" = parseArgs0 xs (anbxonp { synthesistypeenc=(SynthesisTypeEnc {enc=False,encS=True}) })
    | x == cmdSynthesisTypeEnc ++ "10" = parseArgs0 xs (anbxonp { synthesistypeenc=(SynthesisTypeEnc {enc=True,encS=False}) })
    | x == cmdSynthesisTypeEnc ++ "11" = parseArgs0 xs (anbxonp { synthesistypeenc=(SynthesisTypeEnc {enc=True,encS=True}) })

    | x == cmdCheckOptLevel = case xs of
                                    [] -> (anbxonp { outmessage = Just (parsingErrorMissing x) })
                                    (arg:rest) -> case readMaybe arg :: Maybe Int of
                                                        Just i  -> parseArgs0 rest (anbxonp { checkOptLevel = case i of
                                                                                                                            0 -> CheckOptLevel0
                                                                                                                            1 -> CheckOptLevel1
                                                                                                                            2 -> CheckOptLevel2
                                                                                                                            3 -> CheckOptLevel3
                                                                                                                            _ -> CheckOptLevel4
                                                                                                                        })
                                                        Nothing -> anbxonp { outmessage = Just (parsingErrorInvalidDec cmdCheckOptLevel) }
    | x == cmdMaxMethodSize  = case xs of
                                    [] -> (anbxonp { outmessage = Just (parsingErrorMissing x) })
                                    (arg:rest) -> case readMaybe arg of
                                        Just i  -> parseArgs0 rest (anbxonp { maxMethodSize = i })
                                        Nothing -> anbxonp { outmessage = Just (parsingErrorInvalidDec cmdMaxMethodSize) }
    | x == cmdMaxActionsOpt = case xs of
                                    [] -> (anbxonp { outmessage = Just (parsingErrorMissing x) })
                                    (arg:rest) -> case readMaybe arg of
                                        Just i  -> parseArgs0 rest (anbxonp { maxActionsOpt = i })
                                        Nothing -> anbxonp { outmessage = Just (parsingErrorInvalidDec cmdMaxActionsOpt) }

    -- Goal parameters

    | x == cmdNoGoals = parseArgs0 xs (anbxonp { nogoals=True })
    | x == cmdSingleGoals = parseArgs0 xs (anbxonp { singlegoals=True })
    | x == cmdGroupGoals = parseArgs0 xs (anbxonp { groupgoals=True })
    | x == cmdNoPrivateKeyGoals = parseArgs0 xs (anbxonp { noprivatekeygoals=True })
    | x == cmdGoalIndex = case xs of
                                    [] -> (anbxonp { outmessage = Just (parsingErrorMissing x) })
                                    (arg:rest) -> case readMaybe arg of
                                        Just i  -> parseArgs0 rest (anbxonp { goalindex = i })
                                        Nothing -> anbxonp { outmessage = Just (parsingErrorInvalidDec cmdGoalIndex) }
    | x == cmdRelaxGoalsOtherAgentKnow = parseArgs0 xs (anbxonp { relaxGoalsOtherAgentKnow=True })
    | x == cmdOfmcTrace = case xs of
                             [] -> (anbxonp { outmessage = Just (parsingErrorMissing x) })
                             _ -> parseArgs0 (tail xs) (anbxonp { ofmctracefilename=Just (head xs)})
    -- error
    | otherwise = (anbxonp { outmessage = Just (parsingErrorUnrecognised x) })


parsingErrorPrefix :: String
parsingErrorPrefix = "Error parsing arguments. "

parsingErrorUnrecognised :: String -> String
parsingErrorUnrecognised x = parsingErrorPrefix ++ "The following argument was not recognised: " ++ x

parsingErrorMissing :: String -> String
parsingErrorMissing x = parsingErrorPrefix ++ "Missing parameter after " ++ x

parsingErrorInvalidDecHyphen :: String -> String
parsingErrorInvalidDecHyphen x = parsingErrorInvalidDec (cmdSwitchSymbol ++ x)

parsingErrorInvalidDec :: String -> String
parsingErrorInvalidDec x = parsingErrorPrefix ++ "Invalid declaration of the parameter required for argument " ++ x

-- return files with extension ext
getFilesWithExt :: FilePath -> String -> IO [FilePath]
getFilesWithExt path ext = do
                       files <- getDirectoryContents path
                       return (sort (filter (\p -> takeExtension p == extSeparator : ext) files))

getProtNames :: [FilePath] -> [String]
getProtNames files = map takeBaseName files

main :: IO String
main = do
         args <- getArgs
         let anbxonp = parseArgs args
         let noCfgMsg = nocfgmsg anbxonp  -- flag to suppress config and header in the output
         case outmessage anbxonp of
            Just m -> do
                      putStrLn m
                      return m
            _ -> do
                     let filename = anbxfilename anbxonp
                     let outtype = anbxouttype anbxonp
                     case outtype of
                          VDMTest -> do
                                        exists <- doesDirectoryExist filename
                                        do
                                          if exists then
                                            do -- if modulename is not speficied resort to defaults
                                              let modulename = fromMaybe (vdmTestModuleNameDefault (vdmtesttype anbxonp)) (vdmtestmodulename anbxonp)

                                              let outfile = modulename ++ [extSeparator] ++ getExt outtype
                                              let header = if noCfgMsg then "" else
                                                                            fullProductName ++ "\n" ++ "Input directory: " ++ filename ++ "\n" ++ "Output file: " ++ outfile ++ "\n"
                                              putStr header
                                              list <- getFilesWithExt filename (getExt outtype)
                                              let outprot = showVDMTest (vdmtesttype anbxonp) modulename (getProtNames list)
                                              putStr outprot
                                              writeFile outfile outprot
                                              return outprot
                                            else
                                                return "Directory not found - This option requires a valid path"
                          _ -> do
                                  time (takeBaseName filename) noCfgMsg $ do
                                      zt <- getZonedTime
                                      let header = if noCfgMsg then "" else
                                                                    fullProductName ++ "\n" ++ "Started at " ++ show zt ++ "\n" ++ "Input file: " ++ filename ++ "\n"
                                      putStr header
                                      hFlush stdout
                                      str <- readFile filename
                                      cfg <- getCfg anbxonp
                                      if anbximpltype anbxonp==AANB && outtype /= AnB then
                                        return (show AANB ++ " implementation can only be used for AnB file generation")
                                       else do
                                         let anbxprot = getProt str
                                         traceInfo <- case ofmctracefilename anbxonp of
                                                        Just tracefile -> do
                                                                            trace <- readFile tracefile
                                                                            let (anbxTrace,wpassintr,imps,trActsIndexes,intrMsgToPrint) = reconstructAttackTrace filename trace anbxonp cfg anbxprot
                                                                            let trFileName = addExtension (dropExtension filename ++ attackTraceSuffix) (show PTAnBx)
                                                                            let output = showAnBx anbxTrace
                                                                            let showStdOut = not (silentStdOut anbxonp)
                                                                            _ <- writeOutputFile trFileName outtype output showStdOut
                                                                            return (Just (compileAnBx trFileName anbxonp{anbexeccheck=False} cfg anbxTrace Nothing, trFileName,wpassintr,imps,trActsIndexes,intrMsgToPrint))
                                                        Nothing -> return Nothing

                                         case traceInfo of
                                           Just (trProt,trFileName,wPassiveIntr,impersonations,trActsIndexes,intrMsgToPrint) ->
                                             let trImpsAndProt = Just (impersonations,trProt,trActsIndexes,intrMsgToPrint)
                                             in if isOutTypeJava outtype then
																									putStr "Entering Java code generation" >> hFlush stdout >>
                                                  codegen trFileName anbxonp wPassiveIntr trImpsAndProt cfg
                                                else
																									putStr "Entering AnBx output generation" >> hFlush stdout >>
																									file2IntermediateFormats trFileName anbxonp outtype wPassiveIntr cfg trImpsAndProt
                                           Nothing -> if isOutTypeJava outtype then
																												putStr "Entering Java code generation (no traceInfo)" >> hFlush stdout >>
                                                        codegen filename anbxonp anbxprot Nothing cfg
                                                      else if outtype `elem` [AnBx,AnBIntr,AnBxIntr,AnBxLatex] then
																												putStr "Entering AnBx output generation (no traceInfo)" >> hFlush stdout >>
                                                        getAnBxOut filename anbxonp anbxprot cfg
                                                      else
																												putStr "Entering AnB output generation (no traceInfo)" >> hFlush stdout >>
                                                        file2IntermediateFormats filename anbxonp outtype anbxprot cfg Nothing

mkAnBxIntr :: AnBxProtocol -> AnBxOnP -> AnBxProtocol
mkAnBxIntr prot@(_,types,_,_,_,_,_,_,_) anbxonp = let
                                                        agents = getAgents types
                                                        intr = anbxmitm anbxonp
                                                  in     -- introduce explicity the passive intruder in the protocol specification
                                                            -- A -> B: Msg => A -> Intr: Msg; Intr -> B: Msg
                                                            -- intr must be a variable different from the agents
                                                        if (isVarId intr || isHonest intr) && notElem intr agents then buildAnBxIntr prot anbxonp intr
                                                                    else error (intr ++ " is an invalid parameter for " ++ cmdAnBxMitm ++ "\n" ++ "An identifier different from the agents is required")

getAnBxOut :: String -> AnBxOnP -> AnBxProtocol -> AnBxCfg -> IO String
getAnBxOut filename anbxonp prot cfg = let
                                         prot1 = case anbxouttype anbxonp of
                                                    AnBxLatex -> prot
                                                    AnBxIntr -> mkAnBxIntr prot anbxonp
                                                    AnBIntr -> mkAnBxIntr prot anbxonp
                                                    AnBx -> replicateAnBx prot anbxonp
                                                    out -> error ("getAnBxOut - unexpected output type at this stage: " ++ show out)
                                      in printAnBx prot1 filename anbxonp cfg

-- print the protocol specification with passive intruder
printAnBx :: AnBxProtocol -> String -> AnBxOnP -> AnBxCfg -> IO String
printAnBx anbxprot filename anbxonp cfg = let
                                        outtype = anbxouttype anbxonp
                                        showStdOut = not (silentStdOut anbxonp)
                                        intr = anbxmitm anbxonp
                                        basename = dropExtension filename
                                        basename1 = case outtype of
                                                            AnBxIntr -> basename ++ "_" ++ intr
                                                            AnBIntr -> basename ++ "_" ++ intr
                                                            AnBx -> basename ++ "_x" ++ show (anbxreplicate anbxonp)
                                                            _ -> basename
                                        outfile = addExtension basename1 (getExt outtype)
                                     in do
                                            case outtype of
                                                AnBxIntr -> printProtocolAnBx anbxprot outfile outtype showStdOut showAnBx
                                                AnBIntr -> let
                                                                prot = trAnB anbxprot anbxonp
                                                           in printProtocol prot AnB anbxonp cfg outfile Nothing
                                                AnBxLatex -> printProtocolAnBx anbxprot outfile outtype showStdOut (showLatex PTAnBx)
                                                AnBx -> printProtocolAnBx anbxprot outfile outtype showStdOut showAnBx
                                                out -> error ("printAnBx - unexpected output type at this stage: " ++ show out)

-- code generation to Java and other targets
codegen :: String -> AnBxOnP -> AnBxProtocol -> OFMCAttackImpersonationsAndProt -> AnBxCfg -> IO String
codegen filename anbxonp anbxprot impsAndTrProt cfg = do
                            let prot@(_,types,_,_,_,_,_,_,_) = compileAnBx filename (anbxonp {anbxdebugtype=DNone}) cfg anbxprot Nothing
                            let agents = getAgents types
                            let gencode = dbgJavaCode prot anbxonp cfg impsAndTrProt
                            let targetLanguage = outType2Str (anbxouttype anbxonp)
                            putStrLn (targetLanguage ++ " files will be generated in: " ++ pathJavaDest cfg)
                            case agent anbxonp of
                                Just a -> if elem a agents then gencode else error ("agent " ++ a ++ " does not exist!")
                                Nothing -> gencode

addIntrDecl :: AnBxProtocol -> String -> AnBxProtocol
addIntrDecl (protname,types,defs,eqs,(kn,wh),sh,abst,acts,goals) intrName =
  let agentType = AnBxAst.Agent False False [] NoCert
  in (protname, (agentType,[intrName]):
       --((AnBxAst.Function [AnBxAst.FunSign ([agentType],agentType,PubFun)]), [pseudonymFun]):
      types, defs,eqs,((intrName, [Atom intrName]):kn,wh),sh,abst,acts,goals)


-- returns the trace reconstruction protocol, the original protocol with a passive intruder, the impersonations, intruder's trace actions indexes and the potential secret to print
reconstructAttackTrace :: String -> String -> AnBxOnP -> AnBxCfg -> AnBxProtocol -> (AnBxProtocol,AnBxProtocol,SubjectiveImpersonations,[Int],Maybe Msg)
reconstructAttackTrace filename trace anbxonp cfg anbxprot =
      let
        intrName = anbxmitm anbxonp
        withIntrDecl@((_,prottype),_,_,_,_,_,_,_,_) = addIntrDecl anbxprot intrName -- add intr beforehand for it not to be considered as forged id
        wPassiveIntr@(_,_,_,_,anbknow,_,_,_,_) = splitWithIntrAnB (compileAnBx filename anbxonp{anbexeccheck=False} cfg withIntrDecl Nothing) intrName
        (trProt,trHonestknowSec,trActsIndexes,intrMsgToPrint) = getNamedTrace trace wPassiveIntr prottype anbxonp --with indexes of trace acts relative to passive intruder acts
      in (trAnB2AnBx (Just prottype) trProt,
          trAnB2AnBx (Just prottype) wPassiveIntr,
          getSubjectiveImpersonations anbknow trHonestknowSec intrName, trActsIndexes,intrMsgToPrint)


-- process intermediate formats from file storing protocol specification
file2IntermediateFormats :: String -> AnBxOnP -> OutType -> AnBxProtocol -> AnBxCfg -> OFMCAttackImpersonationsAndProt -> IO String
file2IntermediateFormats filename anbxonp outtype anbxprot cfg trProtData =
                        let
                            prot = compileAnBx filename anbxonp cfg anbxprot trProtData
                            basename = dropExtension filename
                            basename0 = case outprotsuffix anbxonp of -- add suffix to file name is any is specified
                                            Just s -> basename ++ s
                                            Nothing -> basename
                            outfile0 = addExtension basename0 (getExt outtype)
                            outfile = case outtype of
                                            VDM -> pathVdmDest cfg ++ takeFileName outfile0 -- only filename
                                            _   -> outfile0
                        in do case outtype of
                                o | elem o [AnB,AnBIF] -> case trProtData of
                                                            Nothing -> anb2IntermediateFormats prot basename0 anbxonp outtype cfg outfile trProtData
                                                            _ -> return "" -- skip generation of trace AnB/IF file with trace reconstruction
                                _   -> if isOutTypePV outtype then anb2IntermediateFormats prot basename0 anbxonp outtype cfg outfile trProtData
                                       else printProtocol prot outtype anbxonp cfg outfile trProtData

-- option for base index for Goals: used by single goal generation
data BaseGoalRange = BaseGoalZero | BaseGoalOne

-- convertion to a numberical value (Int), used for computatioin of indexes
valueofBaseGoal :: BaseGoalRange -> Int
valueofBaseGoal BaseGoalZero = 0
valueofBaseGoal BaseGoalOne = 1

-- the base index (Int)
goalBaseIndex :: Int
goalBaseIndex = valueofBaseGoal BaseGoalOne         -- typically users will enumerate goals from 1, but it can be changed here

cardinal2OrdinalSuffix :: Int -> String
cardinal2OrdinalSuffix 1 = "st"
cardinal2OrdinalSuffix 2 = "nd"
cardinal2OrdinalSuffix 3 = "rd"
cardinal2OrdinalSuffix _ = "th"

-- index computation depending on base
indexofGoal :: Int -> Int -> Int
indexofGoal base i | valueofBaseGoal BaseGoalZero == base = i
indexofGoal base i | valueofBaseGoal BaseGoalOne == base = i - 1
indexofGoal base _ = error ("maxGoalIndex - goalBaseIndex " ++ show base ++ " is not allowed")

-- max index depending on base
maxGoalIndex :: [a] -> Int -> Int
maxGoalIndex [] _ = error "maxGoalIndex - empty list"
maxGoalIndex xs base | valueofBaseGoal BaseGoalZero == base = length xs - 1
maxGoalIndex xs base | valueofBaseGoal BaseGoalOne == base = length xs
maxGoalIndex _ base = error ("maxGoalIndex - goalBaseIndex " ++ show base ++ " is not allowed")

-- process intermediate formats from protocol specification in AnB format
anb2IntermediateFormats :: Protocol -> String -> AnBxOnP -> OutType -> AnBxCfg -> String -> OFMCAttackImpersonationsAndProt -> IO String
anb2IntermediateFormats prot@(_,_,_,_,_,_,_,_,goals) basename anbxonp outtype cfg outfile trProtData
                                     | groupgoals anbxonp = do
                                                     -- print protocols with set of goals of the same type
                                                     createDirectoryIfMissing False basename
                                                     let groupgoals = mkGroupGoals goals
                                                     printProtocolGoals prot basename outtype anbxonp cfg groupgoals trProtData
                                     | singlegoals anbxonp = do
                                                     -- print length(goals) protocols with a single goal
                                                     createDirectoryIfMissing False basename
                                                     let groupgoals = zip (map (\x -> [x]) goals) (goal2enum goals goalBaseIndex)
                                                     printProtocolGoals prot basename outtype anbxonp cfg groupgoals trProtData
                                     | isJust (goalindex anbxonp) = do
                                                    -- print the protocol with the goalindex-th goal
                                                    createDirectoryIfMissing False basename
                                                    let mygoalindex = fromJust (goalindex anbxonp)
                                                    let groupgoals = if (mygoalindex >= goalBaseIndex) && (mygoalindex <= maxGoalIndex goals goalBaseIndex) then
                                                                        let mygoal = [goals!!indexofGoal goalBaseIndex mygoalindex] in zip (map (\x -> [x]) mygoal) (goal2enum goals mygoalindex)
                                                                     else
                                                                        error ("index error: the " ++ show mygoalindex ++ cardinal2OrdinalSuffix mygoalindex  ++ " index does not exist: range[" ++ show goalBaseIndex ++ "-" ++ show (maxGoalIndex goals goalBaseIndex) ++"]")
                                                    printProtocolGoals prot basename outtype anbxonp cfg groupgoals trProtData
                                     | otherwise = printProtocol prot outtype anbxonp cfg outfile trProtData

checkProtName :: Protocol -> AnBxOnP -> String
checkProtName ((protname,_),_,_,_,_,_,_,_,_) anbxonp = let basename = takeBaseName (anbxfilename anbxonp) in
                                                   "Protocol: " ++ protname ++
                                                if map toLower protname == map toLower basename
                                                        then " == "
                                                        else " != Filename: " ++ basename
type GroupGoals = [(Goals,String)]

mkGroupGoals :: Goals -> GroupGoals
mkGroupGoals goals = let
                        chgoals = [x | x@ChGoal {} <- goals]
                        secrecygoals = [x | x@Secret {} <- goals]
                        authgoals = [x | x@Authentication {} <- goals]
                        wauthgoals = [x | x@WAuthentication {} <- goals]
                     in [(chgoals,"ChGoal"),(secrecygoals,"Conf"),(authgoals,"Auth"),(wauthgoals,"WAuth")]

goal2enum :: Goals -> Int -> [String]
goal2enum [] _ = []
goal2enum [_] y = [printf "%02d" (y::Int)]
goal2enum (_:xs) y = printf "%02d" (y::Int) : goal2enum xs (y+1)

printProtocolAnBx :: AnBxProtocol -> FilePath -> OutType -> Bool -> (AnBxProtocol -> String) -> IO String
-- printProtocolAnBx  _ outfile _ _ | trace ("printProtocolAnBx\n\toutfile: " ++ show outfile ++ "\n") False = undefined
printProtocolAnBx prot outfile outtype showStdOut showAnBx = do
                                                                let outprot = showAnBx prot
                                                                writeOutputFile outfile outtype outprot showStdOut

printProtocol :: Protocol -> OutType -> AnBxOnP -> AnBxCfg -> String -> OFMCAttackImpersonationsAndProt -> IO String
-- printProtocol _ _ _ _ outfile _ | trace ("printProtocol\n\toutfile: " ++ show outfile ++ "\n") False = undefined
printProtocol prot outtype options cfg outfile trProtData | isOutTypeNoSaveFile outtype = do
                                                                                            let output = getOut prot outtype options cfg trProtData
                                                                                            putStr output
                                                                                            return output
                                                          | outtype == AnBEqTheory && protHasEquations prot = do
                                                                let filename = pathOfmcStdEqTheory cfg
                                                                exists <- doesFileExist filename
                                                                if exists then do -- read the config file
                                                                                let showStdOut = not (silentStdOut options)
                                                                                stdEqTheory <- readFile filename
                                                                                let output = showEqTheory prot options ++ "\n\n" ++ stdEqTheory
                                                                                writeOutputFile outfile AnBEqTheory output showStdOut
                                                                            else error ("File " ++ filename ++ " does not exist")
                                                          | outtype == AnBEqTheory = do
                                                                                        let output = noEqMsg $ protName prot
                                                                                        putStr output
                                                                                        return output
                                                          | otherwise = writeOutputFile outfile outtype output showStdOut
                                                                where
                                                                    output = getOut prot outtype options cfg trProtData
                                                                    showStdOut = not (silentStdOut options)

printProtocolGoals :: Protocol -> String -> OutType -> AnBxOnP -> AnBxCfg -> GroupGoals -> OFMCAttackImpersonationsAndProt -> IO String
printProtocolGoals prot basename outtype options cfg groupgoals trProtData = do
                               mapM_ (\(x,y) ->
                                                if null x then return ""
                                                else
                                                    let
                                                        newprot = replaceGoals prot x
                                                        newfilename = combine basename ((takeFileName basename ++ "_") ++ y)
                                                        outfile = addExtension newfilename (getExt outtype)
                                                    in printProtocol newprot outtype options cfg outfile trProtData) groupgoals
                               return ""

replaceGoals :: Protocol -> Goals -> Protocol
replaceGoals (protocolname,types,definitions,equations,knowledge,shares,abstraction,actions,_) goals = (protocolname,types,definitions,equations,knowledge,shares,abstraction,actions,goals)

compileAnBx :: String -> AnBxOnP -> AnBxCfg -> AnBxProtocol -> OFMCAttackImpersonationsAndProt -> Protocol
compileAnBx filename options cfg anbxprot trProtData = let
                                      ext = takeExtension filename
                                      anbxprot1 = setInterpretation anbxprot ext
                                      anbxprot2 = case outprotsuffix options of   -- add suffix to protocol name is any is specified
                                                    Just s -> renameProtocol anbxprot1 (getProtName anbxprot1 ++ s)
                                                    Nothing -> anbxprot1
                                      -- if passiveIntruder option is enabled it compiles the AnBxIntr version of the AnBx protocol
                                      anbxprot3 = if passiveIntruder options then mkAnBxIntr anbxprot2 options else anbxprot
                                      prot = buildAnB anbxprot3 options
                                   in case anbxdebugtype options of
                                                DNone -> if isExtAnB ext && (elem outtype [TypedOptExecnarr,TypedOptExecnarrDocker] || isOutTypePV outtype || isOutTypeJava outtype ) then
                                                            error ("Direct code generation from a " ++ ext ++ " file to " ++ show outtype
                                                            ++ " is not possible due to lack of function type signatures.\n"
                                                            ++ "Please rename the file to " ++ [extSeparator] ++ show PTAnBx ++ ","
                                                            ++ " add explicit function type signatures and (optionally) set " ++ show PTAnB ++" interpretation.")
                                                            else prot
                                                         where outtype = anbxouttype options
                                                DAnB -> error (getOut prot AnB options cfg trProtData)
                                                DAnB2AnBx -> error (showAnBx . trAnB2AnBx Nothing $ prot)
                                                -- DAnB2AnBx -> let
                                                --                prot1 = trAnB2AnBx Nothing $ prot
                                                --                prot2 = buildAnB prot1 options
                                                --             in error (showAnB prot2)
                                                -- DAnB2AnBx -> let
                                                --                prot1 = trAnB2AnBx Nothing $ prot
                                                --                prot2 = mkAnB prot1 options
                                                --             in error (showAnBx prot2)                                                             
                                                DAnBEqTheory -> error (showEqTheory prot options)
                                                DAnBIntrGoal -> error (showAnBx . trAnB2AnBx Nothing $ protAttackTraceGoals prot (anbxmitm options) options)
                                                DAnBx -> error (showAnBx anbxprot)
                                                DDefs -> error (dbgDefs anbxprot options)
                                                DJava -> error (getOut prot Java options cfg trProtData)
                                                DSpyer -> error (getOut prot Spyer options cfg trProtData)
                                                DExecnarr -> error (getOut prot Execnarr options cfg trProtData)
                                                DNExecnarr -> error (getOut prot OptExecnarr options cfg trProtData)
                                                DOptExecnarr -> error (getOut prot OptExecnarr options cfg trProtData)
                                                DKnowExecnarr -> error (dbgKnowExecnarr prot options)
                                                DSPI -> error (getOut prot SPI options cfg trProtData)
                                                DPV -> error (getOut prot PV options cfg trProtData)
                                                DPVT -> error (getOut prot PVT options cfg trProtData)
                                                DPVTAnB -> error (getOut prot PVTAnB options cfg trProtData)
                                                DPVTCBAB -> error (getOut prot PVTCBAB options cfg trProtData)
                                                DPVTJava -> error (getOut prot PVTJava options cfg trProtData)
                                                DVDM -> error (getOut prot VDM options cfg trProtData)
                                                d -> error ("unsupported debugging type:  " ++ show d)

isExtAnB :: String -> Bool
isExtAnB ext = map toLower ext == extSeparator : map toLower (getExt AnB)

-- set AnB intepretation if file extension is "AnB"
setInterpretation :: AnBxProtocol -> String -> AnBxProtocol
setInterpretation ((pName,pType),anbxTypes,anbxDefinitions,anbxEquations,anbxKnowledge,anbxShares,anbxAbstraction,anbxActions,anbxGoals) ext =
                        let
                            protType1 = if isExtAnB ext then PTAnB else pType
                        in ((pName,protType1),anbxTypes,anbxDefinitions,anbxEquations,anbxKnowledge,anbxShares,anbxAbstraction,anbxActions,anbxGoals)
                        -- in error (show ext)

getProt :: String -> AnBxProtocol
getProt inputstr = anbxparser . alexScanTokens $ inputstr
-- getProt inputstr = error (show (anbxparser.AnBxLexer.alexScanTokens $ inputstr))
-- getProt inputstr = error (show (AnBxLexer.alexScanTokens $inputstr))

buildAnB :: AnBxProtocol -> AnBxOnP -> Protocol
buildAnB anbxprot options = trAnB (mkAnB anbxprot options) options

dbgPV :: Protocol -> OutType -> AnBxOnP -> AnBxCfg  -> String
dbgPV prot pvout options cfg = printPvtOfExecnarr (mkProt2J prot Nothing options cfg) options pvout

getOut :: Protocol -> OutType -> AnBxOnP -> AnBxCfg -> OFMCAttackImpersonationsAndProt -> String
getOut protocol outtype options cfg trProtData = let
                                        -- translation to AnB adds public keys of unknown agents if they exist. 
                                        -- This is to inform next steps (e.g. ProVerif) to verify the protocol, not for OFMC verification
                                        prot = trAnBAddPublicKeys protocol
                                        showStdOut = not (silentStdOut options)
                                      in case outtype of
                                        None -> error "No output was requested"
                                        ProtName -> checkProtName prot options
                                        AnB -> showAnB protocol                 -- AnB analyse the standard protocol
                                        AnBStats -> (if showStdOut then showAnB protocol ++ "\n" else "")  ++ showAnBStats protocol AnBStats
                                        AnBStatsCSV -> (if showStdOut then showAnB protocol ++ "\n" else "") ++ showAnBStats protocol AnBStatsCSV
                                        AnBIF -> let -- experiment
                                                     args = defaultAnBOpts {numSess = Just (ifsessions options), eqnoexec = True, noowngoal = True} -- eqnoexec = False == standard IF
                                                 in mkIF protocol args options
                                        AnBLatex -> showLatex PTAnB protocol
                                        Spyer -> dbgSpyer prot options
                                        Execnarr -> dbgExecnarr prot trProtData options
                                        KnowExecnarr -> dbgKnowExecnarr prot options
                                        OptExecnarr -> dbgNExecnarr prot trProtData options
                                        TypedOptExecnarr -> dbgJava prot trProtData options cfg
                                        TypedOptExecnarrDocker -> dbgJava prot trProtData options cfg
                                        Java -> dbgJava prot trProtData options cfg
                                        JavaNoOpt -> dbgJava prot trProtData options cfg
                                        JavaDocker -> dbgJava prot trProtData options cfg
                                        SPI -> dbgSpyerSPI prot trProtData options
                                        PV -> dbgPV prot PV options cfg
                                        PVT -> dbgPV prot PVT options cfg
                                        PVTAnB -> dbgPV prot PVTAnB options cfg
                                        PVTCBAB -> dbgPV prot PVTCBAB options cfg
                                        PVTJava -> dbgPV prot PVTJava options cfg
                                        VDM -> showVDM prot VDMIndent   -- VDMLine | VDMIndent
                                        s -> error ("getOut - unsupported output type: " ++ show s)

existConfigFileEntry :: ConfigParser -> String -> String -> Bool
existConfigFileEntry cp category entryname = let
                                                value :: Either CPError String
                                                value = get cp category entryname
                                             in not (isLeft value) && (let
                                                                          v1 = forceEither value
                                                                       in not (all isSpace v1))

readConfigFileEntry :: ConfigParser -> String -> String -> Maybe String -> String
readConfigFileEntry cp category entryname defaultValue = let
                                                            value :: Either CPError String
                                                            value = get cp category entryname
                                                         in if isLeft value then
                                                             case defaultValue of
                                                                Nothing -> error (entryname ++ " entry not found" ++ "\nPlease check your config file")
                                                                Just v -> v
                                                            else let
                                                                    v1 = forceEither value
                                                                 in if all isSpace v1 then error (entryname ++ " entry found but no value was specified" ++ "\nPlease check your config file")
                                                                    else v1

-- Read a parameter name, a string and it checks if it is a valid integer
readIntParam :: String -> String -> Int
readIntParam par s = case readMaybe s :: Maybe Int of
              Just i  -> i
              Nothing -> error ("Error in parameter " ++ par ++ ": " ++ s ++ " is not an integer")


-- some strings used multiple in the config file processing
cfgEntryDefault :: String
cfgEntryDefault = "DEFAULT"
cfgEntryInteface :: String
cfgEntryInteface = "interface"
cfgEntryIpAddress :: String
cfgEntryIpAddress = "ipAddress"
cfgEntryDockerIPBase :: String
cfgEntryDockerIPBase = "dockerIPBase"

getCfg :: AnBxOnP -> IO AnBxCfg
getCfg anbxonp = do
                            let fileName = anbxcfgfile anbxonp
                            exists <- doesFileExist fileName
                            if exists
                                then do -- read the config file
                                    val <- readfile emptyCP fileName
                                    let cp = forceEither val
                                    let v_pathSTemplates = readConfigFileEntry cp cfgEntryDefault "pathSTemplates" Nothing
                                    let v_pathJavaDest = readConfigFileEntry cp cfgEntryDefault "pathJavaDest" Nothing
                                    let v_pathVdmDest = readConfigFileEntry cp cfgEntryDefault "pathVdmDest" Nothing
                                    let v_pathOfmcStdEqTheory = readConfigFileEntry cp cfgEntryDefault "pathOfmcStdEqTheory" Nothing
                                    let v_keyPathDefault = readConfigFileEntry cp cfgEntryDefault "keyPathDefault" Nothing
                                    let v_sharePathDefault = readConfigFileEntry cp cfgEntryDefault "sharePathDefault" Nothing
                                    let v_anbxjPathDefault = readConfigFileEntry cp cfgEntryDefault "anbxjPathDefault" Nothing
                                    let v_functionsST = readConfigFileEntry cp cfgEntryDefault "functionsST" Nothing
                                    let v_aliases = readConfigFileEntry cp cfgEntryDefault "aliases" Nothing

                                    let v_interface = if existConfigFileEntry cp cfgEntryDefault cfgEntryInteface then readConfigFileEntry cp cfgEntryDefault cfgEntryInteface  Nothing else ""
                                    eth_ipAddress <- getIpAddress v_interface
                                    let ip = readConfigFileEntry cp cfgEntryDefault cfgEntryIpAddress (Just eth_ipAddress)
                                    v_ipAddress <- case Net.IPv4.decodeString ip of
                                            Just p -> return p
                                            Nothing -> do
                                                -- Try adjusting the ethernet interface name if the IP address cannot be decoded (eth <=> en)
                                                adjustedInterface <- adjustInterfaceName v_interface
                                                adjustedIp <- getIpAddress adjustedInterface
                                                case Net.IPv4.decodeString adjustedIp of
                                                    Just p -> return p
                                                    Nothing -> error (cfgError ip (cfgEntryInteface ++ " = " ++ v_interface ++ " or " ++ cfgEntryIpAddress) fileName)
                                    let v_startingPort = let
                                                            param = "startingPort"
                                                            v_port = readIntParam param (readConfigFileEntry cp cfgEntryDefault param (Just (show defaultStartingPort)))
                                                         in case mkPortRange v_port of
                                                                Nothing -> error (cfgError (show  v_port) param fileName)
                                                                Just sp -> sp
                                    -- read docker config
                                    let v_dockerImage = readConfigFileEntry cp cfgEntryDefault "dockerImage" Nothing
                                    let v_dockerDYImage = readConfigFileEntry cp cfgEntryDefault "dockerDYImage" Nothing
                                    let v_dockerMemLimit = case jdockerMEMLimit anbxonp of
                                                                Nothing -> readConfigFileEntry cp cfgEntryDefault "dockerMemLimit" Nothing
                                                                Just s -> s -- use value specified from the command line, if provided
                                    let v_dockerCPUQuota = let param = "dockerCPUQuota" in
                                                                case jdockerCPUQuota anbxonp of
                                                                Nothing -> readIntParam param (readConfigFileEntry cp cfgEntryDefault param Nothing)
                                                                Just i -> i -- use value specified from the command line, if provided
                                    let v_dockerSharedFolder = readConfigFileEntry cp cfgEntryDefault "dockerSharedFolder" Nothing
                                    let v_dockerJavaRoot = readConfigFileEntry cp cfgEntryDefault "dockerJavaRoot" Nothing
                                    let v_dockerJavaDest = readConfigFileEntry cp cfgEntryDefault "dockerJavaDest" Nothing
                                    let v_dockerIPBase = let
                                                            ip = readConfigFileEntry cp cfgEntryDefault cfgEntryDockerIPBase Nothing
                                                        in case Net.IPv4.decodeString ip of
                                                            Just p -> if private p then p else error ("The parameter " ++ map toLower cfgEntryDockerIPBase ++ " (" ++ encodeString p ++ ") must be in the private range")
                                                            Nothing -> error (cfgError ip cfgEntryDockerIPBase fileName)
                                    let v_dockerDYTimeout = let param =  "dockerSessionTimeout" in
                                                                readIntParam param (readConfigFileEntry cp cfgEntryDefault param (Just (show dockerSessionTimeoutDefault)))
                                    let v_dockerDYMinTimeout = let param =  "dockerDYMinTimeout" in
                                                                readIntParam param (readConfigFileEntry cp cfgEntryDefault param (Just (show dockerDYMinTimeoutDefault)))
                                    let v_dockerDYInterval = let param =  "dockerDYInterval" in
                                                                readIntParam param (readConfigFileEntry cp cfgEntryDefault param (Just (show dockerDYIntervalDefault)))
                                    -- read crypto_config --
                                    -- use values specified from the command line if provided
                                    let c_cipherScheme = case cryptoCipherScheme anbxonp of
                                                                Nothing -> readConfigFileEntry cp cfgEntryDefault cmdCipherScheme Nothing
                                                                Just s -> s
                                    let c_asymcipherSchemeBlock = case cryptoAsymCipherSchemeBlock anbxonp of
                                                                Nothing -> readConfigFileEntry cp cfgEntryDefault cmdAsymCipherSchemeBlock Nothing
                                                                Just s -> s
                                    let c_keyGenerationScheme = case cryptoKeyGenerationScheme anbxonp of
                                                                Nothing -> readConfigFileEntry cp cfgEntryDefault cmdKeyGenerationScheme Nothing
                                                                Just s -> s
                                    let c_keyGenerationSchemePBE = case cryptoKeyGenerationSchemePBE anbxonp of
                                                                Nothing -> readConfigFileEntry cp cfgEntryDefault cmdKeyGenerationSchemePBE Nothing
                                                                Just s -> s
                                    let c_keyGenerationSize = case cryptoKeyGenerationSize anbxonp of
                                                                Nothing -> readConfigFileEntry cp cfgEntryDefault cmdKeyGenerationSize Nothing
                                                                Just s -> show s
                                    let c_keyPairGenerationScheme = case cryptoKeyPairGenerationScheme anbxonp of
                                                                Nothing -> readConfigFileEntry cp cfgEntryDefault cmdKeyPairGenerationScheme Nothing
                                                                Just s -> s
                                    let c_keyPairGenerationSize = case cryptoKeyPairGenerationSize anbxonp of
                                                                Nothing -> readConfigFileEntry cp cfgEntryDefault cmdKeyPairGenerationSize Nothing
                                                                Just s -> show s
                                    let c_secureRandomAlgorithm = case cryptoSecureRandomAlgorithm anbxonp of
                                                                Nothing -> readConfigFileEntry cp cfgEntryDefault cmdSecureRandomAlgorithm Nothing
                                                                Just s -> s
                                    let c_keyAgreementAlgorithm = case cryptoKeyAgreementAlgorithm anbxonp of
                                                                Nothing -> readConfigFileEntry cp cfgEntryDefault cmdKeyAgreementAlgorithm Nothing
                                                                Just s -> s
                                    let c_keyAgreementKeyPairGenerationScheme = case cryptoKeyAgreementKeyPairGenerationScheme anbxonp of
                                                                Nothing -> readConfigFileEntry cp cfgEntryDefault cmdKeyAgreementKeyPairGenerationScheme (Just (keyAgreementKeyPairGenerationScheme cryptoConfigDefault))
                                                                Just s -> s
                                    let c_hMacAlgorithm = case cryptoHMacAlgorithm anbxonp of
                                                                Nothing -> readConfigFileEntry cp cfgEntryDefault cmdHMacAlgorithm Nothing
                                                                Just s -> s
                                    let c_messageDigestAlgorithm = case cryptoMessageDigestAlgorithm anbxonp of
                                                                Nothing -> readConfigFileEntry cp cfgEntryDefault cmdMessageDigestAlgorithm Nothing
                                                                Just s -> s
                                    let c_keySize = case cryptoKeySize anbxonp of
                                                                Nothing -> readConfigFileEntry cp cfgEntryDefault cmdKeySize Nothing
                                                                Just s -> show s
                                    let c_dhRndExpSize = case cryptoDHRndExpSize anbxonp of
                                                                Nothing -> readConfigFileEntry cp cfgEntryDefault cmdDHRndExpSize Nothing
                                                                Just s -> show s
                                    let c_ecGenParameterSpec = case cryptoECGenParameterSpec anbxonp of
                                                                Nothing -> readConfigFileEntry cp cfgEntryDefault cmdECGenParameterSpec (Just (ecGenParameterSpec cryptoConfigDefault))
                                                                Just s -> s
                                    let c_sslContext = case cryptoSSLContext anbxonp of
                                                                Nothing -> readConfigFileEntry cp cfgEntryDefault cmdSSLContext (Just (sslContext cryptoConfigDefault))
                                                                Just s -> s
                                    let c_securityProvider = case cryptoSecurityProvider anbxonp of
                                                                Nothing -> readConfigFileEntry cp cfgEntryDefault cmdSecurityProvider (Just (securityProvider cryptoConfigDefault))
                                                                Just s -> s
                                    let c_config = CryptoConfig {
                                            cipherScheme = c_cipherScheme,
                                            asymcipherSchemeBlock = c_asymcipherSchemeBlock,
                                            keyGenerationScheme = c_keyGenerationScheme,
                                            keyGenerationSchemePBE = c_keyGenerationSchemePBE,
                                            keyGenerationSize = readIntParam cmdKeyGenerationSize c_keyGenerationSize,
                                            keyPairGenerationScheme = c_keyPairGenerationScheme,
                                            keyPairGenerationSize = readIntParam cmdKeyPairGenerationSize c_keyPairGenerationSize,
                                            secureRandomAlgorithm = c_secureRandomAlgorithm,
                                            hMacAlgorithm = c_hMacAlgorithm,
                                            messageDigestAlgorithm = c_messageDigestAlgorithm,
                                            keyAgreementAlgorithm = c_keyAgreementAlgorithm,
                                            keyAgreementKeyPairGenerationScheme = c_keyAgreementKeyPairGenerationScheme,
                                            keySize = readIntParam cmdKeySize c_keySize,
                                            dhRndExpSize = readIntParam cmdDHRndExpSize c_dhRndExpSize,
                                            ecGenParameterSpec = c_ecGenParameterSpec,
                                            sslContext = c_sslContext,
                                            securityProvider = c_securityProvider
                                        }
                                    let cfgFile = AnBxCfg {
                                                            pathSTemplates = v_pathSTemplates,
                                                            pathJavaDest = v_pathJavaDest,
                                                            pathVdmDest = v_pathVdmDest,
                                                            pathOfmcStdEqTheory = v_pathOfmcStdEqTheory,
                                                            sharePathDefault = v_sharePathDefault,
                                                            keyPathDefault = v_keyPathDefault,
                                                            anbxjPathDefault = v_anbxjPathDefault,
                                                            functionsST = words v_functionsST,
                                                            cfgAliases = words v_aliases,
                                                            cryptoConfig = c_config,
                                                            interface = v_interface,
                                                            ipAddress = v_ipAddress,
                                                            startingPort = v_startingPort,
                                                            dockerImage = v_dockerImage,
                                                            dockerDYImage = v_dockerDYImage,
                                                            dockerMemLimit = v_dockerMemLimit,
                                                            dockerCPUQuota = v_dockerCPUQuota,
                                                            dockerSharedFolder = v_dockerSharedFolder,
                                                            dockerJavaRoot = v_dockerJavaRoot,
                                                            dockerJavaDest = v_dockerJavaDest,
                                                            dockerIPBase = v_dockerIPBase,
                                                            dockerSessionTimeout = v_dockerDYTimeout,
                                                            dockerDYMinTimeout = v_dockerDYMinTimeout,
                                                            dockerDYInterval = v_dockerDYInterval
                                                        }
                                    let outMsg = if nocfgmsg anbxonp then "" else
                                            "Config File found: " ++ fileName  ++ "\n" ++
                                            "Templates Path: " ++ v_pathSTemplates ++ "\n" ++
                                            "Java Code Destination: " ++ v_pathJavaDest ++ "\n" ++
                                            "VDM Code Destination: " ++ v_pathVdmDest ++ "\n" ++
                                            "OFMC Standard EqTheory Location: " ++  v_pathOfmcStdEqTheory ++ "\n" ++
                                            "Shared Knowledge Default Path: " ++ v_sharePathDefault ++ "\n" ++
                                            "KeyStore Default Path: " ++ v_keyPathDefault ++ "\n" ++
                                            "AnBxJ Library Default Path: " ++ v_anbxjPathDefault ++ "\n" ++
                                            "FunctionsST: " ++ v_functionsST ++ "\n" ++
                                            "Aliases: " ++ v_aliases ++ "\n" ++
                                            "Interface: " ++ v_interface ++ "\n" ++
                                            "IP Address: " ++ show v_ipAddress ++ "\n" ++
                                            "Starting Port: " ++ show v_startingPort ++ "\n" ++
                                            "Docker Image: " ++ v_dockerImage ++ "\n" ++
                                            "Docker DY Image: " ++ v_dockerDYImage ++ "\n" ++
                                            "Docker Mem Limit: " ++ v_dockerMemLimit ++ "\n" ++
                                            "Docker CPU Quota: " ++ show v_dockerCPUQuota ++ "\n" ++
                                            "Docker Shared Folder: " ++ v_dockerSharedFolder ++ "\n" ++
                                            "Docker Java Root: " ++ v_dockerJavaRoot ++ "\n" ++
                                            "Docker Java Code Destination: " ++ v_dockerJavaDest ++ "\n" ++
                                            "Docker IP Base Address: " ++ show v_dockerIPBase ++ "\n" ++
                                            "Docker Session Timeout: " ++ show v_dockerDYTimeout ++ "s" ++ "\n" ++
                                            "Docker DY Min Timeout: " ++ show v_dockerDYMinTimeout ++ "s" ++  "\n" ++
                                            "Docker DY Interval: " ++ show v_dockerDYInterval ++ "s" ++  "\n" ++
                                            "Crypto Configuration: " ++ show c_config ++ "\n" ++
                                            "Config File processed" ++ "\n"
                                    putStrLn outMsg
                                    return cfgFile
                                else do
                                        error ("Configuration file " ++ fileName ++ " not found - The program cannot run without a config file")

time :: String -> Bool -> IO t -> IO t
time protname nocfgmsg a = do
    start <- getCPUTime
    v <- a
    end  <- getCPUTime
    let diff = fromIntegral (end - start) / 10 ^ (12 :: Integer)
    let footer = if nocfgmsg
                 then ""
                 else printf "Filename: %s\nComputation time: %0.3f sec\n\n" protname (diff :: Double)
    putStr footer
    return v

-- make all public keys available to all agents (this allows to verify the key if an agent name is learned)
trAnBAddPublicKeys :: Protocol -> Protocol
trAnBAddPublicKeys (pname,types,definitions,equations,knowledge,shares,abstractions,actions,goals) = (pname,types,definitions,equations,trAnBAddPublicKeysKnowledge knowledge,shares,abstractions,actions,goals)

trAnBAddPublicKeysKnowledge :: Knowledge -> Knowledge
trAnBAddPublicKeysKnowledge (k,kw) = let
                                publickeys = concat ( concatMap (\(_,msgs) -> ( [ m | (Comp Inv m) <- msgs])) k )
                                k1 = map (\(ag,msgs) -> (ag,nubOrd (msgs ++ publickeys))) k
                             -- in error (showKnowledge (k1,kw)) -- (k1,kw)
                             in (k1,kw)

-- true if the nic exists
nicIpAddress :: NetworkInterface -> String -> Bool
nicIpAddress _ "" = False
nicIpAddress x s = take (length s) (map toLower (name x)) == s

getIpAddress :: String -> IO String
-- getIpAddress interfaceName | trace ("getIpAddress\n\tinterfaceName: " ++ show interfaceName) False = undefined
getIpAddress interfaceName = do
                                    ns <- getNetworkInterfaces
                                    -- let ns1 = [ x | x <- ns, nicIpAddress x "eth" || nicIpAddress x "en" ]      -- "eth" win/linux, "en" mac
                                    let ns1 = [ x | x <- ns, nicIpAddress x interfaceName ]
                                    return $ case ns1 of
                                                    [] -> show defaultHostClient
                                                    _ -> showInterface (head ns1)

-- adjusts the interface name as "eth" for Linux/Windows is equivalent to "en" for Mac0S
adjustInterfaceName :: String -> IO String
adjustInterfaceName interfaceName = pure $ case os of
    "darwin"   -> convertEthToEn interfaceName  -- MacOS
    "mingw32"  -> convertEnToEth interfaceName  -- Windows
    osName | elem osName ["linux", "linux-android", "freebsd", "netbsd", "openbsd"] -> convertEnToEth interfaceName     -- Linux/Android/BSDs
    _          -> interfaceName

-- fix error on MacOS when interface is set to "eth"
convertEthToEn :: String -> String
convertEthToEn name =
    if "eth" `isPrefixOf` name
        then "en" ++ drop 3 name
        else name

-- fix error on Linux/Windows when interface is set to "en"
convertEnToEth :: String -> String
convertEnToEth name =
    if "en" `isPrefixOf` name
        then "eth" ++ drop 2 name
        else name

showInterface :: NetworkInterface -> String
showInterface n = show (Network.Info.ipv4 n)

