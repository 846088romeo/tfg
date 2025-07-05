{-

 AnBx Compiler and Code Generator

 Copyright 2011-2025 Paolo Modesti
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
{-# LANGUAGE InstanceSigs #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "Use infix" #-}

module AnBxOnP where
import Main_Common
import Data.List (intercalate)
import Control.Monad (when)
import Control.Exception (IOException, catch, evaluate)

-- AnBx implementation type
data ImplType = CCM | CCM2 | CCM3 | CCM4 | APP | CIF | CIF2 | CIF3 | AANB deriving (Eq,Show)

data DebugType = DNone | DAnBx | DAnB | DAnB2AnBx | DAnBEqTheory | DAnBIntrGoal | DJava | DJavaNoOpt | DJavaCode | DJavaDocker | DSpyer | DKnowledge | DDefs | DExecnarr | DNExecnarr | DOptExecnarr | DKnowExecnarr | DSPI | DPV | DPVT | DPVTAnB | DPVTCBAB | DPVTJava | DVDM | DAPS deriving (Eq,Show)

data OutType = None | ProtName | AnBx | AnB | AnBEqTheory | AnBStats | AnBStatsCSV | AnBIF | AnBIntr | AnBxIntr | AnBLatex | AnBxLatex | Java | JavaNoOpt | JavaDocker | Spyer | Execnarr | OptExecnarr | TypedOptExecnarr | TypedOptExecnarrDocker | KnowExecnarr | SPI | PV | PVT | PVTAnB | PVTCBAB | PVTJava | VDM | VDMTest deriving (Eq,Show)

isOutTypePV :: OutType -> Bool
isOutTypePV x = elem x [PV,PVT,PVTAnB,PVTCBAB,PVTJava]

isOutTypeJava :: OutType -> Bool
isOutTypeJava x = elem x [Java,JavaNoOpt,JavaDocker]

isOutAnB :: OutType -> Bool
isOutAnB x = elem x [AnB,AnBEqTheory,AnBStats,AnBStatsCSV,AnBIntr,AnBLatex,AnBxLatex]

isOutTypeNoSaveFile :: OutType -> Bool
isOutTypeNoSaveFile x = elem x [ProtName,AnBStats,AnBStatsCSV,KnowExecnarr]

isExecNarr :: OutType -> Bool
isExecNarr x = elem x [Execnarr,OptExecnarr,TypedOptExecnarr,TypedOptExecnarrDocker,KnowExecnarr]

productNameWithOptions :: AnBxOnP -> String
productNameWithOptions opt = if omitverdatetime opt then productName else fullProductName

data CheckType = CheckAll | CheckOpt | CheckOptFail | CheckEq | CheckNone deriving (Eq)
instance Show CheckType where
    show :: CheckType -> String
    show CheckAll = "all"
    show CheckOpt = "opt"
    show CheckOptFail = "optfail"
    show CheckEq = "eq"
    show CheckNone = "none"

listOfCheckTypes :: String
listOfCheckTypes = intercalate "|" $ map show [CheckAll, CheckOpt, CheckOptFail, CheckEq, CheckNone]

data CheckOptLevel = CheckOptLevel0 | CheckOptLevel1 | CheckOptLevel2 | CheckOptLevel3 | CheckOptLevel4 deriving (Eq)
instance Show CheckOptLevel where
    show :: CheckOptLevel -> String
    show CheckOptLevel0 = "0"
    show CheckOptLevel1 = "1"
    show CheckOptLevel2 = "2"
    show CheckOptLevel3 = "3"
    show CheckOptLevel4 = "4"

-- data EqSyntType = EqSyntType1 | EqSyntType2  deriving (Eq)

data SynthesisTypeEnc = SynthesisTypeEnc {enc:: Bool, encS::Bool}     --  true=considers randomisation - false=standard spyer synthesis
    deriving (Eq,Show)

data DigestType = DTAbstract | DTExpanded             -- used only symbolically (verification)  | digest concrete implementation

data PVXorTheory = PVXorNone | PVXorBasic | PVXorSimple | PVXorAss | PVXorComm | PVXorFull

instance Show PVXorTheory where
        show :: PVXorTheory -> String
        show PVXorNone = "none"
        show PVXorBasic = "basic"
        show PVXorSimple = "simple"
        show PVXorAss = "associativity"
        show PVXorComm = "commutativity"
        show PVXorFull = "full"

-- Define JFRSettings
data JFRSettings = JFRSettingsDefault 
                 | JFRSettingsProfile 
                 | JFRFilePath FilePath
                 deriving (Eq) 

instance Show JFRSettings where
    show :: JFRSettings -> String
    show JFRSettingsDefault = "default"
    show JFRSettingsProfile = "profile"
    show (JFRFilePath path) = path

data VDMTestType = VDMTestSG | VDMTestWF

vdmTestModuleNameDefault :: VDMTestType -> String
vdmTestModuleNameDefault VDMTestSG = "AnB_trace_satisfy_goals"
vdmTestModuleNameDefault VDMTestWF = "AnB_trace_wf"

data AnBxOnP = AnBxOnP {
                         anbxfilename :: String,
                         outmessage :: Maybe String,
                         outprotsuffix :: Maybe String,
                         anbximpltype :: ImplType,
                         anbxdebugtype :: DebugType,
                         anbxouttype :: OutType,
                         anbxcfgfile :: FilePath,
                         anbxmitm  ::  String,
                         anbxmitmpubknowledge :: Bool,
                         anbxreplicate :: Int,
                         nocfgmsg :: Bool,
                         anbxusetags :: Bool,
                         anbxif2cif :: Bool,
                         anbxexpandbullets :: Bool,
                         anbxexpandagree :: Bool,
                         ifsessions :: Int,
                         ifstrictwhere :: Bool,
                         nogoals :: Bool,
                         noprivatekeygoals :: Bool,
                         singlegoals :: Bool,
                         goalindex :: Maybe Int,
                         groupgoals :: Bool,
                         guessprivatefunctions :: Bool,
                         noshareguess :: Bool,
                         anbtypecheck :: Bool,
                         anbexeccheck :: Bool,
                         anbknowcheck :: Bool,
                         relaxGoalsOtherAgentKnow :: RelaxGoalsOtherAgentKnow,
                         optimize :: Bool,
                         do_opt :: Bool,
                         maxMethodSize :: Int,
                         maxActionsOpt :: Int,
                         checkType :: CheckType,
                         checkOptLevel :: CheckOptLevel,
                         silentCode :: Bool,
                         silentStdOut :: Bool,
                         jfr :: Bool,
                         jfrlabel :: String,
                         jfrsettings :: JFRSettings,
                         jdockerpcap :: Bool,
                         jdockerCPUQuota :: Maybe Int,
                         jdockerMEMLimit :: Maybe String,
                         jsessions :: Int,
                         jabortonfail :: Bool,
                         jexectime :: Bool,
                         omitverdatetime :: Bool,
                         filterFailingChecks :: Bool,
                         agent :: Maybe String,
                         synthesistypeenc :: SynthesisTypeEnc,
--                                 anasynmode :: AnaSynMode,
                         basicopt :: Bool,
                         digesttype :: DigestType,
                         vdmtesttype :: VDMTestType,
                         vdmtestmodulename :: Maybe String,
                         pvProbEnc :: Bool,
                         pvReachEvents :: Bool,
                         pvNoMutual :: Bool,
                         pvTagFunTT :: Bool,
                         pvXorTheory :: PVXorTheory,
                         pvPreciseActions :: Bool,
                         pvVerboseGoalReacheable :: Bool,
                         pvVerboseStatistics :: Bool,
                         ofmctracefilename :: Maybe FilePath,
                         passiveIntruder :: Bool,
                         objcheck :: Bool,
                         -- cryptoConfig parameters
                         cryptoCipherScheme :: Maybe String,
                         cryptoKeySize :: Maybe Int,
                         cryptoKeyGenerationScheme :: Maybe String,
                         cryptoKeyGenerationSchemePBE :: Maybe String,
                         cryptoKeyGenerationSize :: Maybe Int,
                         cryptoKeyPairGenerationScheme :: Maybe String,
                         cryptoKeyPairGenerationSize :: Maybe Int,
                         cryptoSecureRandomAlgorithm :: Maybe String,
                         cryptoHMacAlgorithm :: Maybe String,
                         cryptoMessageDigestAlgorithm :: Maybe String,
                         cryptoKeyAgreementAlgorithm :: Maybe String,
                         cryptoKeyAgreementKeyPairGenerationScheme :: Maybe String,
                         cryptoDHRndExpSize :: Maybe Int,
                         cryptoECGenParameterSpec :: Maybe String,
                         cryptoAsymCipherSchemeBlock :: Maybe String,
                         cryptoSSLContext :: Maybe String,
                         cryptoSecurityProvider :: Maybe String
                         }

cfgFileDefault :: String
cfgFileDefault = shortProductName ++ ".cfg"
defmaxMethodSize :: Int
defmaxMethodSize = 50
defmaxActionsOpt :: Int
defmaxActionsOpt = 100000

defCheckType :: CheckType
defCheckType = CheckOpt

defCheckOptLevel :: CheckOptLevel
defCheckOptLevel = CheckOptLevel4

defaultJSessions :: Int
defaultJSessions = 1

defaultIFSessions :: Int
defaultIFSessions = 2

minIFSessions :: Int
minIFSessions = 0           -- (n > minIFSessions)

minAnBxReplicate :: Int
minAnBxReplicate = 1        -- (n > minAnBxReplicate)

anbxMitmDefaultFun :: OutType -> Maybe FilePath -> String
anbxMitmDefaultFun JavaDocker _ = "DY"
anbxMitmDefaultFun TypedOptExecnarrDocker _ = "DY"
anbxMitmDefaultFun _ Nothing = "intr"
anbxMitmDefaultFun _ (Just _) = "Intr"

anbxMitmDefault :: String
anbxMitmDefault = anbxMitmDefaultFun AnB Nothing

iname :: String
iname = "i"
--pseudonymFun = "pseudonym"

type RelaxGoalsOtherAgentKnow = Bool

defaultAnBxOnP :: AnBxOnP
defaultAnBxOnP = AnBxOnP {
                   anbxfilename = "",                           -- first parameter is the filename
                   outmessage = Nothing,                        -- output message for help or version
                   outprotsuffix = Nothing,                     -- specify a suffix to generated (base) filename (except Java); does not change extension, no space allowed
                   anbximpltype = CIF,
                   anbxdebugtype = DNone,
                   anbxouttype = AnB,
                   anbxcfgfile = cfgFileDefault,
                   anbxmitm = anbxMitmDefault,
                   anbxmitmpubknowledge = False,
                   anbxreplicate = 1,
                   ifsessions = defaultIFSessions,
                   ifstrictwhere = False,
                   nocfgmsg = False,
                   silentCode = False,                         -- suppress log messages in the generated code
                   silentStdOut = False,                       -- suppress generated file display in std output 
                   jfr = False,
                   jfrlabel = "",
                   jfrsettings = JFRSettingsDefault,
                   jexectime = False,
                   jdockerpcap = False,
                   jdockerCPUQuota = Nothing,
                   jdockerMEMLimit = Nothing,
                   jsessions = defaultJSessions,
                   jabortonfail = False,
                   omitverdatetime = False,
                   anbxusetags = False,
                   anbxif2cif = False,
                   anbxexpandbullets = False,
                   anbxexpandagree = False,
                   nogoals = False,
                   noprivatekeygoals = False,
                   singlegoals = False,
                   goalindex = Nothing,
                   groupgoals = False,
                   guessprivatefunctions = False,              -- guess AnB private functions
                   noshareguess = False,                       -- do not guess AnBx shares
                   anbtypecheck = True,                        -- typecheck AnB protocols
                   anbexeccheck = True,                        -- execcheck AnB protocols
                   anbknowcheck = True,                        -- check that every declared agent has the initial knowledge 
                   relaxGoalsOtherAgentKnow = False,           -- relax requirement that agents know other agents in goals, when needed according to the goal type  
                   optimize = True,                            -- a general directive to use optimisation
                   do_opt = True,                              -- used as a flag if optimisation is actually feasible given the maxActionsOpt option                        
                   maxMethodSize = defmaxMethodSize,           -- split step methods to avoid larger (>64kB) Java methods
                   maxActionsOpt = defmaxActionsOpt,           -- skip the optimisation when the nr of action is above this threshold to avoid out of memory error
                   checkType = CheckOpt,                       -- since in Java not all checks are implemented we say which checks to consider in optimisation
                   checkOptLevel = defCheckOptLevel,           -- for memory usage reasons, we have different levels of checks/variables optimisation
                   filterFailingChecks = False,
                   agent = Nothing,                            -- optional agent name for vertical compilation + common files
                   synthesistypeenc=(SynthesisTypeEnc {enc=False,encS=False}),  -- enc(M,K)==enc(M,K) ^ encS(M,K)==encS(M,K) (salting and randomisation in asym and sym encryption)
                   basicopt = False,                           --
                   digesttype = DTExpanded,                    -- use standard (expanded) digest type
                   vdmtesttype = VDMTestSG,                      -- default VDM test output 
                   vdmtestmodulename = Nothing,
                   pvProbEnc = False,                          -- ProVerif probabilistic encryption
                   pvReachEvents = False,                      -- ProVerif reach events printed
                   pvTagFunTT = False,                         -- ProVerif tags functions f:T -> T to prevent loops
                   pvNoMutual = False,                         -- ProVerif does not parallelise processes by permutating free agents' names
                   pvXorTheory = PVXorSimple,                  -- ProVerif simple Xor theory
                   pvPreciseActions = False,                   -- ProVerif enable preciseAction flag
                   pvVerboseGoalReacheable  = False,           -- ProVerif enable verboseGoalReacheable flag 
                   pvVerboseStatistics  = False,               -- ProVerif enable verboseStatistics flag   
                   ofmctracefilename = Nothing,                -- OFMC trace filename
                   passiveIntruder = False,
                   objcheck = False,
                   -- cryptoConfig parameters
                   cryptoCipherScheme = Nothing,
                   cryptoKeySize = Nothing,
                   cryptoKeyGenerationScheme = Nothing,
                   cryptoKeyGenerationSchemePBE = Nothing,
                   cryptoKeyGenerationSize = Nothing,
                   cryptoKeyPairGenerationScheme = Nothing,
                   cryptoKeyPairGenerationSize = Nothing,
                   cryptoSecureRandomAlgorithm = Nothing,
                   cryptoHMacAlgorithm = Nothing,
                   cryptoMessageDigestAlgorithm = Nothing,
                   cryptoKeyAgreementAlgorithm = Nothing,
                   cryptoKeyAgreementKeyPairGenerationScheme = Nothing,
                   cryptoDHRndExpSize = Nothing,
                   cryptoECGenParameterSpec = Nothing,
                   cryptoAsymCipherSchemeBlock = Nothing,
                   cryptoSSLContext = Nothing,
                   cryptoSecurityProvider = Nothing
                   }

-- command line parameters names

cmdSwitchSymbol :: String
cmdSwitchSymbol = "-"

cmdOutProtSuffix :: String
cmdOutProtSuffix = cmdSwitchSymbol ++ "outprotsuffix"

cmdVersion :: String
cmdVersion = cmdSwitchSymbol ++ "v"

cmdHelp :: String
cmdHelp = cmdSwitchSymbol ++ "help"

cmdHelp2 :: String
cmdHelp2 = "?"

cmdAnBxImplType :: String
cmdAnBxImplType = "-impl:"

cmdAnBxDebugType :: String
cmdAnBxDebugType = cmdSwitchSymbol ++ "debug:"

cmdAnBxOutType :: String
cmdAnBxOutType = cmdSwitchSymbol ++ "out:"

cmdAnBxCfgFile :: String
cmdAnBxCfgFile = cmdSwitchSymbol ++ "cfg"

cmdAnBxMitm :: String
cmdAnBxMitm = cmdSwitchSymbol ++ "mitm"

cmdAnBxMitmpubknowledge :: String
cmdAnBxMitmpubknowledge = cmdSwitchSymbol ++ "pubmitmknow"

cmdNoCfgMsg :: String
cmdNoCfgMsg = cmdSwitchSymbol ++ "nocfgmsg"

cmdSilentCode :: String
cmdSilentCode = cmdSwitchSymbol ++ "silentcode"

cmdSilent :: String
cmdSilent = cmdSwitchSymbol ++ "silent"

cmdJfr :: String
cmdJfr = cmdSwitchSymbol ++ "jfr"

cmdJfrLabel :: String
cmdJfrLabel = cmdSwitchSymbol ++ "jfrlabel"

cmdJfrSettings :: String
cmdJfrSettings = cmdSwitchSymbol ++ "jfrsettings"

cmdJDockerPCAP :: String
cmdJDockerPCAP = cmdSwitchSymbol ++ "jdockerpcap"

cmdJDockerCPUQuota :: String
cmdJDockerCPUQuota = cmdSwitchSymbol ++ "jdockercpuquota"

cmdJDockerMEMLimit :: String
cmdJDockerMEMLimit = cmdSwitchSymbol ++ "jdockermemlimit"

cmdJSessions :: String
cmdJSessions = cmdSwitchSymbol ++ "jsessions"

cmdIFSessions :: String
cmdIFSessions = cmdSwitchSymbol ++ "ifsessions"

cmdIFStrictWhere :: String
cmdIFStrictWhere = cmdSwitchSymbol ++ "ifstrictwhere"

cmdJAbortOnFail :: String
cmdJAbortOnFail = cmdSwitchSymbol ++ "jabortonfail"

cmdJExecTime :: String
cmdJExecTime = cmdSwitchSymbol ++ "jexectime"

cmdOmitVerDateTime :: String
cmdOmitVerDateTime = cmdSwitchSymbol ++ "omitverdatetime"

cmdAnBxUseTags :: String
cmdAnBxUseTags = cmdSwitchSymbol ++ "usetags"

cmdAnBxIfCif :: String
cmdAnBxIfCif = cmdSwitchSymbol ++ "if2cif"

cmdAnBxReplicate :: String
cmdAnBxReplicate = cmdSwitchSymbol ++ "replicate"

cmdAnBxExpandBullets :: String
cmdAnBxExpandBullets = cmdSwitchSymbol ++ "expandbullets"

cmdAnBxExpandAgree :: String
cmdAnBxExpandAgree = cmdSwitchSymbol ++ "expandagree"

cmdAnBTypeCheck :: String
cmdAnBTypeCheck = cmdSwitchSymbol ++ "noAnBTypeCheck"

cmdAnBExecCheck :: String
cmdAnBExecCheck = cmdSwitchSymbol ++ "noAnBExecCheck"

cmdAnBKnowCheck :: String
cmdAnBKnowCheck = cmdSwitchSymbol ++ "noAnBKnowCheck"

cmdGuessPrivateFunctions :: String
cmdGuessPrivateFunctions = cmdSwitchSymbol ++ "guessprivatefunctions"

cmdNoShareGuess :: String
cmdNoShareGuess = cmdSwitchSymbol ++ "noshareguess"

cmdRelaxGoalsOtherAgentKnow :: String
cmdRelaxGoalsOtherAgentKnow = cmdSwitchSymbol ++ "relaxgoalsotheragentknow"

cmdNoGoals :: String
cmdNoGoals = cmdSwitchSymbol ++ "nogoals"

cmdSingleGoals :: String
cmdSingleGoals = cmdSwitchSymbol ++ "singlegoals"

cmdGroupGoals :: String
cmdGroupGoals = cmdSwitchSymbol ++ "groupgoals"

cmdNoPrivateKeyGoals :: String
cmdNoPrivateKeyGoals = cmdSwitchSymbol ++ "noprivatekeygoals"

cmdGoalIndex :: String
cmdGoalIndex = cmdSwitchSymbol ++ "goalindex"

cmdMaxMethodSize :: String
cmdMaxMethodSize = cmdSwitchSymbol ++ "maxMethodSize"

cmdMaxActionsOpt :: String
cmdMaxActionsOpt = cmdSwitchSymbol ++ "maxActionsOpt"

cmdCheckType :: String
cmdCheckType = cmdSwitchSymbol ++ "checktype:"

cmdCheckOptLevel :: String
cmdCheckOptLevel = cmdSwitchSymbol ++ "checkoptlevel"

cmdFilterFailingChecks :: String
cmdFilterFailingChecks = cmdSwitchSymbol ++ "filterfailingchecks"

cmdAgent :: String
cmdAgent = cmdSwitchSymbol ++ "agent"

cmdSynthesisTypeEnc :: String
cmdSynthesisTypeEnc = cmdSwitchSymbol ++ "probenc:"

cmdBasicOpt :: String
cmdBasicOpt = cmdSwitchSymbol ++ "basicopt"

cmdDigestType :: String
cmdDigestType = cmdSwitchSymbol ++ "symdt"

cmdVdmTestModuleName :: String
cmdVdmTestModuleName = cmdSwitchSymbol ++ "vdmtestmodulename"

cmdVdmTest :: String
cmdVdmTest = cmdSwitchSymbol ++ "vdmtest:"

cmdPvProbEnc :: String
cmdPvProbEnc = cmdSwitchSymbol ++ "pvprobenc"

cmdPvReachEvents :: String
cmdPvReachEvents = cmdSwitchSymbol ++ "pvreachevents"

cmdPvVerboseGoalReacheable :: String
cmdPvVerboseGoalReacheable = cmdSwitchSymbol ++ "pvverbosegoalreacheable"

cmdPvVerboseStatistics :: String
cmdPvVerboseStatistics = cmdSwitchSymbol ++ "pvverbosestatistics"

cmdPvNoMutual :: String
cmdPvNoMutual = cmdSwitchSymbol ++ "pvnomutual"

cmdPvTagFunTT :: String
cmdPvTagFunTT = cmdSwitchSymbol ++ "pvtagfuntt"

cmdPvXorTheory :: String
cmdPvXorTheory = cmdSwitchSymbol ++ "pvxor:"

cmdPvPreciseActions :: String
cmdPvPreciseActions = cmdSwitchSymbol ++ "pvpreciseactions"

cmdOfmcTrace :: String
cmdOfmcTrace = cmdSwitchSymbol ++ "ofmctrace"

cmdPassiveIntruder :: String
cmdPassiveIntruder = cmdSwitchSymbol ++ "passiveintruder"

cmdObjCheck :: String
cmdObjCheck = cmdSwitchSymbol ++ "objcheck"

outType2Str :: OutType -> String
outType2Str outtype | isOutTypeJava outtype || isOutTypePV outtype = let
                                                                        baseLang
                                                                          | isOutTypeJava outtype = "Java"
                                                                          | isOutTypePV outtype = "ProVerif"
                                                                          | otherwise = error ("undetermined target language for output type " ++ show outtype)
                                                                        outTypeLang = show outtype
                                                                     in if baseLang == outTypeLang then baseLang
                                                                                                    else baseLang ++ " (" ++  outTypeLang ++ ")"
                    | otherwise = show outtype

writeOutputFile :: FilePath -> OutType -> String -> Bool -> IO String
writeOutputFile outfile outtype outputStr showStdOut = do
    evaluatedOutput <- evaluate (length outputStr) -- Forces evaluation
    if evaluatedOutput == 0
        then do
            let errorMsg = "\nError: output is empty, file not written: " ++ outfile
            putStrLn errorMsg
            return errorMsg
        else do
            let targetLanguage = outType2Str outtype
            result <- safeWriteFile outfile outputStr
            case result of
                Left err -> do
                    putStrLn err
                    return err
                Right _  -> do
                    when showStdOut $ do -- Show output in standard output
                        s <- readFile outfile
                        putStrLn ("\nGenerated " ++ targetLanguage ++ " File: " ++ outfile ++ "\n\n" ++ s)
                    return outputStr

safeWriteFile :: FilePath -> String -> IO (Either String ())
safeWriteFile path content = catch (Right <$> writeFile path content) handleWriteError
  where
    handleWriteError :: IOException -> IO (Either String ())
    handleWriteError e = return (Left ("\nError writing file " ++ show path ++ ":" ++ show e))

{-
writeOutputFile :: FilePath -> OutType -> String -> Bool -> IO String
writeOutputFile outfile outtype outputStr showStdOut = do
                                                            let targetLanguage = outType2Str outtype
                                                            writeFile outfile outputStr
                                                            when showStdOut $ do -- show output in standard output
                                                                s <- readFile outfile
                                                                putStrLn ("\n" ++ "Generated " ++ targetLanguage ++ " File: " ++ outfile ++ "\n\n" ++ s)
                                                            return outputStr
-}
