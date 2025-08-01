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

{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE InstanceSigs #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "Avoid lambda using `infix`" #-}
{-# HLINT ignore "Use infix" #-}

module JavaCodeGen where
import JavaAst
import AnBxOnP
import AnBAst
import AnBxMsgCommon
import AnB2NExpression
import qualified Data.Map as Map
import Text.StringTemplate
import Data.List ( find, intercalate, isPrefixOf )
import Data.List.Split
import Data.Typeable
import Data.Data
import Data.Char
import Text.StringTemplate.Classes
import System.FilePath (isRelative,takeFileName,takeExtension,(</>))
import Data.Containers.ListUtils (nubOrd)
import System.Directory
import Java_TypeSystem_JType
import JavaType
import JavaCodeGenConfig
import Data.Time
import qualified Net.IPv4
import Net.IPv4 (IPv4)

import Data.Maybe (isNothing)
import AnBxMain (getExt)
import Spyer_Message (Atom (FEq, FInv, FWff, FNotEq))
import Java_TypeSystem_Context (newContext)
import Java_TypeSystem_Evaluator (pkFunOfNExpression)
import Main_Common (version)

outFilePrefix :: FilePath -> String -> String
outFilePrefix fp prot = fp ++ prot

genCode :: JProtocol -> AnBxOnP -> AnBxCfg -> SubjectiveImpersonations -> IO String
genCode jprot@(protname,customtypes,_,shares,agree,_,roles,droles,inactiveagents,steps,channels,fields,methods,actions) options cfg imps = do
        let sharedknowledge = shares ++ agree -- this variable determines how pre-shared knowledge is considered in the code generation. 
                                              -- also check isAbstraction
        let outtype = anbxouttype options
        let outExt = sepDot ++ getExt outtype
        let isObjCheck = objcheck options
        let showStdOut = not (silentStdOut options)
        let srcpath = pathSTemplates cfg
        let destpath = pathJavaDest cfg
        let anbjxpath = anbxjPathDefault cfg
        templates <- directoryGroup srcpath :: IO (STGroup String)
        let prot = protocolName protname
        let package = packageName prot
        currentTime <- fmap show getCurrentTime
        let dirpath = destpath ++ package ++ pathSeparator
        let showverdatetime = not (omitverdatetime options)
        let commonAttribs = [("prot",St prot),("package",St package),("sessionID",St sessionID),("datetime", St currentTime),("version",St version), ("activatechannels", Bl (not isObjCheck)), ("showverdatetime", Bl showverdatetime) ]
        -- the following needs to be read from the config file 
        let dockerDYtimeoutWithSessions = show (max (jsessions options * dockerSessionTimeout cfg) (dockerDYMinTimeout cfg)) -- timeout for DY intruder docker container to allow to run initialisation and protocol
        let dockerPCAP = jdockerpcap options
        let jfrlabelStr
                    | not (jfr options) || null label = ""
                    | last label == '_' = label
                    | otherwise = label ++ "_"
                    where
                        label = jfrlabel options
        -- let jfrlabelDockerPar = if jfr options && not (null jfrlabelStr) then "-Djfrlabel=" ++ jfrlabelStr else ""
        let dockerCPUQuotaCond = dockerCPUQuota cfg > 0
        let dockerMemLimitCond = length (dockerMemLimit cfg) >= 2
        let dockerDYwait = case dylist of
                                [(_,_,secs,_,_)] -> show secs -- extra waiting time in presence of an intruder
                                _ -> "0"
                            where  dylist = [ x | x@(_,_,_,_,JDIntruder) <- droles]
        let commonAttribsDocker = [("dockerimage",St (dockerImage cfg)),("dockerdyimage",St (dockerDYImage cfg)),
                                   ("dockermemlimit",St (dockerMemLimit cfg)),("dockermemlimitcond", Bl dockerMemLimitCond),("dockercpuquota", St (show (dockerCPUQuota cfg))),("dockercpuquotacond", Bl dockerCPUQuotaCond),
                                   ("dockersharedfolder",St (dockerSharedFolder cfg)),("dockerjavaroot",St (dockerJavaRoot cfg)),("dockerjavadest",St (dockerJavaDest cfg)),
                                   ("dockerdytimeout",St dockerDYtimeoutWithSessions), ("dockerdyinterval",St (show (dockerDYInterval cfg))),
                                   ("dockersessiontimeout", St (show (dockerSessionTimeout cfg))),("dockerpcap",Bl dockerPCAP),
                                   ("dockerdyname", St (anbxmitm options)),("dockerdywait",St dockerDYwait),("dockerdyactive",Bl (not (null (ofmctracefilename options))))] 
        let ipBase = dockerIPBase cfg
        let lstRoles = listRoles roles
        let droles1 = [x | x@(_,_,_,_,JDHonest) <- droles] -- only honest agents with run in std containers, the intruder will run in the DY container
        let lstDockerRoles = listDockerRoles droles1 ipBase
        let lstChannels = listChannels "" channels
        let lstInactiveAgents = listRoles inactiveagents
        let silentcodevalue = map toLower (show . not $ silentCode options)
        let jfrValue = if jfr options then "jfr" else ""
        let sessions = show (jsessions options)
        let abortonfail = map toLower (show (jabortonfail options))
        let exectime = map toLower (show (jexectime options))
        let dockerDYIPTest = dockerRole2DYIpTest lstDockerRoles
        createDirectoryIfMissing True dirpath
        -- delete role files, as certain targets create different files $prot"_ROLE_X.java
        deleteFilesWithPattern (protname ++ "_" ++ rolePrefix) outExt dirpath
        -- files always generated
        genConfigFile options cfg dirpath outtype showStdOut jprot imps
        genFile prot dirpath templates outtype showStdOut "" "build" (commonAttribs ++ [("roles",StLst (reverse lstRoles)),("anbjxdir",St anbjxpath),(jfrValue,St jfrValue),("jsessions",St sessions),("jfrlabel",St jfrlabelStr),("jfrsettings", St (show (jfrsettings options)))])
        genFile prot dirpath templates outtype showStdOut "" "Setup" (commonAttribs ++ [("cw",St sessName),("serExt",St serExt),("shareinit",SH (varSharesInit shares)),("agreeinit",SH (varSharesInit agree)),("silentcode",St silentcodevalue)])
        genFile prot dirpath templates outtype showStdOut "" "Roles" (commonAttribs ++ [("roles",StLst (lstRoles ++ lstInactiveAgents))])
        genFile prot dirpath templates outtype showStdOut "" "Channels" (commonAttribs ++ [("channels",StLst lstChannels)])
        genFile prot dirpath templates outtype showStdOut "" "Steps" (commonAttribs ++ [("steps",StLst (listSteps steps))])
        genFile prot dirpath templates outtype showStdOut "" "Principal" commonAttribs
        genFile prot dirpath templates outtype showStdOut "" "main" (commonAttribs ++ [("exectime", St exectime)])
        genFile prot dirpath templates outtype showStdOut "" "CommandLine_Parser" (commonAttribs ++ [("roles", if isObjCheck then StLst [toRole (anbxmitm options)] else StLst lstRoles),("headroles",StLst [head lstRoles]),("tailroles", StLst (tail lstRoles)),("silentcode",St silentcodevalue)])
        genFile prot dirpath templates outtype showStdOut "" "Functions" (commonAttribs ++ [("rolemethods", RM (listPublicFunctions methods (functionsST cfg)))] ++ [("customtypes",StLst customtypes)])
        genFile prot dirpath templates outtype showStdOut "" "ObjCheck" (commonAttribs ++ [("serExt",St serExt),("steps",OC (listOCSteps actions options)),("channels",StLst lstChannels),("channelsteps",CS (listChannelSteps actions))])
        case outtype of
                JavaDocker -> do -- files generated only for Docker
                    genFile prot dirpath templates outtype showStdOut "" "docker-compose" (commonAttribs ++ commonAttribsDocker ++ [("dockerroles",DR lstDockerRoles),("dockerdyiptest",St dockerDYIPTest)])
                    genFile prot dirpath templates outtype showStdOut "" "Dockerfile" (commonAttribs ++ commonAttribsDocker)
                    genFile prot dirpath templates outtype showStdOut "" "Dockerfile_DY" (commonAttribs ++ commonAttribsDocker)
                _ -> return ""

        let genRoles x = genFile prot dirpath templates outtype showStdOut x roleXPrefix (commonAttribs ++ [("role",St x),("serExt",St serExt),
                                                                                                                        ("sessname",St sessName),
                                                                                                                        ("fieldsstatic", VD (varDeclRolesStatic x fields)),
                                                                                                                        ("fields", VD (varDeclRole x fields ++ replayVarsForRole x actions1)),
                                                                                                                        ("fieldsinit", SH (varDeclRoleInit x sharedknowledge)),
                                                                                                                        ("rolemethods", RM (listRoleMethods x methods)),
                                                                                                                        ("channels", StLst mychannels),
                                                                                                                        ("channelroles", CR (listChannelRoles x channels)),
                                                                                                                        ("channelsteps",CS (listChannelStepsRole x actions1)),
                                                                                                                        ("stepactions", SA acts),
                                                                                                                        ("extrasteps", ES exst),
                                                                                                                        ("firstchannel", St firstchannel),
                                                                                                                        ("abortonfail", St abortonfail)])
                                                                    where
                                                                        (acts,exst) = listStepActions x mysteps actions1 (maxMethodSize options) sharedknowledge options protname
                                                                        mysteps = listChannelStepsNum x actions1
                                                                        mychannels = listChannels x channels
                                                                        firstchannel = head mychannels
                                                                        actions1 = if isObjCheck then objCheckActions actions else actions
        let myroles = if isObjCheck then [rolePrefix ++ anbxmitm options] -- generate code for the intruder only (to check received messages)
                        else case agent options of
                                Just a -> [rolePrefix ++ a]           -- generate code for a single agent
                                _ -> lstRoles
        sequence_  (map genRoles myroles)
        return "done"

-- we drop send actions when objcheck is true, as we are interested only in checking received messages
objCheckActions :: [JAction] -> [JAction]
-- objCheckActions actions | trace ("objCheckActions\n\tactions: " ++ show actions) False = undefined
objCheckActions actions =  let
                               actions1 = [ x | x <- actions, not (isJEmitAction x) ]
                            in map moveStepsObjCheck actions1
                            -- moveOddJAssign 


moveStepObjCheck :: Int -> Int
moveStepObjCheck step = if odd step then div (step + 1) 2 else div step 2

-- need to move assignment to even step as odd steps are dropped for intruder when objcheck option is enabled
moveOddJAssign :: JAction -> JAction
moveOddJAssign a@(JAssign (step,role,ident,exp)) = if odd step then JAssign (step + 1,role,ident,exp) else a
moveOddJAssign a = a

moveStepsObjCheck :: JAction -> JAction
moveStepsObjCheck (JNew (step,a,k)) = JNew (moveStepObjCheck step,a,k)
moveStepsObjCheck (JEmit (step,a,ch,e,f)) = JEmit (moveStepObjCheck step,a,ch,e,f)
moveStepsObjCheck (JEmitReplay (step,a,ch,e,f)) = JEmitReplay (moveStepObjCheck step,a,ch,e,f)
moveStepsObjCheck (JReceive (step,a,ch,x)) = JReceive (moveStepObjCheck step,a,ch,x)
moveStepsObjCheck (JCheck (step,a,phi,substep)) = JCheck (moveStepObjCheck step,a,phi,substep)
moveStepsObjCheck (JAssign (step,a,x,e)) = JAssign (moveStepObjCheck step,a,x,e)
moveStepsObjCheck (JComment (step,s)) = JComment (moveStepObjCheck step,s)
moveStepsObjCheck (JCall (step,a,f)) = JCall (moveStepObjCheck step,a,f)
moveStepsObjCheck (JGoal (step,a,fact,typedlabel,e,idexpr,b,effStep)) = JGoal (step,a,fact,typedlabel,e,idexpr,b,effStep)

listPublicFunctions :: JRoleMethods -> [String] -> [RoleMethod]
-- listPublicFunctions ms functionsST = error (show (nubOrd ([ x | (_,x@(RoleMethod {mname=f})) <- ms,not (elem f functionsST)])) ++ "\n" ++ show functionsST ++ "\n" ++ show ms)
listPublicFunctions ms functionsST = nubOrd ([ x | (_,x@(RoleMethod {mname=f})) <- ms, notElem f functionsST])

listRoleMethods :: String -> JRoleMethods -> [RoleMethod]
listRoleMethods role ms  = [x | ((_,r),x) <-ms,role==toRole r]        -- ignore public static functions in functions.st

-- define how the shared expression is printed in the generated code
varSharedExpressionFilename :: Ident -> JRoles -> String
varSharedExpressionFilename f roles = f ++ "_" ++ strDelimiter ++ concatOp ++ agent2aliaslist roles ++ concatOp ++ strDelimiter
-- varSharedExpressionFilename f _ = f

-- print the list of parameters (a list of role names)
agent2aliaslist :: JRoles -> String
agent2aliaslist roles = intercalate (concatOp ++ strDelimiter ++ "_" ++ strDelimiter ++ concatOp) (map mapAgentAliasList roles)

-- map the roles to code that generated parametrised pre-shared messages (e.g. simmetric keys), but type of the paramters must be JAgent
mapAgentAliasList :: JRole -> String
mapAgentAliasList (JAgent,id) = agent2alias id
mapAgentAliasList (t,id) = error ("mapAgentAliasList - error: " ++ id ++ " is of type " ++ showJavaType t ++ " but only type " ++ showJavaType JAgent ++ " can be accepted at this stage")

varSharesInit :: JShares -> [ShareField]
varSharesInit shrs = map (varShareInit shrs) shrs

varShareInit :: JShares -> JShare -> ShareField
-- varShareInit shrs share | trace ("varShareInit\n\tshare: " ++ show share ++ "\n\tshares: " ++ show shrs) False = undefined
varShareInit shrs (_,(t,id),e,roles) = let
                                            n = id -- variable identifier
                                            c = showTypeConstructor t (strDelimiter ++ id ++ strDelimiter ++ applyOp APIgetBytes "")
                                            p = map (\(_,id) -> toRole id) roles
                                            p1 = if isSharableNExpression e then
                                                    case e of
                                                        NEFun _ _ -> varAgentsOfNExpression e
                                                        _ -> []
                                                    else error ("expression " ++ show e ++ " is not sharable")
                                            pars =  map (\(_,id) -> toRole id) p1
                                            filenameprefix = case e of
                                                                    NEFun (_,idf) _ -> idf
                                                                    _ -> id
                                            filename = case isAbstraction e shrs of
                                                                    Just _ -> varSharedExpressionFilename filenameprefix p1 -- filename used to store the pre-shared expression
                                                                    Nothing -> id
                                            tt = showJavaType t
                                      in (ShareField {shname=n, shconstructor=c, shpars=pars, shtype=tt, shfilenameprefix=filenameprefix, shroles=p, shfilename=filename})

varDeclRole :: String -> JRoleFields -> [RoleField]
varDeclRole role decl = [x | ((_,r),x@(RoleField {rolename=_, typeofvar=_, pars=_,static=s}))<-decl,role==toRole r,not s]

varDeclRolesStatic :: String -> JRoleFields -> [RoleField]
varDeclRolesStatic role decl = let
                                  sts = [x | x@((_,r),RoleField {rolename=_, typeofvar=_, pars=p,static=s})<-decl,role==toRole r,p /= "",s]
                               in map (varDeclRoleStatic role) sts

varDeclRoleStatic :: String -> (JRole,RoleField) -> RoleField
varDeclRoleStatic _ (_,RoleField {rolename=n, typeofvar=t}) = let
                                    p = showTypeConstructorStatic t n
                          in (RoleField {rolename=n, typeofvar=t, pars=p,static=True,know=False})

varDeclRoleInit :: String -> JShares -> [ShareField]
-- varDeclRoleInit role shares | trace ("varDeclRoleInit\n\trole: " ++ show role ++ "\n\tshares: "  ++ show shares) False = undefined
varDeclRoleInit role shares = let
                                 myShares = [ x | x@(_,_,_,roles) <- shares, elem role [ toRole y | (JAgent,y) <- roles]]
                              in map (varShareInit shares) myShares

replayVarsForRole :: String -> [JAction] -> [RoleField]
replayVarsForRole role actions =
  [ RoleField {
      rolename = varname,
      typeofvar = SealedObject JNonce,
      pars = "",
      static = False,
      know = False
    }
  | JEmitReplay (step, agent, _, _, _) <- actions,
    toRole agent == role,
    let varname = "VAR_" ++ map toUpper agent ++ "_REPLAY_R" ++ show step
  ]

packageName :: String -> String
packageName [] = []
packageName prot = map toLower prot

protocolName :: String -> String
protocolName [] = []
protocolName (x:xs) = toUpper x:xs

genFile :: String -> String -> STGroup String -> OutType -> Bool -> String -> String -> Attribs -> IO String
genFile prot destpath templates outtype showStdOut outFilemod tempname attribs = do
                                        let t = case getStringTemplate tempname templates of
                                                    Just x -> x
                                                    Nothing -> error ("genFile - no template available for " ++ tempname)
                                        -- let Just t = getStringTemplate tempname templates
                                        let f = toString $ foldr (\(attr,attriblist) -> setAttribute attr attriblist) t attribs
                                        let outprefix = outFilePrefix destpath prot
                                        let outExt = sepDot ++ getExt outtype
                                        let outfile = case tempname of
                                                                "build" -> destpath ++ tempname ++ outXMLExt
                                                                "docker-compose" -> destpath ++ tempname ++ outDockerExt
                                                                "Dockerfile" -> destpath ++ tempname
                                                                "Dockerfile_DY" -> destpath ++ tempname
                                                                "main" -> outprefix ++ outExt
                                                                "ROLE_x" -> outprefix ++ "_" ++ outFilemod ++ outExt
                                                                _ -> outprefix ++ "_" ++ tempname ++ outExt
                                        let f1 = replace "\r\n" newLine f   -- some cleanup CRLF -> LF
                                        writeOutputFile outfile outtype f1 showStdOut

instance ToSElem AttribPars
  where
        toSElem (StLst xs) = toSElem xs
        toSElem (RaLst xs) = toSElem xs
        toSElem (St x) = toSElem x
        toSElem (VD xs) = toSElem xs
        toSElem (SH xs) = toSElem xs
        toSElem (CS xs) = toSElem xs
        toSElem (SA xs) = toSElem xs
        toSElem (CR xs) = toSElem xs
        toSElem (RM xs) = toSElem xs
        toSElem (ES xs) = toSElem xs
        toSElem (DR xs) = toSElem xs
        toSElem (Bl x) = toSElem x
        toSElem (OC xs) = toSElem xs

instance ToSElem RoleAlias
   where toSElem RoleAlias {role=r, alias=a} = SM $! Map.fromList [("role",toSElem r),("alias",toSElem a)]

instance ToSElem ChannelStep
   where toSElem ChannelStep {channel=c, step=s} = SM $! Map.fromList [("channel",toSElem c),("step",toSElem s)]

instance ToSElem ChannelRole
   where toSElem ChannelRole {chname=c, chrole=r, chtype=t} = SM $! Map.fromList [("chname",toSElem c),("chrole",toSElem r),("chtype",toSElem t)]

instance ToSElem RoleField
   where toSElem RoleField {rolename=n, typeofvar=t, pars=p} = SM $! Map.fromList [("name",toSElem n),("typeof", toSElem (showJavaType t)),("pars",toSElem p)]

instance ToSElem ShareField
   where toSElem ShareField {shname=n, shconstructor=c,shpars=p,shtype=tt,shfilenameprefix=filenameprefix,shfilename=filename,shroles=roles} = SM $! Map.fromList [("shname",toSElem n),("shconstructor",toSElem c),("shpars",toSElem p),("shtype",toSElem tt),("shfilenameprefix",toSElem filenameprefix),("shfilename",toSElem filename),("shroles",toSElem roles)]

instance ToSElem StepAction
   where toSElem StepAction {astep=s, action=a, checks=c} = SM $! Map.fromList [("astep",toSElem s),("action",toSElem a),("checks",toSElem c)]

instance ToSElem RoleMethod
   where toSElem RoleMethod {mname=n, mpars=p, mparsnames=pn, mcode=c, rettype=t, retvalue=v} = SM $! Map.fromList [("mname",toSElem n),("mpars",toSElem p),("mparsnames",toSElem pn),("mcode",toSElem c),("rettype",toSElem t),("retvalue",toSElem v)]

instance ToSElem ExtraStep
   where toSElem ExtraStep {ename=n, eaction=a} = SM $! Map.fromList [("ename",toSElem n),("eaction",toSElem a)]

instance ToSElem DockerRole
   where toSElem :: Stringable b => DockerRole -> SElem b
         toSElem DockerRole {dockerrolename=n, ip=i, subnet=s, gateway=g, gatewaybridge=gb, pings=p, ports=ps} = SM $! Map.fromList [("dockerrolename",toSElem n),("ip",toSElem i),("subnet",toSElem s),("gateway",toSElem g),("gatewaybridge",toSElem gb),("pings",toSElem p),("ports",toSElem ps)]

instance ToSElem ObjCheckStep
   where toSElem ObjCheckStep {objtype=ot, objstep=s} = SM $! Map.fromList [("objtype",toSElem ot),("step",toSElem s)]

type Attribs = [(String,AttribPars)]

data AttribPars = St String | Bl Bool | StLst [String] | RaLst [RoleAlias] | VD [RoleField] | SH [ShareField] | CS [ChannelStep] | SA [StepAction] | CR [ChannelRole] | RM [RoleMethod] | ES [ExtraStep] | DR [DockerRole] | OC [ObjCheckStep]
                        deriving (Eq,Show,Data,Typeable)

nullAttribs :: Attribs
nullAttribs = [("",StLst [""])]

dbgJavaCode :: Protocol -> AnBxOnP -> AnBxCfg -> OFMCAttackImpersonationsAndProt -> IO String
dbgJavaCode prot options cfg impsAndTrProt =
  let impersonations = case impsAndTrProt of
                         Just (imps,_,_,_) -> imps
                         Nothing -> Map.empty
  in genCode (mkProt2J prot impsAndTrProt options cfg) options cfg impersonations

listRoles :: JRoles -> [String]
listRoles = map (\(_,r) -> toRole r)

listDockerRoles :: JDRoles -> IPv4 -> [DockerRole]
listDockerRoles droles ipBase = map (toDockerRole ipBase) droles

toDockerRole :: IPv4 -> JDRole -> DockerRole
toDockerRole ipBase ((_,id),n, pings, ports,_)  = DockerRole {dockerrolename=id, ip = Net.IPv4.encodeString (ip2host ipBase n), subnet = Net.IPv4.encodeString (ip2subnet ipBase n), gateway = Net.IPv4.encodeString (ip2gateway ipBase n), gatewaybridge = Net.IPv4.encodeString (ip2gatewayBridge ipBase n), pings = show pings, ports = if null ports then "" else "expose:" ++ dockerRolePorts ports}

dockerRolePorts :: [PortRange] -> [Char]
dockerRolePorts [] = ""
dockerRolePorts (x:xs) = "\n            " ++ "- " ++ "\"" ++ show x ++ "\"" ++ dockerRolePorts xs

-- previous
-- dockerRolePorts ports = intercalate "," (map show ports)

dockerRole2DYIpTest :: [DockerRole] -> String
dockerRole2DYIpTest (x:_) = gateway x
dockerRole2DYIpTest [] = error "error: Docker Roles list is empty"

-- ObjCheck.st steps

listOCSteps :: [JAction] -> AnBxOnP -> [ObjCheckStep]
listOCSteps actions options = 
    let
        isObjCheck = objcheck options
        receiveActions = if isObjCheck 
                         then [ x | x@(JReceive (_, agent, _, _)) <- actions, agent == anbxmitm options ]
                         else [ x | x@(JReceive _) <- actions ]
    in 
        map (\action -> case action of
            JReceive (s, _, _, NEVar (t, _) _) -> ObjCheckStep  { objtype = showJavaType t, objstep = if isObjCheck then toStepObjCheck s else toStep s }
            _ -> error $ "listOCSteps - Unexpected action type: " ++ show action
        ) receiveActions

listSteps :: JSteps -> [String]
listSteps = map toStep

channelName :: JChannel -> String
channelName ((_,r1),ct,(_,r2),_,_,cr,_) = toRole r1 ++ "_channel_" ++ toRole r2 ++ "_" ++ show cr ++ "_" ++ show ct

listChannels :: String -> JChannels -> [String]
listChannels "" chs = [channelName ch | ch<-chs]
listChannels role chs = [channelName ch | ch@((_,r1),_,(_,_),_,_,_,_)<-chs,toRole r1==role]

listChannelRoles :: String -> JChannels -> [ChannelRole]
listChannelRoles role chs = [ChannelRole {chname=channelName ch, chrole=toRole r2, chtype=show (mapChanneType ct)}| ch@((_,r1),ct,(_,r2),_,_,_,_)<-chs,toRole r1==role]

data ShareField = ShareField {shname :: String, shconstructor :: String, shroles :: [String], shpars :: [String], shtype :: String, shfilenameprefix :: String, shfilename :: String }
                           deriving (Data, Typeable, Eq, Show)

data RoleAlias = RoleAlias { role :: String, alias :: String }
                          deriving (Data, Typeable, Eq, Show)

data ChannelStep = ChannelStep { channel :: String, step :: String}
                         deriving (Data, Typeable, Eq, Show, Ord)

data ChannelRole = ChannelRole { chname :: String, chrole :: String , chtype :: String}
                         deriving (Data, Typeable, Eq, Show)

data StepAction = StepAction { astep :: String, action :: String, checks :: String }
                         deriving (Data, Typeable, Eq, Show)

data ExtraStep = ExtraStep { ename :: String, eaction :: String}
                          deriving (Data, Typeable, Eq, Show)

data ObjCheckStep = ObjCheckStep { objtype :: String, objstep :: String }
                         deriving (Data, Typeable, Eq, Show)


listRoleAlias :: JRoles -> [String] -> SubjectiveImpersonations -> [RoleAlias]
listRoleAlias jr aliases imps = let
                                  lstRoles = listRoles jr
                                  ra = assignRoleAliases lstRoles aliases imps
                                  ra1 = map (\(x,y) -> RoleAlias {role=x,alias=y}) ra
                                in ra1

--assume that originally, the ith role in roles corresponds to the ith alias in the returned aliases list
assignRoleAliases :: [String] -> [String] -> SubjectiveImpersonations -> [(String,String)]
assignRoleAliases roles aliases imps | length roles <= length aliases =
                           let
                             originalAssocs = zip roles aliases
                             findAliasforRole role = case find (\(r,_) -> r==role) originalAssocs of
                                                       Just (_,al) -> al
                                                       Nothing -> error ("assignRoleAliases -- Could not find a corresponding alias for role "++ role)
                             subjKnownAliases x = case Map.lookup x imps of
                                                    Just substs -> map (\r -> case Map.lookup r substs of
                                                                                Just s -> findAliasforRole s
                                                                                Nothing -> findAliasforRole r)
                                                                         roles
                                                    Nothing -> take (length roles) aliases
                           in [(x, intercalate "," (subjKnownAliases x)) | x <-roles]
assignRoleAliases roles aliases _  =  error ("insufficient number of aliases for expected roles" ++ "\n" ++
                                                        "\troles: " ++ show roles ++ "\n" ++
                                                        "\taliases: " ++ show aliases ++ "\n")

listChannelSteps :: [JAction] -> [ChannelStep]
--listChannelStepsAgent role actions | trace ("listChannelStepsAgent\n\trole: " ++ show role ++ "\n\tactions: "  ++ show actions) False = undefined
listChannelSteps [] = []
listChannelSteps (JReceive (st,_,ch,_):xs) = ChannelStep {channel=channelName ch,step=toStep st} : listChannelSteps xs
listChannelSteps (_:xs) = listChannelSteps xs


listChannelStepsRole :: String -> [JAction] -> [ChannelStep]
--listChannelStepsAgent role actions | trace ("listChannelStepsAgent\n\trole: " ++ show role ++ "\n\tactions: "  ++ show actions) False = undefined
listChannelStepsRole _ [] = []
listChannelStepsRole role (JEmit (st,agent,ch,_,_):xs) = if toRole agent == role then nubOrd (ChannelStep {channel=channelName ch,step=toStep st} : listChannelStepsRole role xs) else listChannelStepsRole role xs
listChannelStepsRole role (JReceive (st,agent,ch,_):xs) = if toRole agent == role then nubOrd (ChannelStep {channel=channelName ch,step=toStep st} : listChannelStepsRole role xs) else listChannelStepsRole role xs
listChannelStepsRole role (JEmitReplay (st,agent,ch,_,_):xs) = if toRole agent == role then nubOrd (ChannelStep {channel=channelName ch,step=toStep st} : listChannelStepsRole role xs) else listChannelStepsRole role xs

listChannelStepsRole role (_:xs) = listChannelStepsRole role xs

listChannelStepsNum :: String -> [JAction] -> [Int]
--listChannelStepsRole role actions | trace ("listChannelStepsRole\n\trole: " ++ show role ++ "\n\tactions: "  ++ show actions) False = undefined
listChannelStepsNum _ [] = []
listChannelStepsNum role (JEmit (st,agent,_,_,_):xs) = if toRole agent == role then nubOrd (st : listChannelStepsNum role xs) else listChannelStepsNum role xs
listChannelStepsNum role (JReceive (st,agent,_,_):xs) = if toRole agent == role then nubOrd (st : listChannelStepsNum role xs) else listChannelStepsNum role xs
listChannelStepsNum role (JEmitReplay (st,agent,_,_,_):xs) = if toRole agent == role then nubOrd (st : listChannelStepsNum role xs) else listChannelStepsNum role xs
listChannelStepsNum role (_:xs) = listChannelStepsNum role xs

getSteps :: [ChannelStep] -> [String]
getSteps chs = [x | (ChannelStep {channel=_,step=x})<-chs]

cfgRoleShare :: RoleAlias -> String
cfgRoleShare RoleAlias {role=x} = lineSeparator ++ "# Roles/Share" ++ "\n" ++ lineSeparator ++ "ROLESHARE = " ++ x ++ "\n"

cfgRoleAlias :: [RoleAlias] -> JRoles -> [String]
cfgRoleAlias ra roles = ("# Aliases for agents " ++ rolesList ++ " from the point of view of " ++ rolePrefix ++ "x") : map (\(RoleAlias {role=x,alias=y}) -> x ++ " = " ++ y) ra
                                                            where rolesList = intercalate "," [ snd x | x <- roles]

cfgChannels :: JChannels -> [String]
cfgChannels jc = [lineSeparatorBase, "# Channels", lineSeparatorBase]
                            ++ map (\ch@(_,ct,_,host,port,cr,description) -> (if null description then "" else "# " ++ description  ++ newLine) ++
                                                                                channelName ch ++ "_role = " ++ show cr  ++ newLine ++
                                                                                channelName ch ++ "_host = " ++ Net.IPv4.encodeString host ++ newLine ++
                                                                                channelName ch ++ "_port = " ++ show port ++ newLine ++
                                                                                channelName ch ++ "_type = " ++ show (mapChanneType ct)
                                                                                ) jc

cfgPaths :: AnBxCfg -> String -> [String]
cfgPaths cfg package = [lineSeparatorBase, "# Paths", lineSeparatorBase] ++ ["keypath = " ++ keyPathDefault cfg] ++ ["sharepath = " ++ sharePathDefault cfg ++
                                                                                        -- if file is in the same folder do not write package name
                                                                                        if isRelative (sharePathDefault cfg) then "" else package ++ pathSeparator]
                                                                                        ++ ["anbxjpath = " ++ anbxjPathDefault cfg ]

filterStepActions :: String -> String -> [JAction] -> [JAction]
filterStepActions _ _ [] = []
filterStepActions step role (x@(JNew (st,agent,_)):xs) = if toRole agent == role && toStep st == step then x : filterStepActions step role xs else filterStepActions step role xs
filterStepActions step role (x@(JEmit (st,agent,_,_,_)):xs) = if toRole agent == role && toStep st == step then x : filterStepActions step role xs else filterStepActions step role xs
filterStepActions step role (x@(JEmitReplay (st,agent,_,_,_)) : xs) = if toRole agent == role && toStep st == step then x : filterStepActions step role xs else filterStepActions step role xs
filterStepActions step role (x@(JReceive (st,agent,_,_)):xs) = if toRole agent == role && toStep st == step then x : filterStepActions step role xs else filterStepActions step role xs
filterStepActions step role (x@(JCheck (st,agent,_,_)):xs) = if toRole agent == role && toStep st == step then x : filterStepActions step role xs else filterStepActions step role xs
filterStepActions step role (x@(JAssign (st,agent,_,_)):xs) = if toRole agent == role && toStep st == step then x : filterStepActions step role xs else filterStepActions step role xs
filterStepActions step role (x@(JComment (st,_)):xs) = if toStep st == step then x : filterStepActions step role xs else filterStepActions step role xs
filterStepActions step role (x@(JCall (st,agent,_)):xs) = if toRole agent == role && toStep st == step then x : filterStepActions step role xs else filterStepActions step role xs
filterStepActions step role (x@(JGoal (st,agent,_,_,_,_,_,_)):xs) = if toRole agent == role && toStep st == step then x : filterStepActions step role xs else filterStepActions step role xs

mkStepActionsStr :: [JAction] -> JShares -> AnBxOnP -> String -> String
mkStepActionsStr [] _ _ _ = ""
mkStepActionsStr xs sh options protname = foldr (\x y-> "\t\t\t" ++ mkStepActionStr x sh options protname ++ newLine ++ y) "" xs

castofTypeEx :: NExpression -> JType -> String
-- castofTypeEx expr t | trace ("castofTypeEx\n\texpr: " ++ show expr ++ "\n\ttypeofexpr: " ++ show (typeof expr) ++ "\n\ttype: " ++ show t ) False = undefined
castofTypeEx expr t@(SignedObject _) = case typeof expr of
                                                        SignedObject _ -> ""
                                                        _ -> castofType t
castofTypeEx expr t@(SealedPair _) = case typeof expr of
                                                        SealedPair _ -> ""
                                                        _ -> castofType t
castofTypeEx expr t = if typeof expr == t then "" else castofType t

nameofExtraMethod :: Int -> Int -> String
nameofExtraMethod step num = "executeStep_" ++ show step ++ "_" ++ show num

-- here we assume that steps are restricted to an actual role

listStepActions :: String -> JSteps -> [JAction] -> Int -> JShares -> AnBxOnP -> String -> ([StepAction],[ExtraStep])
-- listStepActions role steps@(s:_) actions _ sh _ _ | trace ("listStepActions\n\trole: " ++ show role ++ "\n\tsteps: " ++ show steps ++ "\n\tshares: " ++ show sh ++"\n\t# actions: "  ++ show (length (filterStepActions (toStep s) role actions))) False = undefined
listStepActions  _ [] _ _ _ _ _ = ([],[])
listStepActions role [s] actions maxMethodSize sh options protname = let
                                            myacts = filterStepActions (toStep s) role actions
                                            -- filter and expands checks
                                            (myrealacts,mycomments) = splitActionsComments myacts
                                            (myact,myext) = if length myrealacts > maxMethodSize then
                                                                --- method must be split
                                                                let
                                                                    -- list of list of actions
                                                                    llacts = chunksOf maxMethodSize myrealacts
                                                                    listOfExtraMethods = map (nameofExtraMethod s) [1..length llacts]
                                                                    a2call = map (\x -> JCall (s,role,NEFun (JFunction PubFun (JAnBSession,JVoid),x) (NEName (JString,sessName)))) listOfExtraMethods
                                                                    a = mkStepActionsStr (mycomments ++ a2call) sh options protname
                                                                    ep = zip listOfExtraMethods llacts
                                                                    e = map (\x -> ExtraStep {ename=fst x, eaction=mkStepActionsStr (snd x) sh options protname}) ep
                                                                in (a,e)
                                                            else
                                                                (mkStepActionsStr myacts sh options protname,[])
                                       in ([StepAction {astep=toStep s,action=myact,checks=""}],myext)
listStepActions role (s:ss) actions maxMethodSize sh options protname =
                                       let
                                            (a1,e1) = listStepActions role [s] actions maxMethodSize sh options protname
                                            (a2,e2) = listStepActions role ss actions maxMethodSize sh options protname
                                       in (a1++a2,e1++e2)

genConfigFile :: AnBxOnP -> AnBxCfg -> String -> OutType -> Bool -> JProtocol -> SubjectiveImpersonations -> IO String
genConfigFile opt cfg destpath outtype showStdOut (prot,_,_,_,_,_,roles,_,inactiveagents,_,channels,_,_,_) imps =
        do
                let outfile = outFilePrefix destpath (protocolName prot) ++ ".properties"   -- uses same capitalisation of other generated files
                let targetLanguage = show outtype
                let header = "# Protocol: " ++ prot ++ "\n" ++
                             "# " ++ targetLanguage ++ " Configuration File: " ++ strDelimiter  ++ outfile ++ strDelimiter ++ "\n" ++
                             "# " ++ productNameWithOptions opt ++  "\n"
                let available_aliases = cfgAliases cfg
                let rolealiaslist = listRoleAlias roles available_aliases imps
                let rolealiaslistfull = listRoleAlias (roles ++ inactiveagents) available_aliases imps
                let rolealias = unlines (cfgRoleAlias rolealiaslistfull (roles ++ inactiveagents))
                let roleshare = cfgRoleShare (head rolealiaslist)  -- first role/alias
                let chs = unlines . cfgChannels $ channels
                let paths = unlines (cfgPaths cfg (packageName prot))
                let cryptosettings = cfgCrypto (cryptoConfig cfg)
                let str = header ++ roleshare ++ rolealias ++ chs ++ paths ++ cryptosettings
                writeOutputFile outfile outtype str showStdOut

-- Function to check if a file matches the pattern
matchesPattern :: String -> String -> FilePath -> Bool
matchesPattern prefix ext fp = prefix `isPrefixOf` takeFileName fp && takeExtension fp == ext

-- Function to delete files matching the pattern
deleteFilesWithPattern :: String -> String -> FilePath -> IO ()
deleteFilesWithPattern prefix ext dir = do
    contents <- listDirectory dir
    let filesToDelete = filter (matchesPattern prefix ext) contents
    mapM_ (\file -> removeFile $ dir </> file) filesToDelete


-- Function to update CryptoConfig based on AnBxOnP options (already done in the main.hs so no longer necessary)
setCryptoConfig :: CryptoConfig -> AnBxOnP -> CryptoConfig
setCryptoConfig cryptoConfig options = CryptoConfig
    { cipherScheme = fromMaybe (cipherScheme cryptoConfig) (cryptoCipherScheme options),
      keySize = fromMaybe (keySize cryptoConfig) (cryptoKeySize options),
      keyGenerationScheme = fromMaybe (keyGenerationScheme cryptoConfig) (cryptoKeyGenerationScheme options),
      keyGenerationSchemePBE = fromMaybe (keyGenerationSchemePBE cryptoConfig) (cryptoKeyGenerationSchemePBE options),
      keyGenerationSize = fromMaybe (keyGenerationSize cryptoConfig) (cryptoKeyGenerationSize options),
      keyPairGenerationScheme = fromMaybe (keyPairGenerationScheme cryptoConfig) (cryptoKeyPairGenerationScheme options),
      keyPairGenerationSize = fromMaybe (keyPairGenerationSize cryptoConfig) (cryptoKeyPairGenerationSize options),
      secureRandomAlgorithm = fromMaybe (secureRandomAlgorithm cryptoConfig) (cryptoSecureRandomAlgorithm options),
      hMacAlgorithm = fromMaybe (hMacAlgorithm cryptoConfig) (cryptoHMacAlgorithm options),
      messageDigestAlgorithm = fromMaybe (messageDigestAlgorithm cryptoConfig) (cryptoMessageDigestAlgorithm options),
      keyAgreementAlgorithm = fromMaybe (keyAgreementAlgorithm cryptoConfig) (cryptoKeyAgreementAlgorithm options),
      keyAgreementKeyPairGenerationScheme = fromMaybe (keyAgreementKeyPairGenerationScheme cryptoConfig) (cryptoKeyAgreementKeyPairGenerationScheme options),
      dhRndExpSize = fromMaybe (dhRndExpSize cryptoConfig) (cryptoDHRndExpSize options),
      ecGenParameterSpec = fromMaybe (ecGenParameterSpec cryptoConfig) (cryptoECGenParameterSpec options),
      asymcipherSchemeBlock = fromMaybe (asymcipherSchemeBlock cryptoConfig) (cryptoAsymCipherSchemeBlock options),
      sslContext = fromMaybe (sslContext cryptoConfig) (cryptoSSLContext options),
      securityProvider = fromMaybe (securityProvider cryptoConfig) (cryptoSecurityProvider options)
    }
    where
      fromMaybe _ (Just x) = x
      fromMaybe defaultValue Nothing = defaultValue


--Commented code useful for when individual config files are generated: requires each RoleAlias to correspond to one role, not a list of roles

{-swapRoleAliases :: [RoleAlias] -> Map.Map Ident Ident -> [RoleAlias]
swapRoleAliases ras swaps = map (\(RoleAlias {role=x,knownAliases=y}) ->
                                      RoleAlias {role=x,
                                                 knownAliases= case Map.lookup x swaps of
                                                          Just sw -> case find (\r -> role r == sw) ras of
                                                                       Just ra -> knownAliases ra
                                                                       Nothing -> error("No RoleAlias named "++ sw ++ " can be found for alias swapping.")
                                                          Nothing -> y}
                                ) ras-}

{-
genConfigFile :: AnBxCfg -> String -> Bool -> JProtocol -> SubjectiveImpersonations -> IO()
genConfigFile cfg destpath showStdOut (prot,_,_,_,_,_,_,roles,_,inactiveagents,_,channels,_,_) imps =
        do
                let maincfgfile = outFilePrefix destpath (protocolName prot) ++ ".properties"   -- uses same capitalisation of other generated files
                let header = "# Protocol: " ++ prot ++ 
                             "\n# "++ targetLanguage ++ " Config File: " ++ strDelimiter  ++ maincfgfile ++ strDelimiter ++ "\n\n"
                let available_aliases = cfgAliases cfg
                let rolealiaslist = listRoleAlias roles available_aliases
                let rolealiaslistfull = listRoleAlias (roles++inactiveagents) available_aliases
                let rolealias = unlines . cfgRoleAlias $ rolealiaslistfull 
                traverse (\(RoleAlias {role=x,alias=_}) -> writeFile (outFilePrefix destpath (protocolName prot) ++"_Know_" ++ x ++ ".properties")
                                                                      (case Map.lookup x imps of
                                                                         Just localimps -> unlines . cfgRoleAlias $ swapRoleAliases rolealiaslistfull localimps
                                                                         Nothing -> rolealias)
                         ) rolealiaslistfull
                let roleshare = cfgRoleShare (head rolealiaslist)  -- first role/alias
                let chs = unlines . cfgChannels $ channels
                let paths = unlines (cfgPaths cfg (packageName prot))
                let cryptosettings = cfgCrypto (cryptoConfig cfg)
                let str = header ++ roleshare ++ rolealias ++ chs ++ paths ++ cryptosettings
                writeOutputFile maincfgfile targetLanguage str showStdOut
                -}

-- language dependent part (JAVA) --

sessionID :: String
sessionID = "sessionID"

trueConst :: String
trueConst = "true"

classSuffix :: String
classSuffix = sepDot ++ "class"

type2Class :: NExpression -> String
type2Class e = showJavaType (typeof e)++classSuffix

-- initialisation of string with sessionID
id2sess :: String -> JType -> String
id2sess id t = parsofVar id t ++ concatOp ++ parsofVar "_" t ++ concatOp ++ sessionID

mkStepActionStr :: JAction -> JShares -> AnBxOnP -> String -> String
mkStepActionStr (JComment (_,str)) _ _ _ = commentPrefix ++ str
mkStepActionStr (JNew (_,_, jid@(t,id))) _ _ _ = let
                                               par = case t of
                                                    JString -> id2sess id t
                                                    _ -> ""
                                            in id ++ " = " ++ showTypeConstructor t par ++ eoS ++ if writeActionComments then inlinecommentPrefix ++ show jid else ""
mkStepActionStr (JReceive (step,_,_,NEVar (t,id) _)) _ options protname = id ++ " = " ++ castofType t ++
                                                                                (if objcheck options -- readObject API and specific filename must be used
                                                                                        then applyOp APIReadObject ("\"" ++ objCheckFileName protname step ++ "\"")
                                                                                        else applyOp APIReceive "") ++ eoS
mkStepActionStr act@(JReceive _) _ _ _ = error ("malformed action: " ++ show act)                                                                                      
mkStepActionStr (JAssign (_,_,(t,id),expr)) sh _ _ = id ++ " = " ++ castofTypeEx expr t ++ mkExpression expr sh ++ eoS ++ if writeActionComments then inlinecommentPrefix ++ show expr else ""
mkStepActionStr (JEmit (_,_,_,_,expr)) sh _ _ = applyOp APISend (mkExpression expr sh) ++ eoS ++ if writeActionComments then inlinecommentPrefix ++ show expr else ""
mkStepActionStr (JEmitReplay (step,agent,_,_,expr)) sh _ _ = 
    let replayVar = "VAR_" ++ map toUpper agent ++ "_REPLAY_R" ++ show step
        currentMsg = mkExpression expr sh
    in "if (" ++ replayVar ++ " == null || !(new Random().nextInt(10) < 5)) {\n" ++
       "\t\t\t\tAnBx_Debug.out(layer, \">>> NO ATTACK <<<\");\n" ++
       "\t\t\t\t" ++ replayVar ++ " = " ++ currentMsg ++ ";\n" ++
       "\t\t\t\t" ++ applyOp APISend currentMsg ++ eoS ++ "\n" ++
       "\t\t\t} else {\n" ++
       "\t\t\t\t// Simulate attack by sending previous message\n" ++
       "\t\t\t\tAnBx_Debug.out(layer, \">>> ATTACK <<<\");\n" ++
       "\t\t\t\t" ++ applyOp APISend replayVar ++ eoS ++ "\n" ++
       "\t\t\t}" ++ if writeActionComments then inlinecommentPrefix ++ show expr else ""
mkStepActionStr (JCheck (step,_,chk,substep)) sh _ _ = mkStepActionCheckStr chk (mkCheckLabel step substep) sh
mkStepActionStr (JCall (_,_, f)) sh _ _ = mkExpression f sh ++ eoS
mkStepActionStr (JGoal (step,_,Seen,_,expr,_,_,_)) sh _ _ = applyOp APISeen (mkCheckLabel step 0 ++ mkExpression expr sh) ++ eoS ++ if writeActionComments then inlinecommentPrefix ++ show expr else ""
mkStepActionStr (JGoal _) _ _ _ = ""

objCheckFileName :: String -> Int -> String
objCheckFileName protname step = protname ++ "_" ++ toStep step ++ serExt

toStepObjCheck :: Int -> String
toStepObjCheck step = if odd step then error (oddStepErrMsg step) -- step number must be even as this is applied only to passive intruder
                      else toStep (div step 2)

oddStepErrMsg :: Int -> String
oddStepErrMsg step = "Step: " ++ show step ++ " is an odd number but object check option is true."

mkCheckLabel :: Int -> Int -> String
mkCheckLabel step substep = if showCheckLabel then strDelimiter ++ show step ++ sepDot ++ show substep ++ strDelimiter ++ sepComma else ""

removedCheck :: String -> String
removedCheck label =  commentPrefix ++ "Check # " ++ label ++ " is not necessary or already been computed"

mkStepActionCheckStr :: Atom -> String -> JShares -> String
mkStepActionCheckStr (FEq (e,f,mf)) label sh = applyOp APIEqCheck (label ++ mkExpression e sh ++ sepComma ++ mkExpression f sh ++ if mf then sepComma ++ trueConst else "")
                                                       ++ eoS ++ if writeActionComments then inlinecommentPrefix ++ show e ++ " == " ++ show f else ""
mkStepActionCheckStr (FInv (e,f)) label sh = if e==f then
                                                    applyOp APIInvCheck (label ++ mkExpression e sh ++ sepComma ++ type2Class e) ++ eoS
                                                             ++ if writeActionComments then inlinecommentPrefix ++ show e else ""
                                                    else
                                                            applyOp APIInvCheck (label ++ mkExpression e sh ++ sepComma ++ mkExpression f sh) ++ eoS
                                                            ++ if writeActionComments then inlinecommentPrefix ++ show e ++ " == " ++ show f else ""

mkStepActionCheckStr (FWff e) label sh = applyOp APIWffCheck (label ++ mkExpressionForWff e sh) ++ eoS ++ if writeActionComments then inlinecommentPrefix ++ show e else ""
mkStepActionCheckStr (FNotEq (e,f)) label sh = applyOp APINotEqCheck (label ++ mkExpression e sh ++ sepComma ++ mkExpression f sh) ++ eoS
                                                            ++ if writeActionComments then inlinecommentPrefix ++ show e ++ " != " ++ show f else ""

-- special version of mkExpression that allows private keys for WFF checks
mkExpressionForWff :: NExpression -> JShares -> String
mkExpressionForWff expr@(NEPriv (NEFun _ _) (Just pkf)) _ | exprIsPrivateKeyAgentKnown expr = pki pkf  -- allow private keys in WFF checks
mkExpressionForWff expr sh = mkExpression expr sh

mkExpression :: NExpression -> JShares -> String
-- mkExpression expr sh | trace ("mkExpression\n\texpr: " ++ show expr ++ "\n\tshares: " ++ show sh) False = undefined

mkExpression (NEDec e1 e2) sh = castofTypeExpr (NEDec e1 e2) ++ applyOp APIDecrypt (mkExpression e1 sh ++ decryptExpression e2 pk )
    where
        pk = pkFunOfNExpression e2 newContext
        decryptExpression _ (Just AnBxPK) = ""  -- decryption done with (implicit) recipient private key
        decryptExpression e2 (Just AnBxSK) = sepComma ++ if exprIsPublicKeyAgentKnown e2 
                                                                then error $ "Wrong PrivateKey " ++ show pk ++ " (" ++ agent ++ ") used for decryption"
                                                                else mkExpression e2 sh
        decryptExpression e2 _ = sepComma ++ mkExpression e2 sh
        agent = agentOfKey e2

mkExpression expr@(NEVerify e1 e2) sh = castofTypeExpr expr ++ applyOp APIVerify ( castofTypeEx e1 (SignedObject JObject) ++ mkExpression e1 sh ++ sepComma ++ verifyExpression e2 sk )
    where 
        sk = pkFunOfNExpression e2 newContext
        verifyExpression e2 (Just AnBxSK) | exprIsPublicKeyAgentKnown e2 = agent2alias agent
        verifyExpression e2 _ = if exprIsPublicKeyAgentKnown e2 
                                        then error $ "Wrong PrivateKey " ++ show sk ++ " (" ++ agent ++ ") used for verification"
                                        else mkExpression e2 sh
        agent = agentOfKey e2

mkExpression (NEEnc e1 e2) sh = applyOp APIEncrypt ( mkExpression e1 sh ++ sepComma ++ encryptExpression e2 pk )
    where 
        pk = pkFunOfNExpression e2 newContext
        encryptExpression e2 (Just AnBxPK) | exprIsPublicKeyAgentKnown e2 = agent2alias agent
        encryptExpression e2 (Just AnBxSK) = if exprIsPublicKeyAgentKnown e2 
                                                    then error $ "Wrong PrivateKey " ++ show pk ++ " (" ++ agent ++ ") used for encryption"
                                                    else mkExpression e2 sh
        encryptExpression e2 _ = mkExpression e2 sh
        agent = agentOfKey e2

mkExpression (NEEncS e1 e2) sh = applyOp APIEncryptS (mkExpression e1 sh ++ sepComma ++ mkExpression e2 sh)
mkExpression expr@(NEDecS e1 e2) sh = castofTypeExpr expr ++ applyOp APIDecryptS (mkExpression e1 sh ++ sepComma ++ mkExpression e2 sh)

mkExpression (NESign e k) sh | sk == Just AnBxSK = applyOp APISign (mkExpression e sh)
                             | isNothing sk = applyOp APISign (mkExpression e sh ++ sepComma ++ mkExpression k sh)         -- public/private key pair
                             | otherwise = applyOp APISign (mkExpression e sh ++ sepComma ++ show sk)
                                where sk = pkFunOfNExpression k newContext

-- freshly generated keys 
mkExpression expr@(NEPub (NEName (JPublicKey Nothing,pkID)) Nothing) _  | exprIsPublicKeyFresh expr = pkID ++ sepDot ++ applyOp APIPublicKey ""   -- freshly generated public key
mkExpression expr@(NEPriv (NEName (_,pkID)) _) _                        | exprIsPrivateKeyFresh expr = pkID                      -- private key of a freshly generated public key 

-- pub/priv keys where agent is known prior the protocol execution 

mkExpression expr@(NEPub (NEFun _ ag) (Just pkf)) sh       | exprIsPublicKeyAgentKnown expr = sessName ++ sepDot ++ applyOp APIPublicKey (mkExpression ag sh ++ sepComma ++ pki pkf)
mkExpression expr@(NEPriv (NEFun _ _) (Just pk)) _         | exprIsPrivateKeyAgentKnown expr && (pk == AnBxPK || pk == AnBxSK) = error ("PrivateKey " ++ show expr ++ " should not be used explicitly")
mkExpression expr@(NEPriv (NEFun _ _) (Just pkf)) _        | exprIsPrivateKeyAgentKnown expr = pki pkf

-- mkExpression expr@(NEPriv (NEFun _ ag) (Just AnBxPK)) sh   | exprIsPrivateKeyAgentKnown expr = error ("PrivateKey " ++ show expr ++ " should not be used explicitly") -- mkExpression ag sh
-- mkExpression expr@(NEPriv (NEFun _ ag) (Just AnBxSK)) sh   | exprIsPrivateKeyAgentKnown expr = error ("PrivateKey " ++ show expr ++ " should not be used explicitly") -- mkExpression ag sh

-- pub/priv keys where agent is learned during the protocol execution
mkExpression expr@(NEPub (NEFun _ ag) (Just pkf)) sh  | exprIsPublicKeyAgentLearned expr = sessName ++ sepDot ++ applyOp APIPublicKey (mkExpression ag sh ++ sepComma ++ pki pkf)
mkExpression expr@((NEPriv k _)) _                    | exprIsPrivateKeyAgentLearned expr = error ("PrivateKey " ++ show k ++ " should not be used explicitly")

mkExpression (NEName (JAgent,agent)) _ = agent2alias agent
mkExpression (NEName (_,id)) _ = id
mkExpression n@(NEHash (NEName (_,""))) _ = error ("empty expression in hash(): " ++ show n)
mkExpression (NEHash e) sh = applyOp APIHash (mkExpression e sh)
mkExpression (NEHmac e1 e2) sh = applyOp APIHmac (mkExpression e1 sh ++ sepComma ++ castofTypeExpr e2 ++ mkExpression e2 sh) -- type ok symmetric key, dh-key, hmac-key
mkExpression (NEVar (_,var) _) _ = var
mkExpression (NECat [x]) sh = mkExpression x sh
mkExpression (NECat (x:xs)) sh = showTypeConstructor (AnBxParams []) (mkExpression x sh ++  foldr (\e y -> sepComma ++ mkExpression e sh ++ y) "" xs)
mkExpression n@(NEFun (JFunction _ (_,t2),f) e) sh = case isAbstraction n sh of
                                                            Just expr -> mkExpression expr sh   -- is an abstraction (function)
                                                            Nothing -> f ++ parOpen
                                                                         ++ (if requiresSession t2 then sessName ++ sepComma else "")
                                                                         ++ (case e of
                                                                                    NECat [x] -> mkExpression x sh
                                                                                    NECat xs -> intercalate sepComma (map (\x -> mkExpression x sh) xs)
                                                                                    _  -> mkExpression e sh
                                                                            )
                                                                         ++ parClose

mkExpression expr@(NEProj index _ (NEName (_,id))) _  = castofTypeExpr expr ++ id ++ getIndex index
mkExpression expr@(NEProj index _ (NEVar (_,var) _)) _ = castofTypeExpr expr ++ var ++ getIndex index
mkExpression expr@(NEProj index _ e) sh = castofTypeExpr expr ++ showTypeConstructor (AnBxParams []) (mkExpression e sh) ++ getIndex index

mkExpression (NEKap (NEName (JDHBase,_)) e2) sh = applyOp APIDHPubKey (mkExpression e2 sh)
mkExpression (NEKas e1 e2@(NEName (JDHSecret,_))) sh = applyOp APIDHSecKey (mkExpression e1 sh ++ sepComma ++ mkExpression e2 sh)

mkExpression (NEXor e1 e2) sh = applyOp APIXor (mkExpression e1 sh ++ sepComma ++ mkExpression e2 sh)

mkExpression expr _ = error ("unhandled expression in mkExpression/Java: " ++ show expr)

pki :: AnBxPKeysFun -> String
pki pk = cryptostoretype ++ sepDot ++ show pk ++ "()"

isAbstraction :: NExpression -> JShares -> Maybe NExpression
-- isAbstraction expr sh | trace ("isAbstraction\n\texpr: " ++ show expr ++ "\n\tshares: " ++ show sh) False = undefined
isAbstraction expr sh = let
                            es = [js | js@(_,_,y@(NEFun _ _),_) <- sh , y == expr]       -- consider only functions, so no other abstractions are possible
                        in case es of
                                [] -> Nothing
                                [(_,id,_,_)] -> Just (NEName id)
                                _ -> error ("too many matching expressions in isAbstraction: " ++ show es ++ "\nexpr = " ++ show expr)

-- language dependent part (JAVA) --
