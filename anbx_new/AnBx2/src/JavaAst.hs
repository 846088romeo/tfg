{-

 AnBx Compiler and Code Generator

 Copyright 2011-2025 Paolo Modesti
 Copyright 2021 Rémi Garcia
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

module JavaAst where

import AnBAst
import AnBxAst (AnBxType (..), getAgents)
import AnBxOnP
    ( OutType(TypedOptExecnarrDocker, JavaDocker),
      AnBxOnP(anbxouttype, synthesistypeenc, anbxmitm),
      isOutTypeJava,
      SynthesisTypeEnc(encS, enc) )
import AnB2NExpression
import AnB2NExecnarr
import Spyer_Ast ( Declaration(..), NEShare )
import Spyer_Message
import AnBxMsgCommon
import Data.List ( (\\), elemIndex, intercalate, sort, union )
import Data.Containers.ListUtils (nubOrd)
import Net.IPv4
import Debug.Trace

import Data.Typeable
import Data.Data
import Data.Char (toLower)
import qualified Data.Map as Map
import qualified Data.Set as Set

import Java_TypeSystem_JType
import Java_TypeSystem_Context
import Java_TypeSystem_Evaluator
import JavaType
import JavaCodeGenConfig

import Data.Word (Word8)
import Data.Maybe (fromJust)
import AnBxShow (showActions, showChannelType)

-- Java Protocol

data JChannelRole = Client | Server deriving (Eq,Ord,Show)

type JProtocol = (String,JCustomTypes,JConstants,JShares,JAgree,NEquations,JRoles,JDRoles,JInactiveAgents,JSteps,JChannels,JRoleFields,JRoleMethods,JActions)

data JDRoleType = JDHonest | JDIntruder
        deriving (Eq,Show)

ident2JDRoleType :: NEIdent -> AnBxOnP -> JDRoleType
ident2JDRoleType (JAgent,id) options = if id == anbxmitm options then JDIntruder else JDHonest
ident2JDRoleType (t,id) _ = error ("ident2JDRoleType - unexpected id: " ++ show id ++ " of type: " ++ show t)

type JCustomTypes = [String]
type JRole = NEIdent
type JRoles = [JRole]
type JDRole = (JRole,Word8,Int,[PortRange],JDRoleType)                        -- ident,subnet number, number of pings, [ports], docker role type
type JDRoles = [JDRole]
type JSteps = [Int]
type JChannels = [JChannel]
type JChannel = (JRole,ChannelType,JRole,IPv4,PortRange,JChannelRole,String)  -- agent,role{Client|Server},agent,IPAddress,Port,channeltype,description
type JMethods = [(JRole,[NEIdent])]
type JShare = NEShare       -- var/ident, expr
type JShares = [JShare]
type JAgree = [JShare]
type JConstants = [NEIdent]
type JInactiveAgents = [NEIdent]

data JAction = -- int=step string=agent
         JNew (Int,String,NEIdent)
       | JEmit (Int,String,JChannel,NExpression,NExpression)    -- expr, ground expression
       | JReceive (Int,String,JChannel,NExpression)
       | JCheck (Int,String,Atom,Int)                           -- step,agent,atom,substep
       | JAssign (Int,String,NEIdent,NExpression)
       | JComment (Int,String)
       | JCall (Int,String,NExpression)
       | JGoal (Int,String,Fact,NEIdent,NExpression,[(NEIdent,NExpression)],Bool, Int)               -- bool == side conditions , last int = effective step
    deriving (Eq)

type JActions = [JAction]
instance Show JAction where
    show :: JAction -> String
    show (JNew (step,a,k)) = a ++ "|" ++ show step ++": new " ++ show k
    show (JEmit (step,a,ch,e,f)) = a ++ "|" ++ show step ++": send(" ++ show e ++ "," ++ show f ++ ") \t # ch: " ++ show ch
    show (JReceive (step,a,ch,x)) = a ++ "|" ++ show step ++": " ++ show x ++ " (" ++ show (typeofTS x newContext) ++ ")" ++  " = receive() \t # ch: " ++ show ch
    show (JCheck (step,a,phi,substep)) = a ++ "|" ++ show step ++ "." ++ show substep ++": " ++ show phi
    show (JAssign (step,a,x,e)) = a ++ "|" ++ show step ++": " ++ show x ++ " := " ++ show e
    show (JComment (step,s)) = "(* |" ++ show step ++ " - " ++ s ++ " *)"
    show (JCall (step,a,f)) = a ++ "|" ++ show step ++": " ++  show f
    show (JGoal (step,a,fact,typedlabel,e,idexpr,_,effStep)) = a ++ "|" ++ show step ++ "(" ++ show effStep ++ ")" ++": " ++  show fact ++ "(" ++ show typedlabel ++ "," ++ show e ++ "," ++ show idexpr  ++ ")"

-- send action predicate
isJEmitAction :: JAction -> Bool
isJEmitAction (JEmit _) = True
isJEmitAction _ = False

-- split between real actions and comments
splitActionsComments :: JActions -> (JActions,JActions)
splitActionsComments actions = let
                                    cc = [x | x@(JComment _) <- actions]
                                    aa = actions \\ cc
                                in (aa,cc)

type JRoleFields = [(JRole,RoleField)]
type JRoleMethods = [(JRole,RoleMethod)]
type JMethodPars = [NEIdent]

data RoleMethod = RoleMethod { mname :: String, mpars :: String, mparsnames :: String, mcode :: String, rettype :: String, retvalue :: String}
                        deriving (Data, Typeable, Eq, Show, Ord)

data RoleField = RoleField { rolename :: String, typeofvar :: JType, pars :: String, static :: Bool, know :: Bool}
                        deriving (Data, Typeable, Eq, Show, Ord)

data DockerRole = DockerRole { dockerrolename :: String, ip :: String, subnet :: String, gateway :: String, gatewaybridge :: String, pings :: String, ports :: String}
                        deriving (Data, Typeable, Eq, Show, Ord)

getRoleFieldDec :: [Declaration] -> Set.Set String -> JContext -> JRoleFields
-- getRoleFieldDec decl toIgnore _ | trace ("getRoleFieldDec\n\tdecl: " ++ show decl ++ "\n\ttoIgnore: "  ++ show toIgnore) False = undefined
getRoleFieldDec  [] _ _ = []
getRoleFieldDec (x:xs) toIgnore ctx = let
                                        v = case x of
                                            DKnow (agent,n@(NEName (_,var))) | not (exprIsAgent n) -> [(agent, setRoleField var (NEName (id2NEIdent var ctx)) ctx True False) | not (Set.member var toIgnore || Map.member var (nonIgnoredFunctions ctx toIgnore))]
                                            DGenerates (agent,v) -> let
                                                                       var = nameOfGenerates v
                                                                    in [(agent, setRoleField var (NEName (id2NEIdent var ctx)) ctx False True) | not (Set.member var toIgnore)]
                                            DShare (_,ag@(_,id),_,agents) -> concatMap (\x-> [(x, setRoleField id (NEName ag) ctx True False)]) agents
                                            _ -> []
                                     in (v ++ getRoleFieldDec xs toIgnore ctx)

getRoleFieldNarrJ :: [JAction] -> Set.Set String -> JContext -> JRoleFields
getRoleFieldNarrJ  [] _ _ = []
getRoleFieldNarrJ (x:xs) toIgnore ctx= let
                                    v = case x of
                                                JAssign (_,agent,(_,var),expr) -> [(id2NEIdent agent ctx, setRoleField var expr ctx False False) | not (Set.member var toIgnore)]
                                                JReceive (_,agent,_,v@(NEVar (_,var) _)) -> [(id2NEIdent agent ctx, setRoleField var v ctx False False) | not (Set.member var toIgnore)]
                                                _ -> []
                               in (v ++ getRoleFieldNarrJ xs toIgnore ctx)

setRoleField :: Ident -> NExpression -> JContext -> Bool -> Bool -> RoleField
--setRoleField var expr _ _ _| trace ("setRoleField\n\tvar: " ++ var ++ "\n\texpr: "  ++ show expr) False = undefined
setRoleField var expr ctx myknow new = RoleField {rolename=myvar, typeofvar=typeofExpr, pars=mypars, static=mystatic, know=myknow}
                               where
                                        myvar = var
                                        typeofExpr = case typeofTS expr ctx of
                                                        JPublicKey Nothing -> if new then JKeyPair else JPublicKey Nothing   -- create key pairs , cannot create only a PublicKey, but use public keys
                                                        t -> t
                                        mypars = parsofVar myvar typeofExpr
                                        mystatic = isConstant myvar

parsofVar :: Ident -> JType -> String
--parsofVar var t | trace ("parsofVar\n\tvar: " ++ var ++ "\n\ttype: "  ++ show t) False = undefined
parsofVar var (JConstant _) = strDelimiter ++ var ++ strDelimiter
parsofVar var JString = strDelimiter ++ var ++ strDelimiter
parsofVar _ _ = ""

------------ Msg Conversion -----------------------

ppId2Java :: Ident -> String
ppId2Java = filter (\x -> elem x (['a'..'z'] ++ ['A'..'Z'] ++ ['0'..'9']))

showJActions :: JActions -> String
showJActions xs = foldr (\x y -> showJAction x ++ "\n" ++ y) "" xs

-- used for Debug
showJAction :: JAction -> String
showJAction (JEmit (step,a,ch,e,f)) = a ++ "|" ++ show step ++": send(" ++  show (typeof e) ++ "," ++ show (typeof f) ++ ") \t # ch: " ++ show ch
showJAction (JAssign (step,a,x,e)) = a ++ "|" ++ show step ++": " ++ show x ++ " : " ++ show (typeof e)
showJAction act = show act

getChannel :: NEChannel -> JChannels -> JChannelRole -> JChannel
-- getChannel chType a e chs _ | trace ("getChannel\n\tchType: " ++ show chType ++ "\n\tagent: " ++ show a ++ "\n\texpr: "  ++ show e ++ "\n\tchannels:" ++ show chs) False = undefined
getChannel (a,chType,b) chs chRole = let
                                        lst | a==b = [ch | ch@(a2,ct,b2,_,_,cr,_) <- chs, a==a2,b==b2,ct==chType,cr==chRole]
                                            | otherwise = [ch | ch@(a2,ct,b2,_,_,_,_) <- chs, a==a2,b==b2,ct==chType]
                                     in case lst of
                                                [] -> error ("no channel available for " ++ show chType ++ "\n" ++ "channels:\n" ++ showSep show chs)
                                                [x] -> x
                                                _ -> error ("too many channels available" ++ "\n" ++ "channels:\n" ++ showSep show lst)

mapActions :: [NAction] -> JContext -> JChannels -> Int -> SynthesisTypeEnc -> (JActions,JSteps)
-- mapActions actions _ chs _ _ | trace ("mapActions\n\tactions: " ++ show actions ++ "\n\tchannels:" ++ show chs) False = undefined
mapActions [] _ _ _ _ = ([],[])
mapActions [x] ctx chs substep opt = let
                                            (act,step,_) = mapAction x ctx chs substep opt
                                     in case act of
                                                Just a -> ([a],[step])
                                                Nothing -> ([],[step])
-- skip new/private actions
mapActions (x:xs) ctx chs substep opt = let
                                           (act,newstep,nextsubstep) = mapAction x ctx chs substep opt
                                           (acts,steps) = mapActions xs ctx chs nextsubstep opt
                                        in case act of
                                            Just a -> (a : acts,nubOrd (newstep : steps))
                                            Nothing -> (acts,nubOrd (newstep : steps))

mapAction :: NAction -> JContext -> JChannels -> Int -> SynthesisTypeEnc -> (Maybe JAction,Int,Int)
-- mapAction action _ chs _ _ | trace ("mapAction\n\taction: " ++ show action ++ "\n\tchannels:" ++ show chs) False = undefined
mapAction (NANew (step,a,n)) _ _ substep _ = (Just (JNew (step,a,n)),step,substep) 

-- in the following two, Client/Server parameter are only used for "self" channels, by convention send -> Client, receive -> Server                                                      
mapAction (NAEmit (step,a,ch,e1,e2)) _ chs _ _ = (Just (JEmit (step,a,getChannel ch chs Client,e1,e2)),step,0) -- (Just (JEmit (step,a,getChannel chType a (agentOfNExpression e1) chs ctx Client,e1,e2)),step,0)
mapAction (NAReceive (step,a,ch,v@(NEVar _ _))) _ chs _  _ = (Just (JReceive (step,a,getChannel ch chs Server,v)),step,0)

mapAction a@(NAReceive (_,_,_,_)) _ _ _  _= error ("mapActiopn - the receive action is not well-formed: " ++ show a)
mapAction (NACheck (step,agent,phi)) _ _ substep opt = let
                                                            phi1 = filterAtom (mapAtom phi) opt
                                                       in case phi1 of
                                                            Nothing -> (Nothing,step,substep)
                                                            Just phi2 -> (Just (JCheck (step,agent,phi2,substep+1)),step+1,substep+1)

mapAction (NAAssign (step,a,x,e)) ctx _ substep _ = (Just (JAssign (step,a,(typeofTS e ctx,x),e)),step,substep)
mapAction (NAComment (step,s)) _ _ substep _ = (Just (JComment (step,s)),step,substep)
mapAction (NAGoal (step,a,fact,l,e,idsexpr,b,effStep)) ctx _ substep _ = (Just (JGoal (step,a,fact,(typeofTS expr ctx,l),expr, map (\(agent,exp) -> (id2NEIdent agent ctx,exp)) idsexpr,b,effStep)),step,substep)
                                                                                                           where expr = e

errorMsgPK :: String -> NExpression -> JType -> NExpression -> Maybe AnBxPKeysFun -> String
errorMsgPK s e2 t e pk = s ++ " - expected key " ++ show e2 ++ " of type " ++ show t ++ "\nexpr: " ++ show e ++ "\nkey type found: " ++ show pk

doNotCheckPK :: Bool
doNotCheckPK = False

mapAtom  :: Formula -> Atom
mapAtom (FSingle (FWff e)) = FWff e
mapAtom (FSingle (FEq (e1,e2,mf))) = FEq (e1 ,e2,mf)
mapAtom (FSingle (FInv (e1,e2))) = FInv (e1,e2)
mapAtom (FSingle (FNotEq (e1,e2))) = FNotEq (e1,e2)
mapAtom (FAnd f) = error $ "mapAtom - AND formula not supported at this stage of the compilation" ++ "\n" ++ show f

filterAtomType :: Atom -> JType -> JType -> SynthesisTypeEnc -> Maybe Atom
-- filterAtomType a t1 t2 opt  | trace ("\n\tfilterAtomType - check: " ++ show a ++ "\n\tt1:" ++ show t1 ++ "\n\tt1:" ++ show t2 ++ "\n\topt: " ++ show opt) False = undefined   
-- comparison of encrypted objects ----
filterAtomType a@(FEq _) (SealedPair _) (SealedPair _) opt = if enc opt then Nothing else Just a
filterAtomType a@(FEq _) (SignedObject _) (SignedObject _) opt = if enc opt then Nothing else Just a
filterAtomType a@(FEq _) (SealedObject _) (SealedObject _) opt = if encS opt then Nothing else Just a
-- comparison of generic objects, fails if different types
filterAtomType a@(FEq (e,f,_)) t1 t2 _ = if compareTypes t1 t2 then Just a else error ("EqCheck: different types\n\te: " ++ show e ++ "/" ++ show t1 ++ "\n\tf: " ++ show f ++ "/" ++ show t2)
filterAtomType a@(FNotEq _) JAgent JAgent _ = Just a
filterAtomType a@(FNotEq (e,f)) t1 t2 _ = if compareTypes t1 t2 then Just a else error ("NotEqCheck: different types\n\te: " ++ show e ++ "/" ++ show t1 ++ "\n\tf: " ++ show f ++ "/" ++ show t2)
-- inversion test not performed on pub/priv pair
filterAtomType (FInv _) (JPublicKey _) (JPrivateKey _) _ = Nothing
filterAtomType (FInv _) (JPrivateKey _) (JPublicKey _) _ = Nothing
-- generic inversion test on symmetric keys and dh keys
filterAtomType (FInv (e,f)) JSymmetricKey JSymmetricKey _ = Just (FWff (NEDecS (NEEncS (NECat [e,f]) e) f))
filterAtomType (FInv (e,f)) JDHSecKey JDHSecKey _ = Just (FWff (NEDecS (NEEncS (NECat [e,f]) e) f))
-- generic inversion test
filterAtomType a@(FInv (e,f)) _ _ _ = if e==f then case e of
                                                        NEVar _ _ -> Nothing -- variables are already computed, no need to check them again
                                                        _ -> Just a
                                                        else error ("INVcheck: malformed code - e: " ++ show e ++ "\nf: " ++ show f)

filterAtomType a _ _ _ = error ("filterAtomType - unexpected check: " ++ show a)

-- filter some tests & make some typechecking
filterAtom :: Atom -> SynthesisTypeEnc -> Maybe Atom
filterAtom a@(FWff _) _ = Just a
filterAtom a@(FEq (e,f,_)) opt = filterAtomType a (typeof e) (typeof f) opt
filterAtom a@(FInv (e,f)) opt = filterAtomType a (typeof e) (typeof f) opt
filterAtom a@(FNotEq (e,f)) opt = filterAtomType a (typeof e) (typeof f) opt

mkProt2J :: Protocol -> OFMCAttackImpersonationsAndProt -> AnBxOnP -> AnBxCfg -> JProtocol
mkProt2J prot@(_,ptypes,_,_,_,_,_,_,_) intrProtInfos options cfg = let
                                                                    ((name,declarations,jequations),execnarr) = trProt2NExecnarr prot intrProtInfos options
                                                                    types = case intrProtInfos of
                                                                            Just (_,(_,trtypes,_,_,_,_,_,_,_),_,_) -> trtypes
                                                                            Nothing -> ptypes
                                                                    jcustomtypes = nubOrd [t | (Custom t _,_) <- types]
                                                                    constants = constOfProt prot
                                                                    jconstants =  map (\x-> id2NEIdent x ctx) constants
                                                                    shares = defsShare declarations
                                                                    agree = defsAgree declarations
                                                                    ipBase = ipAddress cfg
                                                                    stPort = startingPort cfg
                                                                    ctx = types2context newContext types
                                                                    roles0 = actions2roles execnarr ctx
                                                                    roles = sortedRoles roles0 options
                                                                    droles0 = enumerateRolesInit roles options  -- enumerate docker roles (no pings calculation, nor port list)
                                                                    channels = actions2channels execnarr stPort ctx [] droles0 (dockerIPBase cfg) ipBase options
                                                                    droles = channels2DRoles channels droles0   -- add pings calculation and port list
                                                                    agents = getAgents types
                                                                    jagents = map (\x-> id2NEIdent x ctx) agents
                                                                    inactiveagents =  jagents \\ roles
                                                                    (jactions,jsteps0) = mapActions execnarr ctx channels 0 (synthesistypeenc options)
                                                                    jsteps = sort jsteps0
                                                                    toIgnore = Set.union (mkToIgnore (identsOfProtocol types)) (shareFun (shares ++ agree))
                                                                    methods = nubOrd (mkRoleMethods declarations ctx toIgnore)
                                                                    fields = nubOrd (getRoleFieldDec declarations toIgnore ctx ++ getRoleFieldNarrJ jactions toIgnore ctx)
                                                                    -- in error(show jdeclarations) 
                                                                    -- in error(show jactions)
                                                                    -- in error("\n" ++ showSep show methods)
                                                                    -- in error (showAnB (mkProtAgree prot))
                                                                 in (name,jcustomtypes,jconstants,shares,agree,jequations,roles,droles,inactiveagents,jsteps,channels,fields,methods,jactions)

-- put the intruder as last role
-- this allow to preserve role alias between different runs if intruder is added later
sortedRoles :: JRoles -> AnBxOnP -> JRoles
sortedRoles roles options =
                    let
                        dyagent = (JAgent,anbxmitm options)
                        intruderList = ([dyagent | elem dyagent roles])
                        notIntruderList = roles \\ intruderList
                    in notIntruderList ++ intruderList


-- extract server roles and put them at the beginning of the list of droles
-- add pings values, and open port list
channels2DRoles :: JChannels -> JDRoles -> JDRoles
channels2DRoles _ [] = []
channels2DRoles chs jdroles = let
                                idServers = nubOrd [ id | (id,_,_,_,_,role,_) <- chs, role == Server] -- preserve the order of role ids
                                dServers = map (role2DRole jdroles) idServers
                                jdroles1 = dServers ++ (jdroles \\ dServers)
                                jdroles2 = map (channels2JDRolePorts chs) jdroles1
                                jdroles3 = map (\x -> setPingsDRole (fromJust $ elemIndex x jdroles2) x) jdroles2
                             in jdroles3
                             -- in error (show jdroles3)

setPingsDRole :: Int -> JDRole -> JDRole
setPingsDRole int (id,net,_,ports,jdroletype) = (id,net,(int+1) * multPingDocker,ports,jdroletype)

-- get the exposed ports from the channels for a given role
channels2JDRolePorts :: JChannels -> JDRole -> JDRole
channels2JDRolePorts chs (id,ip,pings,ports0,jr) = let
                                                        ports1 = [ ports | (idch,_,_,_,ports,role,_) <-chs, role==Server, idch==id ]
                                                   in (id,ip,pings,nubOrd (ports0 ++ ports1),jr)

shareFun :: JShares -> Set.Set Ident
shareFun shares = foldr (\s acc -> case s of
                                     (_,_,NEFun (_,f) _, _) -> Set.insert f acc
                                     _ -> acc)
                 Set.empty shares

-- shares

defsAgree :: [Declaration] -> JAgree
defsAgree [] = []
defsAgree ((DShare x@(SHAgree,_,_,_)):xs) = x : defsAgree xs
defsAgree ((DShare x@(SHAgreeInsecurely,_,_,_)):xs) = x : defsAgree xs
defsAgree (_:xs) = defsAgree xs

defsShare :: [Declaration] -> JShares
defsShare [] = []
defsShare (DShare x@(SHShare,_,(NEFun _ _),_):xs) = x : defsShare xs
defsShare (_:xs) = defsShare xs

mkRoleMethods :: [Declaration] -> JContext -> Set.Set String -> JRoleMethods
mkRoleMethods [] _ _ = []
mkRoleMethods [x] ctx toIgnore = case x of
                                    DKnow (agent,expr@(NEFun (_,f) _)) -> [fun2method agent expr f | Map.member f (nonIgnoredFunctions ctx toIgnore)]
                                    DKnow (agent,expr@(NEName (_,f))) -> [fun2method agent expr f | Map.member f (nonIgnoredFunctions ctx toIgnore)]
                                    _ -> []

mkRoleMethods (x:xs) ctx toIgnore = union (mkRoleMethods [x] ctx toIgnore) (mkRoleMethods xs ctx toIgnore)

fun2method :: NEIdent -> NExpression -> Ident -> (JRole,RoleMethod)
fun2method role expr fun = (role,newmethod)
                                where
                                    jfun = getMethod expr fun
                                    newmethod = setMethod jfun

setMethod :: NEIdent -> RoleMethod
-- for untyped functions we need to compute the default value (sum of hash values) iterating on the array of objects
setMethod f@(JFunction _ (t1@JUntyped,t2),name) = RoleMethod {mname = name, mpars = mypars, mparsnames = myparsnames, mcode = mycode, rettype = showJavaType t2, retvalue = myretvalue}
                                                                                    where
                                                                                        hashvar = show AnBxHash
                                                                                        obj = "obj"
                                                                                        myparsTyped = getMethodsPars [t1] (requiresSession t2)
                                                                                        mypars = getPars myparsTyped
                                                                                        myretvalue = getRetValue myparsTyped t1 t2 hashvar
                                                                                        myparsnames = getParsNames myparsTyped
                                                                                        errorMsg = error ("unexpected parameters in function " ++ show f)
                                                                                        mycodebody x = showJavaType JInt ++ " " ++ hashvar ++ " = 0;" ++ "\n\t\t" ++
                                                                                                            "for (" ++ showJavaType JObject ++ " " ++ obj ++ " : " ++ x ++ ")" ++ "\n\t\t\t" ++
                                                                                                            hashvar ++ " = " ++ hashvar ++ " + " ++ applyOp APIhashCode obj ++ " ;"
                                                                                        mycode = if requiresSession t2 then
                                                                                                        case myparsTyped of
                                                                                                            [_, (_,x)] -> mycodebody x  -- if a session is required we have 2 parameters
                                                                                                            _ -> errorMsg
                                                                                                 else
                                                                                                   case myparsTyped of
                                                                                                            [(_,x)] -> mycodebody x  -- if no session is required we have 1 parameters
                                                                                                            _ -> errorMsg

-- for other the default value is the sum of hash values of all parameters
setMethod (JFunction _ (t1,t2),name) = RoleMethod {mname = name, mpars = mypars, mparsnames = myparsnames, mcode = mycode, rettype = showJavaType t2, retvalue = myretvalue}
                                                                                where
                                                                                        myparsTyped = case t1 of
                                                                                                AnBxParams t -> getMethodsPars t (requiresSession t2)
                                                                                                _ -> getMethodsPars [t1] (requiresSession t2)
                                                                                        mypars = getPars myparsTyped
                                                                                        myretvalue = getRetValue myparsTyped t1 t2 name
                                                                                        myparsnames = getParsNames myparsTyped
                                                                                        mycode = ""
setMethod id = error ("unhandled Java method: " ++ show id)

mkToString :: String -> String
mkToString x = x ++ applyOp APItoString ""

mkhashCode :: String -> String
mkhashCode x = applyOp APIhashCode x

mkConcatHashCode :: [String] -> String
mkConcatHashCode xs = intercalate concatOp (map mkhashCode xs)

mkConcatHashCode2Bytes :: [String] -> String
mkConcatHashCode2Bytes xs = integerType ++ applyOp APIgetBytes (applyOp APItoString (mkConcatHashCode xs))

mkValue2Bytes :: String -> String
mkValue2Bytes x = integerType ++ applyOp APIgetBytes (applyOp APItoString x)

-- mock values for public functions
defPassword :: String
defPassword = "MXW1cuUIsDIsCHp3SRQz"
defSalt :: String
defSalt = "Cixjs6Ci8gBsEunHXVON"

getRetValue :: JMethodPars -> JType -> JType -> String -> String
getRetValue p _ t2@JSymmetricKey name = let -- find if any parameter type matches the return type
                                        matchingPars = [ x | x@(t,_) <- p, t == t2]
                                        parsNameList = [ id | (t,id) <- p, t /= JAnBSession ]
                                      in case matchingPars of
                                           [] -> if null parsNameList then strDelimiter ++ name ++ defPassword ++ strDelimiter ++ concatOp ++ strDelimiter ++ reverse name ++ defSalt ++ strDelimiter
                                                     else if length parsNameList == 1 then mkToString (head parsNameList) ++ concatOp  ++ strDelimiter ++ defSalt ++ reverse name  ++ strDelimiter
                                                     else showTypeConstructorStaticFunction t2 (password ++ sepComma ++ salt)
                                                        where
                                                        password = intercalate concatOp (map mkToString parsNameList)
                                                        salt = intercalate concatOp (map mkToString (reverse parsNameList))
                                           _ -> snd (head matchingPars)

getRetValue _ JUntyped t2 name = showTypeConstructorStaticFunction t2 (mkValue2Bytes name)
getRetValue p _ t2 _ = showTypeConstructorStaticFunction t2 (mkConcatHashCode2Bytes parsNameList)
                                    where
                                        parsNameList = [ id | (t,id) <- p, t /= JAnBSession ]

getMethodsPars :: [JType] -> Bool -> JMethodPars
getMethodsPars t True = (JAnBSession,sessName) : getMethodsPars t False
-- getMethodsPars [] False = []
getMethodsPars t False =  zip t pars
                            where pars = map paramName [1..length t]

getPars :: JMethodPars -> String
getPars p = intercalate sepComma (map listType p)

getParsNames :: JMethodPars -> String
getParsNames p = intercalate sepComma ([ snd x | x <- p])

listType :: NEIdent -> String
listType (t,n) = showJavaType t ++ " " ++ n

paramName :: Int -> String
paramName n = "par"++ show n

getMethod :: NExpression -> String -> NEIdent
getMethod expr@(NEName f@(JFunction {},funname)) myfun = if funname == myfun then f else error ("invalid getMethod request expr: " ++ show expr)
getMethod expr@(NEFun f@(JFunction {},funname) _) myfun = if funname == myfun then f else error ("invalid getMethod request expr: " ++ show expr)
getMethod expr _ = error ("invalid getMethod request expr: " ++ show expr)

-- functions which are already available in the API
mkToIgnore :: [Ident] -> Set.Set String
mkToIgnore idents = let pkiFuns = map show pkiFunList
                    in Set.fromList (concat [map show [AnBxHash,AnBxHmac], pkiFuns
                                     ,[f ++ x | x <- idents, f <- pkiFuns]
                                     ,[p ++ "(" ++ f ++ x ++ ")" | x <- idents,f <- pkiFuns,p <- [show SpyerPriv,show SpyerPub]]])

nonIgnoredFunctions :: JContext -> Set.Set String -> Map.Map String Binding
nonIgnoredFunctions (JContext ctx) ignoreIds = Map.filterWithKey (\id b -> case b of
                                                                (VarBind (JFunction {})) -> Set.notMember id ignoreIds
                                                                _ -> False) ctx

actions2roles :: [NAction] -> JContext -> JRoles
actions2roles [] _ = []
actions2roles (NAEmit (_,_,(id1,_,_),id2exp,_):xs) ctx | exprIsAgent id2exp = let
                                                                            id2 = agentOfNExpression id2exp
                                                                            jid2 = id2NEIdent id2 ctx
                                                                          in nubOrd ([id1,jid2] ++ actions2roles xs ctx)
actions2roles (_:xs) ctx = actions2roles xs ctx

actions2channels :: [NAction] -> PortRange -> JContext -> JChannels -> JDRoles -> IPv4 -> IPv4 -> AnBxOnP -> JChannels
-- actions2channels (action:_) port ctx c droles ipBase hostClient out | trace ("actions2channels\n\taction: " ++ show action ++ "\n\tport: " ++ show port ++ "\n\tchannels: " ++ show c ++ "\n\tdroles: " ++ show droles) False = undefined
actions2channels [] _ _ ch _ _ _ _ = ch
actions2channels (action@(NAEmit (_,_,(id1,ct,id2),id2exp,_)):xs) port ctx chs droles ipBase hostClient options | exprIsAgent id2exp =
                                                                                                if id1 == id2 && isOutTypeJava (anbxouttype options) then -- self channel (A -> A: Msg)
                                                                                                    -- let
                                                                                                        -- jid = id2NEIdent ctx id1
                                                                                                        -- jch = (jid,Self,jid,defaultHostServer,port,ct)
                                                                                                        -- ct1 = addJChannel chs jch
                                                                                                    -- in -- nubOrd (actions2channels xs (port + 1) ctx ct1 hostClient out)
                                                                                                       error ("action: " ++ show action ++ "\n" ++ "cannot be translated as sender and receiver are the same agent " ++ show id1)
                                                                                                 else
                                                                                                let
                                                                                                    out = anbxouttype options
                                                                                                    jip1 = if out==JavaDocker || out==TypedOptExecnarrDocker
                                                                                                                        then case ident2JDRoleType id2 options of
                                                                                                                                    JDHonest -> ip2host ipBase (role2Enum droles id2)
                                                                                                                                    JDIntruder -> ip2gateway ipBase (role2Enum droles id1)
                                                                                                                        else hostClient
                                                                                                    jip2 = defaultHostServer -- for channel purpose, just use the default in any case
                                                                                                    -- for description purpose we compute the ip address of the client
                                                                                                    jip2desc = if out==JavaDocker || out==TypedOptExecnarrDocker
                                                                                                                        then case ident2JDRoleType id1 options of
                                                                                                                                    JDHonest -> ip2host ipBase (role2Enum droles id1)
                                                                                                                                    JDIntruder -> ip2gateway ipBase (role2Enum droles id2)
                                                                                                                        else hostClient
                                                                                                    desc2 = channelDescription id1 id2 jip2desc jip1 port Client ct
                                                                                                    desc1 = channelDescription id2 id1 jip1 jip2desc port Server ct
                                                                                                    jch1 = (id1,ct,id2,jip1,port,Client,desc1)
                                                                                                    jch2 = (id2,ct,id1,jip2,port,Server,desc2)
                                                                                                    chs1 = addJChannel chs jch2    -- add server first
                                                                                                    chs2 = addJChannel chs1 jch1
                                                                                                 in nubOrd (actions2channels xs (nextPort port) ctx chs2 droles ipBase hostClient options)

actions2channels (_:xs) port ctx chs droles ipBase hostClient options = actions2channels xs port ctx chs droles ipBase hostClient options

channelDescription :: JRole -> JRole -> IPv4 -> IPv4 -> PortRange -> JChannelRole -> ChannelType -> String
channelDescription (_,id1) (_,id2) ip1 ip2 port cr ct = let
                                                          channelStr = " " ++ showChannelType ct ++ " "
                                                          portStr = ":" ++ show port
                                                        in
                                                            id1 ++ channelStr ++ id2 ++ " - " ++
                                                            Net.IPv4.encodeString ip1  ++
                                                            (if cr==Server then portStr else "") ++
                                                            channelStr ++
                                                            Net.IPv4.encodeString ip2 ++
                                                            (if cr==Client then portStr else "")


multPingDocker :: Int  -- multiplication factor for computing no of initial pings for docker containers 
multPingDocker = 1

-- initialisation of JDRoles, computes if Honest or Intruder, and assign subnet
enumerateRolesInit :: JRoles -> AnBxOnP -> JDRoles
enumerateRolesInit [] _ = []
enumerateRolesInit xs options = map (\x -> (x,fromIntegral (fromJust $ elemIndex x xs) + 1, 0,[],ident2JDRoleType x options)) xs

-- given a role provide the numeric identified, used for Docker code generation
role2Enum :: JDRoles -> JRole -> Word8
role2Enum [] id = error ("role2Enum: role " ++ show id ++ " does not exist in the list")
role2Enum ((xid,n,_,_,_):xs) id = if xid == id then n else role2Enum xs id

-- given a role provide the numeric identified, used for Docker code generation
role2DRole :: JDRoles -> JRole -> JDRole
role2DRole [] id = error ("role2DRole: role " ++ show id ++ " does not exist in the list")
role2DRole (jd@(xid,_,_,_,_):xs) id = if xid == id then jd else role2DRole xs id

cfgError :: String -> String -> FilePath -> String
cfgError value param filepath = value ++ " is an invalid value, please check the parameter " ++ map toLower param ++ " in your config file: " ++ filepath

ip2node :: IPv4 -> Word8 -> Word8 -> IPv4
ip2node base net forth = ipv4 o1 o2 net forth
                     where (o1,o2,_,_) = toOctets base

-- gateway ip (Docker)
ip2gateway :: IPv4 -> Word8 -> IPv4
ip2gateway base net  = ip2node base net 253

ip2gatewayBridge :: IPv4 -> Word8 -> IPv4
ip2gatewayBridge base net  = ip2node base net 254

-- host ip (Docker)
ip2host :: IPv4 -> Word8 -> IPv4
ip2host base net = ip2node base net 2

-- subnet ip (Docker)
ip2subnet :: IPv4 -> Word8 -> IPv4
ip2subnet base net = ip2node base net 0

-- add channel if not duplicated. preserve order
addJChannel :: JChannels -> JChannel -> JChannels
-- addJChannel chs ch | trace ("addJChannel\n\tchs: " ++ show chs ++ "\n\tch: "  ++ show ch) False = undefined
addJChannel [] ch = [ch]
addJChannel chs ch@(id3,ct2,id4,_,_,_,_) = let
                         chs1 = [ x | x@(id1,ct1,id2,_,_,_,_) <- chs, id1 == id3 && id2 == id4 && ct1 == ct2]
                       in case chs1 of
                            [] -> chs ++ [ch]
                            _ -> chs

dbgJava :: Protocol -> OFMCAttackImpersonationsAndProt -> AnBxOnP -> AnBxCfg -> String
dbgJava origprot trImpsAndProt options cfg =
            let
                (name,jcustomtypes,jconstants,shares,agree,jequations,roles,droles,inactiveagents,steps,channels,fields,methods,jactions) = mkProt2J origprot trImpsAndProt options cfg
                (_,_,_,_,_,_,_,actions,_)  = case trImpsAndProt of
                                             Just (_,trprot,_,_) -> trprot
                                             Nothing -> origprot
                str =   "Protocol: " ++ name ++ "\n"
                        ++ "\n--- AnB Actions  ---\n" ++ showActions actions ++ "\n"
                        ++ "\n--- CustomTypes  ---\n" ++ show jcustomtypes ++ "\n"
                        ++ "\n--- Constants  ---\n" ++ show jconstants ++ "\n"
                        ++ "\n--- Shares ---\n" ++ show shares ++ "\n"
                        ++ "\n--- Agree ---\n" ++ show agree ++ "\n"
                        ++ "\n--- Equations ---\n" ++ Spyer_Message.showEquations jequations
                        ++ "\n--- Methods ---\n" ++ showSep show methods
                        ++ "\n--- Roles ---\n" ++ show roles ++ "\n"
                        ++ "\n--- Docker Roles ---\n" ++ show droles ++ "\n"
                        ++ "\n--- Inactive Agents ---\n" ++ show inactiveagents ++ "\n"
                        ++ "\n--- Steps ---\n" ++ show steps ++ "\n"
                        ++ "\n--- Channels ---\n" ++ showSep show channels
                        ++ "\n--- RoleFields ---\n" ++ showSep show fields
                        ++ "\n--- Actions ---\n" ++ showJActions jactions
            in str

showSep :: (a -> String) -> [a] -> String
showSep _ [] =  ""
showSep f (x:xs) =  f x ++ "\n" ++ showSep f xs
-- -------------------------

mapMsgs :: [Msg] -> JContext -> [NExpression]
mapMsgs [] _ = []
mapMsgs [x] ctx = [mapMsg x  ctx]
mapMsgs msgs ctx = map (\x -> mapMsg x ctx) msgs

mapMsg :: Msg -> JContext -> NExpression
mapMsg msg ctx = trMsg msg ctx
