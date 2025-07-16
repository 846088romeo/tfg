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

{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "Avoid lambda using `infix`" #-}
{-# LANGUAGE InstanceSigs #-}
{-# HLINT ignore "Use infix" #-}

module AnB2PVT where

-- {-# LANGUAGE StrictData #-}

import AnBxMsgCommon
    ( dhPar,
      pkiEncFunList,
      pkiFunList,
      pkiSigFunList,
      ppIdList,
      ppXList,
      replace,
      syncMsg,
      AnBxPKeysFun(AnBxSK),
      AnBxReserved(..),
      ShareType(SHAgree, SHAgreeInsecurely), PrivateFunction (PrivFun, PubFun))
import AnBAst
import AnBxOnP
import qualified Data.Set as Set
import qualified Data.Map as Map
import qualified Data.List as List
import Data.Maybe ( fromJust,listToMaybe )
import Data.List ( foldl', (\\), intercalate, isInfixOf, nubBy, sort, sortBy )
import Debug.Trace
import AnB2NExpression ( Fact(..), NEChannel)
import Java_TypeSystem_JType hiding (showNEIdentList, showNEIdent)
import JavaCodeGenConfig
    ( type_Crypto_SealedPair,
      type_Crypto_ByteArray,
      type_Crypto_KeyPair,showType, typeSealedPair,eqTypePV, bitstring, eqTypePVFunType)
import JavaAst
    ( JAction(..), JActions, JAgree, JProtocol, JShares )
import JavaType ( typeof )
import Data.Char (toLower)
import Spyer_Message
import Java_TypeSystem_Evaluator (pkFunOfNExpression) 
import Java_TypeSystem_Context ( newContext )
import AnBxAst (AnBxChannelType(..))
import Data.Containers.ListUtils (nubOrd)

colonSym :: String
colonSym = ": "
commaSep :: String
commaSep = ","

time :: String
time = "time"
nat :: String
nat = "nat"
builtintypes :: [JType]
builtintypes = [JBool,JObject]
privPrefix :: String
privPrefix = "priv_"
processPrefix :: String
processPrefix = "process_"
privateDecl :: String
privateDecl = "[private]"
channel :: String
channel = "channel"

showMess :: Bool
showMess = False

failedEvent :: String
failedEvent = "failedEvent"
failedCheck :: String
failedCheck = "failedCheck"
successCheck :: String
successCheck = "successCheck"

projOpTypeCharNumber :: Int
projOpTypeCharNumber = 3

notAFreeName :: [NEIdent]
notAFreeName = [(JString,syncMsg),(JString,show AnBxBlind),(JDHBase,dhPar),(JNonce,show AnBxZero)]

-- abbreviation for Type in projectors' names
projParType :: JType -> OutType -> String
projParType x pv | showType x pv == type_Crypto_ByteArray = take projOpTypeCharNumber "ByteArray"
                 | showType x pv == type_Crypto_SealedPair || showType x pv == typeSealedPair = take projOpTypeCharNumber "SePair"
                 | showType x pv == type_Crypto_KeyPair = take projOpTypeCharNumber "CKeyPair"
                 | otherwise =  take projOpTypeCharNumber (showType x pv)

                        -- sealedObject = "SealedObject"
                        -- signedObject = "SignedObject"
                        -- keyPair = "KeyPair"
                        -- secretKey = "SecretKey"
                        -- publicKey = "PublicKey"
                        -- privateKey = "PrivateKey"
                        -- string = "String"
                        -- object = "Object"
                        -- dhParameterSpec = "DHParameterSpec"
                        -- anbx_Params = "AnBxParams"
                        -- anb_Session = "AnB_Session"

nullAgent :: NEIdent
nullAgent = (JAgent,"")

insecureChannel :: NEChannel
insecureChannel = (nullAgent,Insecure,nullAgent)        -- for insecure channel, we need only the type of channel

honestAgent :: NEIdent  -> NEIdent
honestAgent (JAgent,a) = (JAgent,"honest" ++ a)
honestAgent x = error ("cannot build an honest agent from " ++ show x)

xAgentPrefix :: String
xAgentPrefix = "X"

funDeclDataTC :: String
funDeclDataTC = "[data,typeConverter]"
funDeclData :: String
funDeclData = "[data]"
funDeclPrivate :: String
funDeclPrivate = "[private]"

bulletChannels :: [ChannelType]
bulletChannels = [FreshSecure,Secure] ++ [Sharing SHAgree]
isBulletChannel :: ChannelType -> Bool
isBulletChannel ch = elem ch bulletChannels

isFreshChannel :: ChannelType -> Bool
isFreshChannel ch = elem ch [FreshSecure,Sharing SHAgree]

channelName :: NEChannel -> String
channelName (_,Insecure,_) = "ch"
channelName (_,Sharing SHAgreeInsecurely,_) = "ch"
channelName ((JAgent,a),ch,(JAgent,b)) | isBulletChannel ch = "ch_priv_" ++ if a >= b then a ++ "_" ++ b else b ++ "_" ++ a  -- order matches the way channel are declared 
                                       | otherwise = error ("channel " ++ show ch ++ " is undefined in ProVerif")
channelName (_,ch,_) = error ("channel " ++ show ch ++ " is undefined in ProVerif")

processName :: String -> String
processName a = processPrefix ++ a

process2Agent :: String -> String
process2Agent = replace processPrefix ""

isHonestNEIdent :: NEIdent -> Bool
isHonestNEIdent (JAgent,id) = isHonest id
isHonestNEIdent a = error ("error: " ++ show a ++ " is not an agent")

showEvent :: Fact -> NEIdent -> NExpression -> [(NEIdent,NExpression)] -> PE -> OutType -> PVFunType -> String
showEvent fact (_,id) e agsExpr t pv pf = "event " ++ show fact ++ id ++ "(" ++ showExpr e t pv pf ++ commaSep ++ agsExpr1 ++ ")"
        where
            agsExpr1 = intercalate commaSep (map (\x -> showExpr x t pv pf) ags)
            ags = agsExpr2Expr agsExpr

type NEIdentSet = Set.Set NEIdent

data PVProcess =     PZero
                    | PInput (NEIdent,NEChannel,NEIdent,PVProcess)          -- agent name, channel, varname
                    | POutput (NEIdent,NEChannel,NExpression,PVProcess)     -- agent name, channel, expression   
                    | PPar (PVProcess,PVProcess)
                    | PNew (NEIdent,[NEIdent],PVProcess)            -- ident, args, process
                    | PCheck (NEIdent,Atom,[NEIdent],PVProcess)     -- agent name, formula, varagents
                    | PApply (String,[NExpression],PVFunType)       -- PVFunType how to print arguments in apply
                    | PAssign (NEIdent,NExpression,PVProcess)
                    | PGoal (NEIdent,Fact,NEIdent,NExpression,[NEIdent],[(NEIdent,NExpression)],Bool,Int,PVProcess)    -- first ident = process agent-name   bool = print side conditions for honest agents, last int = effective step
                    | PRepl PVProcess
                    | PReach (ReachEvent,NEIdent,PVProcess)      -- reachability event, at the end of each agentprocess
                    | PComment (String,PVProcess)
    deriving (Show)

data ReachEvent =      ReachBegin
                     | ReachEnd
                 deriving (Eq)

instance Show ReachEvent where
    show :: ReachEvent -> String
    show ReachBegin = "begin"
    show ReachEnd = "end"

data PVFunType = PVFun | PVVar       -- ProVerif output type for function declaration. Print a term as Function (e.g. inv(pk(A)) ) or var (e.g. INVPKA)
                deriving (Eq,Show)

ifHonestPrintElse :: Bool
ifHonestPrintElse = False

showProcess :: PVProcess -> OutType -> JShares -> PVFunType -> String
-- showProcess p pv se pf | trace ("\nshowProcess\n\tp: " ++ show p ++ "\n\tpv: " ++ show pv  ++ "\n\tse: " ++ show se ++ "\n\tpf: " ++ show pf) False = undefined 
showProcess PZero _ _ _ = "0"
showProcess pa@(PReach (_,_,p)) pv se pf = showProcessBase pa pv se pf ++ ";\n" ++ showProcess p pv se pf
showProcess pa@(PInput(_,_,_,p)) pv se pf = showProcessBase pa pv se pf ++ ";\n" ++ showProcess p pv se pf
showProcess pa@(POutput(_,_,_,p)) pv se pf = showProcessBase pa pv se pf ++ ";\n" ++ showProcess p pv se pf

showProcess (PPar(p,PZero)) pv se pf = "(" ++ showProcess p pv se pf ++ ")"
showProcess (PPar(PZero,p)) pv se pf = "(" ++ showProcess p pv se pf ++ ")"
showProcess (PPar(p,q)) pv se pf = "(" ++ showProcess p pv se pf ++ ") |\n" ++ showProcess q pv se pf

showProcess pa@(PNew(_,[],p)) pv se pf = showProcessBase pa pv se pf ++ ";\n" ++ showProcess p pv se pf
showProcess pa@(PNew(_,_,p)) pv se pf = showProcessBase pa pv se pf ++ ";\n" ++ showProcess p pv se pf
showProcess pa@(PCheck(_,_,_,p)) pv se pf = showProcessBase pa pv se pf ++ "\n" ++ showProcess p pv se pf
showProcess (PApply(a,es,PVVar)) pv _ _ = a ++ showParamsExpr es PEUntyped pv PVVar
showProcess (PApply(a,es,PVFun)) pv _ _ = a ++ showParamsExpr es PEUntyped pv PVFun

showProcess pa@(PAssign(_,_,p)) pv se pf = showProcessBase pa pv se pf ++ "\n" ++ showProcess p pv se pf

showProcess pa@(PGoal(_,Witness,_,_,_,_,_,_,p)) pv se pf = showProcessBase pa pv se pf ++ ";\n" ++ showProcess p pv se pf
--                                                                        where --- [PV] when an agent is mentioned in an authentication goal payload, is referred as honestX rather than X
--                                                                            v1 = varagents \\ [a]
--                                                                            v2 = map honestAgent v1
--                                                                            xs = zip v1 v2
--                                                                            e1 = substIDExpr e xs

showProcess pa@(PGoal(a,SecretGoal,_,_,varagents,agsExpr,True,_,p)) pv se pf = ifHonest a varagents agsExpr andprep PEUntyped pv pf thenStatement ifHonestPrintElse
                                                                                    ++ showProcess p pv se pf
                                                                                    where
                                                                                        thenStatement = showProcessBase pa pv se pf

showProcess pa@(PGoal(_,SecretGoal,_,_,_,_,False,_,p)) pv se pf = showProcessBase pa pv se pf ++ ";\n" ++ showProcess p pv se pf

showProcess pa@(PGoal(a,GuessableSecretGoal,_,_,varagents,agsExpr,True,_,p)) pv se pf = ifHonest a varagents agsExpr andprep PEUntyped pv pf thenStatement ifHonestPrintElse
                                                                                    ++ showProcess p pv se pf
                                                                                    where
                                                                                        thenStatement = showProcessBase pa pv se pf

showProcess pa@(PGoal(_,GuessableSecretGoal,_,_,_,_,False,_,p)) pv se pf = showProcessBase pa pv se pf ++ ";\n" ++ showProcess p pv se pf

showProcess pa@(PGoal(a,Seen,_,_,varagents,agsExpr,True,_,p)) pv se pf = ifHonest a varagents agsExpr andprep PEUntyped pv pf thenStatement False
                                                                                    ++ showProcess p pv se pf
                                                                                    where
                                                                                        thenStatement = showProcessBase pa pv se pf

showProcess pa@(PGoal(_,Seen,_,_,_,_,False,_,p)) pv se pf = showProcessBase pa pv se pf ++ ";\n" ++ showProcess p pv se pf

showProcess pa@(PGoal(a,Request,_,_,varagents,agsExpr,True,_,p)) pv se pf = ifHonest a varagents agsExpr andprep PEUntyped pv pf thenStatement ifHonestPrintElse
                                                                                    ++ showProcess p pv se pf
                                                                                    where
                                                                                        thenStatement = showProcessBase pa pv se pf

showProcess pa@(PGoal(_,Request,_,_,_,_,False,_,p)) pv se pf = showProcessBase pa pv se pf ++ ";\n" ++ showProcess p pv se pf

showProcess pa@(PGoal(a,Wrequest,_,_,varagents,agsExpr,True,_,p)) pv se pf = ifHonest a varagents agsExpr andprep PEUntyped pv pf thenStatement ifHonestPrintElse
                                                                                    ++ showProcess p pv se pf
                                                                                    where
                                                                                        thenStatement = showProcessBase pa pv se pf
showProcess pa@(PGoal(_,Wrequest,_,_,_,_,False,_,p)) pv se pf = showProcessBase pa pv se pf ++ ";\n" ++ showProcess p pv se pf

showProcess (PRepl p) pv se pf = "!" ++ showProcess p pv se pf

showProcess (PComment (s,p)) pv se pf = "(* " ++ s ++ " *)\n" ++ showProcess p pv se pf

showProcessBase :: PVProcess -> OutType -> JShares -> PVFunType -> String
showProcessBase (PReach (ev,id,_)) _ _ _ = "event " ++ id2reach ev id
showProcessBase (PInput(_,ch@(_,chtype,_),x,_)) pv _ _ = "in(" ++ channelName ch ++ commaSep ++ showNEIdentTyped x pv ++ ")" ++ if isFreshChannel chtype then " [precise]" else ""
showProcessBase (POutput(_,ch,f,_)) pv _ pf = "out(" ++ channelName ch ++ commaSep ++ showExpr f PEUntyped pv pf ++ ")"
showProcessBase (PNew(x,[],_)) pv _ _ = "new " ++ showNEIdentTyped x pv
showProcessBase (PNew(x,ids,_)) pv _ _ = "new " ++ showNEIdentTypedNew x ids pv
showProcessBase (PCheck(ag,phi,varagents,_)) pv _ _ = showFormula phi ag varagents pv PVVar
showProcessBase (PAssign(x@(t,_),e,_)) pv _ pf = "let " ++ showNEIdentTyped x pv ++ " = " ++ type_conv (typeof e) t pv pf e ++ " in "
showProcessBase (PGoal(_,Witness,id,e,_,agsExpr,_,_,_)) pv _ _ = showEvent Witness id e agsExpr PEUntyped pv PVVar
showProcessBase (PGoal(_,Seen,id,e,_,agsExpr,_,_,_)) pv _ _ = showEvent Seen id e agsExpr PEUntyped pv PVVar
showProcessBase (PGoal(_,Request,id,e,_,agsExpr,_,_,_)) pv _ _ = showEvent Request id e agsExpr PEUntyped pv PVVar
showProcessBase (PGoal(_,Wrequest,id,e,_,agsExpr,_,_,_)) pv _ _ = showEvent Wrequest id e agsExpr PEUntyped pv PVVar
showProcessBase (PGoal (_,SecretGoal,ident,e,_,_,_,_,p)) pv se pf = showProcessBase (POutput(ident,insecureChannel,NEEncS jid fe,p)) pv se pf
                                                                                where
                                                                                    jid = NEName ident
                                                                                    fe = if eqTypePV pv JSymmetricKey (typeof e) then e else NEFun (secretGoalFun ident) e
showProcessBase (PGoal (_,GuessableSecretGoal,ident,e,_,_,_,_,p)) pv se pf = showProcessBase (POutput(ident,insecureChannel,NEEncS jid fe,p)) pv se pf
                                                                                where
                                                                                    jid = NEName ident
                                                                                    fe = if eqTypePV pv JSymmetricKey (typeof e) then e else NEFun (secretGoalFun ident) e
showProcessBase p _ _ _ = error ("showProcessBase is underfined for " ++ show p)

honestAgents :: NEIdent -> [NEIdent] -> [(NEIdent,NExpression)] -> [(NEIdent,NExpression)]
honestAgents a varagents agsExpr = [ x | x@(ag,_) <- agsExpr, a /= ag, elem ag varagents]

ifHonest :: NEIdent -> [NEIdent] -> [(NEIdent,NExpression)] -> ([String] -> String) -> PE -> OutType -> PVFunType -> String -> Bool -> String
-- ifHonest a varagents agsExpr opprep t pv pf | trace ("\nifHonestE\n\ta: " ++ show a ++ "\n\tvaragents: " ++ show varagents  ++ "\n\tagsExpr: " ++ show agsExpr ++ "\n\tpv: " ++ show pv ++ "\n\tpf: " ++ show pf) False = undefined      
ifHonest a varagents agsExpr opprep t pv pf thenStatement printElse = let -- find all the pairs (agent, expression) in goal, except agent a and constant agents
                                                                            hh = honestAgents a varagents agsExpr
                                                                            prep = map (\(x,y) -> showExpr y t pv pf ++ " = " ++ showNEIdent (honestAgent x)) hh
                                                                      in case hh of
                                                                            [] -> thenStatement ++ ";\n"
                                                                            _ -> "(if " ++ opprep prep ++ " then " ++ thenStatement ++ (if printElse then " else event " ++ failedEvent else "") ++ ") |\n"

orprep :: [String] -> String
orprep [] = ""
orprep [x] = x
orprep (x:xs) = x ++ " || " ++ orprep xs

andprep :: [String] -> String
andprep [] = ""
andprep [x] = x
andprep (x:xs) = x ++ " && " ++ orprep xs

neIdent2ExprPK :: NEIdent -> NExpression
neIdent2ExprPK (JPublicKey (Just pk),id) = keyOfIdent (Just pk) id
neIdent2ExprPK (JPrivateKey (Just pk),id) = keyOfIdentPriv (Just pk) id
neIdent2ExprPK e = error ("neIdent2ExprPK - unxpected call for expression: " ++ show e)

showNEIdentTyped :: NEIdent -> OutType -> String
showNEIdentTyped id pv = showNEIdent id ++ colonSym ++ showType (fst id) pv

-- Display the NEIdent with a list of additional identifiers (e.g., new variables) and its type
showNEIdentTypedNew :: NEIdent -> [NEIdent] -> OutType -> String
showNEIdentTypedNew (t, id) ids pv =
    id ++ formatIds ids ++ colonSym ++ showType t pv
  where
    formatIds [] = ""
    formatIds ids = "[" ++ ppJIdList ids ++ "]"

ident2Fun :: NEIdent -> JShares -> Maybe NExpression
ident2Fun ident shares =
    let 
        matchingEntries = [expr | (_, id, expr, _) <- shares, id == ident]
    in listToMaybe matchingEntries

ppJIdList :: [NEIdent] -> String
ppJIdList = ppXList showNEIdent commaSep

ppJIdListTyped :: OutType -> [NEIdent] -> String
ppJIdListTyped pv = ppXList (\x-> showNEIdentTyped x pv) commaSep

availableTypes :: [JType]
availableTypes = [SealedPair JVoid, SealedObject JVoid, SignedObject JVoid, JHmac, JHash,
                  JString, JHmacKey, JSymmetricKey, JNonce, AnBxParams [],
                  JSeqNumber, JBool, JDHBase, JDHPubKey, JDHSecret, JDHSecKey, JAgent]
                  ++ map (JPublicKey  . Just) pkiFunList
                  ++ map (JPrivateKey . Just) pkiFunList

showTypePrelude :: [JType] ->  String -> OutType -> String
showTypePrelude _ _ PV = ""
showTypePrelude ts agentProcesses pv = let
                            ts1 = nubBy (eqTypePV pv) ts
                            ts2 = nubOrd (map (\x -> showType x pv) ts1 \\ map (\x -> showType x pv) builtintypes)
                            ts3 = nubOrd (map (\x -> projParType x pv) ts1 \\ map (\x -> projParType x pv) builtintypes)
                        in
                            if length ts2 /= length ts3 then -- sanity check for the declared types and abbreviations used in projectors 
                                error ("error in declared types (" ++ show (length ts2) ++ ") and projectors (" ++ show (length ts3) ++ ")" ++ "\n\t" ++ show ts2 ++ "\n\t" ++ show ts3)
                            else
                            (if null ts2 then "" else
                                "(* Types *)" ++ "\n" ++
                                concatMap (\t -> "type " ++ t ++ ".\n") (sort ts2) ++ "\n") ++
                            typeConversionDecls ts1 agentProcesses pv

eqTypePair :: (JType,JType) -> (JType,JType) -> Bool
eqTypePair (a,b) (c,d) = a==d && c==b || a==c && b==d

-- check if a type converter is actually used
-- simply checking substring 
checkDecls :: [(JType, JType)] -> String -> OutType -> [(JType, JType)]
checkDecls [] _ _ = []
checkDecls ((t1,t2):xs) str pv = ([(t1,t2) | isInfixOf (typeConversionFun t1 t2 pv) str]) ++ checkDecls xs str pv

typeConversionDecls :: [JType] -> String -> OutType -> String
typeConversionDecls _ _ PV = ""
typeConversionDecls types agentProcesses  pv = let
                                    ts = nubBy (eqTypePV pv) (types \\ builtintypes)
                                    ts1 = nubBy eqTypePair ([(x,JObject) | x <-ts, not (eqTypePV pv x JObject)])
                                    ts2 = checkDecls ts1 agentProcesses pv             -- declares only actually used type converters 
                                 in (if null ts2 then "" else
                                        "(* Type converters *)" ++ "\n" ++
                                        concatMap (\(x,y) -> typeConversionDecl x y funDeclDataTC pv) ts2 ++ "\n")

typeConversionDecl :: JType -> JType -> String -> OutType -> String
-- typeConversionDecl t1 t2 pv | trace ("\ntypeConversionDecl - t1: " ++ showType t1 pv ++ " t2: " ++ showType t2 pv ) False = undefined      
typeConversionDecl _ _ _ PV = ""
typeConversionDecl t1 t2 fun_tc_data pv | eqTypePV pv t1 t2 = ""
                                             | otherwise = typeConversionDeclFun t1 t2 fun_tc_data pv ++ typeConversionDeclReduc t1 t2 pv

typeConversionDeclFun :: JType -> JType -> String -> OutType -> String
typeConversionDeclFun  _ _ _ PV = ""
typeConversionDeclFun t1 t2 fun_tc_data pv = "fun " ++ type_conv t1 t2 pv PVVar (showType t1 pv) ++ colonSym ++ showType t2 pv ++ " " ++ fun_tc_data ++ "." ++ "\n"

typeConversionDeclReduc :: JType -> JType -> OutType -> String
typeConversionDeclReduc _ _ PV = ""
typeConversionDeclReduc t1 t2 pv = "reduc forall x: " ++ showType t1 pv ++ "; " ++ type_conv t2 t1 pv PVVar (type_conv t1 t2 pv PVVar "x") ++ " = x.\n"

typeConversionFun :: JType -> JType -> OutType -> String
typeConversionFun t1 t2 pv@PV = error ("no type conversion function " ++ showType t1 pv ++"->" ++ showType t2  pv ++ " should be declared for mode " ++ show pv)
typeConversionFun t1 t2 pv = showType t1 pv ++ "2" ++ showType t2 pv

class TypeConv a where
        type_conv :: JType -> JType -> OutType -> PVFunType ->  a -> String

instance TypeConv String where
        type_conv t1 t2 pv _ s | not (eqTypePV pv t1 t2) = typeConversionFun t1 t2 pv ++ "(" ++ s ++ ")"
                                     | otherwise = s

instance TypeConv NExpression where
        type_conv t1 t2 pv pf e | not (eqTypePV pv t1 t2) = type_conv t1 t2 pv pf (showExpr e PEUntyped pv pf)
        type_conv _ _ pv pf e = showExpr e PEUntyped pv pf

-- specify when an identified needs to be printed with type or not
data PE = PETyped | PEUntyped
 deriving (Show)

keyofAgentPriv :: NExpression -> AnBxPKeysFun -> String
keyofAgentPriv (NEName (JAgent,x)) pk = privPrefix ++ show pk ++ "(" ++ x ++ ")"
keyofAgentPriv x _ = "error: " ++ show x ++ " is not an agent"

keyofAgentPub :: NExpression -> AnBxPKeysFun -> String
keyofAgentPub a@((NEName (JAgent,_))) pk = show pk ++ "(" ++ keyofAgentPriv a pk ++ ")"
keyofAgentPub x _ = "error: " ++ show x ++ " is not an agent"

showPrivateKey :: String -> String -> String
showPrivateKey key expr = privPrefix ++ key ++ "(" ++ expr ++ ")"


showExpr :: NExpression -> PE -> OutType -> PVFunType -> String
-- showExpr e pe pv pf | trace ("showExpr: " ++ show e ++ " - pe: " ++ show pe ++ " - pv " ++ show pv ++ " - pf: " ++ show pf) False = undefined

-- pub/priv keys where agent is known prior the protocol execution 
showExpr expr@(NEPub (NEFun (_,_) ag) (Just pkf)) PEUntyped _ PVVar  | exprIsPublicKeyAgentKnown expr  = showNEIdent jid
                                                                                                                    where 
                                                                                                                            jid = (JPublicKey (Just pkf),id)
                                                                                                                            id = agentOfNExpression ag
                                                                                                                           
showExpr expr@(NEPriv (NEFun (_,_) ag) (Just pkf)) PEUntyped _  PVVar | exprIsPrivateKeyAgentKnown expr = showNEIdent jid  
                                                                                                                    where 
                                                                                                                            jid = (JPrivateKey (Just pkf),id)
                                                                                                                            id = agentOfNExpression ag
showExpr expr@(NEPub (NEFun (_,_) ag) (Just pkf)) PEUntyped _ PVFun  | exprIsPublicKeyAgentKnown expr  = keyofAgentPub ag pkf                                                                                                                          
showExpr expr@(NEPriv (NEFun (_,_) ag) (Just pkf)) PEUntyped _ PVFun | exprIsPrivateKeyAgentKnown expr = keyofAgentPriv ag pkf

-- pub/priv keys where agent is learned during the protocol execution 
showExpr expr@(NEPub (NEFun (_,_) ag) (Just pkf)) PEUntyped pv pf  | exprIsPublicKeyAgentLearned expr = show pkf ++ "(" ++ privPrefix ++ show pkf ++ "(" ++ showExpr ag PEUntyped pv pf ++ "))"
showExpr expr@(NEPriv (NEFun (_,_) ag) (Just pkf)) PEUntyped pv pf | exprIsPrivateKeyAgentLearned expr = privPrefix ++ show pkf ++ "(" ++ showExpr ag PEUntyped pv pf ++ ")"

-- freshly generated keys 
showExpr expr@(NEPub (NEName jid@(JPublicKey Nothing,_)) Nothing) _ _ _ | exprIsPublicKeyFresh expr = showNEIdent jid                                      -- freshly generated public key
showExpr expr@(NEPriv (NEName (JPublicKey Nothing,pkID)) Nothing) _ _ _ | exprIsPrivateKeyFresh expr = show AnBxInv ++ "(" ++ pkID ++ ")"                  -- private key of a freshly generated public key 

-- this is only for parameters of process as they are converted: NExpression -> NEIdent (freenames) -> NExpressions

showExpr (NEName jid@(JPublicKey (Just pkf),ag)) PEUntyped _v PVFun = if isHonest ag then showNEIdent jid else keyofAgentPub id pkf -- show pkf ++ "(" ++ privPrefix ++ show pkf ++ "(" ++ showExpr id PEUntyped pv pf  ++ "))"
                                                                                                                                                                        where id = NEName (JAgent,ag)
showExpr (NEName jid@(JPrivateKey (Just pkf),ag)) PEUntyped _ PVFun = if isHonest ag then showNEIdent jid else keyofAgentPriv id pkf -- privPrefix ++ show pkf ++ "(" ++ showExpr id PEUntyped pv pf  ++ ")"
                                                                                                                                                                        where id = NEName (JAgent,ag)
---------------
showExpr (NEName n) PETyped pv _ = showNEIdentTyped n pv
showExpr (NEName n) PEUntyped _ _ = showNEIdent n
showExpr (NEVar n _) PETyped pv _ = showNEIdentTyped n pv
showExpr (NEVar n _) PEUntyped _ _ = showNEIdent n

showExpr (NEEnc m n) _ pv pf = case pk of
                                        Nothing -> "enc" ++ "(" ++ type_conv (typeof m) JObject pv pf m ++ commaSep ++  type_conv (typeof n) (JPublicKey Nothing) pv pf n ++ ")"
                                        Just pkf -> "enc_" ++ show pkf ++ "(" ++ type_conv (typeof m) JObject pv pf m ++ commaSep ++  type_conv (typeof n) (JPublicKey pk) pv pf n ++ ")"
                                        where pk = pkFunOfNExpression n newContext -- ctx

showExpr e@(NEDec m n) t pv pf = case pk of
                                                Nothing -> type_conv JObject (typeof e) pv pf ("dec" ++ "(" ++ type_conv (typeof m) (SealedPair JVoid) pv pf m ++ commaSep ++ showExpr n t pv pf ++ ")")
                                                Just pkf -> type_conv JObject (typeof e) pv pf ("dec_" ++ show pkf ++ "(" ++ type_conv (typeof m) (SealedPair JVoid) pv pf m ++ commaSep ++ showExpr n t pv pf ++ ")")
                                        where pk = pkFunOfNExpression n newContext -- ctx

showExpr (NEEncS m n) _ pv pf = "encS(" ++ type_conv (typeof m) JObject pv pf m ++ commaSep ++  type_conv (typeof n) JSymmetricKey pv pf n ++ ")"  --  ++ " (* " ++ show (arityOfNExpression n) ++ commaSep ++ show n ++ " *)"
showExpr e@(NEDecS m n) t pv pf = type_conv JObject (typeof e) pv pf ("decS(" ++ type_conv (typeof m) (SealedObject JVoid) pv pf m ++ commaSep ++ showExpr n t pv pf ++ ")" ) -- ++ " (* " ++ show (arityOfNExpression n) ++ commaSep ++ show n ++ " *)"

showExpr (NESign m n) t pv pf = case sk of
                                                Nothing -> "sign_" ++ show AnBxSK ++ "("  ++ type_conv (typeof m) JObject pv pf m ++ commaSep ++ showExpr n t pv pf ++ ")"   -- freshly generated key
                                                Just skf -> "sign_" ++ show skf ++ "("  ++ type_conv (typeof m) JObject pv pf m ++ commaSep ++ showExpr n t pv pf ++ ")"
                                                where sk = pkFunOfNExpression n newContext -- ctx

showExpr e@(NEVerify m n) t pv pf = case sk of
                                                Nothing -> type_conv JObject (typeof e) pv pf ("verify_" ++ show AnBxSK ++ "(" ++ type_conv (typeof m) (SignedObject JVoid) pv pf m ++ commaSep ++ showExpr n t pv pf ++ ")") -- freshly generated key
                                                Just skf -> type_conv JObject (typeof e) pv pf ("verify_" ++ show skf ++ "(" ++ type_conv (typeof m) (SignedObject JVoid) pv pf m ++ commaSep ++ showExpr n t pv pf ++ ")")  
                                                where sk = pkFunOfNExpression n newContext -- ctx

-- showExpr e@(NEVerify m n (Just sk)) t pv pf = type_conv JObject (typeof e) pv pf ("getmess_" ++ show sk ++ "(" ++ type_conv (typeof m) (SignedObject JVoid) pv pf m ++ ")")
-- showExpr e@(NEVerify m n Nothing) t pv pf = type_conv JObject (typeof e) pv pf ("getmess_" ++ show AnBxSK ++ "(" ++ type_conv (typeof m) (SignedObject JVoid) pv pf m ++ ")") -- freshly generated key

showExpr (NEHash m) _ pv pf= show AnBxHash ++ "(" ++  type_conv (typeof m) JObject pv pf m ++ ")"
showExpr (NEHmac m n) t pv pf = show AnBxHmac ++ "(" ++ type_conv (typeof m) JObject pv pf m ++ commaSep ++ showExpr n t pv pf ++ ")"

showExpr (NEKap m n) t pv pf = show AnBxKap ++ "(" ++ showExpr m t pv pf ++ commaSep ++ showExpr n t pv pf ++ ")"
showExpr (NEKas m n) t pv pf = show AnBxKas ++ "(" ++ showExpr m t pv pf ++ commaSep ++ showExpr n t pv pf ++ ")"

showExpr (NEFun (JFunction _ (NEVarArgs,_),f) n) _ pv pf = f  ++ "(" ++ type_conv (typeof n) NEVarArgs pv pf n ++ ")"      -- functions without signature
showExpr (NEFun (JFunction _ (AnBxParams [x],_),f) n) _ pv pf = f ++ "(" ++ type_conv (typeof n) x pv pf n  ++ ")"
showExpr (NEFun (JFunction _ (AnBxParams xx,_),f) (NECat nn)) _ pv pf = f ++ "(" ++ intercalate commaSep (map (\(x,y) -> type_conv (typeof y) x pv pf y) (zip xx nn)) ++ ")"
showExpr (NEFun (JFunction _ (t1,_),f) n) _ pv pf = f ++ "(" ++  type_conv (typeof n) t1 pv pf n ++ ")"

showExpr (NEXor m n) _ pv pf = show AnBxXor ++ "(" ++ type_conv (typeof m) JNonce pv pf m ++ commaSep ++ type_conv (typeof n) JNonce pv pf n ++ ")"

showExpr (NECat []) _ _ _ = ""
showExpr (NECat [x]) t pv pf = showExpr x t pv pf
showExpr (NECat (x:xs)) pe pv pf = "(" ++ showExpr x pe pv pf ++ foldr (\x y -> commaSep ++ showExpr x pe pv pf ++ y) "" xs ++ ")"

showExpr e@(NEProj idx n m) pe pv pf = projOperatorFunName idx n (typeof m) (typeof e) pv ++ "(" ++ showExpr m pe pv pf ++ ")"

showExpr e pe pv pf = error ("showExpr - unhandled expression in PV " ++ show e ++ " - pe: " ++ show pe ++ " - pv " ++ show pv ++ " - pf: " ++ show pf)

showFormula :: Atom -> NEIdent -> [NEIdent] -> OutType -> PVFunType -> String
showFormula (FEq(e,f,_)) ag vargents pv pf = "if " ++ showEqTestCond e f ag vargents pv pf False ++ " then" -- ++ " event " ++ successCheck ++ " else event " ++ failedCheck ++ ";"
-- showFormula (FWff _) _ _ = "" -- always true 
showFormula (FWff e) ag vargents pv pf = showFormula (FEq(e,e,True)) ag vargents pv pf
showFormula (FInv(e,f)) ag vargents pv pf = showFormula (FEq (NEDecS (NEEncS e f) f,e,True)) ag vargents pv pf
showFormula (FNotEq(e,f)) ag vargents pv pf = "if not (" ++ showEqTestCond e f ag vargents pv pf False ++ ") then"

showEqTestCond :: NExpression -> NExpression -> NEIdent -> [NEIdent] -> OutType -> PVFunType -> Bool -> String
--showEqTestCond e f ag varagents pv pf | trace ("\n\tshowEqTestCond - agent: " ++ showNEIdent ag ++ "\n\t" ++ showExpr e PEUntyped pv pf ++ " = " ++ showExpr f PEUntyped pv pf ++ "\n\tvaragents: " ++ show varagents ) False = undefined   
showEqTestCond e f ag varagents pv pf True = let -- currently not used, honestX instead of X in eqchecks
                                          hh = varagents \\ [ag]
                                          lhs = case e of
                                                  (NEName n@(JAgent,_)) -> if elem n hh then showNEIdent (honestAgent n) else showExpr e PEUntyped pv pf
                                                  _ -> showExpr e PEUntyped pv pf
                                          rhs = case f of
                                                  (NEName n@(JAgent,_)) -> if elem n hh then showNEIdent (honestAgent n) else showExpr f PEUntyped pv pf
                                                  _ -> showExpr f PEUntyped pv pf
                                        in lhs ++ " = " ++ rhs
showEqTestCond e f _ _ pv pf False = showExpr e PEUntyped pv pf ++ " = " ++ showExpr f PEUntyped pv pf

projOp :: Int -> Int -> String
projOp i n | i <= n = "proj_" ++ show i ++ "_" ++ show n
           | otherwise = error ("proj error: " ++ show i ++ " > " ++ show n ++ " !")

projOpTyped :: Int -> Int -> JType -> OutType -> String
projOpTyped i n t pv | i <= n = "proj_" ++ show i ++ "_" ++ show n ++ "_" ++ showType t pv
                     | otherwise = error ("proj error: " ++ show i ++ " > " ++ show n ++ " !")

nBitstring :: Int -> String
nBitstring n = ppIdList $ map (const bitstring) [1..n]

gentupledefproj :: Int -> String
gentupledefproj n | n > 0 =
                       let
                            range = [1..n]
                            varname a = "x" ++ show a
                            xn = map varname range
                            xnsig_reduc = map (\x -> varname x ++  colonSym ++ bitstring) range
                            pn = if n == 1 then ppIdList xn else "(" ++ ppIdList xn ++ ")"
                            pn_reduc = intercalate commaSep xnsig_reduc
                            singleproj i n = "reduc forall " ++ pn_reduc ++ "; "  ++ projOp i n ++ "(" ++ pn ++ ") = " ++ varname i ++ "."
                       in
                            concatMap (\x -> singleproj x n ++ "\n") range
                  | otherwise = error ("cannot define tuple of size " ++ show n)

nBitstring2Type :: JType -> OutType -> Int -> String
nBitstring2Type t pv n  ="fun " ++  bitstring ++ "2" ++ showType t pv ++ show n ++ "(" ++ nBitstring n ++ "): " ++ showType t pv  ++ " " ++ funDeclData ++ ".\n"

-- probabilistic public key encryption 
-- fun inv(privatekey): publickey.
-- fun internal_enc(bitstring, publickey, seed): bitstring.
-- reduc forall x: bitstring, y: privatekey, r: seed; decrypt(internal_enc(x,inv(y),r), y) = x.
-- letfun enc(x: bitstring, y: publickey) = new r: seed; internal_enc(x,y,r).

--(* Public key encryption *)
--fun inv(PublicKey): PrivateKey [private].
--fun enc(bitstring,PublicKey): Crypto_SealedPair.
--    reduc forall x: bitstring, y: PublicKey; dec(enc(x,y),inv(y)) = x.

pkiEncFunBase ::  OutType -> Bool -> String
pkiEncFunBase pv pvprobenc =
                                (if pvprobenc && pv/=PV then "type " ++ typeSeed pv ++ "."  ++ "\n" else "") ++
                                "fun " ++ show AnBxInv ++ "(" ++ showType (JPublicKey Nothing) pv ++ "): " ++ showType (JPrivateKey Nothing) pv ++ " " ++ privateDecl ++ "." ++ "\n" ++
                                if pvprobenc then
                                    "fun internal_enc" ++  "(" ++ bitstring ++ commaSep ++ showType (JPublicKey Nothing) pv ++ commaSep ++ typeSeed pv ++ "): " ++ showType (SealedPair JVoid) pv ++ "."  ++ "\n" ++
                                    "    reduc forall x: " ++ bitstring ++ ", y: " ++ showType (JPublicKey Nothing) pv ++ ", r: " ++ typeSeed pv ++ "; dec(internal_enc(x,y,r), inv(y)) = x." ++ "\n" ++
                                    "    letfun enc(x:" ++ bitstring ++ ", y: " ++ showType (JPublicKey Nothing) pv ++ ") = new r: " ++ typeSeed pv ++" ; internal_enc(x,y,r)."
                                    else
                                     "fun enc" ++  "(" ++ bitstring ++ commaSep ++ showType (JPublicKey Nothing) pv ++ "): " ++ showType (SealedPair JVoid) pv ++ "."  ++ "\n" ++
                                     "    reduc forall x: " ++ bitstring ++ ", y: " ++ showType (JPublicKey Nothing) pv ++ "; dec(enc(x,y),inv(y)) = x."

pkiEncFun ::  OutType -> Bool -> AnBxPKeysFun ->  String
pkiEncFun pv pvprobenc pk = "fun " ++ privPrefix ++ show pk ++ "(" ++ showType JAgent pv ++ "): " ++ showType (JPrivateKey (Just pk)) pv ++ " " ++ privateDecl ++ "." ++ "\n" ++
                              "fun " ++ show pk ++ "(" ++ showType (JPrivateKey (Just pk)) pv ++ "): " ++ showType (JPublicKey (Just pk)) pv ++ "."  ++ "\n" ++
                              if pvprobenc then
                                    "fun internal_enc_" ++ show pk ++  "(" ++ bitstring ++ commaSep ++ showType (JPublicKey (Just pk)) pv ++ commaSep ++ typeSeed pv ++ "): " ++ showType (SealedPair JVoid) pv ++ "."  ++ "\n" ++
                                    "    reduc forall x: " ++ bitstring ++ ", y: " ++ showType (JPrivateKey (Just pk)) pv ++ ", r: " ++ typeSeed pv ++ "; dec_" ++ show pk ++ "(internal_enc_" ++ show pk ++ "(x," ++ show pk ++ "(y),r),y) = x." ++ "\n" ++
                                    "    letfun enc_" ++ show pk ++ "(x:" ++ bitstring ++ ", y: " ++ showType (JPublicKey (Just pk)) pv ++ ") = new r: " ++ typeSeed pv ++ "; internal_enc_" ++ show pk ++ "(x,y,r)." ++ "\n"
                                    else
                                      "fun enc_" ++ show pk ++ "(" ++ bitstring ++ commaSep ++ showType (JPublicKey (Just pk)) pv ++ "): " ++ showType (SealedPair JVoid) pv ++ "."  ++ "\n" ++
                                      "    reduc forall x: " ++ bitstring ++ ", y: " ++ showType (JPrivateKey (Just pk)) pv ++ "; dec_" ++ show pk ++ "(enc_" ++ show pk ++ "(x," ++ show pk ++ "(y)),y) = x." ++ "\n"

--fun priv_pk(Agent): PrivateKey [private].
--fun pk(PrivateKey): PublicKey.
--fun enc_pk(bitstring,PublicKey): SealedPair.
--    reduc forall x: bitstring, y: PrivateKey; dec_pk(enc_pk(x,pk(y)),y) = x.


--fun priv_pk(Agent): PrivateKey [private].
--fun pk(PrivateKey): PublicKey.
--fun internal_enc_pk(bitstring,PublicKey,seed): SealedPair.
--    reduc forall x: bitstring, y: PublicKey, r: seed; dec_pk(internal_enc_pk(x,y,r), pk(y)) = x.
--    letfun enc_pk(x:bitstring, y: PublicKey) = new r: seed ; internal_enc_pk(x,y,r).

--(* Signatures *)
--fun priv_sk(Agent): PrivateKey [private].
--fun sk(PrivateKey): PublicKey.
--fun sign_sk(bitstring,PrivateKey): SignedObject.
--    reduc forall m: bitstring, k: PrivateKey; getmess_sk(sign_sk(m,k)) = m.
--    reduc forall m: bitstring, k: PrivateKey; verify_sk(sign_sk(m,k),sk(k)) = m.

pkiSigFun ::  OutType -> Bool -> AnBxPKeysFun ->  String
pkiSigFun pv pvprobenc sk = "fun " ++ privPrefix ++ show sk ++ "(" ++ showType JAgent pv ++ "): " ++ showType (JPrivateKey (Just sk)) pv  ++ " " ++ privateDecl ++ "." ++ "\n" ++
                              "fun " ++ show sk ++ "(" ++ showType (JPrivateKey (Just sk)) pv ++ "): " ++ showType (JPublicKey (Just sk)) pv  ++ "."  ++ "\n" ++
                              if pvprobenc then
                                "fun internal_sign_" ++ show sk ++  "(" ++ bitstring ++ commaSep ++ showType (JPrivateKey (Just sk)) pv ++ commaSep ++ typeSeed pv ++ "): " ++ showType (SignedObject JVoid) pv ++ "."  ++ "\n" ++
                                "    reduc forall m: " ++ bitstring ++ ", k: " ++ showType (JPrivateKey (Just sk)) pv ++ ", r: " ++ typeSeed pv ++ "; getmess_" ++ show sk ++ "(internal_sign_" ++ show sk ++ "(m,k,r)) = m." ++ "\n" ++
                                "    reduc forall m: " ++ bitstring ++ ", k: " ++ showType (JPrivateKey (Just sk)) pv ++ ", r: " ++ typeSeed pv ++ "; verify_" ++ show sk ++ "(internal_sign_" ++ show sk ++ "(m,k,r)," ++ show sk ++ "(k)) = m." ++ "\n" ++
                                "    letfun sign_" ++ show sk ++ "(m: " ++ bitstring ++ ", k: " ++ showType (JPrivateKey (Just sk)) pv ++ ") = new r: " ++ typeSeed pv ++ "; internal_sign_" ++ show sk ++ "(m,k,r)." ++ "\n"
                                   else
                                "fun sign_" ++ show sk ++ "(" ++ bitstring ++ commaSep ++ showType (JPrivateKey (Just sk)) pv ++ "): " ++ showType (SignedObject JVoid) pv ++ "." ++ "\n" ++
                                "    reduc forall m: " ++ bitstring ++ ", k: " ++ showType (JPrivateKey (Just sk)) pv ++ "; getmess_" ++ show sk ++ "(sign_"  ++ show sk ++ "(m,k)) = m."  ++ "\n" ++
                                "    reduc forall m: " ++ bitstring ++ ", k: " ++ showType (JPrivateKey (Just sk)) pv ++ "; verify_" ++ show sk ++ "(sign_" ++ show sk ++ "(m,k)," ++ show sk ++ "(k)) = m."   ++ "\n"


supportNewProVerifSettings :: Bool
supportNewProVerifSettings = True

pvPreludeSettingsList :: AnBxOnP -> [(Bool,String,String,String)]
pvPreludeSettingsList opt = [
                            -- show,settingName,defultValue,possibleValues
                            (True,"ignoreTypes",ignoreTypes,"true|false"),
                            (True,"traceDisplay","none","short|long|none"),
                            (True,"verboseRules","false","false|true"),
                            (True,"verboseBase","false","true|false"),
                            (supportNewProVerifSettings,"verboseGoalReachable",verboseGoalReacheable,"true|false"),        -- supported by ProVerif 2.05+
                            (supportNewProVerifSettings,"verboseStatistics",verboseGoalStatistics,"true|false"),           -- supported by ProVerif 2.05+
                            (True,"verboseClauses","none","short|none|explained"),
                            (False,"abbreviateClauses","true","true|false"),
                            (True,"simplifyDerivation","true","true|false"),
                            (False,"explainDerivation","false","true|false"),
                            (True,"abbreviateDerivation","true","true|false"),
                            (False,"reconstructDerivation","true","true|false"),
                            (False,"displayDerivation","false","true|false"),
                            (False,"unifyDerivation","true","true|false"),
                            (True,"reconstructTrace","true","n|true|false n=4 default"),
                            (True,"traceBacktracking","true","true|false"),
                            (False,"verboseDestructors","true","true|false"),
                            (True,"preciseActions", preciseActions,"true|false|trueWithoutArgsInNames")
                            ]
                        where 
                                ignoreTypes = if anbxouttype opt == PV then "true" else "false"
                                preciseActions = map toLower (show (pvPreciseActions opt))
                                verboseGoalReacheable = map toLower (show (pvVerboseGoalReacheable opt))
                                verboseGoalStatistics = map toLower (show (pvVerboseStatistics opt))

-- sel1 :: (String,String,String) -> String
sel1 :: (a, b, c, d) -> a
sel1 (x,_,_,_) = x
sel2 :: (a, b, c, d) -> b
sel2 (_,x,_,_) = x
sel3 :: (a, b, c, d) -> c
sel3 (_,_,x,_) = x
sel4 :: (a, b, c, d) -> d
sel4 (_,_,_,x) = x

pvPreludeSettings :: [(Bool,String,String,String)] -> String
pvPreludeSettings [] = ""
pvPreludeSettings xs = let
                            xs1 = [ x | x@(True,_,_,_) <- xs ]
                         in
                         "(* Some ProVerif settings *)" ++ "\n" ++
                         concatMap (\x -> "set " ++ sel2 x ++ " = " ++ sel3 x  ++ ". "
                                    ++ (if sel4 x == "" then sel4 x else "\t\t(* " ++ sel4 x ++ " *)") ++ "\n") xs1

pvPrelude :: OutType -> [NEChannel] -> String -> AnBxOnP -> String
pvPrelude pv ch protName opt =
                 "(* Protocol: " ++ process2Agent protName ++ " *)" ++ "\n" ++
                 "(* ProVerif/Applied-pi specification mode: " ++ show pv ++ " *)" ++ "\n" ++
                 "(* Automatically generated by the *)" ++ "\n" ++
                 "(* " ++ productNameWithOptions opt ++  " *)" ++ "\n\n" ++
                 pvPreludeSettings (pvPreludeSettingsList opt) ++
                 "\n" ++
                 "(* Public channel declaration *)" ++ "\n" ++
                 "free " ++ channelName insecureChannel ++ ": " ++ channel ++ "." ++ "\n\n" ++
                 if null ch then "" else
                 "(* Private channel declaration *)" ++ "\n" ++
                 concatMap (\x ->  "free " ++ channelName x ++ ": " ++ channel ++ " " ++ privateDecl ++ "." ++ "\n" ) ch
                 ++ "\n"

--
--(* Probabilistic shared key encryption *)
--
--type sseed.
--fun internal_sencrypt(bitstring,nonce,sseed): bitstring.
--reduc forall x: bitstring, y: nonce, r: sseed; sdecrypt(internal_sencrypt(x,y,r),y) = x.
--letfun sencrypt(x: bitstring, y: nonce) = new r: sseed; internal_sencrypt(x,y,r).
--
--
--
--
--(* Probabilistic public key encryption *)
--
--type seed.
--fun pk(skey): pkey.
--fun internal_encrypt(bitstring, pkey, seed): bitstring.
--reduc forall x: bitstring, y: skey, r: seed; 
--        decrypt(internal_encrypt(x,pk(y),r),y) = x.
--letfun encrypt(x: bitstring, y:pkey) = new r: seed; internal_encrypt(x,y,r).                 


-- types for seed for probabilistic encryption                 
typeSeed :: OutType -> String
typeSeed PV = bitstring
typeSeed _ = "seed"

typeSeedS :: OutType -> String
typeSeedS PV = bitstring
typeSeedS _ = "seedS"

pvPreludeCryptoPrimitives :: AnBxOnP -> OutType -> String
pvPreludeCryptoPrimitives options pv =
                 let
                    pvprobenc = pvProbEnc options
                    pvxortheory = pvXorTheory options
                 in
                 "(* hash/hmac functions *)" ++ "\n" ++
                 "fun " ++ show AnBxHash ++ "(" ++ bitstring ++ "): " ++ showType JHash pv ++ "."  ++ "\n" ++
                 -- hash: the absence of any associated destructor or equational theory captures pre-image resistance, second pre-image resistance and collision resistance properties of cryptographic hash functions.    
                 "fun " ++ show AnBxHmac ++ "(" ++ bitstring ++ commaSep ++ showType JHmacKey pv ++ "): " ++ showType JHmac pv ++ "."  ++ "\n" ++
                 -- MAC is assumed to be a pseudo-random function (PRF)
                 -- If the MAC is assumed to be unforgeable (UF-CMA), we can add this (see Proverif Manual ch. 4)
                 -- "reduc forall m: " ++ bitstring ++ ",k: " ++ showType JHmacKey pv ++ "; getMessHMac(hmac(m,k)) = m " ++ "."  ++ "\n" ++
                 "\n" ++
                 "(* Public key encryption *)"  ++ "\n" ++
                 pkiEncFunBase pv pvprobenc
                 ++ "\n\n" ++
                 "(* Public key encryption *)"  ++ "\n" ++
                 concatMap (pkiEncFun pv pvprobenc) pkiEncFunList
                 ++ "\n" ++
                 "(* Signatures *)"  ++ "\n" ++
                 concatMap (pkiSigFun pv pvprobenc) pkiSigFunList
                 ++ "\n" ++
                 "(* Symmetric encryption *)"  ++ "\n" ++
                 (if pvprobenc then
                 (
                 if pv /= PV then "type " ++ typeSeedS pv ++ "."  ++ "\n" else "") ++
                 "fun internal_encS(" ++ bitstring ++ commaSep ++ showType JSymmetricKey pv ++ "," ++ typeSeedS pv ++ "): " ++ showType (SealedObject JVoid) pv ++ "."  ++ "\n" ++
                 "    reduc forall x: " ++ bitstring ++ ", y: " ++ showType JSymmetricKey pv ++ ", r: " ++ typeSeedS pv ++ ";" ++ " " ++ "decS(internal_encS(x,y,r),y) = x." ++ "\n" ++
                 "letfun encS(x: " ++ bitstring ++ ", y: " ++ showType JSymmetricKey pv ++ ") = new r: " ++ typeSeedS pv ++ "; internal_encS(x,y,r)."
                  else
                 "fun encS(" ++ bitstring ++ commaSep ++ showType JSymmetricKey pv ++ "): " ++ showType (SealedObject JVoid) pv ++ "."  ++ "\n" ++
                 "    reduc forall x: " ++ bitstring ++ ", y: " ++ showType JSymmetricKey pv ++ "; decS(encS(x,y),y) = x."
                 )
                 ++ "\n\n" ++
                 "(* Diffie-Hellman *)"  ++ "\n" ++
                 "const " ++ dhPar ++ colonSym ++ showType JDHBase pv ++ " " ++ funDeclData ++ "." ++ "\n" ++
                 "fun " ++ show AnBxKas ++ "(" ++ showType JDHPubKey pv ++ commaSep ++ showType JDHSecret pv ++ "): " ++ showType JDHSecKey pv ++ "."  ++ "\n" ++
                 "fun " ++ show AnBxKap ++ "(" ++ showType JDHBase pv ++ commaSep ++ showType JDHSecret pv ++ "): " ++ showType JDHPubKey pv ++ "."  ++ "\n" ++
                 ("equation forall x: " ++ showType JDHSecret pv ++ ", y: " ++ showType JDHSecret pv ++ "; " ++
                 show AnBxKas ++ "(" ++ show AnBxKap ++ "(g,x),y)" ++ " = " ++ show AnBxKas ++ "(" ++ show AnBxKap ++ "(g,y),x)") ++ ".\n" ++
                 "\n" ++
                 "(* XOR - " ++ show pvxortheory ++ " theory *)"  ++ "\n" ++
                 xorTheoryDisclaimer True ++
                 xorTheory pvxortheory pv

xorTheoryDisclaimer :: Bool -> String
xorTheoryDisclaimer False = ""
xorTheoryDisclaimer True = "(* Due to ProVerif limitation in handling certain types of equations, *)" ++ "\n" ++
                             "(* some xor properties can not be modelled. Results may be not reliable *)" ++ "\n"

-- definition of properties of the xor theory                           
xorZeroDecl :: OutType -> String
xorZeroDecl pv = "const " ++ show AnBxZero ++ colonSym ++ showType JNonce pv ++ " " ++ funDeclData ++ "." ++ "\n"

xorFunDecl :: OutType -> String
xorFunDecl pv = "fun xor(" ++ showType JNonce pv  ++ commaSep ++ showType JNonce pv ++"): " ++ showType JNonce pv ++ "." ++ "\n"

xorErasureDecl :: OutType -> String
xorErasureDecl pv = "equation forall x:" ++ showType JNonce pv ++ ",y:" ++ showType JNonce pv ++ "; xor(xor(x,y),y) = x." ++ "\n"

xorAssociativityDecl :: OutType -> String
xorAssociativityDecl pv =  "equation forall x:" ++ showType JNonce pv ++ ",y:" ++ showType JNonce pv ++ ",z:" ++ showType JNonce pv ++ "; xor(x,xor(y,z)) = xor(xor(x,y),z)." ++ "\n"

xorCommutatitivityDecl :: OutType -> String
xorCommutatitivityDecl pv =  "equation forall x:" ++ showType JNonce pv ++ ",y:" ++ showType JNonce pv ++ "; xor(x,y) = xor(y,x)." ++ "\n"

xorNilpotenceDecl :: OutType -> String
xorNilpotenceDecl pv = "equation forall x:" ++ showType JNonce pv ++ "; xor(x,x) = " ++ show AnBxZero ++ "." ++ "\n"

xorNeutralElementDecl :: OutType -> String
xorNeutralElementDecl pv = "equation forall x:" ++ showType JNonce pv ++ "; xor(x," ++ show AnBxZero ++ ") = x." ++ "\n"

xorNeutralElementDecl2 :: OutType -> String
xorNeutralElementDecl2 pv = "equation forall x:" ++ showType JNonce pv ++ "; xor(" ++ show AnBxZero ++ ",x) = x." ++ "\n"


-- different xor theories available
xorTheory :: PVXorTheory -> OutType -> String
xorTheory PVXorNone pv = xorFunDecl pv
xorTheory PVXorAss pv = xorFunDecl pv ++ xorAssociativityDecl pv
xorTheory PVXorComm pv = xorFunDecl pv ++ xorCommutatitivityDecl pv
xorTheory PVXorBasic pv = xorFunDecl pv ++ xorErasureDecl pv
xorTheory PVXorSimple pv = xorZeroDecl pv ++ xorTheory PVXorBasic pv ++ xorNeutralElementDecl pv ++ xorNeutralElementDecl2 pv ++xorNilpotenceDecl pv
xorTheory PVXorFull pv = xorZeroDecl pv ++ xorFunDecl pv ++ xorAssociativityDecl pv ++ xorCommutatitivityDecl pv ++ xorNeutralElementDecl pv ++ xorNilpotenceDecl pv

--const zero:bitstring [data].
--fun xor(bitstring,bitstring): bitstring.
--(* associativity *)
--equation forall x:bitstring, y:bitstring, z:bitstring; xor(x, xor(y, z)) = xor(xor(x, y), z).
--(* commutativity *)
--equation forall x:bitstring, y:bitstring; xor(x, y) = xor(y, x).
--(* neutral element *)
--equation forall x:bitstring; xor(x, zero) = x.
--(* nilpotence *)
--equation forall x:bitstring; xor(x, x) = zero.

type Functions = [NEIdent]
type FunctionsProj = [(NEIdent,Int)]

printDeclFunctions :: Functions -> OutType -> String
printDeclFunctions [] _ = ""
printDeclFunctions ((JFunction priv (t1,t2),x):xs) pv = "fun " ++ x ++ "(" ++ typeSig t1 pv ++ ")" ++ colonSym ++ showType t2 pv
                                                                        ++ (if priv==PrivFun then " " ++ funDeclPrivate else "") ++ ".\n"            -- private functions
                                                                        ++ printDeclFunctions xs pv
printDeclFunctions ((t,x):_) _ = error ("unexpected function " ++ x ++ " of type " ++ show t)

printDeclEquations :: NEquations -> Functions -> OutType -> String
printDeclEquations [] _ _ = ""
printDeclEquations (x:xs) fn pv = printDeclEquation x fn pv  ++ printDeclEquations xs fn pv

printDeclEquation :: NEquation -> Functions -> OutType -> String
printDeclEquation (NEqt e1 e2 jids) fn pv = if null jidsNoFun || hideEquation then "" else "equation forall "
                                      ++ intercalate "," (map (\(t,id) -> id ++ ": " ++ showType t pv) jidsNoFun) ++ "; "
                                      ++ showExpr e1 PEUntyped pv PVFun ++ " = " ++ showExpr e2 PEUntyped pv PVFun ++ ".\n"
                                      where
                                        hideEquation = not (null (eqFunctions \\ fn))               -- hide equation if contains undeclared functions (they are not used)
                                        eqFunctions = [ x | x@(JFunction {},_) <- jids ]            -- functions used in the equation
                                        jidsNoFun = jids \\ eqFunctions                             -- identifier which are not functions (parameters)

printDeclFunctionsReduc :: FunctionsProj -> OutType -> String
printDeclFunctionsReduc [] _ = ""
printDeclFunctionsReduc (((JFunction _ (t1,_),x),i):xs) pv = "reduc forall "  ++ typeSigPar t1 pv PVFun ++ "; " ++ x ++ "((" ++ typeSigPar t1 pv PVVar ++ "))" ++ " = x" ++ show i ++ ".\n"  -- "(())" tuple
                                                                        ++ printDeclFunctionsReduc xs pv
printDeclFunctionsReduc (((t,x),_):_) _ = error ("unexpected function " ++ x ++ " of type " ++ show t)

typeSig :: JType ->  OutType -> String
typeSig t@(AnBxParams []) _ = error ("malformed type: " ++ show t)
typeSig (AnBxParams ts) pv = let
                                   xnsig = map (\t -> showType t pv) ts
                             in intercalate commaSep xnsig
typeSig t pv = showType t pv

typeSigPar :: JType ->  OutType -> PVFunType -> String
typeSigPar t@(AnBxParams []) _ _ = error ("malformed type: " ++ show t)
typeSigPar (AnBxParams ts) pv pf =
                               let
                                   xnsig = zipWith (\ t i -> "x" ++ show i ++ if pf == PVFun then ":" ++ showType t pv else "") ts [1..(length ts)]
                               in intercalate commaSep xnsig
typeSigPar t pv PVFun = "x:" ++ showType t pv
typeSigPar _ _ PVVar = "x"

-- private channels 
privChannels :: JActions -> [NEChannel]
privChannels [] = []
privChannels ((JEmit (_,_,(a,ch,b,_,_,_,_),_,_)):xs) | isBulletChannel ch = (if a >= b then [(a,ch,b)] else [(b,ch,a)]) ++ privChannels xs
                                                   | otherwise = privChannels xs
privChannels ((JReceive (_,_,(a,ch,b,_,_,_,_),_)):xs) | isBulletChannel ch = (if a >= b then [(a,ch,b)] else [(b,ch,a)]) ++ privChannels xs
                                                    | otherwise = privChannels xs
privChannels (_:xs) = privChannels xs

eqPrivChannel :: NEChannel -> NEChannel ->  Bool
eqPrivChannel (a1,ch1,b1) (a2,ch2,b2) = (ch1 == ch2 || ch1 == Secure && ch2 == Sharing SHAgree || ch2 == Secure && ch1 == Sharing SHAgree)
                                        && (a1==a2 && b1==b2 || a1==b2 && a2==b1)

-- the name of goal functions
secretGoalFunName :: String -> String
secretGoalFunName id = "fun_goal_" ++ id

secretGoalFuns :: JActions -> OutType -> Functions
secretGoalFuns [] _ = []
secretGoalFuns (JGoal (_,_,fact,(t,id),_,_,_,_):xs) pv | (fact == SecretGoal || fact == GuessableSecretGoal) && not (eqTypePV pv t JSymmetricKey) =
                                                                        secretGoalFun (t,id) : secretGoalFuns xs pv
                                                     | otherwise = secretGoalFuns xs pv
secretGoalFuns (_:xs) pv = secretGoalFuns xs pv

secretGoalFun :: NEIdent -> NEIdent
secretGoalFun (t,id) = (JFunction PubFun (t,JSymmetricKey),secretGoalFunName id)

projOperatorsActions :: JActions -> OutType -> FunctionsProj
projOperatorsActions [] _ = []
projOperatorsActions (x:xs) pv = projOperatorsAction x pv ++ projOperatorsActions xs pv

projOperatorsAction :: JAction -> OutType -> FunctionsProj
-- projOperatorsAction a _ | trace ("projOperatorsAction: " ++ show a) False = undefined
projOperatorsAction (JEmit (_,_,_,e,e1)) pv = projOperatorExpr e pv ++ projOperatorExpr e1 pv
projOperatorsAction (JAssign (_,_,_,e)) pv = projOperatorExpr e pv                    -- ground expression   int = arity
projOperatorsAction (JCall (_,_,e)) pv = projOperatorExpr e pv
projOperatorsAction (JGoal (_,_,_,_,e,xs,_,_)) pv = projOperatorExpr e pv ++ concatMap (\x -> projOperatorExpr x pv) ex
                                                                                                        where ex = [ x | (_,x) <- xs ]      -- bool == side conditions 
projOperatorsAction (JCheck (_,_,phi,_)) pv = projOperatorsActionAtom phi pv
projOperatorsAction _ _ = []

projOperatorsActionAtom :: Atom -> OutType -> FunctionsProj
-- projOperatorsActionAtom a _ | trace ("projOperatorsActionAtom: " ++ show a) False = undefined
projOperatorsActionAtom (FWff e) pv = projOperatorExpr e pv
projOperatorsActionAtom (FEq (e1,e2,_)) pv = projOperatorExpr e1 pv ++ projOperatorExpr e2 pv
projOperatorsActionAtom (FInv (e1,e2)) pv = projOperatorExpr e1 pv ++ projOperatorExpr e2 pv
projOperatorsActionAtom (FNotEq (e1,e2)) pv = projOperatorExpr e1 pv ++ projOperatorExpr e2 pv

projOperatorExpr :: NExpression -> OutType -> FunctionsProj
-- projOperatorExpr e _ | trace ("projOperatorExpr: " ++ show e) False = undefined
projOperatorExpr (NEFun _ e) pv = projOperatorExpr e pv
projOperatorExpr (NEEnc m n) pv = projOperatorExpr m pv ++ projOperatorExpr n pv
projOperatorExpr (NEEncS m n) pv = projOperatorExpr m pv ++ projOperatorExpr n pv
projOperatorExpr (NEDec m n) pv = projOperatorExpr m pv ++ projOperatorExpr n pv
projOperatorExpr (NEDecS m n) pv = projOperatorExpr m pv ++ projOperatorExpr n pv
projOperatorExpr (NESign m n) pv = projOperatorExpr m pv ++ projOperatorExpr n pv
projOperatorExpr (NEVerify m n) pv = projOperatorExpr m pv ++ projOperatorExpr n pv
projOperatorExpr (NEHash m) pv = projOperatorExpr m pv
projOperatorExpr (NEHmac m n) pv = projOperatorExpr m pv ++ projOperatorExpr n pv
projOperatorExpr (NEKap m n) pv = projOperatorExpr m pv ++ projOperatorExpr n pv
projOperatorExpr (NEKas m n) pv = projOperatorExpr m pv ++ projOperatorExpr n pv
projOperatorExpr (NEXor m n) pv = projOperatorExpr m pv ++ projOperatorExpr n pv
projOperatorExpr (NECat [x]) pv = projOperatorExpr x pv
projOperatorExpr (NECat (x:xs)) pv = projOperatorExpr x pv ++ projOperatorExpr (NECat xs) pv
projOperatorExpr (NEProj _ n m) pv = projOperatorFun n m pv ++ projOperatorExpr m pv
projOperatorExpr (NEPub m _) pv = projOperatorExpr m pv
projOperatorExpr (NEPriv m _) pv = projOperatorExpr m pv

projOperatorExpr _ _ =  []

projOperatorFun :: Int -> NExpression -> OutType -> [(NEIdent,Int)]
projOperatorFun n e pv = map (\j -> let
                                           t1 = typeof e
                                           t2 = case t1 of
                                                 AnBxParams xs -> if j <= n && n == length xs then xs!!(j-1) else error ("malformed proj function: " ++ show t1)
                                                 _ -> error ("malformed proj function: " ++ show t1)
                                    in  ((JFunction PubFun (t1,t2),projOperatorFunName j n t1 t2 pv),j)
                             ) [1..n] -- generates all n projectors

projOperatorFunName :: Int -> Int -> JType -> JType -> OutType -> String
projOperatorFunName i n _ _ PV  = "proj_" ++ show i ++ "_" ++ show n
projOperatorFunName i n t1 t2 pv = "proj_" ++ show i ++ "_" ++ show n ++ "_" ++ t1_name ++ "_" ++ showType t2 pv

                                        where t1_name = case t1 of
                                                        AnBxParams xs -> concatMap (\x -> projParType x pv) xs   -- first n chars of type name
                                                        _ -> showType t1 pv

showParams :: [NEIdent] -> PE -> OutType -> String
showParams es t pv = "(" ++ showNEIdentList es t pv ++ ")"

showListExpr :: [NExpression] -> PE -> OutType -> PVFunType -> String
showListExpr [] _ _ _ = ""
showListExpr [e] t pv pf = showExpr e t pv pf
showListExpr (e:es) t pv pf = showExpr e t pv pf ++ commaSep ++ showListExpr es t pv pf

showParamsExpr :: [NExpression] ->  PE -> OutType -> PVFunType -> String
-- showParamsExpr es pe _ pf  | trace ("showParamsExpr: " ++ show es ++ "\nPE: " ++ show pe ++ "\nPF: " ++ show pf) False = undefined
showParamsExpr es pe pv pf = "(" ++ showListExpr es pe pv pf ++ ")"

functionsOfPVExpr :: NExpression -> NEIdentSet
-- functionsOfPVExpr e | trace ("functionsOfPVExpr: " ++ show e) False = undefined
functionsOfPVExpr (NEFun f e) = Set.union (Set.singleton f) (functionsOfPVExpr e)
functionsOfPVExpr (NEName _)  = Set.empty
functionsOfPVExpr (NEVar _ _) = Set.empty
functionsOfPVExpr (NEEnc m n) = Set.union (functionsOfPVExpr m) (functionsOfPVExpr n)
functionsOfPVExpr (NEEncS m n) = Set.union (functionsOfPVExpr m) (functionsOfPVExpr n)
functionsOfPVExpr (NEDec m n) = Set.union (functionsOfPVExpr m) (functionsOfPVExpr n)
functionsOfPVExpr (NEDecS m n) = Set.union (functionsOfPVExpr m) (functionsOfPVExpr n)
functionsOfPVExpr (NESign m n) = Set.union (functionsOfPVExpr m) (functionsOfPVExpr n)
functionsOfPVExpr (NEVerify m n) = Set.union (functionsOfPVExpr m) (functionsOfPVExpr n)
functionsOfPVExpr (NEHash m) = functionsOfPVExpr m
functionsOfPVExpr (NEHmac m n) = Set.union (functionsOfPVExpr m) (functionsOfPVExpr n)
functionsOfPVExpr (NEKap m n) = Set.union (functionsOfPVExpr m) (functionsOfPVExpr n)
functionsOfPVExpr (NEKas m n) = Set.union (functionsOfPVExpr m) (functionsOfPVExpr n)
functionsOfPVExpr (NEXor m n) = Set.union (functionsOfPVExpr m) (functionsOfPVExpr n)
functionsOfPVExpr (NECat [x]) = functionsOfPVExpr x
functionsOfPVExpr (NECat (x:xs)) = Set.union (functionsOfPVExpr x) (functionsOfPVExpr (NECat xs))
functionsOfPVExpr (NEProj  _ _ m) = functionsOfPVExpr m
functionsOfPVExpr _ =  Set.empty

functionsOfProcess :: PVProcess -> NEIdentSet
-- functionsOfProcess p | trace ("functionsOfProcess: " ++ show p) False = undefined
functionsOfProcess PZero = Set.empty
functionsOfProcess (PReach (_,_,p)) = functionsOfProcess p
functionsOfProcess (PInput(_,_,_,p)) = functionsOfProcess p -- Set.union (functionsOfPVExpr e) (functionsOfProcess p)
functionsOfProcess (POutput(_,_,f,p)) = Set.union (functionsOfPVExpr f) (functionsOfProcess p)
functionsOfProcess (PPar(p,q)) = Set.union (functionsOfProcess p) (functionsOfProcess q)
functionsOfProcess (PNew(_,_,p)) = functionsOfProcess p
functionsOfProcess (PCheck(_,phi,_,p)) = Set.union (functionsOfPVForm phi) (functionsOfProcess p)
functionsOfProcess (PApply(_,es,_)) = foldl' (\s e -> Set.union (functionsOfPVExpr e) s) Set.empty es
functionsOfProcess (PAssign(_,e,p)) = Set.union (functionsOfPVExpr e) (functionsOfProcess p)
functionsOfProcess (PGoal(_,_,_,e,_,_,_,_,p)) = Set.union (functionsOfPVExpr e) (functionsOfProcess p)
functionsOfProcess (PRepl p) = functionsOfProcess p
functionsOfProcess (PComment (_,p)) = functionsOfProcess p

functionsOfPVForm :: Atom -> NEIdentSet
functionsOfPVForm (FEq(m,n,_)) =  Set.union (functionsOfPVExpr m) (functionsOfPVExpr n)
functionsOfPVForm (FWff m) = functionsOfPVExpr m
functionsOfPVForm (FInv(m,n)) = Set.union (functionsOfPVExpr m) (functionsOfPVExpr n)
functionsOfPVForm (FNotEq(m,n)) = Set.union (functionsOfPVExpr m) (functionsOfPVExpr n)

namesOfPVExpr :: NExpression -> PVStatus -> NEIdentSet
-- namesOfPVExpr e _ | trace ("namesOfPVExpr: " ++ show e) False = undefined
namesOfPVExpr (NEName n@(JAgent,id)) _ = if isHonest id then Set.empty else Set.singleton n
namesOfPVExpr (NEName n) (const,se,PVFun) = if elem n notAFreeName || elem n const || elem n [ x | (_,x,_,_) <- se] then Set.empty else Set.singleton n
namesOfPVExpr (NEName n) (const,_,PVVar) = if elem n notAFreeName || elem n const then Set.empty else Set.singleton n
namesOfPVExpr (NEVar n _) _ = Set.singleton n
namesOfPVExpr (NEEnc m n) ps = Set.union (namesOfPVExpr m ps) (namesOfPVExpr n ps)
namesOfPVExpr (NEEncS m n) ps = Set.union (namesOfPVExpr m ps) (namesOfPVExpr n ps)
namesOfPVExpr (NEDec m n) ps = Set.union (namesOfPVExpr m ps) (namesOfPVExpr n ps)
namesOfPVExpr (NEDecS m n) ps = Set.union (namesOfPVExpr m ps) (namesOfPVExpr n ps)
namesOfPVExpr (NESign m n) ps = Set.union (namesOfPVExpr m ps) (namesOfPVExpr n ps)
namesOfPVExpr (NEVerify m n) ps = Set.union (namesOfPVExpr m ps) (namesOfPVExpr n ps)
namesOfPVExpr (NEHash m) ps = namesOfPVExpr m ps
namesOfPVExpr (NEHmac m n) ps = Set.union (namesOfPVExpr m ps) (namesOfPVExpr n ps)
namesOfPVExpr (NEKap m n) ps = Set.union (namesOfPVExpr m ps) (namesOfPVExpr n ps)
namesOfPVExpr (NEKas m n) ps = Set.union (namesOfPVExpr m ps) (namesOfPVExpr n ps)
namesOfPVExpr (NEFun _ m) ps = namesOfPVExpr m ps
namesOfPVExpr (NEXor m n) ps = Set.union (namesOfPVExpr m ps) (namesOfPVExpr n ps)
namesOfPVExpr (NECat [x]) ps = namesOfPVExpr x ps
namesOfPVExpr (NECat (x:xs)) ps = Set.union (namesOfPVExpr x ps) (namesOfPVExpr (NECat xs) ps)
namesOfPVExpr (NEProj  _ _ m) ps = namesOfPVExpr m ps
namesOfPVExpr e@(NEPub m@(NEFun (_,_) ag) (Just pkf)) ps | exprIsPublicKeyAgentKnown e = Set.singleton jid    
                                                          | otherwise = namesOfPVExpr m ps
                                                          where 
                                                                jid = (JPublicKey (Just pkf),id)
                                                                id = agentOfNExpression ag
namesOfPVExpr e@(NEPriv m@(NEFun (_,_) ag) (Just pkf)) ps | exprIsPrivateKeyAgentKnown e = Set.singleton jid    
                                                          | otherwise = namesOfPVExpr m ps
                                                          where 
                                                                jid = (JPrivateKey (Just pkf),id)
                                                                id = agentOfNExpression ag
namesOfPVExpr (NEPub m _) ps = namesOfPVExpr m ps
namesOfPVExpr (NEPriv m _) ps = namesOfPVExpr m ps
namesOfPVExpr e _ = error ("namesOfPVExpr - unhandled expression in PV " ++ show e)

namesOfPVForm :: Atom -> PVStatus -> NEIdentSet
namesOfPVForm (FEq(m,n,_)) ps = namesOfPVExpr (NECat [m,n]) ps
namesOfPVForm (FInv(m,n)) ps = namesOfPVExpr (NECat [m,n]) ps
namesOfPVForm (FNotEq(m,n)) ps = namesOfPVExpr (NECat [m,n]) ps
namesOfPVForm (FWff m) ps = namesOfPVExpr m ps

freeNamesOfProcess :: PVProcess -> PVStatus -> NEIdentSet
-- freeNamesOfProcess p const | trace ("freeNamesOfProcess: " ++ showProcess p PVT [] PVFun) False = undefined
freeNamesOfProcess PZero _ = Set.empty
freeNamesOfProcess (PReach (_,_,p)) ps = freeNamesOfProcess p ps
freeNamesOfProcess (PInput(_,_,x,p)) ps = Set.delete x (freeNamesOfProcess p ps) -- Set.union (namesOfPVExpr e const) (Set.delete x (freeNamesOfProcess p const))
freeNamesOfProcess (POutput(_,_,f,p)) ps = Set.union (namesOfPVExpr f ps) (freeNamesOfProcess p ps)
freeNamesOfProcess (PPar(p,q)) ps = Set.union (freeNamesOfProcess p ps) (freeNamesOfProcess q ps)
freeNamesOfProcess (PNew(x,ids,p)) ps = Set.union (Set.delete x (freeNamesOfProcess p ps)) (Set.fromList ids)
freeNamesOfProcess (PCheck(_,phi,_,p)) ps = Set.union (namesOfPVForm phi ps) (freeNamesOfProcess p ps)
freeNamesOfProcess (PApply(_,es,PVFun)) ps = foldl' (\s e -> case e of
                                                                        -- NEName (JPrivateKey _,id) _ -> if isHonest id then Set.union (namesOfPVExpr e ps) s else s
                                                                        -- NEName (JPublicKey _,id) _ -> if isHonest id then Set.union (namesOfPVExpr e ps) s else s
                                                                        (NEPub _ _) -> if isHonest (agentOfKey e) then Set.union (namesOfPVExpr e ps) s else s
                                                                        (NEPriv _ _) -> if isHonest (agentOfKey e) then Set.union (namesOfPVExpr e ps) s else s
                                                                        -- (NEPub (NEFun (_,_) ag) (Just pkf)) | exprIsPublicKeyAgentKnown e -> if isHonest id || True then Set.insert jid s else s
                                                                        --                                                        where 
                                                                        --                                                                jid = (JPublicKey (Just pkf),id)
                                                                        --                                                                id = agentOfNExpression ag
                                                                                                                            
                                                                        -- (NEPriv (NEFun (_,_) ag) (Just pkf)) | exprIsPrivateKeyAgentKnown e -> if isHonest id || True then Set.insert jid s else s 
                                                                        --                                                        where 
                                                                        --                                                                jid = (JPrivateKey (Just pkf),id)
                                                                        --                                                                id = agentOfNExpression ag
                                                                        _ -> Set.union (namesOfPVExpr e ps) s) Set.empty es

freeNamesOfProcess (PApply(_,es,PVVar)) ps = foldl' (\s e -> Set.union (namesOfPVExpr e ps) s) Set.empty es
freeNamesOfProcess (PAssign(x,e,p)) ps = Set.delete x (Set.union (namesOfPVExpr e ps) (freeNamesOfProcess p ps))
freeNamesOfProcess (PGoal(_,Witness,_,e,_,agsExpr,_,_,p)) ps = Set.union s3 (freeNamesOfProcess p ps)
                                                         where s1 = namesOfPVExpr e ps
                                                               s2 = foldl' (\s e -> Set.union (namesOfPVExpr e ps) s) Set.empty (map NEName ags)
                                                               s3 = Set.union s1 s2
                                                               ags = agsExpr2ags agsExpr
freeNamesOfProcess (PGoal(_,Request,_,e,varagents,agsExpr,_,_,p)) ps = Set.union s4 (freeNamesOfProcess p ps)
                                                         where s1 = namesOfPVExpr e ps
                                                               s2 = foldl' (\s e -> Set.union (namesOfPVExpr e ps) s) Set.empty (map NEName ags)
                                                               s3 = Set.union s1 s2
                                                               s4 = Set.union s3 (Set.fromList varagents)
                                                               ags = agsExpr2ags agsExpr
freeNamesOfProcess (PGoal(_,Wrequest,_,e,varagents,agsExpr,_,_,p)) ps = Set.union s4 (freeNamesOfProcess p ps)
                                                         where s1 = namesOfPVExpr e ps
                                                               s2 = foldl' (\s e -> Set.union (namesOfPVExpr e ps) s) Set.empty (map NEName ags)
                                                               s3 = Set.union s1 s2
                                                               s4 = Set.union s3 (Set.fromList varagents)
                                                               ags = agsExpr2ags agsExpr
freeNamesOfProcess (PGoal(_,SecretGoal,_,e,varagents,_,_,_,p)) ps = Set.union s1 (freeNamesOfProcess p ps)
                                                         where s1 = Set.union (namesOfPVExpr e ps) (Set.fromList varagents)
freeNamesOfProcess (PGoal(_,GuessableSecretGoal,_,e,varagents,_,_,_,p)) ps = Set.union s1 (freeNamesOfProcess p ps)
                                                         where s1 = Set.union (namesOfPVExpr e ps) (Set.fromList varagents)
freeNamesOfProcess (PGoal(_,Seen,_,e,varagents,_,_,_,p)) ps = Set.union s1 (freeNamesOfProcess p ps)
                                                         where s1 = Set.union (namesOfPVExpr e ps) (Set.fromList varagents)

freeNamesOfProcess (PRepl p) ps = freeNamesOfProcess p ps
freeNamesOfProcess (PComment (_,p)) ps = freeNamesOfProcess p ps

type MapSPI = Map.Map String (PVProcess -> PVProcess)

showMapSPI:: MapSPI -> String
showMapSPI m = "[" ++ keys ++ "]"
      where
        keys = unwords $ Map.keys m

type SPIDef = (String,[NEIdent],PVProcess)              -- name, typed parameters, process
type PVStatus =([NEIdent],JShares,PVFunType)

getDef :: String -> String -> MapSPI  -> (PVProcess -> PVProcess)
-- getDef a sysname defs  | trace ("getDef\n\ta: " ++ show a ++ "\n\tMapSPI keys: " ++ showMapSPI defs) False = undefined
getDef a sysname defs
  | a == sysname = error ("invalid system name " ++ sysname)
  | Map.notMember a defs =
        let
           defs1 = Map.insert a id defs
        in fromJust (Map.lookup a defs1)
  | otherwise = fromJust (Map.lookup a defs)

gUpdateDef :: String -> (PVProcess -> PVProcess) -> MapSPI -> MapSPI
-- gUpdateDef a p defs | trace ("gUpdateDef\n\ta: " ++ show a ++ "\n\tMapSPI keys: " ++ showMapSPI defs) False = undefined
gUpdateDef a p defs = let
                            defs1 = Map.delete a defs
                            defs2 = Map.insert a p defs1
                      in defs2

translate :: [NEIdent] -> [NEIdent] -> NEIdentSet -> String -> [JAction] -> MapSPI -> [ReachEvent] -> (NEIdentSet,MapSPI)
-- translate varagents honagents privnames sysname xn defs _ | trace ("translate\n\tMapSPI keys: " ++ showMapSPI defs  ++ "\n\tvaragents: " ++ show varagents ++ "\n\thonagents: " ++ show honagents ++ "\n\tprivnames: " ++ show privnames ++ "\n\taction: " ++ if null xn then "" else show (head xn) ++ "\n\tsysname: " ++ show sysname) False = undefined
translate varagents honagents privnames sysname [] defs reachEvents = let -- add reach events at the end of each agent process
                                                                            defs2 = if elem ReachEnd reachEvents then
                                                                                                    foldr (\x@(_,a) d -> let
                                                                                                        pa = getDef a sysname d
                                                                                                        defs1 = gUpdateDef a (\p -> pa (PReach(ReachEnd,x,p))) d
                                                                                                    in defs1) defs (varagents ++ honagents)
                                                                                    else defs
                                                                      in (privnames,defs2)

translate varagents honagents privnames sysname (JNew(_,a,k):xs) defs reachEvents = let
                                                                            pa = getDef a sysname defs
                                                                            defs1 = gUpdateDef a (\p -> pa (PNew(k,[],p))) defs
                                                                        in translate varagents honagents privnames sysname xs defs1 reachEvents
translate varagents honagents privnames sysname (JAssign(_,a,x,e):xs) defs reachEvents =  let
                                                                        pa = getDef a sysname defs
                                                                        defs1 = gUpdateDef a (\p -> pa (PAssign(x,e,p))) defs
                                                                    in translate varagents honagents privnames sysname xs defs1 reachEvents

translate varagents honagents privnames sysname (JEmit(_,ag,(a,ch,b,_,_,_,_),_,f):xs) defs reachEvents = let
                                                                   pa = getDef ag sysname defs
                                                                   defs1 = gUpdateDef ag (\p -> pa (POutput(a,(a,ch,b),f,p))) defs
                                                              in translate varagents honagents privnames sysname xs defs1 reachEvents

translate varagents honagents privnames sysname (JEmitReplay(_,ag,(a,ch,b,_,_,_,_),_,f):xs) defs reachEvents = let
                                                                 pa = getDef ag sysname defs
                                                                 defs1 = gUpdateDef ag (\p -> pa (POutput(a,(a,ch,b),f,p))) defs
                                                             in translate varagents honagents privnames sysname xs defs1 reachEvents

translate varagents honagents privnames sysname (JReceive(_,ag,(a,ch,b,_,_,_,_),NEVar x _):xs) defs reachEvents = let
                                                                                pa = getDef ag sysname defs
                                                                                defs1 = gUpdateDef ag (\p -> pa (PInput((JAgent,ag),(a,ch,b),x,p))) defs
                                                                            in translate varagents honagents privnames sysname xs defs1 reachEvents

translate _ _ _ _ act@(JReceive(_,_,(_,_,_,_,_,_,_),x):_) _ _ = error ("term " ++ show x ++ " is not a variable in action: " ++ show act)

translate varagents honagents privnames sysname (JCheck(_,a,phi,_):xs) defs reachEvents = let
                                                                   pa = getDef a sysname defs
                                                                   defs1 = gUpdateDef a (\p -> pa (PCheck((JAgent,a),phi,varagents,p))) defs
                                                               in translate varagents honagents privnames sysname xs defs1 reachEvents

translate varagents honagents privnames sysname (JComment (_,s):xs) defs reachEvents = let
                                                                               defs2 = foldr (\(_,a) d -> let
                                                                                                              pa = getDef a sysname d
                                                                                                              defs = gUpdateDef a (\p -> pa (PComment(s,p))) d
                                                                                                            in defs) defs (varagents ++ honagents)
                                                                           in translate varagents honagents privnames sysname xs defs2 reachEvents

translate varagents honagents privnames sysname (JGoal (_,a,f,l,e,agsexpr,b,effstep):xs) defs reachEvents = let
                                                                              pa = getDef a sysname defs
                                                                              defs1 = gUpdateDef a (\p -> pa (PGoal((JAgent,a),f,l,e,varagents,agsexpr,b,effstep,p))) defs
                                                                              xs1 = xs
                                                                              -- to enable "global" conditions in if-then-else
                                                                              -- xs1 = if f==SecretGoal || f==Wrequest || f==Request then setCond xs a False else xs  
                                                                            -- in error (show "\n\tvaragents: "  ++ show varagents ++ "\n\txs1: " ++ show xs1) 
                                                                            in translate varagents honagents privnames sysname xs1 defs1 reachEvents

translate _ _ _ _ (act@(JCall _) : _) _ _ =  error ("unsupported PV translation: " ++ show act)

-- translate _ _ _ x _ = error ("unsupported PV translation: " ++ show x)

mapAgentsList :: [NExpression] -> [NEIdent]
mapAgentsList [] = []
mapAgentsList [NEName id] = [id]
mapAgentsList [NEVar id _] = [id]
mapAgentsList [e] = error ("unsupported expression: " ++ show e)
mapAgentsList (x:xs) = mapAgentsList [x] ++ mapAgentsList xs

agsExpr2ags :: [(NEIdent,NExpression)] -> [NEIdent]
agsExpr2ags agsexpr = [ fst x | x <- agsexpr ]

agsExpr2Expr :: [(NEIdent,NExpression)] -> [NExpression]
agsExpr2Expr agsexpr = [ snd x | x <- agsexpr ]

getAllDefs :: [NEIdent] -> MapSPI -> PVStatus -> (Functions,[SPIDef])  -- functions,processes
getAllDefs va defs ps = let
                                psdef = Map.foldrWithKey (\a p ds -> (processName a,Set.toList (freeNamesOfProcess (p PZero) ps) ++ map honestAgent (va \\ [(JAgent,a)]), p PZero):ds) [] defs
                                fn = sortBy compareNEIdent $ nubOrd (concat (Map.foldrWithKey (\_ p ds -> Set.toList (functionsOfProcess (p PZero)):ds) [] defs))
                          in (fn,psdef)

querySecret :: [JAction] -> OutType -> String
querySecret xs pv = concatMap (\y -> showEventdecl SecretGoal y [] pv) ids
                                     where ids = nubOrd [ id | (JGoal (_,_,SecretGoal,id,_,_,_,_)) <- xs]

queryGuessableSecret :: [JAction] -> OutType -> String
queryGuessableSecret xs pv = concatMap (\y -> showEventdecl GuessableSecretGoal y [] pv) ids
                                     where ids = nubOrd [ id | (JGoal (_,_,GuessableSecretGoal,id,_,_,_,_)) <- xs]

notAttacker :: [NEIdent] -> String
notAttacker xs = concatMap (\x -> "not attacker(new " ++ showNEIdent x ++ ").\n") xs

queryReach :: [NEIdent] -> [ReachEvent] -> OutType -> String
queryReach _ [] _ = ""
queryReach xs reachEvents pvout = "(* Process reachability queries *)" ++ "\n"
                 -- ++ concatMap (\(ev,x) -> "event " ++ id2reach ev x ++ ".\n") ([(ev,x) | ev <- reachEvents, x <- xs])
                 ++ concatMap (\ev -> "event " ++ show ev ++ "(" ++ showType JAgent pvout ++ ")" ++ ".\n") reachEvents
                 ++ (if elem ReachEnd reachEvents then
                        concatMap (\x -> "query event(" ++ id2reach ReachEnd x ++ ").\n") xs
                        else "")
                 ++ "\n"

id2reach :: ReachEvent -> NEIdent -> String
id2reach ev x = show ev ++ "(" ++ showNEIdent x ++ ")"

declEvents :: [JAction] -> [String] -> OutType -> String
declEvents [] _ _ = ""
declEvents (x:xs) sqn pv = declOfEvents x sqn pv ++ declEvents xs sqn pv

showEventdecl :: Fact -> NEIdent -> [NEIdent] -> OutType -> String
showEventdecl SecretGoal ident _ pv = "free " ++ showNEIdentTyped ident pv  ++ " " ++ privateDecl ++ "." ++  "query attacker(" ++ showNEIdent ident ++ ").\n"
                                      ++ if showMess then "query mess(" ++ channelName insecureChannel ++ commaSep ++ showNEIdent ident ++ ").\n" else ""
showEventdecl GuessableSecretGoal ident _ pv = "free " ++ showNEIdentTyped ident pv  ++ " " ++ privateDecl ++ "." ++ "weaksecret" ++ " " ++ showNEIdent ident ++ ".\n"
                                      ++ if showMess then "query mess(" ++ channelName insecureChannel ++ commaSep ++ showNEIdent ident ++ ").\n" else ""
showEventdecl fact (t,id) [] pv = "event " ++ show fact ++ id ++ "(" ++ showType t pv ++  ").\n"
showEventdecl fact (t,id) ags pv = "event " ++ show fact ++ id ++ "(" ++ showType t pv ++ commaSep ++ showTypeSign ags pv ++ ").\n"

showTypeSign :: [NEIdent] -> OutType -> String
showTypeSign [] _ = ""
showTypeSign [(t,_)] pv = showType t pv
showTypeSign ((t,_):xs) pv = showType t pv ++ commaSep ++ showTypeSign xs pv

showNEIdent :: NEIdent -> String
showNEIdent (JPublicKey (Just pk),id) = show pk ++ id
showNEIdent (JPrivateKey (Just pk),id) = "Inv" ++ show pk ++ id
showNEIdent (_,id) = id

showNEIdentList :: [NEIdent] -> PE -> OutType -> String
showNEIdentList [] _ _ = ""
showNEIdentList [x] PEUntyped _ = showNEIdent x
showNEIdentList [x] PETyped pv = showNEIdentTyped x pv
showNEIdentList (x:xs) PEUntyped pv = showNEIdent x ++ commaSep ++ showNEIdentList xs PEUntyped pv
showNEIdentList (x:xs) PETyped pv = showNEIdentTyped x pv ++ commaSep ++ showNEIdentList xs PETyped pv

seenGoalCond :: String -> String -> String
seenGoalCond x id = "\n|| inj-event(seen" ++ x ++ "(sqn,a1)) && " ++ "event(" ++ show Witness ++ id ++ "(m,a1,a2))"

showEventQuery :: Fact -> NEIdent -> [NEIdent] -> [String] -> OutType -> String
showEventQuery fact (t,id) [(t1,_),(t2,_)] sqn pv | fact == Request || fact == Wrequest =
                                                             let
                                                                inj = if fact==Request then "inj-" else ""
                                                                --  A -> B: Msg # insecure channel goals
                                                                insecurecond = if isInfixOf (show Insecure) id then
                                                                    " || " ++ inj ++ "event(" ++ show fact ++ id ++ "(m,a1,a2))"
                                                                    else "" --  hack to make the goal not fail 
                                                             in if null sqn then
                                                                     "query m: " ++ showType t pv ++ ", a1: " ++ showType t1 pv ++ ", a2: " ++ showType t2 pv ++ "; " ++
                                                                     inj ++ "event(" ++ show fact ++ id ++ "(m,a1,a2)) ==> " ++ inj ++ "event(" ++ show Witness ++ id ++ "(m,a1,a2))" ++
                                                                     insecurecond ++ ".\n"
                                                                else
                                                                     "query m: " ++ showType t pv ++ ", a1: " ++ showType t1 pv ++ ", a2: " ++ showType t2 pv ++ ", sqn: " ++ showType JSeqNumber pv ++ "; " ++
                                                                     inj ++ "event(" ++ show fact ++ id ++ "(m,a1,a2)) ==> " ++ inj ++ "event(" ++ show Witness ++ id ++ "(m,a1,a2))" ++
                                                                     (if inj=="" then "" else concatMap (\x -> seenGoalCond x id) sqn) ++
                                                                     insecurecond ++ ".\n"
                                                  | otherwise = ""
showEventQuery fact tid xs sqn _ = error ("malformed goal: " ++ show fact ++ " " ++ show tid ++ " - agents: " ++ show xs ++ " - sqn: " ++ show sqn ++
                                        if fact == Request || fact == Wrequest then
                                                    "\n" ++ "if the option " ++ cmdRelaxGoalsOtherAgentKnow ++ " was used then it is likely that" ++
                                                    "\n" ++ "the goal has failed because the receiving agent does not know the sender," ++
                                                    "\n" ++ "i.e. the authentication goal cannot be achieved"
                                                else "")

declOfEvents :: JAction -> [String] -> OutType -> String
declOfEvents (JGoal (_,_,Witness,id,_,agsexpr,_,_)) _ pv  = showEventdecl Witness id ags pv
                                                            where
                                                                ags = agsExpr2ags agsexpr
declOfEvents (JGoal (_,_,Request,id,_,agsexpr,_,_)) sqn pv = showEventdecl Request id ags pv ++ showEventQuery Request id ags sqn pv
                                                            where
                                                                ags = agsExpr2ags agsexpr
declOfEvents (JGoal (_,_,Wrequest,id,_,agsexpr,_,_)) sqn pv = showEventdecl Wrequest id ags pv ++ showEventQuery Wrequest id ags sqn pv
                                                            where
                                                                ags = agsExpr2ags agsexpr
declOfEvents (JGoal (_,_,Seen,id,_,agsexpr,_,_)) _ pv  = showEventdecl Seen id ags pv
                                                            where
                                                                ags = agsExpr2ags agsexpr
declOfEvents _ _ _ = ""

inX :: [NEIdent] -> PVProcess -> PVProcess
inX [] p = p
inX [ag@(JAgent,_)] p = PInput(ag,insecureChannel,ag,p)
inX (ag@(JAgent,_):xs) p = PInput(ag,insecureChannel,ag,inX xs p)
inX xs _ = error (show xs  ++ " must be a list of agents")

xAgent :: NEIdent -> NEIdent
xAgent (JAgent,x) = (JAgent,xAgentPrefix ++ x)
xAgent x = error (show x ++ " must be an agent")

substID :: NEIdent -> [(NEIdent,NEIdent)] -> JShares -> NExpression
substID i@(JPublicKey pk,id) (((JAgent,id1),(JAgent,id2)):xs) se = if id==id1 then keyOfIdent pk id2 else substID i xs se
substID i@(JPrivateKey pk,id) (((JAgent,id1),(JAgent,id2)):xs) se = if id==id1 then keyOfIdent pk id2 else substID i xs se
substID i@(JAgent,id) (((JAgent,id1),jid2@(JAgent,_)):xs) se = if id==id1 then NEName jid2 else substID i xs se              -- NEName (JAgent,id2)
substID i _ _ = NEName i

substIDExpr :: NExpression -> [(NEIdent,NEIdent)] -> NExpression
substIDExpr j@(NEName jid) ((jid1,jid2):xs) = if jid==jid1 then NEName jid2 else substIDExpr j xs
substIDExpr (NECat xs) subs = NECat (map (\x -> substIDExpr x subs) xs)                                                                     -- tuples
substIDExpr (NEProj i1 i2 e) subs = NEProj i1 i2 (substIDExpr e subs)
substIDExpr (NEEnc e1 e2) subs = NEEnc (substIDExpr e1 subs) (substIDExpr e2 subs) 
substIDExpr (NEEncS e1 e2) subs = NEEncS (substIDExpr e1 subs) (substIDExpr e2 subs)
substIDExpr (NEDec e1 e2) subs = NEDec (substIDExpr e1 subs) (substIDExpr e2 subs) 
substIDExpr (NEDecS e1 e2) subs = NEDecS (substIDExpr e1 subs) (substIDExpr e2 subs)
substIDExpr (NESign e1 e2) subs = NESign (substIDExpr e1 subs) (substIDExpr e2 subs) 
substIDExpr (NEVerify e1 e2) subs = NEVerify (substIDExpr e1 subs) (substIDExpr e2 subs)
substIDExpr (NEHash e) subs = NEHash (substIDExpr e subs)                                           -- hash
substIDExpr (NEHmac e1 e2) subs = NEHmac (substIDExpr e1 subs) (substIDExpr e2 subs)                -- hmac
substIDExpr (NEKap e1 e2) subs = NEKap (substIDExpr e1 subs) (substIDExpr e2 subs)                  -- exp(g,x) - kap(g,x)                 
substIDExpr (NEKas e1 e2) subs = NEKas (substIDExpr e1 subs) (substIDExpr e2 subs)                  -- exp(exp(g,x(,y)) - kas((g,x),y)
substIDExpr (NEFun (t,id) e) subs = NEFun (t,id) (substIDExpr e subs)
substIDExpr (NEXor e1 e2) subs = NEXor (substIDExpr e1 subs) (substIDExpr e2 subs)
substIDExpr (NEPub e1 pk) subs = NEPub (substIDExpr e1 subs) pk
substIDExpr (NEPriv e1 pk) subs = NEPriv (substIDExpr e1 subs) pk
substIDExpr e _ = e

transp :: PVProcess -> (String,[NEIdent]) -> [NEIdent] -> JShares -> PVProcess
transp p (a,na) va share = let
                                ma = (JAgent,process2Agent a)
                                va1  = va \\ [ma]
                                xs = map xAgent va1
                                mp = zip va1 xs ++ (if null va1 then [] else map (\x-> (honestAgent x,x)) va1)
                                na1 = map (\x -> substID x mp share) na
                                debug = False
                           in
                            if debug then
                                error ("\nmp: " ++ show mp ++
                                       "\nma: " ++ show ma ++
                                       "\nna1: " ++ show na1 ++
                                       "\nna: " ++ show na ++
                                       "\nva: " ++ show va ++
                                       "\nva1: " ++ show va1
                                       )
                            else PPar(PRepl(inX xs (PApply(a,na1,PVFun))),p)

mkAgreeActions :: JAgree -> JActions -> JActions
mkAgreeActions [] xs = xs
mkAgreeActions (_:as) xs = mkAgreeActions as xs

pvDefOfExecnarr :: JProtocol -> OutType -> [ReachEvent] -> (Functions,[(NEIdent,Int)],Functions,[NEChannel],[NEIdent],[SPIDef],SPIDef)
pvDefOfExecnarr (sysname0,_,const,shares,agrees,_,roles,_,inactiveagents,_,_,_,_,actions0) pv reachEvents =
  let
        sysname = processName sysname0
        agents = roles ++ inactiveagents
        varAgents = [ a | a <- agents, not (isHonestNEIdent a)]   -- var agents are used as new arguments 
        hon_agents = agents \\ varAgents
        actions = mkAgreeActions agrees actions0
        -- add Begin event to each process
        mapDefs = if elem ReachBegin reachEvents then
                             foldr (\x@(_,a) d -> let
                                        pa = getDef a sysname d
                                        defs = gUpdateDef a (\p -> pa (PReach(ReachBegin,x,p))) d
                                     in defs) Map.empty agents
                             else Map.empty
        -- translate actions to process
        (privnames,defs1) = translate varAgents hon_agents Set.empty sysname actions mapDefs reachEvents
        (fn,all_defs) = getAllDefs varAgents defs1 (const,shares,PVVar)
        all_defs1 = List.sortBy (\(a,_,_) (b,_,_) -> compare a b) all_defs
        na = nubOrd.sort.concat $ ([ x | (_,x,_) <- all_defs1])        -- free_names
        pk = [ x | x@(JPublicKey _,id) <- na , not (isHonest id)]
        sk = [ x | x@(JPrivateKey _,id) <- na , not (isHonest id)]
        ids = []
        sysdef = foldl' (\p (a,na,_) -> transp p (a,na) varAgents shares) PZero all_defs1
        sysdef1 = foldr (\n p -> PNew(n,ids,p)) sysdef (Set.toList privnames)
        nsys = Set.toList (freeNamesOfProcess sysdef1 (const,shares,PVFun))
        fnSecretgoal = nubOrd(secretGoalFuns actions pv)
        fnProj = nubBy (eqTypePVFunType pv) (projOperatorsActions actions pv)
        privChs = sort (nubBy eqPrivChannel (privChannels actions))
        debug = False    
  in if debug then
        error (
            "\nsysname: " ++ show sysname
            ++ "\nnsys: " ++ show nsys
            ++ "\nprivnames: " ++ show privnames
            ++ "\nroles: " ++ show roles
            ++ "\nna: " ++ show na
            ++ "\npk: " ++ show pk
            ++ "\nsk: " ++ show sk
            ++ "\nsysdef1: " ++ showProcess sysdef1 pv shares PVVar
            ++ "\nagents: " ++  show agents
            ++ "\nvarAgents: " ++  show varAgents
            ++ "\nhon_agents: " ++  show hon_agents
            ++ "\nshare: " ++  show shares
            ++ "\nfn: " ++  show fn
            ++ "\nconst: " ++ show const
            ++ "\nprojOp: " ++ show fnProj
            ++ "\nsecretgoalfun: "  ++ show fnSecretgoal
            ++ "\n" ++ printDeclFunctions fnSecretgoal pv
            ++ "\nprivChs: "  ++ show privChs 
            ++ "\nall_defs1" ++ show all_defs1
            )
        else (fn,fnProj,fnSecretgoal,privChs,na,all_defs1 ++ [(sysname,nsys,sysdef1)],(sysname,nsys,PZero))

data DeclType = DeclConst | DeclFree | DeclNew

instance Show DeclType where
    show :: DeclType -> String
    show DeclConst = "const"
    show DeclFree = "free"
    show DeclNew = "new"

endSymbDecl :: DeclType -> String
endSymbDecl DeclConst = "."
endSymbDecl DeclFree = "."
endSymbDecl DeclNew = ";"

showParamsDecl :: DeclType -> [NEIdent]  -> OutType -> String
showParamsDecl _ [] _ = ""
showParamsDecl dt es pv = concatMap (\x -> show dt ++ " " ++ showNEIdentTyped x pv ++ endSymbDecl dt ++ "\n") es

showParamsPublic :: [NEIdent] -> String
showParamsPublic [] = ""
showParamsPublic es = concatMap (\x -> "out(" ++ channelName insecureChannel ++ commaSep ++ showNEIdent x ++ ");\n") es

showParamsPublicExpr :: [NExpression] -> OutType -> String
showParamsPublicExpr [] _ = ""
showParamsPublicExpr es pvtyped = intercalate ";\n" (map (\x-> "out(" ++ channelName insecureChannel ++ commaSep ++  showExpr x PEUntyped pvtyped PVFun ++ ")") es) ++ ";\n"

showParamsPk :: [NEIdent] -> String
showParamsPk [] = ""
showParamsPk es = concatMap (\x@(t,id) -> case t of
                                                       JPublicKey (Just pk) -> "let " ++ showNEIdent x ++ " = " ++ show pk ++ "(" ++ showNEIdent (JPrivateKey (Just pk),id) ++ ") in out(" ++ channelName insecureChannel ++ commaSep ++ showNEIdent x ++ ");\n"
                                                       _ -> error ("cannot handle key: " ++ show x)) es

printPVDefs :: [SPIDef] -> OutType -> JShares -> String
printPVDefs [] _ _ = ""
-- single/last process
printPVDefs [(a,na,pa)] pv se = "(* Process " ++  process2Agent a ++ " *)" ++ "\n" ++
                                  "let " ++ a ++ showParams na PETyped pv ++ " =\n"
                                  -- ++ "("
                                  ++ showProcess pa pv se PVVar
                                  -- ++ ")"
                                  ++ ".\n\n"

printPVDefs ((a,na,pa):ds) pv se = "(* Process " ++  process2Agent a ++ " *)" ++ "\n" ++
                                  "let " ++ a ++ showParams na PETyped pv ++ " =\n"
                                  ++ showProcess pa pv se PVVar
                                  ++ ".\n\n" ++ printPVDefs ds pv se

getNEIdents :: [NEIdent] -> JType -> [NEIdent]
getNEIdents xs t = [ x | x@(t1,_) <- xs, t1==t]

-- returns the max size of proj   
maxProjActs :: JActions -> Int
maxProjActs xs = foldr (max . maxProjAct) 1 xs
-- maxProjActs [] = 1
-- maxProjActs (x:xs) = max (maxProjAct x) (maxProjActs xs)

maxProjAct :: JAction -> Int
maxProjAct (JNew _) = 1
maxProjAct (JEmit (_,_,_,e,f)) = max (maxProjExpr e) (maxProjExpr f)
maxProjAct (JEmitReplay (_,_,_,e,f)) = max (maxProjExpr e) (maxProjExpr f)
maxProjAct (JReceive _) = 1
maxProjAct (JCheck (_,_,phi,_)) = maxProjAtom phi
maxProjAct (JAssign (_,_,_,e)) = maxProjExpr e
maxProjAct (JComment _) = 1
maxProjAct (JCall (_,_,f)) = maxProjExpr f
maxProjAct (JGoal (_,_,_,_,e,_,_,_)) = maxProjExpr e

maxProjAtom :: Atom -> Int
maxProjAtom (FWff e) = maxProjExpr e
maxProjAtom (FEq (e1,e2,_)) = max (maxProjExpr e1) (maxProjExpr e2)
maxProjAtom (FInv (e1,e2)) = max (maxProjExpr e1) (maxProjExpr e2)
maxProjAtom (FNotEq (e1,e2)) = max (maxProjExpr e1) (maxProjExpr e2)

-- returns the max length of a tuple or the max index size of a projection
maxProjExpr :: NExpression -> Int
maxProjExpr (NEVar _ _)  = 1
maxProjExpr (NEName _) = 1
maxProjExpr (NECat xs) = length xs
maxProjExpr (NEProj _ size e) = max size (maxProjExpr e)
maxProjExpr (NEEnc e1 e2) = max (maxProjExpr e1) (maxProjExpr e2)
maxProjExpr (NEEncS e1 e2) = max (maxProjExpr e1) (maxProjExpr e2)
maxProjExpr (NEDec e1 e2) = max (maxProjExpr e1) (maxProjExpr e2)
maxProjExpr (NEDecS e1 e2) = max (maxProjExpr e1) (maxProjExpr e2)
maxProjExpr (NESign e1 e2) = max (maxProjExpr e1) (maxProjExpr e2)
maxProjExpr (NEVerify e1 e2) = max (maxProjExpr e1) (maxProjExpr e2)
maxProjExpr (NEHash e) = maxProjExpr e
maxProjExpr (NEHmac e1 e2) = max (maxProjExpr e1) (maxProjExpr e2)
maxProjExpr (NEKap e1 e2) = max (maxProjExpr e1) (maxProjExpr e2)
maxProjExpr (NEKas e1 e2) = max (maxProjExpr e1) (maxProjExpr e2)
maxProjExpr (NEFun _ e) = maxProjExpr e
maxProjExpr (NEXor e1 e2) = max (maxProjExpr e1) (maxProjExpr e2)
maxProjExpr (NEPub e _) = maxProjExpr e
maxProjExpr (NEPriv e _) = maxProjExpr e

newX :: NEIdent -> OutType -> String
newX a@(JAgent,x) pvtyped = showParamsDecl DeclNew [a] pvtyped
                            ++ intercalate ";\n" (map (\x-> "out(" ++ channelName insecureChannel ++ commaSep ++ showExpr x PEUntyped pvtyped PVFun ++ ")") pkv)
                                where
                                    pkv = NEName a : keys
                                    keys = map (\pk -> keyOfIdentPriv (Just pk) x) pkiFunList                               
newX _ _ =  ""

newXshare :: NEIdent -> JShares -> [NEIdent] -> OutType -> String
newXshare _ [] _ _ =  ""    -- no shares
newXshare _ _ [] _ =  ""    -- no var agents
newXshare a@(JAgent,_) jshares varAgents pvtyped = let
                                                        subst = map (\x -> (x,a)) varAgents    -- all subst Variable Agents -> "X"
                                                        allsubst = [ (x,(a,b)) | x <- subst, (_,a,b,_) <- jshares, substIDExpr b [x] /= b ]     -- consider only substitution changing expressions
                                                        exprs = nubOrd (map (\(x,(_,y)) -> substIDExpr y [x]) allsubst)
                                                    in case exprs of
                                                            [] -> ""
                                                            _  -> ";\n" ++ intercalate ";\n" (map (\x -> "out(" ++ channelName insecureChannel ++ commaSep ++ showExpr x PEUntyped pvtyped PVFun ++ ")") exprs)
newXshare _ _ _ _=  ""

fKeys :: (Maybe AnBxPKeysFun -> JType) -> [NEIdent] -> [NEIdent] -> AnBxPKeysFun -> [NEIdent]
fKeys keyConstructor _ agents pk = 
    map (\ident -> case ident of
                    (JAgent, x) -> (keyConstructor (Just pk), x)
                    _           -> error $ "fKeys - Unexpected pattern: " ++ show ident
        ) agents

fPrivateKeys :: [NEIdent] -> [NEIdent] -> AnBxPKeysFun -> [NEIdent]
fPrivateKeys = fKeys JPrivateKey

fPublicKeys :: [NEIdent] -> [NEIdent] -> AnBxPKeysFun -> [NEIdent]
fPublicKeys = fKeys JPublicKey

fAgents :: [NEIdent] -> [NEIdent]
fAgents na = getNEIdents na JAgent

fHonestAgents :: [NEIdent] -> [NEIdent] -> [NEIdent]
fHonestAgents na roles = fAgents roles \\ fAgents na

privatefun  :: JShares -> Functions
privatefun  [] = []
privatefun  sharexpr = let
                           es = [ y | (_,_,y,_) <- sharexpr]
                           fn = nubOrd (concatMap (Set.toList . functionsOfPVExpr) es)
                       in fn

printPvtOfExecnarr :: JProtocol -> AnBxOnP -> OutType ->  String
printPvtOfExecnarr xnarr@(_,customtypes,const,sharexpr,agreeexpr,equations,roles,_,inactiveagents,_,_,_,_,actions) options pv = let
                                                                            -- reach events to be printed
                                                                            reachEvents = [ ReachEnd | pvReachEvents options ]
                                                                            -- reachEvents = [ReachBegin,ReachEnd] 
                                                                            (fn,fnProj,fnSecretgoal,privChs,na,ps1,(sysname,nasys,_)) = pvDefOfExecnarr xnarr pv reachEvents
                                                                            share = [ x | (_,x,_,_) <- sharexpr]
                                                                            agree = [ x | (_,x,_,_) <- agreeexpr]
                                                                            secrecy = querySecret actions
                                                                            guessablesecrecy = queryGuessableSecret actions
                                                                            query = declEvents actions
                                                                            agents = roles ++ inactiveagents
                                                                            honestAgents = fHonestAgents nasys agents
                                                                            varAgents = agents \\ honestAgents
                                                                            const1 = nubOrd (const ++ honestAgents)
                                                                            -- constants to declare
                                                                            const2 = const1 \\ notAFreeName

                                                                            -- this worked with the old version of JExpression, however the public keys are not published out(ch,pk(priv_pk(A)))
                                                                            -- it dependes from the na variable list of idents that does not include keys at the moment but just agent names
                                                                            privateKeysVar = [ x | x@(JPrivateKey _,id) <- na , not (isHonest id)]
                                                                            publicKeysVar0 = [ x | x@(JPublicKey _,id) <- na , not (isHonest id)]
                                                                            publicKeysVar1 = [ (JPublicKey pk,id) | (JPrivateKey pk,id) <- privateKeysVar]
                                                                            publicKeysVar = nubOrd (publicKeysVar1 ++ publicKeysVar0)

                                                                            -- instead of considering the freenames, we consider the publickeys of each agent and publish them on the insecure channel 
                                                                            privateKeysHon = concatMap (fPrivateKeys nasys honestAgents) pkiFunList
                                                                            publicKeysHon = concatMap (fPublicKeys nasys honestAgents) pkiFunList

                                                                            freshMain = nasys \\ (publicKeysVar ++ publicKeysHon ++ privateKeysVar ++ varAgents ++ agree ++ share)
                                                                            parMain = nasys \\ (publicKeysVar ++ privateKeysVar ++ agree ++ share)

                                                                            -- set the agreed parameters (last process)
                                                                            (pname,pars,pa) = last ps1
                                                                            pars1 = (pars \\ privateKeysVar) \\  publicKeysVar             -- remove private/public keys of varagents from the main process
                                                                            proc1 = foldr (\x y -> PNew (x,[],y)) pa agree
                                                                            ps2 = tail (reverse ps1) ++ [(pname,pars1 \\ agree,proc1)]
                                                                            pfn = privatefun sharexpr            -- private functions
                                                                            fn1 = fn \\ pfn                      -- public functions
                                                                            pkv = map NEName varAgents ++ map neIdent2ExprPK publicKeysVar
                                                                            -- sequence numbers
                                                                            sqn = nubOrd ([ x | (JGoal (_,_,Seen,(_,x),_,_,_,_)) <- actions])
                                                                            pvtypes = availableTypes ++ map JUserDef customtypes
                                                                            -- maxproj =  maxProjActs actions  
                                                                            agentProcesses = printPVDefs ps2 pv sharexpr
                                                                            debug = False
                                                                          in
                                                                          if debug then
                                                                                error("\nagents: " ++ show agents
                                                                                    ++ "\nfn: " ++ show fn
                                                                                    ++ "\nfn1: " ++ show fn1
                                                                                    ++ "\npfn: " ++ show pfn
                                                                                    ++ "\npkv: " ++ show pkv
                                                                                    ++ "\nagree: " ++ show agree
                                                                                    ++ "\nshare: " ++ show share
                                                                                    ++ "\nsharexpr: " ++ show sharexpr
                                                                                    ++ "\nconst: " ++ show const2
                                                                                    ++ "\nnotAFreeName: " ++ show notAFreeName
                                                                                    ++ "\nna: " ++ show na
                                                                                    ++ "\nnasys: " ++ show nasys
                                                                                    ++ "\nroles: " ++ show roles
                                                                                    ++ "\nvarAgents: " ++ show varAgents
                                                                                    ++ "\nhonestAgents: " ++ show honestAgents
                                                                                    ++ "\npublicKeysVar: " ++ show publicKeysVar
                                                                                    ++ "\nprivateKeysVar: " ++ show privateKeysVar
                                                                                    ++ "\npublicKeyHon: " ++ show publicKeysHon
                                                                                    ++ "\nprivateKeysHon: " ++ show privateKeysHon
                                                                                    ++ "\nparMain: " ++ show parMain
                                                                                    ++ "\nfreshMain: " ++ show freshMain
                                                                                    ++ "\nsqn: " ++ show sqn
                                                                                    ++ "\npvtypes" ++ show pvtypes
                                                                                    )
                                                                                else
                                                                                    pvPrelude pv privChs sysname options
                                                                                    ++ showTypePrelude pvtypes agentProcesses pv
                                                                                    ++ (if null fnProj then "" else
                                                                                                "(* Projectors *)" ++ "\n" ++
                                                                                                printDeclFunctionsReduc fnProj pv ++ "\n")
                                                                                    ++ pvPreludeCryptoPrimitives options pv ++ "\n"
                                                                                    ++ (if null fn1 && null pfn then "" else
                                                                                                "(* Functions *)" ++ "\n")
                                                                                    ++ (if null fn1 then "" else
                                                                                                printDeclFunctions fn1 pv ++ "\n")
                                                                                    ++ (if null pfn then "" else
                                                                                                printDeclFunctions pfn pv ++ "\n")
                                                                                    ++ (if null equations then "" else
                                                                                                "(* Custom NEquations *)" ++ "\n" ++
                                                                                                printDeclEquations equations fn pv ++ "\n")
                                                                                    ++ (if null fnSecretgoal then "" else
                                                                                                "(* Secret Goal Testing Functions *)" ++ "\n" ++
                                                                                                printDeclFunctions fnSecretgoal pv ++ "\n")
                                                                                    ++ (if null varAgents then "" else
                                                                                                "(* Variable agents *)" ++ "\n"
                                                                                                ++ showParamsDecl DeclFree varAgents pv ++ "\n")     -- agent names (var)                                                                                                
                                                                                    ++ (if null const2 then "" else
                                                                                                "(* Constants *)" ++ "\n" ++
                                                                                                showParamsDecl DeclConst const2 pv ++ "\n")
                                                                                    ++ (if null privateKeysHon then "" else
                                                                                                "(* Secrecy assumptions *)" ++ "\n"
                                                                                                ++ notAttacker privateKeysHon  ++ "\n")
                                                                                    ++ "(* Goal queries *)" ++ "\n"
                                                                                    ++ secrecy pv
                                                                                    ++ guessablesecrecy pv
                                                                                    ++ query sqn pv ++ "\n"
                                                                                    ++ queryReach agents reachEvents pv
                                                                                    ++ (if ifHonestPrintElse then
                                                                                                -- concatMap (\x -> "event " ++ x ++ ".\n" ++ "query event(" ++ x ++ ").\n") [failedEvent] ++ "\n" 
                                                                                                "event " ++ failedEvent ++ ".\n\n"
                                                                                            else "")
                                                                                    ++ agentProcesses
                                                                                    ++ "(* Initialisation process *)" ++ "\n"
                                                                                    ++ "process\n"
                                                                                    ++ "(!"
                                                                                    ++ newX (JAgent,"X") pv
                                                                                    ++ newXshare (JAgent,"X") sharexpr varAgents pv
                                                                                    ++ "\n"
                                                                                    ++ ") | (\n"
                                                                                    ++ showParamsPublicExpr pkv pv             -- pub key and agent names (var)
                                                                                    ++ showParamsDecl DeclNew (nubOrd(freshMain ++ privateKeysHon)) pv
                                                                                    ++ showParamsPk publicKeysHon
                                                                                    ++ mainProcess sysname parMain varAgents PEUntyped pv (pvNoMutual options)
                                                                                    ++ ")"

-- list permutation - Simon Thompson's Haskell: The Craft of Functional Programming
perms :: Eq a => [a] -> [[a]]
perms [] = [[]]
perms xs = [ x:ps | x <- xs , ps <- perms ( xs \\ [x] ) ]

mainProcess :: String -> [NEIdent] -> [NEIdent] -> PE -> OutType -> Bool -> String
mainProcess sysname parMain _ pv pvtyped True = sysname ++ showParams parMain pv pvtyped
mainProcess sysname parMain varAgents pv pvtyped False = let -- parallelise processes by permutating free agents' names
                                                             par_other  = parMain \\ varAgents
                                                             ps_agents = perms varAgents
                                                             ps = map (\x -> sysname ++ showParams (x ++ par_other) pv pvtyped) ps_agents
                                                         in intercalate  " | " ps
