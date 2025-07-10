{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE InstanceSigs #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "Avoid lambda using `infix`" #-}
{-# HLINT ignore "Use infix" #-}
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

module AnB2NExpression where
import Spyer_Ast
import Data.Char
import AnBxMsgCommon
import AnBxMsg ( AnBxMsg (Comp,Atom), patternMsgError)
import Spyer_Message
import AnBAst
import Debug.Trace
import qualified Data.Map as Map
import Data.Hashable (hash)
import Web.Hashids
import Data.ByteString.UTF8 (toString)

import Crypto.MAC.SipHash
import qualified Data.ByteString.Char8 as B
import qualified GHC.Word
import Data.List (intercalate)
import Java_TypeSystem_Evaluator (typeofTS)
import Java_TypeSystem_Context
import Java_TypeSystem_JType
import AnBxAst (AnBxEquation(..))
import AnBxShow (showChannelType)
import qualified Data.Text as T
import qualified Data.Text.Encoding as E
import Data.Containers.ListUtils (nubOrd)


k0 :: GHC.Word.Word64
k0 = 0xaaaaaaaaaaaaaaaa
k1 :: GHC.Word.Word64
k1 = 0xbbbbbbbbbbbbbbbb

type NEChannel = (NEIdent,ChannelType,NEIdent)

data ChannelDirection = CDSend | CDRec

showNEChannel :: NEChannel -> ChannelDirection -> String
showNEChannel (a,ct,b) CDSend = snd a ++ " " ++ showChannelType ct ++ " " ++ snd b
showNEChannel (a,ct,b) CDRec = showNEChannel (b,ct,a) CDSend

data  NAction =
         NANew (Int,String,NEIdent)                               -- set,agent, typedidentifier
       | NAEmit (Int,String,NEChannel,NExpression,NExpression)   -- step,agent,channel,dest expression,message
       | NAEmitReplay (Int,String,NEChannel,NExpression,NExpression) -- step,agent,channel,dest expression,message
       | NAReceive (Int,String,NEChannel,NExpression)             -- step,agent,channel,expression
       | NACheck (Int,String,Formula)                             -- step,agent,formula
       | NAAssign (Int,String,String,NExpression)                 -- step.agent,varname,expression
       | NAComment (Int,String)                                   -- step,comment    
       | NAGoal (Int,String,Fact,String,NExpression,[(String,NExpression)],Bool,Int) -- bool ==> side conditions -- last int ==> first step of occurrence of the expression
       deriving (Eq,Ord)

instance Show NAction where
    show :: NAction -> String
    show (NANew (step,a,(_,k))) = showStepNA step Nothing  ++ a ++ ": " ++ "new " ++ k
    show (NAEmit (step,a,ch,e,f)) = showStepNA step Nothing  ++ a ++ ": send(" ++ show e ++ ";" ++ show f ++ ")" ++ "\t# " ++ showNEChannel ch CDSend
    show (NAEmitReplay (step,a,ch,e,f)) = showStepNA step Nothing  ++ a ++ ": sendReplay(" ++ show e ++ ";" ++ show f ++ ")" ++ "\t# " ++ showNEChannel ch CDSend
    show (NAReceive (step,a,ch,x)) = showStepNA step Nothing ++ a ++ ": " ++ show x ++ " := receive()" ++ "\t# " ++ showNEChannel ch CDRec
    show (NACheck (step,a,phi)) = showStepNA step Nothing  ++ a ++ ": " ++ show phi
    show (NAAssign (step,a,x,e)) = showStepNA step Nothing  ++ a ++ ": " ++ x ++ " := " ++ show e
    show (NAComment (step,s)) = "\n" ++ showStepNA step Nothing  ++ "# " ++ s
    show (NAGoal (step,a,fact,idents,e,ags,sidecond,effStep)) = showStepNA step (Just effStep) ++ a ++ ": " ++ show fact ++ "(" ++  idents ++ "," ++  show e ++ "," ++  showAgs ++ ")" ++ " # side condition: " ++ show sidecond
                                                                        where showAgs = "[" ++ intercalate "," (map (\x -> "(" ++ showAgentExpr x ++ ")") ags) ++ "]"

data Fact = Witness                   -- Ident Ident Msg 
         |  Request                   -- Ident Ident Msg Msg
         |  Wrequest                  -- Ident Ident Msg Msg
         |  SecretGoal                -- Msg Ident [Ident]
         |  GuessableSecretGoal       -- Msg Ident [Ident]
         |  Seen                      -- Msg Ident Ident
       deriving (Eq,Ord)

instance Show Fact where
        show :: Fact -> String
        show Witness = "witness"
        show Request = "request"
        show Wrequest = "wrequest"
        show SecretGoal = "secret"
        show GuessableSecretGoal  = "guessablesecret"
        show Seen = "seen"

showAgentExpr :: (String,NExpression) -> String
showAgentExpr (s,e) = s ++"," ++ show e

type NExecnarr = (NEDeclaration,Execnarr)
type Execnarr = [NAction]
type MapSK = Map.Map String KnowledgeMap        -- string = agent name

printMapSK :: MapSK -> String
printMapSK kappa = concatMap (\(a,k) -> printSKAgent a k ++ "\n") (Map.toList kappa)

printSKAgent :: String -> KnowledgeMap -> String
printSKAgent a k = "K(" ++ a ++ "): " ++ showKnowledgeMap k

mustShowStepNA :: Bool
mustShowStepNA = True -- true only for debug

showStepNA :: Int -> Maybe Int -> String
showStepNA step (Just effStep) = if mustShowStepNA then show step ++ "(" ++ show effStep ++ ")" ++ "| " else ""
showStepNA step Nothing = if mustShowStepNA then show step ++ "| " else ""

mustShowStepA :: Bool
mustShowStepA = True -- true only for debug

showStepA :: Int -> String
showStepA int = if mustShowStepA then show int ++ "| " else ""

showExecnarr :: Execnarr -> String
showExecnarr [] = "\n"
showExecnarr (x:xs) = show x ++ "\n" ++ showExecnarr xs

showNExecnarr :: NExecnarr -> String
showNExecnarr ((name,ds,equations),xs) = "Protocol: " ++ name ++ "\n\n" ++
                                        (if null ds then "" else "Knowledge: " ++ "\n" ++ showDeclarationsCompact ds ++ "\n") ++
                                        (if null equations then "" else "Equations: " ++ "\n" ++ showEquations equations ++ "\n") ++
                                        (if null xs then "" else "Actions: " ++ "\n" ++ showExecnarr xs)

stepOfNAction :: NAction -> Int
stepOfNAction (NANew (step,_,_)) = step
stepOfNAction (NAEmit (step,_,_,_,_)) = step
stepOfNAction (NAReceive (step,_,_,_)) = step
stepOfNAction (NACheck (step,_,_)) = step
stepOfNAction (NAAssign (step,_,_,_)) = step
stepOfNAction (NAComment (step,_)) = step
stepOfNAction (NAGoal (step,_,_,_,_,_,_,_)) = step

agentOfNAction:: NAction -> Maybe String
agentOfNAction (NANew (_,a,_)) = Just a
agentOfNAction (NAEmit (_,a,_,_,_)) = Just a
agentOfNAction (NAReceive (_,a,_,_)) = Just a
agentOfNAction (NACheck (_,a,_)) = Just a
agentOfNAction (NAAssign (_,a,_,_)) = Just a
agentOfNAction (NAComment _) = Nothing
agentOfNAction (NAGoal (_,a,_,_,_,_,_,_)) = Just a

getIdent :: Msg -> JContext -> String
getIdent msg ctx = getIdentExpr $ trMsg msg ctx

getIdentExpr :: NExpression -> String
getIdentExpr expr = varNameCleanup . varExp2Name $ showVarName expr

getNEIdentExpr :: NExpression -> JContext -> NEIdent
getNEIdentExpr expr ctx = (t,id) 
                        where id = getIdentExpr expr
                              t = typeofTS expr ctx

varExp2Name :: String -> String
-- varExp2Name expr | trace ("varExp2Name\n\texpr: " ++ show expr) False = undefined
varExp2Name [] = []
varExp2Name (x:xs)
        | isDigit x || (isAscii x && isAlpha x) = x : varExp2Name xs
        | otherwise = varExp2Name xs

-- makes varnames shorter
varNameCleanup :: String -> String
-- varNameCleanup expr | trace ("varNameCleanup\n\texpr: " ++ show expr) False = undefined
varNameCleanup [] = []
varNameCleanup str = let
                        patterns =[("VAR",""),("FST","1"),("SND","2"),("PK","P"),("SK","S"),("ENC","E"),("SIGN","E"),
                                   ("DEC","D"),("VERIFY","D"),("HASH","H"),("HMAC","M"),("PROJ","J"),("PRIV","V"),("PUB","U"),("_","")]
                        str1 = map toUpper str
                        str2 = foldr (\(a,b) y -> replace a b y) str1 patterns
                     in str2

varName :: String -> NExpression -> String
-- varName agent expr | trace ("varName\n\tagent: " ++ show agent ++ "\n\texpr: " ++ show expr) False = undefined
varName agent expr = map toUpper ("var_" ++ agent ++ "_" ++ funName expr)

funName :: NExpression -> String
funName = funName0

-- different functions to generate var ids

funName0 :: NExpression -> String
funName0 = getIdentExpr -- varNameCleanup . varExp2Name $ showVarName expr

funName1 :: NExpression -> String
funName1 expr = let
                    n = Data.Hashable.hash (funName0 expr)
                    m = if n < 0  then -n else n
               in show m

funName2 :: NExpression -> String
funName2 expr = let
                    n = Data.Hashable.hash (funName0 expr)
                    m = if n < 0  then encode' (-n) else encode' n
               in toString m


funName3 :: NExpression -> String
funName3 expr = let
                    str = funName0 expr
                    --(SipHash h) = Crypto.MAC.SipHash.hash (SipKey k0 k1) (B.pack str)varExp2Name
                    (SipHash h) = Crypto.MAC.SipHash.hash (SipKey k0 k1) (E.encodeUtf8 $ T.pack str)
                in show h

context :: HashidsContext
context = hashidsSimple "dsjhaosdrpoawduspfoaweuruvaw"

encode' :: Int -> B.ByteString
encode' = encode context
encodeList' :: [Int] -> B.ByteString
encodeList' = encodeList context
decode' :: B.ByteString -> [Int]
decode' = decode context

-- AnB -> Execnarr translation of identifiers -------------------

id2NExpression :: Ident -> JContext -> NExpression
-- id2NExpression id ctx | trace ("id2NExpression\n\tid: " ++ id ++ "\n\tcontext: " ++ show ctx) False = undefined 
id2NExpression id ctx = NEName $ id2NEIdent id ctx
-- id2NExpression id ctx = NEName (t,id) 
--                            where
--                                (_,VarBind t) = getBindingByName ctx id

agent2NExpression :: Ident -> JContext -> NExpression
-- agent2NExpression id ctx | trace ("agent2NExpression\n\tid: " ++ id ++ "\n\tcontext: " ++ show ctx) False = undefined 
agent2NExpression id ctx = case t of
                           JAgent -> id2NExpression id ctx
                           _ ->  error ("unexpected agent2NExpression for ident: " ++ id) 
                        where t = typeofTS (id2NExpression id ctx) ctx                                              

id2NEIdent :: Ident -> JContext -> NEIdent
-- id2NEIdent id ctx | trace ("id2NEIdent\n\tid: " ++ id ++ "\n\tcontext: " ++ show ctx) False = undefined
id2NEIdent id ctx = let (_,VarBind t) = getBindingByName ctx id in (t,id)

agent2NEIdent :: Ident -> JContext -> NEIdent
-- agent2NEIdent id ctx | trace ("agent2NEIdent\n\tid: " ++ id ++ "\n\tcontext: " ++ show ctx) False = undefined 
agent2NEIdent id ctx = case t of
                           JAgent -> id2NEIdent id ctx
                           _ ->  error ("unexpected agent2NExpression for ident: " ++ id) 
                        where t = typeofTS (id2NExpression id ctx) ctx    


-- id = agent name, pk = pkfun
spKeyFunIDPub :: Maybe AnBxPKeysFun -> Ident -> JContext -> NExpression
-- spKeyFunIDPub pk id ctx | trace ("spKeyFunIDPub\n\tpk: " ++ show pk ++ "\n\tid: " ++ id ++ "\n\tcontext: " ++ show ctx) False = undefined 
spKeyFunIDPub (Just pk) id ctx | isPKFun pkf = NEPub e (Just pk)
                               | otherwise = error ("cannot apply spKeyFunIDPub to keyfunction:" ++ show pk ++ " id: " ++ show id)                                
                                        where 
                                                e = NEFun (t,pkf) (agent2NExpression id ctx)
                                                t = typeofTS (id2NExpression pkf ctx) ctx
                                                pkf = show pk                                
spKeyFunIDPub Nothing id _ = keyOfIdent Nothing id

spKeyFunIDPriv :: Maybe AnBxPKeysFun -> Ident -> JContext -> NExpression
spKeyFunIDPriv pk id ctx = 
    case spKeyFunIDPub pk id ctx of
        NEPub e1 e2 -> NEPriv e1 e2
        expr       -> error $ "spKeyFunIDPriv - Expected NEPub but got: " ++ show expr

trEquations :: AnBEquations -> Types -> JContext -> NEquations
trEquations [] _ _ = []
trEquations (x:xs) types ctx = trEquation x types ctx : trEquations xs types ctx

trEquation :: AnBEquation -> Types -> JContext -> NEquation
-- trEquation eq _ ctx  | trace ("trEquation\n\teq: " ++ AnBAst.showEquation eq ++ "\n\tcontext: " ++ show ctx) False = undefined 
trEquation (Eqt msg1 msg2) types ctx = NEqt (trMsg msg1 ctx) (trMsg msg2 ctx) jids
                                                        where
                                                                jids = nubOrd (jids1 ++ jids2)
                                                                -- these ids contain also the function declaration
                                                                jids1 = map (\x-> id2NEIdent x ctx) (spMsg2Idents msg1 types)
                                                                jids2 = map (\x-> id2NEIdent x ctx) (spMsg2Idents msg2 types)

trMsgs :: [Msg] -> JContext -> NExpression
trMsgs [] _ = error "trMsgs - no messages to translate to NExpression format"
trMsgs [x] ctx = trMsg x ctx
trMsgs msgs ctx = NECat (map (\x -> trMsg x ctx) msgs)

trMsg :: Msg -> JContext -> NExpression
-- trMsg msg ctx | trace ("trMsg\n\tmsg: " ++ show msg ++ "\n\tcontext: " ++ show ctx) False = undefined 
trMsg (Atom a) ctx = case typeofTS id ctx of
                                JAgent -> agent2NExpression a ctx
                                JPublicKey _-> keyOfIdent Nothing a   -- freshly created public key
                                _ -> id
                                where id = id2NExpression a ctx

-- Asymmetric Encryption (PKI) --

-- extra checks on the type of terms (e.g. Public/Private Key), also typechecked overall message if typechecker is eanbled
-- Case: PKA
trMsg (Comp Crypt (x@(Atom a):xs)) ctx
  | compareTypes tpar (JPublicKey Nothing) = NEEnc (trMsgs xs ctx) (trMsg x ctx)
  | otherwise =  error ("unexpected term of type " ++ show x ++ " - msg: " ++ show x)
    where
        tpar = typeofTS par ctx
        par = id2NExpression a ctx

-- Case: pk(A)
trMsg (Comp Crypt (x@(Comp Apply [Atom f, Atom a]):xs)) ctx = expr
  where
    expr | elem pk pkiSigFunList = NESign (trMsgs xs ctx) (trMsg x ctx)
         | elem pk pkiEncFunList = NEEnc (trMsgs xs ctx) (trMsg x ctx)
         | otherwise = error ("unexpected term of type " ++ show tx ++ " - msg: " ++ show x)
    pk
      | isPKFun f && compareTypes tpar JAgent && compareTypes tx (JPublicKey (Just (getKeyFun f))) = getKeyFun f
      | otherwise = error ("unexpected term of type " ++ show tx ++ " - msg: " ++ show x)
    tpar = typeofTS par ctx
    tx = typeofTS ex ctx
    par = id2NExpression a ctx
    ex = trMsg x ctx 

-- Case: inv(PKA)
trMsg (Comp Crypt (x@(Comp Inv [Atom a]):xs)) ctx
  | compareTypes tpar (JPublicKey Nothing) = NESign (trMsgs xs ctx) (trMsg x ctx)
  | otherwise =  error ("unexpected term of type " ++ show x ++ " - msg: " ++ show x)
    where
        tpar = typeofTS par ctx
        par = id2NExpression a ctx

-- Case: inv(pk(A))
trMsg (Comp Crypt (x@(Comp Inv [y@(Comp Apply [Atom f, par@(Atom _)])]):xs)) ctx = expr
  where
    expr | elem pk pkiSigFunList = NESign (trMsgs xs ctx) (trMsg x ctx)
         | elem pk pkiEncFunList = NEEnc (trMsgs xs ctx) (trMsg x ctx)
         | otherwise = error ("unexpected term of type " ++ show tx ++ " - msg: " ++ show x)
    pk
      | isPKFun f && compareTypes tpar JAgent && compareTypes ty (JPublicKey (Just (getKeyFun f))) = getKeyFun f
      | otherwise = error ("unexpected term of type " ++ show tx ++ " - msg: " ++ show x)
    ty = typeofTS ey ctx
    tpar = typeofTS epar ctx
    tx = typeofTS ex ctx
    ex = trMsg x ctx
    ey = trMsg y ctx
    epar = trMsg par ctx

-- Generic Asymmetric Encryption
trMsg (Comp Crypt (x:xs)) ctx = NEEnc (trMsgs xs ctx) (trMsg x ctx)
--  where
--    pk
--      | compareTypes tx (JPrivateKey Nothing) || compareTypes tx (JPublicKey Nothing) = Nothing
--      | otherwise = error ("unexpected term of type " ++ show tx ++ " - msg: " ++ show x)
--    tx = typeofTS ex ctx
--    ex = trMsg x ctx

---- Symmetric Enc
trMsg (Comp Scrypt (x:xs)) ctx = NEEncS (trMsgs xs ctx) (trMsg x ctx)

-- PK keys
-- inv(PKA)
trMsg m@(Comp Inv [Atom a]) ctx = case typeofTS k ctx of
                                        JPublicKey _ -> keyOfIdentPriv Nothing a                            -- freshly generated private key
                                        _ -> error ("undefined expression for PrivateKey: " ++ show m)
                                        where k = id2NExpression a ctx
-- inv(pk(A))
trMsg (Comp Inv [Comp Apply [Atom pk , Atom id]]) ctx | isPKFun pk = spKeyFunIDPriv pkf id ctx
                                                      | pk == show AnBxBlind = NEPriv (NEFun (t,pk) (agent2NExpression id ctx)) pkf      -- used by blind operator 
                                                            where 
                                                                t = typeofTS (id2NExpression pk ctx) ctx
                                                                pkf = Just (getKeyFun pk)
-- DH --
-- note that the equivalence relation is implemented in inSynthesis (Spyer_Knowledge.hs)
-- DH exp(g,X) and exp(exp(g,x),y)

trMsg msg@(Comp Exp [Comp Exp [m1,m2],m3]) ctx = if m2==m3 then error ("error in msg: " ++ show msg ++ " - exponents are equal")
                                                            else  NEKas (NEKap (trMsg m1 ctx) (trMsg m2 ctx)) (trMsg m3 ctx)
trMsg (Comp Exp [m1,m2]) ctx = NEKap (trMsg m1 ctx) (trMsg m2 ctx)

-- pk(A)
trMsg (Comp Apply [Atom pk, Atom id]) ctx | isPKFun pk = spKeyFunIDPub pkf id ctx
                                                            where
                                                                pkf = Just (getKeyFun pk)

--- DigestHmac
trMsg (Comp Apply [Atom f,Comp Cat [m1,m2]]) ctx | f == show AnBxHmac = NEHmac (trMsg m1 ctx) (trMsg m2 ctx)
-- cat element is the key
trMsg (Comp Apply [Atom f,m]) _ | f == show AnBxHmac = error ("unhandled " ++ show AnBxHmac ++ " of " ++ show m)

---- DigestHash
trMsg (Comp Apply [Atom f,m]) ctx | f == show AnBxHash = NEHash (trMsg m ctx)

---- XOR
trMsg (Comp Xor [m1,m2]) ctx = NEXor (trMsg m1 ctx) (trMsg m2 ctx)

-- Generic Function --
-- we use it simply as a function
trMsg (Comp Apply [Atom f,m]) ctx = NEFun (t,f) (trMsg m ctx)
                                        where
                                            t = typeofTS (id2NExpression f ctx) ctx

-- tuplas
trMsg (Comp Cat m) ctx = trMsgs m ctx
trMsg m@(Comp op _) _ = error ("unhandled operator - Comp " ++ show op ++ "\n\tmsg: " ++ show m)

trMsg m _ = error $ patternMsgError m "trMsg"  

