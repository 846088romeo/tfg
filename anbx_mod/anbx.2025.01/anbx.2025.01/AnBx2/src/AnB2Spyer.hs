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
{-# HLINT ignore "Use infix" #-}

module AnB2Spyer where

import AnBxMsgCommon
import AnBxMsg ( AnBxMsg (Comp,Atom))
import AnBAst
import AnBxOnP
import Data.List ( partition, sort, union )
import Debug.Trace
import Spyer_Ast

import AnB2NExpression (trMsg, spKeyFunIDPub, agent2NExpression, id2NExpression, trEquations, agent2NEIdent)
import Java_TypeSystem_JType
import Java_TypeSystem_Context
import Java_TypeSystem_Evaluator (typeofTS)
import Data.Maybe (fromJust)
import AnBxAst (AnBxChannelType(..), AnBxType (..))
import AnBxShow (showChannel)

-- AnB to Spyer protocol translation
-- This is useful to output spyer code
-- The tools can also translate directly from AnB to Execnarr actions (see compileAnB2Execnarr in Spyer_Execnarr.hs)

shareSymFun :: Bool
shareSymFun = True     -- True -> shk(A,B), False -> shkAB         shkAB name is generate as private anyway

trAnB2Spyer :: Protocol -> AnBxOnP -> Narration
trAnB2Spyer prot@((protname,_),types,_,equations,_,_,_,actions,_) options = let
                                                                        ctx = buildJContext prot
                                                                        decs = trAnB2ExecnarrKnowledge prot ctx options
                                                                        eqts = trEquations equations types ctx
                                                                        acts = trAnB2SpyerActions actions ctx options
                                                                      in ((protname,decs,eqts),acts)
                                                          -- in error (show shares)
                                                          -- in error ("\n" ++ showDeclarationsCompact decs)

-- AnB Actions translation to Spyer ----------
trAnBActions2Spyer :: Actions -> JContext -> AnBxOnP -> [Exchange]
trAnBActions2Spyer [] _ _  = []
trAnBActions2Spyer (((_,ActionComment _ s,_),_,_,_):xs) ctx opt = XComment s : trAnBActions2Spyer xs ctx opt
trAnBActions2Spyer ((((a,_,_),Insecure,(b,_,_)),msg,_,_):xs) ctx opt = XSend (a,b,trMsg msg ctx) : trAnBActions2Spyer xs ctx opt
trAnBActions2Spyer (((_,Sharing _,_),_,_,_):xs) ctx opt = trAnBActions2Spyer xs ctx opt     -- skip sharing actions
trAnBActions2Spyer ((ch,_,_,_):_) _ _ = error ("can not translate to Spyer channel " ++ showChannel ch)

-- actions translations
trAnB2SpyerActions :: Actions -> JContext -> AnBxOnP -> [Exchange]
trAnB2SpyerActions actions ctx opt =
    let
        acts = trAnBActions2Spyer actions ctx opt
        acts1 = case acts of
            (XSend(_, _, NEName (_, e)) : xs) | e == syncMsg -> xs 
            _ -> acts
    in acts1

-- the following models the knowledge mapping between AnB and ExecNarr

-- AnB knowledge translation
trAnB2ExecnarrKnowledge :: Protocol -> JContext -> AnBxOnP -> [Declaration]
trAnB2ExecnarrKnowledge (_,types,_,_,knowledge,shares,_,actions,_) ctx opt = trDeclarationsFinalize $ trDeclarations types actions knowledge shares ctx opt

-- since share actions generate private fact they must be the first to be translated
trDeclarations :: Types -> Actions -> Knowledge ->  AnBShares -> JContext -> AnBxOnP -> [Declaration]
-- trDeclarations _ _ k sh _ | trace ("trDeclarations\n\tknowledge: " ++ show k ++ "\n\tshares: " ++ show sh) False = undefined
trDeclarations t a k sh ctx opt = union (union (trShareActions a k sh ctx out) (trKnowledge k t sh ctx opt) ) (trTypes t a out)
                                    where out = anbxouttype opt

-- create the DKnow facts from the declaration given AnB Types and Knowledge
-- moreover DGenerate facts are produced by "addident"

trShareActions :: Actions -> Knowledge -> AnBShares -> JContext -> OutType -> [Declaration]
trShareActions  [] _ _ _ _ = []
-- handle shared knowledge (ignored if output is ProVerif)
trShareActions  ((((a,_,_),Sharing _,(b,_,_)),Comp Cat (msg:ms),_,_):xs) k sh ctx out | not (isOutTypePV out) = let
                                                                                                                    na = agent2NEIdent a ctx
                                                                                                                    nb = agent2NEIdent b ctx
                                                                                                                    d1 = trShareActionsFacts na nb msg sh ctx
                                                                                                                    d2 = case ms of
                                                                                                                            [] -> []
                                                                                                                            s -> concatMap (\x -> trShareActionsFacts na nb x sh ctx) s
                                                                                                                    d3 = union d1 d2
                                                                                                                in union d3 (trShareActions xs k sh ctx out)
trShareActions  ((( (a,_,_),Sharing _,(b,_,_)),msg,_,_):xs) k sh ctx out | not (isOutTypePV out) = union (trShareActionsFacts na nb msg sh ctx) (trShareActions xs k sh ctx out)
                                                                                                                 where 
                                                                                                                    na = agent2NEIdent a ctx
                                                                                                                    nb = agent2NEIdent b ctx
-- for authentic and (fresh-)secure channels we assume that agents knows their names (but no pseudonym are used)

trShareActions  ((( (a,False,_),Authentic,(b,_,_)),_,_,_):xs) k sh ctx out = union [DKnow (nb,agent2NExpression a ctx)] (trShareActions xs k sh ctx out)
                                                                                                                 where 
                                                                                                                    nb = agent2NEIdent b ctx
trShareActions  ((( (a,ap,_),ct,(b,bp,_)),_,_,_):xs) k sh ctx out | ct == Secure || ct == FreshSecure = union (if not ap then [DKnow (nb,agent2NExpression a ctx)] else ([DKnow (na,agent2NExpression b ctx) | not bp])) (trShareActions xs k sh ctx out)
                                                                  | otherwise = trShareActions xs k sh ctx out
                                                                   where 
                                                                            na = agent2NEIdent a ctx
                                                                            nb = agent2NEIdent b ctx

trShareActionsFacts :: NEIdent -> NEIdent -> Msg -> AnBShares -> JContext -> [Declaration]
-- trShareActionsFacts a b msg t sh | trace ("trShareActionsFacts\n\ta: " ++ a ++ "\n\tb: " ++ b ++ "\n\tmsg: " ++ show msg ++ "\n\ttypes: " ++ show t ++ "\n\tshares: " ++ show sh) False = undefined
trShareActionsFacts _ _ (Atom m) _ _ | m == syncMsg = []      -- ignore synchronisation msg
trShareActionsFacts a b msg@(Atom id) sh ctx = let
                                                    t = typeofTS expr ctx
                                                    base = [DKnow (a,trMsg msg ctx),DKnow (b,trMsg msg ctx)]
                                                    priv = DShare (fromJust $ isCompShared msg sh,(t,id),trMsg msg ctx,[a,b]) : base
                                                    expr = trMsg msg ctx
                                               in case t of
                                                        JNonce -> priv
                                                        JSeqNumber -> priv
                                                        JPublicKey _ -> priv
                                                        JSymmetricKey -> priv
                                                        _ ->  base
trShareActionsFacts a b (Comp Cat [x]) sh ctx = trShareActionsFacts a b x sh ctx
trShareActionsFacts a b (Comp Cat (x:xs)) sh ctx = trShareActionsFacts a b x sh ctx ++ trShareActionsFacts a b (Comp Cat xs) sh ctx

trShareActionsFacts a b msg sh ctx = case isCompShared msg sh of
                                            (Just st) -> DShare (st,(t,spMsg2Ident msg),expr,[a,b]) : base      -- (id,msg) msg is translated to an ID for shares
                                            Nothing -> base
                                          where
                                            base = [DKnow (a,expr),DKnow (b,expr)]
                                            expr = trMsg msg ctx
                                            t = typeofTS expr ctx

-- type declaration also need to be analysed in order to build the declaration section
trTypes :: Types -> Actions -> OutType -> [Declaration]
trTypes [] _ _ = []
trTypes [x] a out = trType x a out
trTypes (x:xs) a out = union (trType x a out) (trTypes xs a out)

trType :: (Type,[Ident]) -> Actions -> OutType -> [Declaration]
trType (_,[]) _ _ = []
trType (t@(Number opt),x:xs) a out = union (addIdent x t a out) (trType (Number opt,xs) a out)
trType (t@(SeqNumber opt),x:xs) a out = union (addIdent x t a out) (trType (SeqNumber opt,xs) a out)
trType (t@(PublicKey opt),x:xs) a out = union (addIdent x t a out) (trType (PublicKey opt,xs) a out)
trType (t@(SymmetricKey opt),x:xs) a out = union (addIdent x t a out) (trType (SymmetricKey opt,xs) a out)
trType (t@(Untyped opt),x:xs) a out = union (addIdent x t a out) (trType (Untyped opt,xs) a out)
trType (t@(Custom ty opt),x:xs) a out = union (addIdent x t a out) (trType (Custom ty opt,xs) a out)
trType (_,_) _ _ = []

addIdent :: Ident -> Type -> Actions -> OutType -> [Declaration]
-- addIdent id _ a _ | trace("addIdent\n\tid: " ++ id ++ "\n\ta: " ++ show a) False = undefined
addIdent id t a out =
                      if isVariable id then
                                 case firstAgent id a out of
                                            Nothing -> []
                                            Just id1 -> case t of
                                                            -- if an agent generates PublicKey they should know also the PrivateKey
                                                            PublicKey _ -> [DGenerates (jid1,keyOfIdent Nothing id) , DGenerates (jid1, keyOfIdentPriv Nothing id)]
                                                            _ -> [DGenerates (jid1,NEName (mapAnBTypes (t,id),id))]
                                                            where jid1 = (JAgent,id1)
                      else []

---------------------------------------------------------------

-- agent lists -----
allAgents :: Actions -> [Ident]
allAgents [] = []
allAgents (((_,ActionComment _ _,_),_,_,_):xs) = allAgents xs
allAgents ((((a,_,_),_,(b,_,_)),_,_,_):xs) = union [a,b] (allAgents xs)

-- agents known by agent id
knownAgents :: Ident -> [Msg] -> Types -> [Ident]
knownAgents _ [] _ = []
knownAgents id (Atom a:xs) t = let
                            ags = case id2Type a t of
                                            Agent {} -> [a | id /= a]
                                            _ -> []
                            in ags ++ knownAgents id xs t
knownAgents id (_:xs) t = knownAgents id xs t

-- AnB Knowledge translation ----

trKnowledge :: Knowledge -> Types -> AnBShares -> JContext -> AnBxOnP -> [Declaration]
-- trKnowledge know _ _ _ _ | trace ("trKnowledge\n\tknow: " ++ show know) False = undefined
trKnowledge ([],_) _ _ _  _ = []   -- where declarations are ignored
trKnowledge (x@(id,msgs):xs,wk) t sh ctx opt = let
                                              a = knownAgents id msgs t
                                           in union (trKnow x t a sh ctx opt) (trKnowledge (xs,wk) t sh ctx opt)

trKnow :: (Ident,[Msg]) -> Types -> [Ident] -> AnBShares -> JContext -> AnBxOnP -> [Declaration]
-- trKnow (id,msg) types knownagents shares _ _ | trace ("trKnow\n\tid: " ++ id ++ "\n\tmsg: " ++ show msg ++" \n\ttypes: " ++ show types ++ "\n\tknowagents: " ++ show knownagents ++ "\n\tshares: " ++ show shares ) False = undefined
trKnow (_,[]) _ _ _ _ _ = []
trKnow (id,(Atom a):ms) t knownagents sh ctx opt = union (trKnow (id,ms) t knownagents sh ctx opt) (case id2Type a t of
                                                                                                      Agent _ _ _ NoCert -> [DKnow (jid, agent2NExpression a ctx)]
                                                                                                      Agent _ _ _ Cert -> DKnow (jid, agent2NExpression a ctx) : map (\pk-> DKnow (jid, spKeyFunIDPub (Just pk) a ctx)) pkiFunList
                                                                                                      Function _ -> let
                                                                                                                      knownpubkeys = if isPKFun a
                                                                                                                                           then map (\x -> DKnow (jid, spKeyFunIDPub pka x ctx)) knownagents
                                                                                                                                           else []
                                                                                                                    in  DKnow (jid, id2NExpression a ctx) : knownpubkeys
                                                                                                      _ -> [DKnow (jid, id2NExpression a ctx)])
                                                                                                      where 
                                                                                                            jid = agent2NEIdent id ctx
                                                                                                            pka = Just (getKeyFun a)

-- application of functions
trKnow (id,m@(Comp Apply [Atom f,_]):ms) t a sh ctx opt = union (trKnow (id,ms) t a sh ctx opt) dKnowFacts -- make sure that ids are sorted (well-formedness)
                                                                                          where 
                                                                                                jid = agent2NEIdent id ctx
                                                                                                dKnowFacts = DKnow (jid,trMsg m ctx) : dPrivFact
                                                                                                sharecond = if guessprivatefunctions opt then SHShare else fromJust $ isCompShared m sh
                                                                                                myShares = [ x | x@(shtype,_,msg) <-sh , elem m msg, shtype==SHShare]
                                                                                                dPrivFact = case myShares of
                                                                                                                [] -> []
                                                                                                                ((_,ids,_):_) -> [DShare (sharecond,(t1,spMsg2Ident m),expr, sort (map (\x -> agent2NEIdent x ctx) ids)) | isPrivFun f t]
                                                                                                                where 
                                                                                                                    t1 = typeofTS expr ctx
                                                                                                                    expr = trMsg m ctx
-- otherwise translate the messages
trKnow (id,m:ms) t a sh ctx opt = union (trKnow (id,ms) t a sh ctx opt) [DKnow (jid,trMsg m ctx)]
                                                                                        where 
                                                                                            jid = agent2NEIdent id ctx


-- build elementary facts from tuples in analogy with spyer preprocessor
-- sort DKnow facts as they where declared in the Knowledge

trDeclarationsFinalize :: [Declaration] -> [Declaration]
trDeclarationsFinalize decls =
    let (dKnowFacts, otherFacts) = partition isDKnow decls
        expandedDKnow = concatMap expandDKnowDeclaration dKnowFacts
    in reverse expandedDKnow ++ otherFacts
  where
    isDKnow :: Declaration -> Bool
    isDKnow (DKnow _) = True
    isDKnow _         = False

    expandDKnowDeclaration :: Declaration -> [Declaration]
    expandDKnowDeclaration (DKnow (id, NECat xs)) = map (\x -> DKnow (id, x)) xs
    expandDKnowDeclaration d = [d]