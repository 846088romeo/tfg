{-

 AnBx Compiler and Code Generator

 Copyright 2011-2025 Paolo Modesti
 Copyright 2022 Rémi Garcia
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

 Copyright Sebastien Briais and Uwe Nestmann, 
      for the portion of code adapted from the OCaml source code of spyer: a cryptographic protocol compiler, GNU General Public Licence
      http://sbriais.free.fr/tools/spyer/

Copyright Sam Sepstrup Olesen 
      for the portion of code adapted from the OCaml source code of narcapi 
      https://github.com/samolesen/narcapi
      
-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "Replace case with fromMaybe" #-}
{-# HLINT ignore "Replace case with maybe" #-}
{-# HLINT ignore "Use lambda-case" #-}
{-# HLINT ignore "Avoid lambda" #-}
{-# HLINT ignore "Use infix" #-}
{-# HLINT ignore "Avoid lambda using `infix`" #-}

module Spyer_Knowledge where
import Spyer_Message
import Spyer_Common
import qualified Data.Set as Set
import qualified Data.Map as Map
import AnBxOnP
import AnBxMsgCommon
import Debug.Trace(trace)
import Data.Containers.ListUtils (nubOrd)
import AnB2NExpression (id2NExpression)
import Java_TypeSystem_Context
import Java_TypeSystem_JType
import Data.List (foldl', isInfixOf)

-- differents ways to synthetise a tuple
-- default (fast): 1
-- alternative (slow with large protocols): 2
-- (other) fastest in some cases, but may miss some checks: any other number 
optMCat :: Int
optMCat = 1 -- default: 1

msgErrorContext :: NExpression -> String -> String
msgErrorContext e m = show e ++ " must be a message in this context (" ++ m ++ ")"

msgUndefined :: NExpression -> String -> String
msgUndefined e m = m ++ " is undefined for term: " ++ show e

-- synthesis/analysis computation methods -----------------------------------

-- compute the expressions (if they exists) that can be used to synthesize m
synthesis :: KnowledgeMap -> NExpression -> NEquations -> JContext -> AnBxOnP -> ExpressionSet
-- synthesis knowledge msg equations _ _ | trace ("synthesis\n\tknowledge: " ++ showKnowledgeMap knowledge ++ "\n\tmsg: " ++ show msg ++ "\n\tequations: " ++ show equations) False = undefined
synthesis knowledge msg equations ctx opt | not (exprIsMessage msg) = error (msgErrorContext msg "synthesis")
                               | otherwise = let
                                    base = case Map.lookup msg knowledge of
                                                    Just e -> e
                                                    Nothing -> Set.empty
                                    encOption = synthesistypeenc opt
                                 in case msg of
                                        NEName _ -> base
                                        NECat [] -> base
                                        NECat [m] -> case optMCat of
                                                                 1 -> Set.union base (synthesis knowledge m equations ctx opt)
                                                                 2 -> Set.union base (synthesis knowledge m equations ctx opt)
                                                                 _ -> base
                                        NECat (m:ms) -> case optMCat of
                                                                    -- default (fast)
                                                                    1 -> let
                                                                            syn_m2 = map (\z -> Set.toList (synthesis knowledge z equations ctx opt)) (m:ms)
                                                                        in Set.union base (Set.fromList [NECat x | x <- zipLists syn_m2])
                                                                    -- alternative (slow with large protocols)
                                                                    2 -> let
                                                                        syn_m1 = synthesis knowledge m equations ctx opt
                                                                        syn_m2 = synthesis knowledge (NECat ms) equations ctx opt
                                                                        in foldset (\e1 es1 -> foldset (\e2 es2 -> Set.insert (NECat (e1 : case e2 of
                                                                                                                                NECat xs -> xs
                                                                                                                                _ -> [e2])) es2) es1 syn_m2) base syn_m1
                                                                    -- fastest in some cases, but may miss some checks
                                                                    _ -> base
                                        NEEnc m1 m2 -> if enc encOption then base
                                                                else
                                                                    let
                                                                        syn_m1 = synthesis knowledge m1 equations ctx opt
                                                                        syn_m2 = synthesis knowledge m2 equations ctx opt
                                                                    in foldset (\e1 es1 -> foldset (\e2 es2 -> Set.insert (NEEnc e1 e2) es2) es1 syn_m2) base syn_m1
                                        NESign m1 m2 -> if enc encOption then base
                                                                else
                                                                    let
                                                                        syn_m1 = synthesis knowledge m1 equations ctx opt
                                                                        syn_m2 = synthesis knowledge m2 equations ctx opt
                                                                    in foldset (\e1 es1 -> foldset (\e2 es2 -> Set.insert (NESign e1 e2) es2) es1 syn_m2) base syn_m1
                                        NEEncS m1 m2 -> if encS encOption then base
                                                                else
                                                                    let
                                                                        syn_m1 = synthesis knowledge m1 equations ctx opt
                                                                        syn_m2 = synthesis knowledge m2 equations ctx opt
                                                                    in foldset (\e1 es1 -> foldset (\e2 es2 -> Set.insert (NEEncS e1 e2) es2) es1 syn_m2) base syn_m1
                                        -- no need to synthesize private keys
                                        NEPriv _ _ -> base
                                        NEPub (NEFun m1@(_,pk) m2) _ | isPKFun pk && exprIsAgent m2 -> let
                                                                                                            syn_m1 = synthesis knowledge (id2NExpression pk ctx) equations ctx opt
                                                                                                            syn_m2 = synthesis knowledge m2 equations ctx opt
                                                                                                       in foldset (\_ es1 -> foldset (\e2 es2 -> Set.insert (NEPub (NEFun m1 e2) (Just (getKeyFun pk))) es2) es1 syn_m2) base syn_m1
                                                                                                            -- where a = agentOfNExpression m2
                                        NEPub m _-> let
                                                            syn_m = synthesis knowledge m equations ctx opt
                                                    in foldset (\e es -> Set.insert (NEPub e Nothing) es) base syn_m
                                        NEHash m -> let
                                                            syn_m = synthesis knowledge m equations ctx opt
                                                    in foldset (\e es -> Set.insert (NEHash e) es) base syn_m
                                        NEHmac m1 m2 -> let
                                                            syn_m1 = synthesis knowledge m1 equations ctx opt
                                                            syn_m2 = synthesis knowledge m2 equations ctx opt
                                                          in foldset (\e1 es1 -> foldset (\e2 es2 -> Set.insert (NEHmac e1 e2) es2) es1 syn_m2) base syn_m1
                                        NEKas m1 m2 -> let
                                                            syn_m1 = synthesis knowledge m1 equations ctx opt
                                                            syn_m2 = synthesis knowledge m2 equations ctx opt
                                                        in foldset (\e1 es1 -> foldset (\e2 es2 -> Set.insert (NEKas e1 e2) es2) es1 syn_m2) base syn_m1
                                        NEKap m1 m2 -> let
                                                            syn_m1 = synthesis knowledge m1 equations ctx opt
                                                            syn_m2 = synthesis knowledge m2 equations ctx opt
                                                        in foldset (\e1 es1 -> foldset (\e2 es2 -> Set.insert (NEKap e1 e2) es2) es1 syn_m2) base syn_m1
                                        NEFun m1@(_,f) m2 -> let
                                                            syn_m1 = synthesis knowledge (id2NExpression f ctx) equations ctx opt
                                                            syn_m20 = synthesis knowledge m2 equations ctx opt
                                                            syn_m2 = Set.filter (\x -> case x of
                                                                                            NEVar _ _ -> arityOfNExpression m2 == 1       -- excludes variables if the arity of m2 is greater than 1 (nr of parameters of the function)
                                                                                            _ -> True) syn_m20
                                                        in foldset (\_ es1 -> foldset (\e2 es2 -> Set.insert (NEFun m1 e2) es2) es1 syn_m2) base syn_m1
                                        NEXor m1 m2 -> let
                                                            syn_m1 = synthesis knowledge m1 equations ctx opt
                                                            syn_m2 = synthesis knowledge m2 equations ctx opt
                                                        in foldset (\e1 es1 -> foldset (\e2 es2 -> Set.insert (NEXor e1 e2) es2) es1 syn_m2) base syn_m1
                                        e -> error ("unexpected term as this stage: " ++ show e)


projOp :: ExpressionSet ->  [NExpression] -> [(NExpression, ExpressionSet)]
-- projOp e xs | trace ("projOp\n\te: " ++ show e ++ "\n\txs: " ++ show xs) False = undefined
projOp _ [] = error "error: length of tuple is 0"                                                                
projOp e xs = map (\x -> (snd x, Set.map (\e1 -> NEProj (fst x) l e1) e)) pairs
              where 
                    l = length xs
                    pairs = zip [1..l] xs

analysisStep :: KnowledgeMap -> NEquations -> JContext -> AnBxOnP -> (KnowledgeMap,KnowledgeMap)
-- analysisStep k _ _ _ | trace ("analysisStep\n\tk: " ++ showKnowledgeMap k) False = undefined
analysisStep k equations ctx opt = Map.foldrWithKey (\msg e (ak,newk) ->
                                                        case msg of
                                                        NECat [x] -> (knAdd x e ak equations ctx opt, knAdd x e newk equations ctx opt)
                                                        NECat xs -> let
                                                                        projections = projOp e xs
                                                                        add myk = foldr (\(m,ex) k -> knAdd m ex k equations ctx opt) myk projections
                                                                    in (add ak, add newk)
                                                                    -- in error ("\n\tlist: " ++ show list ++ "\n\tak: "++ show (add ak) ++ "\n\tnewk: " ++ show (add newk))                 
                                                        NEEnc m n -> case inSynthesis k (inverseNExpression n) equations ctx opt of
                                                                                        Nothing -> (knAdd msg e ak equations ctx opt,newk)
                                                                                        Just f -> let add myk = knAdd m (Set.map (\e1 -> NEDec e1 f) e) myk equations ctx opt in (add ak, add newk)
                                                        NESign m n -> case inSynthesis k (inverseNExpression n) equations ctx opt of
                                                                                        Nothing -> (knAdd msg e ak equations ctx opt,newk)
                                                                                        Just f -> let add myk = knAdd m (Set.map (\e1 -> NEVerify e1 f) e) myk equations ctx opt in (add ak, add newk)
                                                        NEEncS m n -> case inSynthesis k (inverseNExpression n) equations ctx opt of
                                                                                        Nothing -> (knAdd msg e ak equations ctx opt,newk)
                                                                                        Just f -> let add myk = knAdd m (Set.map (\e1 -> NEDecS e1 f) e) myk equations ctx opt in (add ak, add newk)
                                                        -- allow to retrieve x if y is known - xor(xor(x,y),y) = x
                                                        NEXor m n -> case inSynthesis k m equations ctx opt of
                                                                            Nothing -> case inSynthesis k n equations ctx opt of
                                                                                            Nothing -> (knAdd msg e ak equations ctx opt,newk)
                                                                                            Just e_n -> let add myk = knAdd m (Set.map (\e1 -> NEXor e1 e_n) e) myk equations ctx opt in (add ak, add newk)
                                                                            Just e_m -> case inSynthesis k n equations ctx opt of
                                                                                            Nothing -> let add myk = knAdd n (Set.map (\e1 -> NEXor e1 e_m) e) myk equations ctx opt in (add ak, add newk)
                                                                                            Just _ -> (knAdd msg e ak equations ctx opt, newk)
                                                        _  -> (knAdd msg e ak equations ctx opt,newk)
                                                        )  (Map.empty,Map.empty) k

analysis :: KnowledgeMap -> NEquations -> JContext -> AnBxOnP -> KnowledgeMap
-- analysis k | trace ("analysis\n\tk: " ++ showKnowledgeMap k) False = undefined
analysis k = auxa k k

auxa :: KnowledgeMap -> KnowledgeMap -> NEquations -> JContext -> AnBxOnP-> KnowledgeMap
-- auxa ana_k ana_n_k _ _ _ | trace ("auxa\n\tana_k: " ++ show ana_k ++ "\n\tana_n_k: " ++ show ana_n_k) False = undefined
auxa ana_k ana_n_k equations ctx opt = let
                                            (ak,newk) = analysisStep ana_n_k equations ctx opt
                                       in if Map.null newk then ana_k else auxa (Map.unionWith Set.union ana_k newk) ak equations ctx opt

{- enleve les paires et les messages cryptes enc(M,N) tel que N et inverse(N) soient connus -}
{- si k est analyse, on n'enleve donc rien a la synthese -}

-- reduce the knowledge set 
reduce :: KnowledgeMap -> NEquations -> JContext -> AnBxOnP -> KnowledgeMap
-- reduce k _ _ _ | trace ("reduce\n\tk: " ++ showKnowledgeMap k) False = undefined
reduce k equations ctx opt = Map.filterWithKey (\m _ -> case m of
                                        NECat _ -> False
                                        NEEnc _ n -> case inSynthesis k n equations ctx opt of
                                                                Nothing -> True
                                                                (Just _) -> case inSynthesis k (inverseNExpression n) equations ctx opt of
                                                                                        Nothing -> True
                                                                                        (Just _) -> False
                                        NESign _ n -> case inSynthesis k n equations ctx opt of
                                                                Nothing -> True
                                                                (Just _) -> case inSynthesis k (inverseNExpression n) equations ctx opt of
                                                                                        Nothing -> True
                                                                                        (Just _) -> False
                                        NEEncS _ n -> case inSynthesis k n equations ctx opt of
                                                                Nothing -> True
                                                                (Just _) -> case inSynthesis k (inverseNExpression n) equations ctx opt of
                                                                                        Nothing -> True
                                                                                        (Just _) -> False
                                        _ -> True) k

irr :: KnowledgeMap -> NEquations -> JContext -> AnBxOnP -> KnowledgeMap
-- irr k _ _ _ | trace ("irr\n\tk: " ++ showKnowledgeMap k) False = undefined
irr k equations ctx opt = let irr_k = Map.filterWithKey (\m _ ->
                                  case m of
                                    NEName _ -> True
                                    NECat[] -> True
                                    NECat [m] -> case inSynthesis k m equations ctx opt of
                                                            Nothing -> True
                                                            (Just _) -> False
                                    NECat(x:xs) -> case inSynthesis k x equations ctx opt of
                                                                Nothing -> True
                                                                (Just _) -> case inSynthesis k (NECat xs) equations ctx opt of
                                                                                        Nothing -> True
                                                                                        (Just _) -> False
                                    NEEnc m n -> case inSynthesis k m equations ctx opt of
                                                                Nothing -> True
                                                                (Just _) -> case inSynthesis k n equations ctx opt of
                                                                                        Nothing -> True
                                                                                        (Just _) -> False
                                    NESign m n -> case inSynthesis k m equations ctx opt of
                                                                Nothing -> True
                                                                (Just _) -> case inSynthesis k n equations ctx opt of
                                                                                        Nothing -> True
                                                                                        (Just _) -> False
                                    NEEncS m n -> case inSynthesis k m equations ctx opt of
                                                                Nothing -> True
                                                                (Just _) -> case inSynthesis k n equations ctx opt of
                                                                                        Nothing -> True
                                                                                        (Just _) -> False
                                    NEPub m@(NEFun (_,pk) m2) _ | exprIsAgent m2 && isPKFun pk -> case inSynthesis k m equations ctx opt of
                                                                                                                    Nothing -> True
                                                                                                                    (Just _) -> not (isPKFun pk) && error ("error in irr of msg: " ++ show m)
                                                                | otherwise -> True
                                    -- "atomic" keys cannot be reduced
                                    NEPub _ _ -> True
                                    NEPriv _ _ -> True
                                    NEHash m -> case inSynthesis k m equations ctx opt of
                                                            Nothing -> True
                                                            (Just _) -> False
                                    NEHmac m n -> case inSynthesis k m equations ctx opt of
                                                                Nothing -> True
                                                                (Just _) -> case inSynthesis k n equations ctx opt of
                                                                                        Nothing -> True
                                                                                        (Just _) -> False
                                    NEKap m n -> case inSynthesis k m equations ctx opt of
                                                                Nothing -> True
                                                                (Just _) -> case inSynthesis k n equations ctx opt of
                                                                                        Nothing -> True
                                                                                        (Just _) -> False
                                    NEKas m n -> case inSynthesis k m equations ctx opt of
                                                                Nothing -> True
                                                                (Just _) -> case inSynthesis k n equations ctx opt of
                                                                                        Nothing -> True
                                                                                        (Just _) -> False
                                    NEFun (_,f) n -> case inSynthesis k (id2NExpression f ctx) equations ctx opt of
                                                                Nothing -> True
                                                                (Just _) -> case inSynthesis k n equations ctx opt of
                                                                                        Nothing -> True
                                                                                        (Just _) -> False
                                    NEXor m n -> case inSynthesis k m equations ctx opt of
                                                                Nothing -> True
                                                                (Just _) -> case inSynthesis k n equations ctx opt of
                                                                                        Nothing -> True
                                                                                        (Just _) -> False
                                    e ->  error ("no irr for " ++ show e)) k
        in irr_k

irreducibles :: KnowledgeMap -> NEquations -> JContext -> AnBxOnP -> KnowledgeMap
-- irreducibles k _ _ _ | trace ("irreducibles\n\tk: " ++ showKnowledgeMap k) False = undefined
irreducibles k equations ctx opt = irr (analysis k equations ctx opt) equations ctx opt

-- returns the chosen expression first, the other one second
choixExpression :: NExpression -> NExpression -> (NExpression,NExpression)
-- choixExpression e f | trace ("choixExpression\n\te: " ++ show e ++ "\n\tf: " ++ show f) False = undefined
choixExpression e f = case (exprIsMessage e,exprIsMessage f) of
                                        (True,False) -> (e,f)
                                        (False,True) -> (f,e)
                                        _ -> case (exprContainsVar e,exprContainsVar f) of
                                                            (False,True) -> (e,f)
                                                            (True,False) -> (f,e)
                                                            _ -> if sizeOfNExpression e < sizeOfNExpression f then (e,f) else (f,e)

rep :: KnowledgeMap -> NEquations -> JContext -> AnBxOnP -> KnowledgeMap
-- rep k | trace ("rep\n\tk: " ++ showKnowledgeMap k) False = undefined
rep k = auxrep Map.empty k

auxrep :: KnowledgeMap -> KnowledgeMap -> NEquations -> JContext -> AnBxOnP -> KnowledgeMap
-- auxrep rep_k k _ _ _ | trace ("auxrep\n\trep_k: " ++ showKnowledgeMap rep_k ++ "\n\tknowledge: " ++ showKnowledgeMap k) False = undefined
auxrep rep_k k equations ctx opt = if Map.null k then rep_k
                                else let
                                        ((m,e),k1) = Map.deleteFindMin k
                                        (oneex,exs) = Set.deleteFindMin e
                                        e1 = Set.singleton (foldset (\candex currex -> fst(choixExpression currex candex)) oneex exs)
                                     in auxrep (knAdd m e1 rep_k equations ctx opt) k1 equations ctx opt


mkEq :: NExpression -> NExpression -> Bool -> Atom           -- bool = may fail
-- mkEq e f mf | trace ("mkEq\n\te: " ++ show e ++ "\n\tf: " ++ show f ++ "\n\tmf: " ++ show mf) False = undefined
mkEq e f mf | e == f = FWff e
            | otherwise = let
                              o = choixExpression e f
                          in FEq (fst o,snd o,mf)

mkInv :: NExpression -> NExpression -> Atom
-- mkInv e f | trace ("mkInv\n\te: " ++ show e ++ "\n\tf: " ++ show f) False = undefined
mkInv e f = FInv (choixExpression e f)

isSubExprOfAtom :: NExpression -> Atom -> Bool
-- isSubExprOfAtom e at | trace ("isSubExprOfAtom\n\te: " ++ show e ++ "\n\tat: " ++ show at) False = undefined
isSubExprOfAtom e (FWff f) = isSubExpr e f
isSubExprOfAtom e (FEq (f1,f2,_)) = isSubExpr e f1 || isSubExpr e f2
isSubExprOfAtom e (FInv (f1,f2)) = isSubExpr e f1 || isSubExpr e f2
isSubExprOfAtom e (FNotEq (f1,f2)) = isSubExpr e f1 || isSubExpr e f2

atomImplWff :: NExpression -> Atom -> Bool
-- atomImplWff e at | trace ("atomImplWff\n\te: " ++ show e ++ "\n\tat: " ++ show at) False = undefined
atomImplWff (NEProj _ n e) at = any (\x -> isSubExprOfAtom (NEProj x n e) at) [1..n]            -- any projection allows to test the well-formedness of e
atomImplWff e at  = isSubExprOfAtom e at

-- determine if an expression needs WFF check even if it's a message
-- Generalized: apply WFF check to any value that appears in a goal
needsWffCheck :: [NExpression] -> NExpression -> Bool
needsWffCheck goalExprs e =
    isGoalDep e goalExprs ||
    case e of
        NEPub _ _ -> True
        NEPriv _ _ -> True
        NEProj _ _ _ -> True
        NEDec _ _ -> True
        NEDecS _ _ -> True
        NEVerify _ _ -> True
        NEEnc e1 e2 -> needsWffCheck goalExprs e1 || needsWffCheck goalExprs e2
        NESign e1 e2 -> needsWffCheck goalExprs e1 || needsWffCheck goalExprs e2
        NEEncS e1 e2 -> needsWffCheck goalExprs e1 || needsWffCheck goalExprs e2
        NEName (_,name) -> "sk(" `isInfixOf` name || "inv(" `isInfixOf` name
        NEFun (_,fname) e' -> ("sk" == fname || "inv" == fname) || needsWffCheck goalExprs e'
        NECat es -> any (needsWffCheck goalExprs) es
        _ -> False

-- Helper: checks if the expression is one of the goal dependencies
isGoalDep :: NExpression -> [NExpression] -> Bool
isGoalDep e goalExprs = e `elem` goalExprs

{- simplifie les wff en ajoutant l'atome -}
simplAdd :: Atom -> AtomSet -> AtomSet
-- simplAdd at ats | trace ("simplAdd\n\tat: " ++ show at ++ "\n\tats: " ++ show ats) False = undefined
simplAdd at ats = Set.insert at (Set.filter (\x -> case x of
                                                        FWff e -> not (atomImplWff e at)
                                                        _ -> True ) ats)

{- renvoie True si on est sur que l'expression inverse doit etre identique -}
invIsSame :: NExpression -> Bool
-- invIsSame e | trace ("invIsSame\n\te: " ++ show e) False = undefined
invIsSame e = inverseNExpression e == e

{- ensemble des expressions egales -}
expressionEqual :: AtomSet -> NExpression -> ExpressionSet
-- expressionEqual ats e | trace ("expressionEqual\n\tats: " ++ show ats ++ "\n\te: " ++ show e) False = undefined
expressionEqual ats e =
  foldset (\at es ->
                  case at of
                    FWff f -> if f == e then Set.insert e es else es
                    FEq(f,g,_) -> if f == e || g == e then Set.insert f (Set.insert g es) else es
                    _ -> es)  Set.empty ats

{- on ajoute la simplification suivante: si on doit ajouter fst(e) = m et -}
{- que snd(e) = n est deja teste alors on remplace par e = <m,n> (m et n etant des messages) -}
pairSimpl :: [NExpression] -> NExpression -> NExpression -> NExpression -> (NExpression -> NExpression) -> Bool -> Atom -> AtomSet -> AtomSet
-- pairSimpl goalExprs e f _ _ _ _ _ | trace ("pairSimpl\n\te: " ++ show e ++ "\n\tf: " ++ show f) False = undefined
pairSimpl goalExprs e f opp_e pair_e mf at ats =
    if exprIsMessage f then
        let (ats_e,ats1) = Set.partition (\e -> case e of
                FEq(e1,e2,_) -> ((e1 == opp_e) && exprIsMessage e2) || ((e2 == opp_e) && exprIsMessage e1)
                _ -> False) ats
        in if Set.null ats_e then simplAdd at ats1
        else
            let
                at_e = setChoose ats_e
                g = case at_e of
                    FEq(e1,e2,_) -> if e1 == opp_e then e2 else e1
                    _ -> error ("pairSimpl - error in pair simplification:  " ++ show e ++ " " ++ show f)
            in addAtom goalExprs (FEq(e,pair_e g,mf)) ats1
    else simplAdd at ats

--{- ajoute un atome et simplifie legerement la formule resultante -}
addAtom :: [NExpression] -> Atom -> AtomSet -> AtomSet
-- addAtom goalExprs at ats | trace ("addAtom\n\tat: " ++ show at ++ "\n\tats: " ++ show ats) False = undefined
addAtom _ (FNotEq _) ats = ats
addAtom goalExprs at@(FWff e) ats
    | setExist (atomImplWff e) ats = ats
    | exprIsMessage e && not (needsWffCheck goalExprs e) = ats
    | otherwise = Set.insert at ats

addAtom goalExprs at@(FEq(e,f,mf)) ats =
    if e == f then addAtom goalExprs (FWff e) ats
    else
        case (e,f) of
            (NEProj  1 2 e',f') -> let
                    opp_e = NEProj 2 2 e'
                    pair_e g = NECat [f',g]
                in pairSimpl goalExprs e f opp_e pair_e mf at ats
            (f',NEProj 1 2 e') -> let
                    opp_e = NEProj 2 2 e'
                    pair_e g = NECat [f',g]
                in pairSimpl goalExprs e f opp_e pair_e mf at ats
            (NEProj 2 2 e',f')  -> let
                    opp_e = NEProj 1 2 e'
                    pair_e g = NECat [g,f']
                in pairSimpl goalExprs e f opp_e pair_e mf at ats
            (f',NEProj 2 2 e') -> let
                    opp_e = NEProj 1 2 e'
                    pair_e g = NECat [g,f']
                in pairSimpl goalExprs e f opp_e pair_e mf at ats
            _ -> simplAdd at ats

addAtom goalExprs at@(FInv(e,f)) ats =
    if e == f then
        if invIsSame e then addAtom goalExprs (mkEq e f False) ats
        else simplAdd at ats
    else
        case (e,f) of
            (NEPub g a,h) -> if Set.member (NEPriv g a) (expressionEqual ats h) then addAtom goalExprs (FWff g) ats else simplAdd at ats
            (h,NEPub g a) -> if Set.member (NEPriv g a) (expressionEqual ats h) then addAtom goalExprs (FWff g) ats else simplAdd at ats
            (NEPriv g a,h) -> if Set.member (NEPub g a) (expressionEqual ats h) then addAtom goalExprs (FWff g) ats else simplAdd at ats
            (h,NEPriv g a) -> if Set.member (NEPub g a) (expressionEqual ats h) then addAtom goalExprs (FWff g) ats else simplAdd at ats
            _-> simplAdd at ats

addAtomK :: [NExpression] -> NExpression -> Atom -> AtomSet -> AtomSet
-- addAtomK  goalExprs e at ats | trace ("addAtomK\n\te: " ++ show e ++ "\n\tat: " ++ show at ++ "\n\tats: " ++ show ats) False = undefined
addAtomK goalExprs e at ats = if isSubExprOfAtom e at then addAtom goalExprs at ats else ats

{- ici, on implemente la formule du papier mais on ne garde que les atomes qui contiennent e -}
{- on fait aussi un appel a reduce pour eviter les messages "inutiles" (paires, messages encryptes que l'on peut decrypter et reconstruire) -}
{- ca marche parce qu'on ne reduit pas e lors du calcul de l'analyse -}

addKnowledge :: [NExpression] -> (NExpression,NExpression) -> KnowledgeMap -> NEquations -> JContext -> AnBxOnP -> (KnowledgeMap,Formula)
-- addKnowledge goalExprs (m,e) k _ _ _ | trace ("addknowledge\n\t(m,e): " ++ show (m,e) ++ "\n\tknowledge: " ++ showKnowledgeMap k) False = undefined
addKnowledge goalExprs (m,e) k equations ctx opt
    = case Map.lookup m k of
        Just ex | Set.member e ex -> (k,FAnd Set.empty)
        _ -> let
            ak = let v = analysis (knAdd m (Set.singleton e) k equations ctx opt) equations ctx opt in trace ("[addKnowledge] ak (analysis result):\n" ++ showKnowledgeMap v) v
            phi = let v = formulas goalExprs ak equations ctx opt in trace ("[addKnowledge] phi (formulas result):\n" ++ show v) v
            k1 = let v = rep (irr ak equations ctx opt) equations ctx opt in trace ("[addKnowledge] k1 (final knowledge):\n" ++ showKnowledgeMap v) v
            in (k1,phi)

formulas :: [NExpression] -> KnowledgeMap -> NEquations -> JContext -> AnBxOnP -> Formula
-- formulas goalExprs ak _ _ _ | trace ("formulas\n\tak: " ++ showKnowledgeMap ak) False = undefined
formulas goalExprs ak equations ctx opt =
    let ats = form goalExprs Set.empty (reduce ak equations ctx opt) ak equations ctx opt
    in FAnd ats

form :: [NExpression] -> AtomSet -> KnowledgeMap -> KnowledgeMap -> NEquations -> JContext -> AnBxOnP -> AtomSet
-- form goalExprs ats k ak _ _ _ | trace ("form\n\tats: " ++ show ats ++ "\n\tknowledge: " ++ showKnowledgeMap k ++ "\n\tak: " ++ showKnowledgeMap ak) False = undefined
form goalExprs ats k ak equations ctx opt =
    if Map.null k then ats
    else
        let
            ((m,ex),k1) = Map.deleteFindMin k
            e = setChoose ex
            es = synthesis ak m equations ctx opt
            ats1 = foldset (\f ats' -> addAtomK goalExprs e (mkEq e f False) ats') ats es
            ats2 = formsub goalExprs m es ats1 ak equations ctx opt
        in form goalExprs ats2 k1 ak equations ctx opt

formsub :: [NExpression] -> NExpression -> ExpressionSet -> AtomSet -> KnowledgeMap -> NEquations  -> JContext -> AnBxOnP -> AtomSet
-- formsub goalExprs m es ats ak _ _ _ | trace ("formsub\n\tmessage: " ++ show m ++ "\n\tes: " ++ showExpressionSet es ++ "\n\tats: " ++ show ats ++ "\n\tak: " ++ showKnowledgeMap ak) False = undefined
formsub goalExprs m es ats ak equations ctx opt =
    let invm = inverseNExpression m in
    if m == invm then
        if Set.null es then ats
        else let e = chooseForInv es in addAtomK goalExprs e (mkInv e e) ats
    else
        let fs = synthesis ak invm equations ctx (opt {synthesistypeenc=(SynthesisTypeEnc {enc=False,encS=False})}) in
        if Set.null fs || Set.null es then ats
        else
            let e = chooseForInv es
                f = chooseForInv fs
            in addAtomK goalExprs e (mkInv e f) ats

chooseForInv :: ExpressionSet -> NExpression
-- chooseForInv es | trace ("chooseForInv\n\tes: " ++ showExpressionSet es) False = undefined
chooseForInv es = if not (Set.null es) then let
                                                (es1,es2) = Set.partition invIsSame es
                                            in if Set.null es1 then setChoose es2 else setChoose es1
                                       else error "chooseForInv: null set"

{- les test inv(e,f) sont remplaces par des tests wff(dec(enc(g,e),f)) -}
{- ou g est soit une expression qui apparait dans un wff -}
{- soit, si il n'existe pas de tel g, un nom de <e,f> -}

removeInv :: AtomSet -> AtomSet
-- removeInv ats | trace ("removeInv ats\n\tats: " ++ show ats) False = undefined
removeInv ats = let
        (ats_wff,ats1) = Set.partition (\x -> case x of
                                                    FWff _ -> True
                                                    _ -> False) ats
        (ats_inv,ats_eq) = Set.partition (\x -> case x of
                                                    FInv _ -> True
                                                    _ -> False) ats1
        (ats_wff1,ats2) = foldset (\x y -> removeInvFun x y) (ats_wff,ats_eq) ats_inv
  in Set.union ats_wff1 ats2

-- used only when generating SPI - not really matters if Enc or EncS is used, using Enc/Dec with Nothing pk fun
removeInvFun :: Atom -> (AtomSet,AtomSet) -> (AtomSet,AtomSet)
-- removeInvFun at (ats1,ats2) | trace ("removeInvFun\n\tat: " ++ show at ++ "\n\tats1: " ++ show ats1 ++ "\tats2: " ++ show ats2) False = undefined
removeInvFun (FInv (e,f)) (ats_wff, ats_eq) =
    let (at1, ats_wff1) = 
            if Set.null ats_wff 
            then 
                let g = nameOrVarOf (NECat [e, f])
                in (FWff (NEDec (NEEnc g e) f), ats_wff)
            else 
                case setChoose ats_wff of
                    FWff g   -> let ats_wff2 = Set.delete (FWff g) ats_eq
                                in (FWff (NEDec (NEEnc g e) f), ats_wff2)
                    atom    -> error $ "removeInvFun - Unexpected pattern: " ++ show atom
    in (Set.insert at1 ats_wff1, ats_eq)

removeInvFun a _ = error ("error calling removeInvFun in Atom: " ++ show a)

knAdd :: NExpression -> ExpressionSet -> KnowledgeMap  -> NEquations -> JContext -> AnBxOnP -> KnowledgeMap
-- knAdd msg es knowledge equations _ _ | trace ("knAdd\n\tmsg: " ++ show msg ++ "\n\tknowledge: " ++ showKnowledgeMap knowledge ++ "\n\tes: " ++ showExpressionSet es  ++ "\n\tequations: " ++ show equations) False = undefined
knAdd msg es knowledge equations ctx opt = analysisStepEq k2 equations ctx opt
                                            where k1 = Map.insertWith Set.union msg es knowledge
                                                  k2 = case equations of
                                                            [] -> k1
                                                            _  -> normalizeKnowledge k1 equations --normalise only if there are equations


-- give one expression (if it exists) that can be used to synthesize m
inSynthesis :: KnowledgeMap -> NExpression -> NEquations  -> JContext -> AnBxOnP -> Maybe NExpression
-- inSynthesis knowledge msg equations _ _ | trace ("inSynthesis\n\tmsg: " ++ show msg ++ "\n\tknowledge: " ++ showKnowledgeMap knowledge ++ "\n\tequations: " ++ show equations ) False = undefined
inSynthesis knowledge msg equations ctx opt | not (exprIsMessage msg) = error (msgErrorContext msg "inSynthesis")
                                        | otherwise = case Map.lookup msg knowledge of
                                                            Just e -> Just (setChoose e)
                                                            Nothing -> inSynthesisSub knowledge msg equations ctx opt

subSynthesisTerm :: KnowledgeMap -> NExpression -> [NExpression] -> NEquations -> JContext -> AnBxOnP -> [NExpression]
-- subSynthesisTerm knowledge msg es equations _ _ | trace ("subSynthesisTerm\n\tmsg: " ++ show msg ++ "\n\tknowledge: " ++ showKnowledgeMap knowledge ++ "\n\tequations: " ++ show equations ++ "\n\tes: " ++ show es) False = undefined
subSynthesisTerm knowledge msg es equations ctx opt = map (changeInnerTerms msg) synthesizedSubtermsList
                                                  -- error (show synthesizedSubtermsList)  
                                                        where
                                                            synthesizedSubtermsList = foldr synthesizeAndAddTerm [[]] es
                                                            synthesizeAndAddTerm e replist = let
                                                                                                addRepresentation ret rep = foldl' (\a x -> (rep : x) : a) ret replist
                                                                                             in foldl' addRepresentation [] (inSynthesisSub knowledge e equations ctx opt)

-- compute an expression (if it exists) that can be used to synthesize msg
inSynthesisSub :: KnowledgeMap -> NExpression -> NEquations -> JContext -> AnBxOnP -> Maybe NExpression
-- inSynthesisSub knowledge msg equations _ _ | trace ("inSynthesisSub\n\tmsg: " ++ show msg ++ "\n\tknowledge: " ++ showKnowledgeMap knowledge ++ "\n\tequations: " ++ show equations) False = undefined
inSynthesisSub knowledge msg equations ctx opt  | not (exprIsMessage msg) = error (msgErrorContext msg "inSynthesisSub")
                                            | otherwise = if null list then Nothing else Just (minimum list)     -- we return just one element, this avoids performance issues
                                                            where
                                                                    -- encOption = synthesistypeenc opt
                                                                    list = concatMap representations (equationInstances msg equations)
                                                                    base t = maybe [] Set.toList (Map.lookup t knowledge)   -- base, term available in knowledge
                                                                    representations t = subSynthesis t ++ base t
                                                                    subSynthesis outer = case outer of
                                                                                    NEVar _ _ -> []
                                                                                    NEName _ -> []
                                                                                    NEPriv _ _ -> []
                                                                                    NECat [] -> []
                                                                                    NECat es -> subSynthesisTerm knowledge outer es equations ctx opt
                                                                                    NEEnc e1 e2 -> subSynthesisTerm knowledge outer [e1,e2] equations ctx opt
                                                                                    NESign e1 e2 -> subSynthesisTerm knowledge outer [e1,e2] equations ctx opt
                                                                                    -- if a term is encrypted with a DH key check for equivalent expression
                                                                                    NEEncS m n@(NEKas (NEKap g x) y) -> case inSynthesis knowledge n equations ctx opt of
                                                                                        Nothing -> case Map.lookup (NEEncS  m (NEKas (NEKap g y) x)) knowledge of
                                                                                                    Nothing -> []
                                                                                                    (Just e) -> Set.toList e
                                                                                        (Just f) -> case inSynthesis knowledge m equations ctx opt of
                                                                                                    Nothing -> []
                                                                                                    Just e_m -> [NEEncS e_m f]

                                                                                    NEEncS e1 e2 -> subSynthesisTerm knowledge outer [e1,e2] equations ctx opt
                                                                                    NEFun (_,f) xs -> case Map.lookup (id2NExpression f ctx) knowledge of
                                                                                                            Nothing -> []
                                                                                                            Just _ -> case xs of
                                                                                                                            NECat es -> subSynthesisTerm knowledge outer es equations ctx opt
                                                                                                                            _ -> subSynthesisTerm knowledge outer [xs] equations ctx opt
                                                                                    NEPub  e1 _  -> subSynthesisTerm knowledge outer [e1] equations ctx opt
                                                                                    NEHash e -> case Map.lookup (id2NExpression (show AnBxHash) ctx) knowledge of
                                                                                                            Nothing -> []
                                                                                                            Just _ -> subSynthesisTerm knowledge outer [e] equations ctx opt

                                                                                    -- if a term is hmac-ed with a DH key check for equivalent key expression
                                                                                    NEHmac  m n@(NEKas (NEKap  g x) y) -> case Map.lookup (id2NExpression (show AnBxHmac) ctx) knowledge of
                                                                                                Nothing -> []
                                                                                                Just _ -> case inSynthesis knowledge n equations ctx opt of
                                                                                                        Nothing -> case Map.lookup (NEHmac m (NEKas (NEKap g y) x)) knowledge of
                                                                                                                    Nothing -> []
                                                                                                                    (Just e) -> Set.toList e
                                                                                                        (Just f) -> case inSynthesis knowledge m equations ctx opt of
                                                                                                                    Nothing -> []
                                                                                                                    Just e_m -> [NEHmac e_m f]

                                                                                    NEHmac e1 e2 -> case Map.lookup (id2NExpression (show AnBxHmac) ctx) knowledge of
                                                                                                            Nothing -> []
                                                                                                            Just _ -> subSynthesisTerm knowledge outer [e1,e2] equations ctx opt

                                                                                    -- kas(kap(g,x),y) = kas(kap(g,y),x) --
                                                                                    -- hardcoded DH theory 

                                                                                    NEKas (NEKap g x) y -> case Map.lookup (NEKas (NEKap g y) x) knowledge of
                                                                                            Just e -> Set.toList e
                                                                                            Nothing -> case inSynthesis knowledge x equations ctx opt of
                                                                                                            Nothing -> case inSynthesis knowledge y equations ctx opt of
                                                                                                                            Nothing -> []
                                                                                                                            Just _ -> case inSynthesis knowledge (NEKas (NEKap g y) x) equations ctx opt of
                                                                                                                                                Nothing -> []
                                                                                                                                                Just em -> [em]
                                                                                                            Just e_x -> case inSynthesis knowledge (NEKap g y) equations ctx opt of
                                                                                                                                    Nothing -> []
                                                                                                                                    Just e_gy -> [NEKas e_gy e_x]

                                                                                    NEKas e1 e2 -> subSynthesisTerm knowledge outer [e1,e2] equations ctx opt
                                                                                    NEKap e1 e2 -> subSynthesisTerm knowledge outer [e1,e2] equations ctx opt

                                                                                    -- hardcoded XOR theory 
                                                                                    NEXor (NEXor m n) o -> case mXOrAssociative knowledge m n o equations ctx opt of   
                                                                                                                    Nothing -> []
                                                                                                                    Just e -> [e]
                                                                                    NEXor m (NEXor n o) -> case mXOrAssociative knowledge m n o equations ctx opt of      
                                                                                                                    Nothing -> []
                                                                                                                    Just e -> [e]   
                                                                                    NEXor m n -> if m==n then [neXorZero] else -- xor (x,x) = zero
                                                                                                    case Map.lookup (NEXor n m) knowledge of -- xor(x,y) = xor(y,x) if expression already exists (commutativity)
                                                                                                        Nothing -> case inSynthesis knowledge m equations ctx opt of
                                                                                                                            Nothing -> []
                                                                                                                            Just e_m -> case inSynthesis knowledge n equations ctx opt of
                                                                                                                                            Nothing -> []
                                                                                                                                            Just e_n -> if e_n==e_m then [neXorZero]       -- xor (x,x) = zero
                                                                                                                                                                    else if e_n==neXorZero then [e_m] -- xor(x,zero)  = x
                                                                                                                                                                    else if e_m==neXorZero then [e_n] -- xor(zero,y)  = y
                                                                                                                                                                    else [NEXor e_m e_n]
                                                                                                        Just e -> Set.toList e

                                                                                    NEDec e1 e2 -> subSynthesisTerm knowledge outer [e1,e2] equations ctx opt
                                                                                    NEVerify e1 e2 -> subSynthesisTerm knowledge outer [e1,e2] equations ctx opt
                                                                                    NEDecS e1 e2 -> subSynthesisTerm knowledge outer [e1,e2] equations ctx opt
                                                                                    NEProj _ _ e -> subSynthesisTerm knowledge outer [e] equations ctx opt

mXOrAssociative :: KnowledgeMap -> NExpression -> NExpression -> NExpression -> NEquations -> JContext -> AnBxOnP -> Maybe NExpression
-- mXOrAssociative k m n o equations _ _ | trace ("mXOrAssociative\n\tm: " ++ show m ++ "\n\tn: " ++ show n ++ "\n\to: " ++ show o ++ "\n\tknowledge: " ++ showKnowledgeMap k ++ "\n\tequations: " ++ show equations) False = undefined
mXOrAssociative k m n o equations ctx opt
  | m==n = -- xor(xor(x,x),y) = y && xor(x,xor(x,y)) = y
        inSynthesisSub k o equations ctx opt
  | n==o = -- xor(xor(x,y),y) = x && xor(x,xor(y,y)) = x
        inSynthesisSub k m equations ctx opt
  | m==o =  -- xor(xor(y,x),y) = x && xor(x,xor(y,x)) = y
        inSynthesisSub k n equations ctx opt
  | otherwise = case inSynthesis k o equations ctx opt of
                           Nothing -> case inSynthesis k (NEXor n o) equations ctx opt of        -- associativity
                                                 Nothing -> case inSynthesis k (NEXor m o) equations ctx opt of
                                                         Nothing -> Nothing
                                                         Just e_mo -> case inSynthesis k n equations ctx opt of
                                                                 Nothing -> Nothing
                                                                 Just e_n -> Just (NEXor e_mo e_n)
                                                 Just e_no -> case inSynthesis k m equations ctx opt of
                                                         Nothing -> Nothing
                                                         Just e_m -> Just (NEXor e_m e_no)

                           Just e_o -> case inSynthesis k (NEXor m n) equations ctx opt of
                                                 Nothing -> Nothing
                                                 Just e_nm -> Just (NEXor e_nm e_o)

--Theory Xor:
--  % Bitwise exclusive or.
--  Signature:
--    e/0, 
--    xor/2
--  Cancellation:
--    xor(xor(X1,X1),X2) = X2
--    xor(X1,X1) = e
--    xor(X1,e)  = X1
--  Topdec:
--  % xor is associative and commutative
--   topdec(xor,xor(T1,T2))=
--     [T1,T2]
--     [T2,T1]
--     if T1==xor(Z1,Z2){
--       [Z1,xor(Z2,T2)]
--       [xor(Z1,T2),Z2]
--       if T2==xor(Z3,Z4){
--         [xor(Z1,Z3),xor(Z2,Z4)]}}
--     if T2==xor(Z1,Z2){
--       [xor(T1,Z1),Z2]
--       [Z1,xor(T1,Z2)]}
--  Analysis:
--    decana(xor(X1,X2))= 
--      [X1]->[X2] 
--      %[xor(X1,X3)]->[xor(X2,X3)]

analysisStepEq :: KnowledgeMap -> NEquations -> JContext -> AnBxOnP -> KnowledgeMap
-- analysisStepEq knowledge equations _ _ | trace ("analysisStepEq\n\tknowledge: " ++ showKnowledgeMap knowledge ++ "\n\tequations: " ++ show equations ) False = undefined
analysisStepEq knowledge [] _ _ = knowledge
analysisStepEq knowledge equations ctx opt = foldl' deriveFromEquation knowledge equations
                                                where
                                                    deriveFromEquation res eq = let
                                                                                    (NEqt eq_left eq_right _) = eq
                                                                                    substitutions = findSubstitutions eq knowledge equations ctx opt
                                                                                    createRepresentations res sub =
                                                                                        let
                                                                                            exp = applySubstitution eq_right sub
                                                                                            representations = inSynthesisSub knowledge (applySubstitution eq_left sub) equations ctx opt
                                                                                        in foldl' (\k x -> case inSynthesis k exp equations ctx opt of
                                                                                                                    Nothing -> Map.insert exp (Set.singleton x) k
                                                                                                                    Just _ -> k) res representations
                                                                                        -- in foldl' (\k x -> addKnowledge k equations exp x opt) res representations
                                                                                 in foldl' createRepresentations res substitutions

changeInnerTerms :: NExpression -> [NExpression] -> NExpression
-- changeInnerTerms term e | trace ("changeInnerTerms\n\tterm: " ++ show term ++ "\n\te: " ++ show e) False = undefined
changeInnerTerms msg _ | not (exprIsMessage msg) = error (msgErrorContext msg "changeInnerTerms")
changeInnerTerms term [] = error ("changeInnerTerms: empty expression list in term " ++ show term)
changeInnerTerms term e = case term of
    NECat _ -> NECat e
    NEVar _ _ -> error "Variables do not contain inner terms"
    NEName _ -> error "Names do not contain inner terms"
    NEFun f _ -> case e of
                          [x] -> NEFun f x
                          _ -> NEFun f (NECat e)
    NEEncS _ _ -> case e of
                [x,y] -> NEEncS x y
                _ -> NEEncS (NECat x) y
                        where
                            y = last e
                            x = init e
    NEEnc _ _  -> case e of
            [x,y] -> NEEnc x y
            _ -> NEEnc (NECat x) y
                    where
                        y = last e
                        x = init e
    NESign _ _ -> case e of
            [x,y] -> NESign x y
            _ -> NESign (NECat x) y
                    where
                        y = last e
                        x = init e
    NEHmac _ _ -> case e of
                [x,y] -> NEHmac x y
                _ -> NEHmac (NECat x) y
                    where
                        y = last e
                        x = init e
    NEHash _ -> case e of
                    [x] -> NEHash x
                    _ -> NEHash (NECat e)
    NEPub (NEName _) Nothing -> case e of
                    [x] -> NEPub x Nothing
                    _ -> error ("changeInnerTerms - NEPub error in arity of expression: " ++ show term)
    NEPub _ a -> case e of
                    [x] -> NEPub x a
                    _ -> NEPub (NECat e) a
    NEKap _ _ -> case e of
                          [x,y] -> NEKap x y
                          _ -> error ("changeInnerTerms - NEKap error in arity of expression: " ++ show term)
    NEKas _ _ -> case e of
                          [x,y] -> NEKas x y
                          _ -> error ("changeInnerTerms - NEKas error in arity of expression: " ++ show term)
    NEXor _ _ -> case e of
                [x,y] -> NEXor x y
                _ -> error ("changeInnerTerms - NEXor error in arity of expression: " ++ show term)
    e -> error (msgUndefined e "changeInnerTerms")

equationInstances :: NExpression -> NEquations -> [NExpression]
-- equationInstances msg equations | trace ("equationInstances\n\tterm: " ++ show msg ++ "\n\tequations: " ++ show equations) False = undefined
equationInstances msg _ | not (exprIsMessage msg) = error (msgErrorContext msg "equationInstances")
equationInstances msg [] = [msg]
equationInstances msg equations = foldl' addEquationInstance [msg] equations
                                        where addEquationInstance a (NEqt left right _) =
                                                            case termUnification left Map.empty msg of
                                                                    Just s -> -- error ("eq instance:" ++ show s)
                                                                            if not (existNonsubstitutedParameter right s)
                                                                               then applySubstitution right s : a
                                                                               else if exprIsConstantMessage right then [right] else a     -- if the right hand side is a constant, substitute the left with the right
                                                                    _ -> a

existSubstitutedParameter :: NExpression -> Substitution -> Bool
-- existSubstitutedParameter term substitution | trace ("existSubstitutedParameter\n\tterm: " ++ show term ++ "\n\tsubstitution: " ++ show substitution) False = undefined
existSubstitutedParameter term substitution = existParameter term (\x -> Map.member x substitution)

existNonsubstitutedParameter :: NExpression -> Substitution -> Bool
-- existNonsubstitutedParameter term substitution | trace ("existNonsubstitutedParameter\n\tterm: " ++ show term ++ "\n\tsubstitution: " ++ show substitution) False = undefined
existNonsubstitutedParameter term substitution = existParameter term (\x -> not (Map.member x substitution))

applySubstitution :: NExpression -> Substitution -> NExpression
-- applySubstitution term substitution | trace ("applySubstitution\n\tterm: " ++ show term ++ "\n\tsubstitution: " ++ show substitution) False = undefined
applySubstitution term _ | not (exprIsMessage term) = error (msgErrorContext term "applySubstitution")
applySubstitution term substitution = case term of
                                            -- NEVar (_,x) ->
                                            --    case Map.lookup x substitution of
                                            --    Just t -> t
                                            --    Nothing -> NECat []
                                            NEName (_,x) ->
                                                case Map.lookup x substitution of
                                                Just t -> t
                                                Nothing -> NECat []
                                            NEFun _ (NECat es) ->
                                                let substitutedTerms = map (\e -> applySubstitution e substitution) es
                                                in changeInnerTerms term substitutedTerms
                                            NEFun _ es ->
                                                let substitutedTerms = map (\e -> applySubstitution e substitution) [es]
                                                in changeInnerTerms term substitutedTerms
                                            NECat es ->
                                                let substitutedTerms = map (\e -> applySubstitution e substitution) es
                                                in changeInnerTerms term substitutedTerms
                                            e -> error (msgUndefined e "applySubstitution")

sameOuterTerm :: NExpression -> NExpression -> Bool
-- sameOuterTerm term1 term2 | trace ("sameOuterTerm\n\tterm1: " ++ show term1 ++ "\n\tterm2: " ++ show term2) False = undefined
sameOuterTerm term1 term2 | not (exprIsMessage term1 && exprIsMessage term2) = error (msgErrorContext term1 "sameOuterTerm" ++ "\n" ++ msgErrorContext term2 "sameOuterTerm")
sameOuterTerm term1 term2 = case (term1, term2) of
                            (NEEnc {}, NEEnc {}) -> True
                            (NESign {}, NESign {}) -> True
                            (NEPub _ _, NEPub _ _) -> True
                            (NEEncS _ _, NEEncS _ _) -> True
                            (NECat _, NECat _) -> True
                            (NEHash _, NEHash _) -> True
                            (NEHmac _ _, NEHmac _ _) -> True
                            (NEKap _ _, NEKap _ _) -> True
                            (NEKas _ _, NEKas _ _) -> True
                            (NEFun (f1,_) _, NEFun (f2,_) _) -> f1 == f2
                            (NEXor _ _ , NEXor _ _) -> True
                            _ -> error (msgUndefined term1 "sameOuterTerm" ++ "\n" ++ msgUndefined term2 "sameOuterTerm")
                            -- _ -> False

existParameter :: NExpression -> (String -> Bool) -> Bool
-- existParameter term  _ | trace ("existParameter\n\tterm: " ++ show term) False = undefined
existParameter term _ | not (exprIsMessage term) = error (msgErrorContext term "existParameter")
existParameter term predicate = case term of
                                    -- NEVar (_,x) -> predicate x
                                    NEName (_,x) -> predicate x
                                    NEFun _ (NECat e) -> any (\x -> existParameter x predicate) e
                                    NEFun _ e -> existParameter e predicate
                                    NECat e -> any (\x -> existParameter x predicate) e
                                    e -> error (msgUndefined e "existParameter")

termUnification :: NExpression -> Substitution -> NExpression -> Maybe Substitution
-- termUnification term1 substitution term2 | trace ("termUnification\n\tterm1: " ++ show term1 ++ "\n\tterm2: " ++ show term2 ++ "\n\tsubstitution: " ++ show substitution) False = undefined
termUnification term1 _ term2 | not (exprIsMessage term1 && exprIsMessage term2) = error (msgErrorContext term1 "termUnification" ++ "\n" ++ msgErrorContext term2 "termUnification")
termUnification term1 substitution term2 = case (term1, term2) of
                                                -- (NEVar (_,x), _) -> if Map.member x substitution
                                                --                    then (if (substitution Map.! x) == term2 then Just substitution else Nothing)
                                                --                    else Just (Map.insert x term2 substitution)
                                                (NEName (_,x), _) -> if Map.member x substitution 
                                                                        then (if (substitution Map.! x) == term2 then Just substitution else Nothing)
                                                                        else if isVariable x || term1 == term2 then -- unification only if the name is a variable or if the two names are the same constant
                                                                                Just (Map.insert x term2 substitution) 
                                                                                else Nothing
                                                (NEFun _ e1, NEFun _ e2) -> if sameOuterTerm term1 term2 -- N.B sameOuterTermm tests function name is the same
                                                                                    then
                                                                                    let unifySubterms res x1 x2 =
                                                                                            case res of
                                                                                                Just s -> termUnification x1 s x2
                                                                                                Nothing -> Nothing
                                                                                        in let
                                                                                                zipExpr = case (e1,e2) of
                                                                                                                    ep@(NECat c1,NECat c2) -> if length c1 == length c2 then zip c1 c2 else error ("termUnification - wrong length: "  ++ show ep)
                                                                                                                    _ -> zip [e1] [e2]
                                                                                            in foldl' (\s (t1,t2) -> unifySubterms s t1 t2) (Just substitution) zipExpr
                                                                                            -- in error (show zipExpr)
                                                                                    else Nothing
                                                (NECat e1, NECat e2) -> if sameOuterTerm term1 term2
                                                                            then
                                                                            let unifySubterms res x1 x2 =
                                                                                    case res of
                                                                                        Just s -> termUnification x1 s x2
                                                                                        Nothing -> Nothing
                                                                            in foldl' (\s (t1,t2) -> unifySubterms s t1 t2) (Just substitution) (zip e1 e2)
                                                                            else Nothing
                                                (_,_) -> Nothing
                                                -- e -> error (msgUndefined term1 "termUnification" ++ "\n" ++ msgUndefined term2 "termUnification") 

findSubstitutions :: NEquation -> KnowledgeMap -> NEquations -> JContext -> AnBxOnP -> [Substitution]
-- findSubstitutions equation knowledge equations _ | trace ("findSubstitutions\n\tequation: " ++ show equation ++"\n\tknowledge: " ++ showKnowledgeMap knowledge  ++ "\n\tequations: " ++ show equations) False = undefined
findSubstitutions equation knowledge equations ctx opt = Map.foldrWithKey (\k es sub -> concatMap (\_ -> addSubstitutions k sub) es) [] knowledge
                                                            where
                                                                (NEqt eqLeft _ _) = equation
                                                                addSatisfiedSubstitution a s = satisfySubstitution eqLeft s knowledge equations ctx opt ++ a
                                                                addSubstitutions term a = foldl' addSatisfiedSubstitution a (termFit term equation)

termFit :: NExpression -> NEquation -> [Substitution]
-- termFit term eq | trace ("termFit\n\tterm: " ++ show term ++ "\n\teq: " ++ show eq) False = undefined
termFit term _ | not (exprIsMessage term) = error (msgErrorContext term "termFit")
termFit term (NEqt left right _) = termFit' term left
                                    where
                                        termFit' :: NExpression -> NExpression -> [Substitution]
                                        termFit' term left = case left of
                                                                    -- NEVar _ -> []
                                                                    NEName _ -> []
                                                                    NEFun _ es ->
                                                                        case termUnification left Map.empty term of
                                                                        Just s -> [s | not (existNonsubstitutedParameter right s)]
                                                                        Nothing -> foldl' (\res e -> res ++ termFit' term e) [] (case es of
                                                                                                                                    NECat xs -> xs
                                                                                                                                    _ -> [es])
                                                                    NECat es ->
                                                                        case termUnification left Map.empty term of
                                                                        Just s -> [s | not (existNonsubstitutedParameter right s)]
                                                                        Nothing -> foldl' (\res e -> res ++ termFit' term e) [] es
                                                                    e ->  error (msgUndefined e "termFit")

satisfySubstitution :: NExpression -> Substitution -> KnowledgeMap -> NEquations -> JContext -> AnBxOnP -> [Substitution]
-- satisfySubstitution term substitution knowledge equations _ | trace ("satisfySubstitution\n\tterm: " ++ show term  ++ "\n\tsubstitution: " ++ show substitution ++ "\n\tknowledge: " ++ showKnowledgeMap knowledge ++ "\n\tequations: " ++ show equations) False = undefined
satisfySubstitution term _ _ _ _ _ | not (exprIsMessage term) = error (msgErrorContext term "satisfySubstitution")
satisfySubstitution term substitution knowledge equations ctx opt = satisfySubstitution' [] [term] substitution
                                                                    where
                                                                        termSubs = knowledgeSubstitutions term substitution knowledge equations ctx opt
                                                                        termSub termlist ignoredterms = let
                                                                                                            satisfyTermSub res sub = satisfySubstitution' termlist ignoredterms sub ++ res
                                                                                                        in foldl' satisfyTermSub [] termSubs
                                                                        satisfySubstitution' termlist ignoredterms sub =
                                                                                case termlist of
                                                                                [] -> [sub]
                                                                                (term : terms) -> case term of
                                                                                                        NEFun _ (NECat es) ->
                                                                                                            let subtermSub = satisfySubstitution' (es ++ terms) ignoredterms sub
                                                                                                            in if null subtermSub then termSub (ignoredterms ++ terms) [] else subtermSub
                                                                                                        NEFun _ es ->
                                                                                                            let subtermSub = satisfySubstitution' (es : terms) ignoredterms sub
                                                                                                            in if null subtermSub then termSub (ignoredterms ++ terms) [] else subtermSub
                                                                                                        NECat es ->
                                                                                                            let subtermSub = satisfySubstitution' (es ++ terms) ignoredterms sub
                                                                                                            in if null subtermSub then termSub (ignoredterms ++ terms) [] else subtermSub
                                                                                                        NEName (_,x) ->
                                                                                                            if Map.member x substitution
                                                                                                            then termSub terms ignoredterms
                                                                                                            else satisfySubstitution' terms (term : ignoredterms) sub
                                                                                                        -- NEVar (_,x) ->
                                                                                                        --    if Map.member x substitution
                                                                                                        --    then termSub terms ignoredterms
                                                                                                        --    else satisfySubstitution' terms (term : ignoredterms) sub
                                                                                                        e -> error (msgUndefined e "satisfySubstitution")

knowledgeSubstitutions :: NExpression -> Substitution -> KnowledgeMap -> NEquations -> JContext -> AnBxOnP -> [Substitution]
-- knowledgeSubstitutions term substitution knowledge equations _ | trace ("knowledgeSubstitutions\n\tterm: " ++ show term  ++ "\n\tsubstitution: " ++ show substitution ++ "\n\tknowledge: " ++ showKnowledgeMap knowledge ++ "\n\tequations: " ++ show equations) False = undefined
knowledgeSubstitutions term _ _ _ _ _ | not (exprIsMessage term) = error (msgErrorContext term "knowledgeSubstitutions")
knowledgeSubstitutions term substitution knowledge equations ctx opt =
                                                                case term of
                                                                    NEName (_,x) -> case inSynthesis knowledge (substitution Map.! x ) equations ctx opt of
                                                                                        Just _ -> [substitution | Map.member x substitution]
                                                                                        Nothing -> []
                                                                    _ -> let unifyWithKnowledge k _ a =
                                                                                case termUnification term substitution k of
                                                                                    Nothing -> a
                                                                                    Just m -> m : a
                                                                        in Map.foldrWithKey unifyWithKnowledge [] knowledge

-- productOfList :: [a] -> [a]
productOfList :: (Show (t1 (t2 a)), Foldable t1, Foldable t2) => t1 (t2 a) -> [[a]]
-- productOfList list | trace ("productOfList\n\tlist: " ++ show list) False = undefined
productOfList list = let addListToProduct elist result =
                            let
                                addElementToProduct ret e = foldl' (\a x -> (e:x):a) ret result
                            in foldl' addElementToProduct [] elist
                     in foldr addListToProduct [[]] list


subTermVariants :: NExpression -> [NExpression] -> NEquations -> [NExpression]
-- subTermVariants term es equations | trace ("termVariants\n\tterm: " ++ show term  ++ "\n\tes: " ++ show es ++ "\n\tequations: " ++ show equations) False = undefined
subTermVariants term _ _ | not (exprIsMessage term) = error (msgErrorContext term "subTermVariants")
subTermVariants term es equations = map (changeInnerTerms term) synthesizedSubtermsList
                                where synthesizedSubtermsList = productOfList (map (termVariants equations) es)


termVariants :: [NEquation] -> NExpression -> [NExpression]
-- termVariants equations term | trace ("termVariants\n\tterm: " ++ show term  ++ "\n\tequations: " ++ show equations) False = undefined
termVariants _ term | not (exprIsMessage term) = error (msgErrorContext term "termVariants)")
termVariants [] term = [term]
termVariants equations term = nubOrd (equationInstances term equations ++ expressions)
                                    where expressions = case term of
                                                        -- NEVar _ -> []
                                                        NEName _ -> []
                                                        NEPriv _ _ -> []
                                                        NECat es -> subTermVariants term es equations
                                                        NEEnc e1 e2 -> subTermVariants term [e1,e2] equations
                                                        NESign e1 e2 -> subTermVariants term [e1,e2] equations
                                                        NEEncS e1 e2 -> subTermVariants term [e1,e2] equations
                                                        NEFun _ es -> case es of
                                                                        NECat xs -> subTermVariants term xs equations
                                                                        _ -> subTermVariants term [es] equations
                                                        NEPub  e1 _  -> subTermVariants term [e1] equations
                                                        NEHash e -> subTermVariants term [e] equations
                                                        NEHmac e1 e2 -> subTermVariants term [e1,e2] equations
                                                        NEKas e1 e2 -> subTermVariants term [e1,e2] equations
                                                        NEKap e1 e2 -> subTermVariants term [e1,e2] equations
                                                        NEXor e1 e2 -> subTermVariants term [e1,e2] equations
                                                        NEDec e1 e2 -> subTermVariants term [e1,e2] equations
                                                        NEVerify e1 e2 -> subTermVariants term [e1,e2] equations
                                                        NEDecS e1 e2 -> subTermVariants term [e1,e2] equations
                                                        NEProj _ _ e -> subTermVariants term [e] equations
                                                        -- _ -> []
                                                        _  -> error (msgUndefined term "termVariants")

normalizeTerm :: NExpression -> NEquations -> ExpressionSet
-- normalizeTerm term equations | trace ("normalizeTerm\n\tterm: " ++ show term  ++ "\n\tequations: " ++ show equations) False = undefined
normalizeTerm term _ | not (exprIsMessage term) = error (msgErrorContext term "normalizeTerm")
normalizeTerm term equations = normalizeTerm' (Set.singleton term)
                                    where normalizeTerm' terms = let
                                                                    newTerms = foldr Set.insert Set.empty (concatMap (termVariants equations) (Set.elems terms))
                                                                 in if terms == newTerms then newTerms else normalizeTerm' newTerms

addNormalizedTerms :: NExpression -> ExpressionSet -> KnowledgeMap -> NEquations -> KnowledgeMap
-- addNormalizedTerms term rep knowledge equations | trace ("addNormalizedTerms\n\tterm: " ++ show term++ "\n\tknowledge: " ++ showKnowledgeMap knowledge ++ "\n\trep: " ++ show rep  ++ "\n\tequations: " ++ show equations) False = undefined
addNormalizedTerms term _ _ _ | not (exprIsMessage term) = error (msgErrorContext term "addNormalizedTerms")
addNormalizedTerms term rep knowledge equations = foldr (\t acc -> if Map.member t acc then acc else Map.insert t rep acc) knowledge (normalizeTerm term equations)

normalizeKnowledge :: KnowledgeMap -> NEquations -> KnowledgeMap
-- normalizeKnowledge knowledge equations | trace ("normalizeKnowledge\n\tknowledge: " ++ showKnowledgeMap knowledge  ++ "\n\tequations: " ++ show equations) False = undefined
normalizeKnowledge knowledge [] = knowledge
normalizeKnowledge knowledge equations = Map.foldrWithKey (\k v acc -> addNormalizedTerms k v acc equations) Map.empty knowledge

