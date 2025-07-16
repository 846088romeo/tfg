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

module AnB2NExecnarr where

import AnB2NExpression
  ( Execnarr,
    Fact (Seen),
    NAction (..),
    NExecnarr,
    showExecnarr,
    showNExecnarr,
    stepOfNAction,
    varName, printMapSK, trEquations
  )
import AnB2Spyer (trAnB2ExecnarrKnowledge, trAnB2Spyer)
import AnBxMsgCommon (Ident, ProtType(..))
import AnBxOnP
  ( AnBxOnP
      ( anbxouttype,
        basicopt,
        checkOptLevel,
        checkType,
        do_opt,
        filterFailingChecks,
        maxActionsOpt,
        optimize, anbtypecheck,
        anbxmitm
      ),
    CheckOptLevel (CheckOptLevel0, CheckOptLevel3, CheckOptLevel4),
    CheckType (CheckAll, CheckEq, CheckNone, CheckOpt, CheckOptFail),
    OutType,
    isOutTypeJava,
    isOutTypePV,
  )
import Data.List (nubBy, sort, (\\), union)
import Data.Containers.ListUtils (nubOrd)
import qualified Data.Set as Set
import Debug.Trace ()
import Spyer_Ast ( showNarration, Declaration (..))
import Spyer_Execnarr (execnarrOfProt, knowOfProt,mergeHonestAndTraceExecNarrs)
import Spyer_Message (Formula (FSingle, FAnd), Atom (FEq, FInv, FNotEq, FWff), AtomSet)
import Spyer_Spi (showSpiOfExecnarr)
import AnBTypeChecking (typeCheckProtocol)


import Debug.Trace
import Java_TypeSystem_Context
import Java_TypeSystem_JType
import AnBAst
import Java_TypeSystem_Evaluator (typeofTS)

--  translation Spyer -> NExecnarr

trNExecnarrActionsTuple :: Execnarr -> AnBxOnP -> Execnarr
trNExecnarrActionsTuple xs options = concatMap (\x -> trNExecnarrActionTuple x options) xs

-- translate from pair -> proj --
trNExecnarrActionTuple :: NAction -> AnBxOnP -> Execnarr
-- trNExecnarrActionTuple a _ | trace ("trNExecnarrActionTuple\n\taction " ++ show a) False = undefined
-- trNExecnarrActionTuple a@(NACheck (_, _, FSingle _)) _ = error ("no single check expected at this stage - action: " ++ show a)
trNExecnarrActionTuple (NACheck (step, agent, FAnd phi)) options = map (\x -> NACheck (step, agent, FSingle x)) (filterChecks phi options) -- flatten the list of lists
trNExecnarrActionTuple a _ = [a]

mayFail :: [Atom] -> OutType -> Bool -> [Atom]
-- mayFail ats out | trace ("mayFail\n\tatoms " ++ show ats ++ "\n\tout: " ++ show out) False = undefined
mayFail ats out filterFailingChecks = map (\x -> mayFailCheckAtom x out filterFailingChecks) ats

mayFailCheckAtom :: Atom -> OutType -> Bool -> Atom
-- mayFailCheckAtom a | trace ("mayFailCheckAtom\n\tatoms " ++ show a) False = undefined
mayFailCheckAtom (FEq (e1@(NEEnc {}), e2, _)) _ _ = FEq (e1, e2, True)
mayFailCheckAtom (FEq (e1@(NESign {}), e2, _)) _ _ = FEq (e1, e2, True)
mayFailCheckAtom (FEq (e1@(NEEncS _ _ ), e2, _)) _ _ = FEq (e1, e2, True)
mayFailCheckAtom (FEq (e1, e2@(NEEnc {}), _)) _ _ = FEq (e1, e2, True)
mayFailCheckAtom (FEq (e1, e2@(NESign {}), _)) _ _ = FEq (e1, e2, True)
mayFailCheckAtom (FEq (e1, e2@(NEEncS _ _), _)) _ _ = FEq (e1, e2, True)
mayFailCheckAtom (FEq (e1@(NEHash m1), e2@(NEHash m2), _)) out filterFailingChecks = FEq (e1, e2, failingSubExpr m1 out filterFailingChecks || failingSubExpr m2 out filterFailingChecks)
mayFailCheckAtom (FEq (e1@(NEHmac m1 k1), e2@(NEHmac m2 k2), _)) out filterFailingChecks = FEq (e1, e2, failingSubExpr m1 out filterFailingChecks || failingSubExpr m2 out filterFailingChecks || failingSubExpr k1 out filterFailingChecks || failingSubExpr k2 out filterFailingChecks )
mayFailCheckAtom (FEq (e1@(NEFun f1 m1), e2@(NEFun f2 m2), _)) out filterFailingChecks | f1==f2 = FEq (e1, e2, failingSubExpr m1 out filterFailingChecks || failingSubExpr m2 out filterFailingChecks)

-- mayFailCheckAtom (FEq (e1@(NEProj (i, _, m1)), e2, _)) out filterFailingChecks = FEq (e1, e2, failingSubExpr m1 out filterFailingChecks || failingSubExpr e2 out filterFailingChecks)

mayFailCheckAtom (FEq (e1, e2, _)) out filterFailingChecks = FEq (e1, e2, failingSubExpr e1 out filterFailingChecks || failingSubExpr e2 out filterFailingChecks)
mayFailCheckAtom e _ _ = e

-- checks if expressions involving encryption are going to fail due to randomising/salting
-- just a sanity check, it does not detect all failing expressions (depends on variables)
failingSubExpr :: NExpression -> OutType -> Bool -> Bool
-- failingSubExpr e | trace ("failingSubExpr\n\texpr " ++ show e) False = undefined
failingSubExpr e out ffc =
  let isCheckFailing = isOutTypeJava out || (ffc && not (isOutTypePV out)) -- checks are filtered for Java or if flag is explicit but not ProVerif
  -- isCheckFailing = isOutTypeJava out || ffc
   in case e of
        (NEVar _ n) -> False -- failingSubExpr n out ffc   -- at this stage the only variables are the received messages
        (NEName _) -> False
        (NEEnc m n) -> isCheckFailing || (failingSubExpr m out ffc || failingSubExpr n out ffc) -- encryption randomisation
        (NESign m n) -> isCheckFailing || (failingSubExpr m out ffc || failingSubExpr n out ffc) -- encryption randomisation
        (NEEncS m n) -> isCheckFailing || (failingSubExpr m out ffc || failingSubExpr n out ffc) -- encryption randomisation
        (NEDec m n) -> failingSubExpr m out ffc || failingSubExpr n out ffc
        (NEVerify m n) -> failingSubExpr m out ffc || failingSubExpr n out ffc
        (NEDecS m n) -> failingSubExpr m out ffc || failingSubExpr n out ffc
        (NEPub _ _) -> False
        (NEPriv _ _) -> False
        (NEHash m) -> failingSubExpr m out ffc
        (NEHmac m n) -> failingSubExpr m out ffc || failingSubExpr n out ffc
        (NEKap _ _) -> False
        (NEKas _ _) -> False
        (NEXor m n) -> failingSubExpr m out ffc || failingSubExpr n out ffc
        (NEFun _ n) -> failingSubExpr n out ffc
        (NECat []) -> False
        (NECat [x]) -> failingSubExpr x out ffc
        (NECat xs) -> any (\x -> failingSubExpr x out ffc) xs
        (NEProj i _ m) -> case m of
          NECat ys -> if length ys > i then failingSubExpr (ys !! i) out ffc else error ("NEProj - index: " ++ show i ++ " length: " ++ show (length ys))
          _ -> failingSubExpr m out ffc

-- filters checks based  on command line parameter
filterChecks :: AtomSet -> AnBxOnP -> [Atom]
-- filterChecks phi _ | trace ("filterChecks\n\tatoms: " ++ show phi) False = undefined
filterChecks phi options = case checkType options of
  CheckAll -> chkList
  CheckEq -> [x | x@(FEq _) <- chkList]
  CheckOptFail -> cleanChecks chkList False
  CheckOpt -> cleanChecks chkList True
  CheckNone -> []
  where
    chkList = mayFail (Set.toList phi) out ffc
    out = anbxouttype options
    ffc = filterFailingChecks options

-- pre-optimisation cleanup step

cleanChecks :: [Atom] -> Bool -> [Atom]
-- cleanChecks phi _ | trace ("cleanChecks\n\tatoms: " ++ show phi) False = undefined
cleanChecks [] _ = []
cleanChecks (x : xs) mf = cleanCheck x mf ++ cleanChecks xs mf

cleanCheck :: Atom -> Bool -> [Atom]
-- cleanCheck a _ | trace ("cleanCheck\n\tatom: " ++ show a) False = undefined
cleanCheck x@(FInv (NEPub e1 _, NEPriv e2 _)) _ = [x | e1 /= e2] -- remove inv(Pub x/Priv x) checks
cleanCheck x@(FInv (NEPriv e1 _, NEPub e2 _)) _ = [x | e1 /= e2] -- remove inv(Priv x/Pub x) checks
cleanCheck (FEq (_, _, True)) True = [] -- remove failing EqCheck
cleanCheck x@(FInv (NEVar e1 _, NEVar e2 _)) _ = [x | e1 /= e2] -- remove inv check on variable names
cleanCheck x _ = [x]

-- post optimisation checks - capture variable assignments
semplifyChecks :: NAction -> Bool
-- semplifyChecks a | trace ("semplifyChecks\n\taction: " ++ show a) False = undefined
semplifyChecks (NACheck (_, _, FSingle (FInv (NEVar v1 _, NEVar v2 _)))) = v1 /= v2
semplifyChecks (NACheck (_, _, FSingle (FEq (NEVar v1 _, NEVar v2 _, _)))) = v1 /= v2
semplifyChecks _ = True

-- move the new actions just before the first usage in emit

trExecnarrNewActOpt :: Execnarr -> JContext -> Execnarr
-- trExecnarrNewActOpt (x:_) |  trace ("trExecnarrNewActOpt\n\tactions[1]: " ++ show x) False = undefined
trExecnarrNewActOpt [] _ = []
trExecnarrNewActOpt acts ctx = fixNewActions acts (mapnewEmit acts ctx)

fixNewActions :: Execnarr -> [(NAction, NAction)] -> Execnarr
-- fixNewActions (x:_) maps | trace ("fixNewActions\n\tactions[1]: " ++ show x ++ "\n\tmaps: " ++ show maps) False = undefined
fixNewActions [] _ = []
-- fixNewActions x [] = x
fixNewActions (x : xs) maps = case x of
  NANew _ -> fixNewActions xs maps
  NAGoal (step,_,_,_,_,_,_,_) -> ordNew step x xs maps
  NAEmit (step,_,_,_, _) -> ordNew step x xs maps
  NAEmitReplay (step, _, _, _, _) -> ordNew step x xs maps
  _ -> x : fixNewActions xs maps


ordNew :: Int -> NAction -> Execnarr -> [(NAction, NAction)] -> [NAction]
-- ordNew step x xs maps | trace ("ordNew\n\taction: " ++ show x ++ "\n\tmaps: " ++ show maps) False = undefined
ordNew step x xs maps =
    let emits = [snd z | z <- maps]
        -- Collect NANew actions related to the current action
        newacts = if x `elem` emits then getNewKeyActions x step maps ++ [x] else [x]
        -- Remove processed mappings
        newmaps = if x `elem` emits then [z | z <- maps, snd z /= x] else maps
    in newacts ++ fixNewActions xs newmaps

getNewKeyActions :: NAction -> Int -> [(NAction, NAction)] -> Execnarr
-- getNewKeyActions a _ maps | trace ("getNewKeyActions\n\t" ++ "action: " ++ show a ++ "\n\t" ++ "maps: " ++ show maps) False = undefined
getNewKeyActions _ _ [] = []
getNewKeyActions a step ((NANew (_, agent, ident), act) : xs)
                                    | a == act  = NANew (step, agent, ident) : getNewKeyActions a step xs
                                    | otherwise = getNewKeyActions a step xs
getNewKeyActions a _ _ = error ("Unexpected action: NANew mapping not found " ++ show a)

mapnewEmit :: Execnarr -> JContext ->[(NAction, NAction)]
-- mapnewEmit (x:_) |  trace ("mapnewEmit\n\tactions[1]: " ++ show x) False = undefined
mapnewEmit [] _ = []
mapnewEmit (x : xs) ctx = case x of
  NANew _ -> occursName x xs ctx ++ mapnewEmit xs ctx
  _ -> mapnewEmit xs ctx

occursName :: NAction -> Execnarr -> JContext -> [(NAction, NAction)]
-- occursName a xs  | trace ("occursName\n\t" ++ "action: " ++ show a ) False = undefined
occursName _ [] _ = []  
occursName a@(NANew (_, agent, ident)) (a1 : xs) ctx = case a1 of -- use isSubExpr, not CSE version, as it must detect fresh names!
                                                        NAGoal (_, agent1, _, _, expr, _, _, _) | agent == agent1 && isSubExpr (NEName ident) expr -> [(a, a1)]
                                                        NAEmit (_,agent1,_, _, expr) | agent == agent1 && isSubExpr (NEName ident) expr -> [(a, a1)]
                                                        NAEmitReplay (_,agent1,_, _, expr) | agent == agent1 && isSubExpr (NEName ident) expr -> [(a, a1)]
                                                        _ -> occursName a xs ctx
occursName _ _ _ = []

-- apply variable subst

trVarsAction :: NAction -> Execnarr -> AnBxOnP -> JContext -> (Execnarr, Execnarr)
-- trVarsAction a actions@(x:_) _ | trace ("trVarsAction\n\taction: " ++ show a ++ "\n\tactions[1]: " ++ show x) False = undefined
trVarsAction a@(NAEmit (step, agent,_, _,expr)) xs options ctx = trVarsActionExpr a xs step agent [expr] options ctx -- emit checks for subexpressions in the sent messages
trVarsAction a@(NAEmitReplay (step, agent,_, _,expr)) xs options ctx = trVarsActionExpr a xs step agent [expr] options ctx -- emit replay checks for subexpressions in the sent messages
trVarsAction a@(NACheck (step, agent, FSingle (FEq (expr1, expr2, _)))) xs options ctx = trVarsActionExpr a xs step agent [expr1, expr2] options ctx
trVarsAction a@(NACheck (step, agent, FSingle (FInv (expr1, expr2)))) xs options ctx = trVarsActionExpr a xs step agent [expr1, expr2] options ctx
trVarsAction a@(NACheck (step, agent, FSingle (FNotEq (expr1, expr2)))) xs options ctx = trVarsActionExpr a xs step agent [expr1, expr2] options ctx
trVarsAction a@(NACheck (step, agent, FSingle (FWff expr))) xs options ctx = trVarsActionExpr a xs step agent [expr] options ctx
trVarsAction a@(NACheck (_, _, FAnd _)) _ _  _= error ("FAnd checks unexpected at this stage" ++ show a)
trVarsAction a@(NAReceive (step,agent,_, x)) xs _ ctx = let     
                                                                    vars = [(step, agent, varName agent x, x)]
                                                                    a1 = substVars [a] vars ctx
                                                                    as1 = substVars xs vars ctx
                                                                in (a1, as1)
trVarsAction a@(NAGoal (step, agent, Seen, _, expr, _, _, _)) xs options ctx = trVarsActionExpr a xs step agent [expr] options ctx
trVarsAction a xs _ _ = ([a], xs)

-- prune unused var mappings
usedVarMappings :: VarMappings -> VarMappings
usedVarMappings xs = [x | x <- xs, isVarMappingUsed x (xs \\ [x])]

-- check if a var mapping is used
isVarMappingUsed :: VarMapping -> VarMappings -> Bool
isVarMappingUsed (_, _, _, expr) xs =
  let exprs = [e | (_, _, _, e) <- xs]
   in any (\x -> isSubExprCSE expr x) exprs

trVarsActionExpr :: NAction -> Execnarr -> Int -> Ident -> [NExpression] -> AnBxOnP -> JContext -> (Execnarr, Execnarr)
-- trVarsActionExpr a actions@(x:_) _ _ _ _ _ | trace ("trVarsAction2Expr\n\taction: " ++ show a ++ "\n\tactions[1]: " ++ show x) False = undefined
trVarsActionExpr act actions step agent xs options ctx =
  let optlevel = checkOptLevel options
      -- check current action
      vars1 = concatMap (\x -> substVarMappings (usedVarMappings . sort $ nubBy eqCand (findVars step agent x [act] optlevel)) ctx) xs
      -- check subsequent actions
      vars2 = concatMap (\x -> findVars step agent x actions optlevel) xs
      -- merge variables
      vars = mergeVarMappings [vars1, vars2] ctx
      assign_stats = map (\(_, _, v, e) -> NAAssign (step, agent, v, e)) vars
      a1 = substVars [act] vars ctx
      as1 = substVars actions vars ctx
   in (assign_stats ++ a1, as1)

-- in error (show vars1 ++ "\n" ++ show vars2 ++ "\n" ++ show vars)

-- optimise assign actions order

-- find if an assign statement has a depending (sub) assignments
findDepAssignAction :: NAction -> (Execnarr, Execnarr) -> (Execnarr, Maybe NAction, Execnarr)
-- findDepAssignAction a (_,x:_) | trace ("findDepAssignAction\n\taction: " ++ show a ++ "\n\txs2: " ++ show (x)) False = undefined
findDepAssignAction a (xs, []) = (a : xs, Nothing, [])
findDepAssignAction a@(NAAssign (_, agent, _, expr)) (acts, x : xs) = case x of
  (NAAssign (step1, agent1, var1, expr1)) ->
    if agent == agent1 && expr /= expr1 && isSubExprCSE expr1 expr
      then
        let st = if null acts then step1 else stepOfNAction (head acts)
         in (acts, Just (NAAssign (st, agent1, var1, expr1)), xs)
      else findDepAssignAction a (acts ++ [x], xs)
  _ -> findDepAssignAction a (acts ++ [x], xs)
findDepAssignAction a _ = error ("findDepAssignAction - unexpected action: " ++ show a)

trAssignAction :: NAction -> Execnarr -> JContext -> (Execnarr, Execnarr)
-- trAssignAction a (x:_) _ | trace ("trAssignAction\n\taction: " ++ show a ++ "\n\tactions[1]: " ++ show x) False = undefined
trAssignAction a@(NAAssign (_, agent, var, expr)) (x : xs) ctx =
  let (act1, ad, act2) = findDepAssignAction a ([], x : xs)
   in case ad of
        Just a1@(NAAssign (s, a, v, e)) -> ([a1, NAAssign (stepOfNAction x, agent, var, substExpr expr (s, a, v, e) ctx)], act1 ++ act2)
        _ ->
          let (act1, act2) = trAssignAction x xs ctx
           in (NAAssign (stepOfNAction x, agent, var, expr) : act1, act2)
trAssignAction a (x : xs) ctx =
  let (act1, act2) = trAssignAction x xs ctx
   in (a : act1, act2)
trAssignAction a [] _ = ([a], [])

-- opt eq checks 3rd step
-- replace expr with var if check is ok

trEqCheckOpt :: NAction -> Execnarr -> JContext -> Execnarr
-- trEqCheckOpt a (x:_) _ | trace ("trEqCheckOpt\n\taction: " ++ show a ++ "\n\tactions[1]: " ++ show x) False = undefined
-- if the equality check is successful, we can replace directly the expressions with the variable
-- this is applied to check that may not fail
trEqCheckOpt a@(NACheck (step, agent, FSingle (FEq (NEVar (_,v) _, e, False)))) xs ctx = a : substVarEq xs (step, agent, v, e) ctx
trEqCheckOpt a@(NACheck (step, agent, FSingle (FEq (e, NEVar (_,v) _, False)))) xs ctx = a : substVarEq xs (step, agent, v, e) ctx
trEqCheckOpt a xs _ = a : xs

substVarEq :: Execnarr -> VarMapping -> JContext -> Execnarr
-- substVarEq actions@(x:xs) var _ | trace ("substVarEq\n\tactions[1]: " ++ show x ++ "\n\tvar: " ++ show var) False = undefined
substVarEq [] _ _ = []
substVarEq (x : xs) mp@(step, agent, _, _) ctx = case x of
  NACheck (s, a, FSingle at) ->
    if (a == agent) && (s == step)
      then
        let at1 = case at of
              FEq (e1, e2, mf) -> FEq (substExprEq e1 mp ctx, substExprEq e2 mp ctx, mf)
              _ -> at
         in NACheck (step, agent, FSingle at1) : substVarEq xs mp ctx
      else x : substVarEq xs mp ctx
  _ -> x : substVarEq xs mp ctx

substExprEq :: NExpression -> VarMapping -> JContext -> NExpression
-- substExprEq f (_,a,v,e) | trace ("substExprEq\n\tvar: " ++ show v ++ "\n\texpr1: " ++ show e ++ "\n\texpr2: " ++ show f) False = undefined
substExprEq f mp@(_, _, v, e) ctx =
  if e == f
    then NEVar (typeofTS e ctx,v) e
    else case f of
      NEEnc f1 f2 -> NEEnc (substExprEq f1 mp ctx) (substExprEq f2 mp ctx)
      NESign f1 f2 -> NESign (substExprEq f1 mp ctx) (substExprEq f2 mp ctx)
      NEEncS f1 f2 -> NEEncS (substExprEq f1 mp ctx) (substExprEq f2 mp ctx)
      NEDec f1 f2 -> NEDec (substExprEq f1 mp ctx) (substExprEq f2 mp ctx)
      NEVerify f1 f2 -> NEVerify (substExprEq f1 mp ctx) (substExprEq f2 mp ctx) 
      NEDecS f1 f2 -> NEDecS (substExprEq f1 mp ctx) (substExprEq f2 mp ctx)
      NECat xs -> NECat (map (\x -> substExprEq x mp ctx) xs)
      NEProj idx n f -> NEProj idx n (substExprEq f mp ctx)
      NEPub f a -> NEPub (substExprEq f mp ctx) a
      NEPriv f a -> NEPriv (substExprEq f mp ctx) a
      NEHash f -> NEHash (substExprEq f mp ctx)
      NEHmac f1 f2 -> NEHmac (substExprEq f1 mp ctx) (substExprEq f2 mp ctx)
      NEKap f1 f2 -> NEKap (substExprEq f1 mp ctx) (substExprEq f2 mp ctx)
      NEKas f1 f2 -> NEKas (substExprEq f1 mp ctx) (substExprEq f2 mp ctx)
      NEFun f1 f2 -> NEFun f1 (substExprEq f2 mp ctx)
      NEXor f1 f2 -> NEXor (substExprEq f1 mp ctx) (substExprEq f2 mp ctx)
      _ -> f

type VarMappings = [VarMapping]
type VarMapping = (Int, String, String, NExpression) -- (step,agent,var,expr)

mergeVarMappings :: [VarMappings] -> JContext ->  VarMappings
-- mergeVarMappings xs _ | trace ("mergeVarMappings\n\tVarMappings: " ++ show xs) False = undefined
mergeVarMappings xs ctx = substVarMappings vars ctx
  where
    vars = sort (nubBy eqCand (concat xs))

eqCand :: VarMapping -> VarMapping -> Bool
eqCand (_, a1, v1, _) (_, a2, v2, _) = a1 == a2 && v1 == v2

substVarMappings :: VarMappings -> JContext -> VarMappings
substVarMappings [] _ = []
substVarMappings [x] _ = [x]
substVarMappings (x : xs) ctx = x : substVarMappings (map (\(iy, ay, vy, ey) -> (iy, ay, vy, substExpr ey x ctx)) xs) ctx

showMapping :: VarMapping -> String
showMapping (step, agent, var, expr) = "(" ++ show step ++ show agent ++ "," ++ show var ++ "," ++ show expr ++ ")"

showMappings :: VarMappings -> String
showMappings [] = ""
showMappings [x] = "[" ++ showMapping x ++ "]"
showMappings (x : xs) = "[" ++ showMapping x ++ "," ++ showMappings xs ++ "]"

-- find vars which are used in the following actions
findVars :: Int -> String -> NExpression -> Execnarr -> CheckOptLevel -> VarMappings
-- findVars step agent expr (x:_) _ | trace ("findVars\n\tstep:" ++ show step ++ "\n\tagent: " ++ show agent ++ "\n\texpr: " ++ show expr ++ "\n\tactions[1]: " ++ show x) False = undefined
findVars _ _ _ [] _ = []
findVars _ _ (NEVar _ _) _ _ = []
findVars _ _ (NEName _) _ _ = []
findVars _ _ (NEPub _ _) _ _ = []
findVars _ _ (NEPriv _ _) _ _ = []
findVars _ _ (NEKap _ _) _ _ = []
findVars _ _ (NEKas _ _) _ _ = []
findVars step agent (NECat xs) actions optlevel =
  let res = concatMap (\x -> findVars step agent x actions optlevel) xs
   in sort (nubBy eqCand res)
findVars step agent expr actions optlevel =
  let candidate = (step, agent, varName agent expr, expr) -- check the entire expression
   in if substVarOccurs actions candidate optlevel
        then [candidate] -- error ("candidate: " ++ show candidate)
        else case expr of
          (NEEnc e1 e2) -> findVars step agent e1 actions optlevel ++ findVars step agent e2 actions optlevel
          (NESign e1 e2) -> findVars step agent e1 actions optlevel ++ findVars step agent e2 actions optlevel
          (NEEncS e1 e2) -> findVars step agent e1 actions optlevel ++ findVars step agent e2 actions optlevel
          (NEDec e1 e2) -> findVars step agent e1 actions optlevel ++ findVars step agent e2 actions optlevel
          (NEVerify e1 e2) -> findVars step agent e1 actions optlevel ++ findVars step agent e2 actions optlevel
          (NEDecS e1 e2) -> findVars step agent e1 actions optlevel ++ findVars step agent e2 actions optlevel
          (NEHash e) -> findVars step agent e actions optlevel
          (NEHmac e1 e2) -> findVars step agent e1 actions optlevel ++ findVars step agent e2 actions optlevel
          (NEFun _ e2) -> findVars step agent e2 actions optlevel
          (NEXor e1 e2) -> findVars step agent e1 actions optlevel ++ findVars step agent e2 actions optlevel
          (NEProj _ _ e) -> findVars step agent e actions optlevel

substVars :: Execnarr -> VarMappings ->  JContext -> Execnarr
-- substVars (x:_) vars _ | trace ("substVars\n\tactions[1]: " ++ show x ++ "\n\tvars: " ++ show vars) False = undefined
substVars [] _ _ = []
substVars actions [] _ = actions
substVars actions [x] ctx = substVar actions x ctx
substVars actions (x : xs) ctx = substVars (substVar actions x ctx) xs ctx

substVar :: Execnarr -> VarMapping -> JContext -> Execnarr
-- substVar (x:_) var _ | trace ("substVar\n\tactions[1]: " ++ show x ++ "\n\tvar: " ++ show var) False = undefined
substVar [] _ _ = []
substVar (x : xs) mp@(_, agent, _, _) ctx = case x of
  NAEmit (step,ag,ch,be,e) -> (if ag == agent then [NAEmit (step, ag,ch,be,substExpr e mp ctx)] else [x]) ++ substVar xs mp ctx
  NAEmitReplay (step,ag,ch,be,e) -> (if ag == agent then [NAEmitReplay (step, ag,ch,be,substExpr e mp ctx)] else [x]) ++ substVar xs mp ctx
  NAReceive (step,ag,ch,e) -> (if ag == agent then [NAReceive (step,ag,ch,substExpr e mp ctx)] else [x]) ++ substVar xs mp ctx
  NACheck (step, a, FSingle at) ->
    ( if a == agent
        then
          let at1 = case at of
                FWff e -> FWff (substExpr e mp ctx)
                FEq (e1, e2, mf) -> FEq (substExpr e1 mp ctx, substExpr e2 mp ctx, mf)
                FInv (e1, e2) -> FInv (substExpr e1 mp ctx, substExpr e2 mp ctx)
                FNotEq (e1, e2) -> FInv (substExpr e1 mp ctx, substExpr e2 mp ctx)
           in [NACheck (step, agent, FSingle at1)]
        else [x]
    )
      ++ substVar xs mp ctx
  NAGoal (s, a, fact, label, e, agsexpr, b, es) -> (if a == agent then [NAGoal (s, a, fact, label, substExpr e mp ctx, map (\(ag, exp) -> (ag, substExpr exp mp ctx)) agsexpr, b, es)] else [x]) ++ substVar xs mp ctx
  _ -> x : substVar xs mp ctx

substExpr :: NExpression -> VarMapping -> JContext -> NExpression
-- substExpr f (_,a,v,e) _ | trace ("substExpr\n\tvar: " ++ show v ++ "\n\texpr1: " ++ show e ++ "\n\texpr2: " ++ show f) False = undefined
substExpr f mp@(_, _, v, e) ctx =
  if e == f -- EVar (v,e)
    then case f of
      NEVar (t,_) ev -> NEVar (t,v) ev
      NEName (t,_) -> NEVar (t,v) e
      _ -> NEVar (t,v) e  -- generic type used
                    where t = typeofTS e ctx
    else case f of
      NEEnc f1 f2 -> NEEnc (substExprEq f1 mp ctx) (substExprEq f2 mp ctx)
      NESign f1 f2 -> NESign (substExprEq f1 mp ctx) (substExprEq f2 mp ctx)
      NEEncS f1 f2 -> NEEncS (substExprEq f1 mp ctx) (substExprEq f2 mp ctx)
      NEDec f1 f2 -> NEDec (substExprEq f1 mp ctx) (substExprEq f2 mp ctx)
      NEVerify f1 f2 -> NEVerify (substExprEq f1 mp ctx) (substExprEq f2 mp ctx)
      NEDecS f1 f2 -> NEDecS (substExprEq f1 mp ctx) (substExprEq f2 mp ctx)
      NECat xs -> NECat (map (\x -> substExpr x mp ctx) xs)
      NEProj idx n f -> NEProj idx n (substExpr f mp ctx)
      NEPub f a -> NEPub (substExpr f mp ctx) a
      NEPriv f a -> NEPriv (substExpr f mp ctx) a
      NEHash f -> NEHash (substExpr f mp ctx)
      NEHmac f1 f2 -> NEHmac (substExprEq f1 mp ctx) (substExprEq f2 mp ctx)
      NEKap f1 f2 -> NEKap (substExprEq f1 mp ctx) (substExprEq f2 mp ctx)
      NEKas f1 f2 -> NEKas (substExprEq f1 mp ctx) (substExprEq f2 mp ctx)
      NEFun f1 f2 -> NEFun f1 (substExprEq f2 mp ctx)
      NEXor f1 f2 -> NEXor (substExprEq f1 mp ctx) (substExprEq f2 mp ctx)
      _ -> f

substVarOccurs :: Execnarr -> VarMapping -> CheckOptLevel -> Bool
-- substVarOccurs actions@(x:xs) var _ | trace ("substVarOccurs\n\tactions[1]: " ++ show x ++ "\n\tvar: " ++ show var) False = undefined
substVarOccurs [] _ _ = False
substVarOccurs (x : xs) mp@(_, agent, _, expr) optlevel | optlevel == CheckOptLevel3 || optlevel == CheckOptLevel4 = case x of
  NAEmit (_,a,_, _, e) -> ((a == agent) && isSubExprCSE expr e) || substVarOccurs xs mp optlevel
  NAEmitReplay (_,a,_, _, e) -> ((a == agent) && isSubExprCSE expr e) || substVarOccurs xs mp optlevel
  -- NAReceive (_,_,a,_,e) -> if (a==agent) && (isSubExprCSE expr e) then True  else substVarOccurs xs mp optlevel
  NACheck (_, a, FSingle at) ->
    ((a == agent)
    && (case at of
           FWff e -> isSubExprCSE expr e
           FEq (e1, e2, _) -> isSubExprCSE expr e1 || isSubExprCSE expr e2
           FInv (e1, e2) -> isSubExprCSE expr e1 || isSubExprCSE expr e2
           FNotEq (e1, e2) -> isSubExprCSE expr e1 || isSubExprCSE expr e2
       )) || substVarOccurs xs mp optlevel
  _ -> substVarOccurs xs mp optlevel
substVarOccurs (_ : xs) mp CheckOptLevel0 = substVarOccurs xs mp CheckOptLevel0
substVarOccurs (x : xs) mp _ = substVarOccurs (x : xs) mp CheckOptLevel3

nrofActions :: Execnarr -> AnBxOnP -> Int
-- nrofActions (a:_) _ | trace ("nrofActions\n\texpr: " ++ show a) False = undefined
-- we need to count actions expanding the checks (one action for every check component)
nrofActions [] _ = 0
nrofActions [a] options = case a of
  NACheck (_, _, FAnd atoms) -> length (filterChecks atoms options)
  NAComment _ -> 0
  NAGoal _ -> 0
  _ -> 1
nrofActions (a : aa) options = nrofActions [a] options + nrofActions aa options

-- optimisation passes

-- compute the variable substitutions
trNVExecnarrOptPass1 :: Execnarr -> AnBxOnP -> JContext -> Execnarr
-- trNVExecnarrOptPass1 xs _ ctx | trace ("trNVExecnarrOptPass1\n\tactions: " ++ show xs) False = undefined
trNVExecnarrOptPass1 [] _ _ = []
trNVExecnarrOptPass1 [x] _ _ = [x] -- no opt needed
trNVExecnarrOptPass1 (x : xs) options ctx = as1 ++ trNVExecnarrOptPass1 as2 options ctx
  where
    (as1, as2) = trVarsAction x xs options ctx

-- reorder a variable assignment
trNVExecnarrOptPass2 :: Execnarr -> JContext -> Execnarr
-- trNVExecnarrOptPass2 xs _ | trace ("trNVExecnarrOptPass2\n\tactions: " ++ show xs) False = undefined
trNVExecnarrOptPass2 [] _ = []
trNVExecnarrOptPass2 [x] _ = [x]
trNVExecnarrOptPass2 (x : xs) ctx = as1 ++ trNVExecnarrOptPass2 as2 ctx
  where
    (as1, as2) = trAssignAction x xs ctx

-- clean up duplicated checks
trNVExecnarrOptPass3 :: Execnarr -> JContext -> Execnarr
-- trNVExecnarrOptPass3 xs | trace ("trNVExecnarrOptPass3\n\tactions: " ++ show xs) False = undefined
trNVExecnarrOptPass3 [] _ = []
trNVExecnarrOptPass3 [x] _ = [x]
trNVExecnarrOptPass3 (x : xs) ctx = nubOrd acts2 -- some clean up must be done in order to get rid of duplicated checks
  where
    acts2 = foldr (\a aa -> trEqCheckOpt a aa ctx) [] (x : xs) 
     -- replace expression, with variable if check successful

-- translate only (with typechecking)
trProt2Execnarr :: Protocol -> OFMCAttackImpersonationsAndProt -> AnBxOnP -> Execnarr
trProt2Execnarr origprot trImpsAndProt options =
  case trImpsAndProt of
    Just (imps,trprot,trActsIdx,toprint) -> execnarrOfProt origprot (Just (imps,checkProt trprot,trActsIdx,toprint)) options
    Nothing -> execnarrOfProt (checkProt origprot) Nothing options
  where
    -- type checks AnB protocol before translating to Execnarr
      checkProt prot = if anbtypecheck options then typeCheckProtocol prot PTAnB else prot

-- translate and optimise
trProt2NExecnarr :: Protocol -> OFMCAttackImpersonationsAndProt-> AnBxOnP -> NExecnarr
trProt2NExecnarr prot@((name,_), types, _,anbequations,_, shares, _, _, _) intrProt options =
  let
      ctx = buildJContext prot -- PTAnB
      -- check if optimisation can be applied and updates options
      options1 = options {do_opt = optimize options && nrofActions ex options <= maxActionsOpt options}
      prot1 = if anbtypecheck options1 then typeCheckProtocol prot PTAnB else prot
      equations = trEquations anbequations types ctx
      (decl,ex,ctx2) = let
                         declsWithoutIntrValues = trAnB2ExecnarrKnowledge prot1 ctx options1
                         passiveIntrNarr = execnarrOfProt prot1 Nothing options1
                       in case intrProt of
                           Just (_,(trname,trtypes,trdefs,treqs,trkn,trsh,trabs,tracts,goals),trActsIdx,intrMsgToPrint) ->
                                  let
                                    intrName = anbxmitm options
                                    trProt = (trname,trtypes,trdefs,treqs,trkn,union trsh shares, trabs, tracts,goals)
                                    trCtx = buildJContext trProt
                                    trDecls = trAnB2ExecnarrKnowledge trProt trCtx options1
                                    narrWithIntrActions = mergeHonestAndTraceExecNarrs passiveIntrNarr trProt trActsIdx intrMsgToPrint options1
                                  in (filter (\decl -> case decl of
                                                        DKnow ((_,a),_) -> a==intrName
                                                        DGenerates ((_,a),_) -> a==intrName
                                                        DShare (_,_,_,nags) -> elem intrName ags
                                                                where ags = [ id | (_,id) <- nags]
                                             ) trDecls
                                       ++ declsWithoutIntrValues,
                                     narrWithIntrActions,trCtx)
                           Nothing -> (declsWithoutIntrValues, passiveIntrNarr,ctx)

      ex1 = trExecnarrNewActOpt ex ctx2
      ex2 = trNExecnarrActionsTuple ex1 options1 -- Checks: FAnd -> FSingle 
      execnarr =
        if do_opt options1
          then
            let acts1 = trNVExecnarrOptPass1 ex2 options1 ctx2
                acts2 = trNVExecnarrOptPass2 acts1 ctx2
                -- subst of successful eqcheck involving vars, if agent is not "basicopt"
                acts3 = if basicopt options then acts2 else trNVExecnarrOptPass3 acts2 ctx2
                acts4 = filter semplifyChecks acts3 -- post optimisation check clean up
             in acts4
          else ex2
   in ((name, decl, equations),execnarr)

------------------------------------------------------------------------------------------------------------------------------------------

-- debug/print

protName :: Protocol -> String
protName ((name,_),_,_,_,_,_,_,_,_) = name

dbgSpyer :: Protocol -> AnBxOnP -> String
dbgSpyer prot options = showNarration (trAnB2Spyer prot options)

dbgExecnarr :: Protocol -> OFMCAttackImpersonationsAndProt -> AnBxOnP -> String
dbgExecnarr origprot trImpsAndProt options =
  let prot = case trImpsAndProt of
              Just (_,trprot,_,_) -> trprot
              Nothing -> origprot
  in "(* Protocol: " ++ protName prot ++ " *)" ++ "\n\n" ++ showExecnarr (trProt2Execnarr origprot trImpsAndProt options)

dbgNExecnarr :: Protocol -> OFMCAttackImpersonationsAndProt -> AnBxOnP -> String
dbgNExecnarr prot trProtData options = showNExecnarr (trProt2NExecnarr prot trProtData options)

dbgSpyerSPI :: Protocol -> OFMCAttackImpersonationsAndProt -> AnBxOnP -> String
dbgSpyerSPI prot trImpsAndProt options = showSpiOfExecnarr (protName prot) $ execnarrOfProt prot trImpsAndProt options

dbgKnowExecnarr :: Protocol -> AnBxOnP -> String
dbgKnowExecnarr prot options = let
                                 kappa = knowOfProt prot options
                               in printMapSK kappa ++ "\n"
