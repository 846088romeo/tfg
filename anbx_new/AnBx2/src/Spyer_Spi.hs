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

 Copyright Sebastien Briais and Uwe Nestmann, 
      for the portion of code adapted from the OCaml source code of spyer: a cryptographic protocol compiler, GNU General Public Licence)
-}
{-# LANGUAGE InstanceSigs #-}

module Spyer_Spi where
import AnB2NExpression
import Spyer_Message
import Spyer_Common ( foldset )
import qualified Data.Set as Set
import qualified Data.Map as Map
import qualified Data.List as List
import Data.Maybe ( fromJust )
import Debug.Trace()
import Data.List (foldl')
import AnBxMsgCommon (AnBxReserved(..))
import Java_TypeSystem_JType
import AnBxAst (AnBxChannelType(..))

agentName :: String -> String
agentName s = "agent_" ++ s

varNameSPI :: String -> String
varNameSPI s = "VAR_"++ s

data SpiExpression =
        SName String
        | SPair SpiExpression SpiExpression
        | SEnc SpiExpression SpiExpression 
        | SDec SpiExpression SpiExpression
        | SFst SpiExpression
        | SSnd SpiExpression
        | SPub SpiExpression
        | SPriv SpiExpression
        | SHash SpiExpression
        | SHmac SpiExpression SpiExpression
        | SKap SpiExpression SpiExpression
        | SKas SpiExpression SpiExpression
        | SFun SpiExpression SpiExpression
        | SXor SpiExpression SpiExpression
        | SCat [SpiExpression]
        | SProj Int Int SpiExpression

instance Show SpiExpression where
    show :: SpiExpression -> String
    show (SName n) = n
    show (SPair m n) = "<"++ show m ++", "++ show n ++">"
    show (SEnc m n) = "enc("++ show m ++", "++ show n ++")"
    show (SDec m n) = "dec("++ show m ++", "++ show n ++")"
    show (SFst m) = "fst("++ show m ++")"
    show (SSnd m) = "snd("++ show m ++")"
    show (SPub m) = "pub("++ show m ++")"
    show (SPriv m) = "priv("++ show m ++")"
    show (SHash m) = show AnBxHash ++ "("++ show m ++")"
    show (SHmac m n) = show AnBxHmac ++ "(["++ show m ++"],"++ show n ++")"
    show (SKap m n) = show AnBxKap ++ "("++ show m ++","++ show n ++")"
    show (SKas m n) = show AnBxKas ++ "("++ show m ++","++ show n ++")"
    show (SFun m n) = show m ++ "("++ show n ++")"
    show (SXor m n) = show AnBxXor ++ "("++ show m ++","++ show n ++")"
    show (SCat []) = ""
    show (SCat [x]) = show x
    show (SCat (x:xs)) = "<" ++ show x  ++ foldr (\x y -> "," ++ show x ++ y) "" xs ++ ">"
    show (SProj idx n m) = "proj["++ show idx ++"/" ++ show n ++ "]["++ show m ++"]"

data SpiFormula =    STrue
                                | SEq (SpiExpression,SpiExpression)
                                | SWff SpiExpression
                                | SAnd (SpiFormula,SpiFormula)

instance Show SpiFormula where
    show :: SpiFormula -> String
    show STrue = ""
    show (SEq(e,f)) = "eq(" ++ show e ++ "," ++ show f ++")"
    show (SWff e) = "wff(" ++ show e ++ ")"
    show (SAnd(phi,STrue)) = show phi
    show (SAnd(STrue,phi)) = show phi
    show (SAnd(phi,psi)) = show phi ++" /\\ "++ show psi

data SpiProcess = PZero
                    | PInput (SpiExpression,String,SpiProcess)
                    | POutput (SpiExpression,SpiExpression,SpiProcess)
                    | PPar (SpiProcess,SpiProcess)
                    | PNew (String,SpiProcess)
                    | PCheck (SpiFormula,SpiProcess)
                    | PApply (String,[SpiExpression])

instance Show SpiProcess where
    show :: SpiProcess -> String
    show PZero = "0"
    show (PInput (e,x,p)) = show e ++ "(" ++ x ++ ")." ++ show p
    show (POutput (e,f,p)) = "'"++ show e ++"<"++ show f ++">."++ show p
    show (PPar (p,PZero)) = show p
    show (PPar (PZero,p)) = show p
    show (PPar (p,q)) = show p ++" | " ++ show q
    show (PNew (x,p)) = "(^" ++ x ++ showNew p
    show (PCheck (phi,p)) = "{" ++ show phi ++ "}" ++ show p
    show (PApply (a,es)) = a ++  showParams es

spiExprOfExpr :: NExpression -> SpiExpression
spiExprOfExpr (NEVar (_,s) _) = SName (varNameSPI s)
spiExprOfExpr e@(NEName (_,s)) = if exprIsAgent e then SName (agentName s) else SName s
spiExprOfExpr (NEEnc m n) = SEnc (spiExprOfExpr m) (spiExprOfExpr n)
spiExprOfExpr (NESign m n) = SEnc (spiExprOfExpr m) (spiExprOfExpr n)
spiExprOfExpr (NEEncS m n) = SEnc (spiExprOfExpr m) (spiExprOfExpr n)           -- we do not distinguish between here sym and asym enc, sign or enc
spiExprOfExpr (NEDec m n) = SDec (spiExprOfExpr m) (spiExprOfExpr n)
spiExprOfExpr (NEVerify m n) = SDec (spiExprOfExpr m) (spiExprOfExpr n)
spiExprOfExpr (NEDecS m n) = SDec (spiExprOfExpr m) (spiExprOfExpr n)           -- we do not distinguish between here sym and asym enc, verify or dec
spiExprOfExpr (NEPub m _) = SPub (spiExprOfExpr m)
spiExprOfExpr (NEPriv m _) = SPriv (spiExprOfExpr m)
spiExprOfExpr (NEHash m) = SHash (spiExprOfExpr m)
spiExprOfExpr (NEHmac m n) = SHmac (spiExprOfExpr m) (spiExprOfExpr n)
spiExprOfExpr (NEKap m n) = SKap (spiExprOfExpr m) (spiExprOfExpr n)
spiExprOfExpr (NEKas m n) = SKas (spiExprOfExpr m) (spiExprOfExpr n)
spiExprOfExpr (NEFun (_,f) n) = SFun (SName f) (spiExprOfExpr n)
spiExprOfExpr (NEXor m n) = SXor (spiExprOfExpr m) (spiExprOfExpr n)
spiExprOfExpr (NECat []) = error "SPI - empty tuple"
spiExprOfExpr (NECat [x]) = spiExprOfExpr x
spiExprOfExpr (NECat xs) = SCat (map spiExprOfExpr xs)
spiExprOfExpr (NEProj  idx n m) = SProj idx n (spiExprOfExpr m)

spiFormOfForm :: Formula -> SpiFormula
spiFormOfForm (FAnd ats) =
        foldset (\at phi ->
                  let test = case at of
                                        FWff e -> SWff(spiExprOfExpr e)
                                        FEq (e,f,_) -> SEq(spiExprOfExpr e,spiExprOfExpr f)
                                        FNotEq _ -> error "FNotEq not implemented"
                                        FInv (e,f) -> let
                                                                e' = spiExprOfExpr e
                                                                f' = spiExprOfExpr f
                                                        in SWff(SDec (SEnc e' e') f')
                  in SAnd(test,phi)) STrue ats
spiFormOfForm (FSingle at) = spiFormOfForm (FAnd (Set.singleton at))

showListSPI :: [SpiExpression] -> String
showListSPI [] = ""
showListSPI [e] = show e
showListSPI (e:es) = show e ++", " ++ showListSPI es

showParams :: [SpiExpression] -> String
showParams [] = ""
showParams es = "("++ showListSPI es ++")"

showNew:: SpiProcess -> String
showNew (PNew(x,p)) = ", " ++ x ++ showNew p
showNew p = ")(" ++ show p ++ ")"

namesOfSpiExpr :: SpiExpression -> StringSet
namesOfSpiExpr (SName n) = Set.singleton n
namesOfSpiExpr (SPair m n) = Set.union (namesOfSpiExpr m) (namesOfSpiExpr n)
namesOfSpiExpr (SEnc m n) = Set.union (namesOfSpiExpr m) (namesOfSpiExpr n)
namesOfSpiExpr (SDec m n) = Set.union (namesOfSpiExpr m) (namesOfSpiExpr n)
namesOfSpiExpr (SFst m) = namesOfSpiExpr m
namesOfSpiExpr (SSnd m) = namesOfSpiExpr m
namesOfSpiExpr (SPub m) = namesOfSpiExpr m
namesOfSpiExpr (SPriv m) = namesOfSpiExpr m
namesOfSpiExpr (SHash m) = namesOfSpiExpr m
namesOfSpiExpr (SHmac m n) = Set.union (namesOfSpiExpr m) (namesOfSpiExpr n)
namesOfSpiExpr (SKap m n) = Set.union (namesOfSpiExpr m) (namesOfSpiExpr n)
namesOfSpiExpr (SKas m n) = Set.union (namesOfSpiExpr m) (namesOfSpiExpr n)
namesOfSpiExpr (SFun m n) = Set.union (namesOfSpiExpr m) (namesOfSpiExpr n)
namesOfSpiExpr (SXor m n) = Set.union (namesOfSpiExpr m) (namesOfSpiExpr n)
namesOfSpiExpr (SCat []) =  Set.empty
namesOfSpiExpr (SCat [x]) =  namesOfSpiExpr x
namesOfSpiExpr (SCat (x:xs)) =  Set.union (namesOfSpiExpr x) (namesOfSpiExpr (SCat xs))
namesOfSpiExpr (SProj _ _ m) =  namesOfSpiExpr m

namesOfSpiForm :: SpiFormula -> StringSet
namesOfSpiForm STrue = Set.empty
namesOfSpiForm (SEq(m,n)) = namesOfSpiExpr (SPair m n)
namesOfSpiForm (SWff m) = namesOfSpiExpr m
namesOfSpiForm (SAnd(phi,psi)) = Set.union (namesOfSpiForm phi) (namesOfSpiForm psi)

freeNamesOfProcess :: SpiProcess -> StringSet
--freeNamesOfProcess p | trace ("freeNamesOfProcess: " ++ show p) False = undefined
freeNamesOfProcess PZero = Set.empty
freeNamesOfProcess (PInput (e,x,p)) = Set.union (namesOfSpiExpr e) (Set.delete x (freeNamesOfProcess p))
freeNamesOfProcess (POutput (e,f,p)) = Set.union (namesOfSpiExpr (SPair e f)) (freeNamesOfProcess p)
freeNamesOfProcess (PPar (p,q)) = Set.union (freeNamesOfProcess p) (freeNamesOfProcess q)
freeNamesOfProcess (PNew (x,p)) = Set.delete x (freeNamesOfProcess p)
freeNamesOfProcess (PCheck (phi,p)) = Set.union (namesOfSpiForm phi) (freeNamesOfProcess p)
freeNamesOfProcess (PApply (_,es)) = foldl' (\s e -> Set.union (namesOfSpiExpr e) s) Set.empty es

type MapSPI = Map.Map String (SpiProcess -> SpiProcess)
type SPIDef = (String, [String], SpiProcess)

getDef :: String -> String -> MapSPI  ->(SpiProcess -> SpiProcess)
--getDef a sysname defs  | trace ("getDef\n\ta: " ++ show a) False = undefined
getDef a sysname defs
  | a == sysname = error ("invalid system name "++ sysname)
  | Map.notMember a defs =
        let
                defs1 = Map.insert a id defs
        in fromJust (Map.lookup a defs1)
  | otherwise = fromJust (Map.lookup a defs)

updateDef :: String -> (SpiProcess -> SpiProcess) -> MapSPI -> MapSPI
--updateDef a p defs | trace ("updateDef\n\ta: " ++ show a) False = undefined
updateDef a p defs = let
                        defs1 = Map.delete a defs
                        defs2 = Map.insert a p defs1
                      in defs2

translate :: StringSet -> String -> [NAction] -> MapSPI -> (StringSet,MapSPI)
--translate privnames sysname xn defs | trace ("translate\n\tprivnames: " ++ show privnames ++ "\n\taction: " ++ if null xn then "" else show (head(xn)) ++ "\n\tsysname: " ++ show sysname) False = undefined
translate privnames  _ [] defs = (privnames,defs)
translate privnames sysname (NANew (_,a,(_,k)):xs) defs =  let
                                                                pa = getDef a sysname defs
                                                                defs1 = updateDef a (\p -> pa (PNew(k,p))) defs
                                                          in translate privnames sysname xs defs1
translate privnames sysname (NAEmit (_,a,(_,Insecure,_),e,f):xs) defs = let
                                                                   pa = getDef a sysname defs
                                                                   defs1 = updateDef a (\p -> pa (POutput(spiExprOfExpr e,spiExprOfExpr f,p))) defs
                                                        in translate privnames sysname xs defs1
translate privnames sysname (NAReceive (_,a,(_,Insecure,_),x):xs) defs  = let
                                                                  pa = getDef a sysname defs
                                                                  var = case x of
                                                                            NEVar (_,id) _ -> id
                                                                            _ -> error ("unexpected term: " ++ show x)
                                                                  defs1 = updateDef a (\p -> pa (PInput(SName (agentName a),varNameSPI var,p))) defs
                                                           in translate privnames sysname xs defs1
translate privnames sysname (NACheck (_,a,phi):xs) defs  = let
                                                                       pa = getDef a sysname defs
                                                                       defs1 = updateDef a (\p -> pa (PCheck (spiFormOfForm phi,p))) defs
                                                         in translate privnames sysname xs defs1
translate privnames sysname (NAComment _:xs) defs  = translate privnames sysname xs defs

translate privnames sysname (NAGoal _:xs) defs  = translate privnames sysname xs defs

translate _ _ x _ = error ("unsupported SPI translation: " ++ show x)

getAllDefs :: MapSPI -> [SPIDef]
getAllDefs defs = Map.foldrWithKey (\a p ds -> (a,Set.toList (freeNamesOfProcess (p PZero)) ,p PZero):ds) [] defs

spiDefOfExecnarr :: String -> [NAction] -> [SPIDef]
spiDefOfExecnarr sysname xn =
  let
        (privnames,defs1) = translate Set.empty sysname xn Map.empty
        all_defs = getAllDefs defs1
        all_defs1 = List.sortBy (\(a,_,_) (b,_,_) -> Prelude.compare a b) all_defs
        sysdef = foldl' (\p (a,na,_) -> PPar(p,PApply(a,map SName na))) PZero all_defs1
        sysdef1 = foldr (\n p -> PNew (n,p)) sysdef (Set.toList privnames)
        nsys = Set.toList (freeNamesOfProcess sysdef1)
 -- in error (show "privnames: " ++ show privnames)  
 -- in error (show "sysdef1: " ++ show sysdef1)
 -- in error (show "nsys: " ++ show nsys)
 --in error (show "all_defs1: " ++ show all_defs1)
 in all_defs1 ++ [(sysname,nsys,sysdef1)]

showSpiDefs :: [SPIDef] -> String
showSpiDefs [] = ""
showSpiDefs ((a,na,pa):ds) = "agent " ++ a ++ showParams (map SName na) ++ " = " ++ show pa ++ "\n\n" ++ showSpiDefs ds

showSpiOfExecnarr ::  String -> Execnarr -> String
showSpiOfExecnarr sysname xnarr = showSpiDefs (spiDefOfExecnarr sysname xnarr)
