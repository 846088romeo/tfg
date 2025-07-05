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
      for the portion of code adapted from the OCaml source code of spyer: a cryptographic protocol compiler, GNU General Public Licence)
-}
{-# LANGUAGE InstanceSigs #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "Use newtype instead of data" #-}

module Spyer_Message where
import qualified Data.Set as Set
import Debug.Trace
import qualified Data.Map as Map
import Data.List (intercalate)
import Spyer_Common (foldset)
import Java_TypeSystem_JType ( namesOfNExpression, NEIdent, NExpression, StringSet )

type ExpressionSet = Set.Set NExpression
type KnowledgeMap = Map.Map NExpression ExpressionSet

data Atom =
          FWff NExpression
        | FEq (NExpression,NExpression,Bool) -- (expr1,expr2,mayfail)
        | FNotEq (NExpression,NExpression)
        | FInv (NExpression,NExpression)
    deriving (Eq,Ord)

instance Show Atom where
    show :: Atom -> String
    show (FWff e) = "wff("++ show e ++")"
    show (FEq (e,f,mf)) = "eq(" ++ show e ++","++ show f++")" ++ if mf then "\t (* may fail *)" else "" -- "\t (* not going to fail *)"
    show (FInv (e,f)) ="inv(" ++ show e ++","++ show f++")"
    show (FNotEq (e,f)) = "not" ++ show (FEq (e,f,False))

type AtomSet = Set.Set Atom
data Formula = FAnd AtomSet | FSingle Atom deriving (Eq,Ord)

instance Show Formula where
    show :: Formula -> String
    show (FAnd ats) = "(*" ++ show (Set.size ats) ++ "*)" ++ "\n" ++  foldset (\a s -> show a ++ "\n" ++ s) "" ats
    show (FSingle a) = show a     -- single atom / used when doing CSE for performance

namesOfKnowlegde :: KnowledgeMap -> StringSet
namesOfKnowlegde = Map.foldrWithKey (\m _ s -> Set.union (namesOfNExpression m) s) Set.empty

showKnowledgeMap :: KnowledgeMap -> String
showKnowledgeMap k = show (map (\(k,es) -> "(" ++ show k ++ ":" ++ showExpressionSet es ++ ")") (Map.toList k))

showExpressionSet :: ExpressionSet -> String
showExpressionSet es = intercalate  "," (map show ls)
                            where
                                ls = Set.toList es

data NEquation = NEqt NExpression NExpression [NEIdent]
               deriving (Eq)

type NEquations = [NEquation]

instance Show NEquation where
           show :: NEquation -> String
           show (NEqt msg1 msg2 ids) = show msg1 ++ " = " ++ show msg2 ++ "\t# " ++ show ids

showEquations :: NEquations -> String
showEquations = foldr (\x y -> show x ++ "\n" ++ y) ""

type EncLabel = Maybe Int

type Substitution = Map.Map String NExpression
