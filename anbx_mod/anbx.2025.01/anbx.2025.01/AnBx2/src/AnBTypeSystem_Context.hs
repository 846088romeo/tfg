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

 Copyright Ryan W. Porter
      for the portion of code adapted from Haskell ports of OCaml implementations for "Types and Programming Languages" (TAPL) by Benjamin C. Pierce, New BDS Licence)
      http://code.google.com/p/tapl-haskell/, 
-}
{-# OPTIONS_GHC -Wno-missing-fields #-}

module AnBTypeSystem_Context where

import AnBAst
import AnBxMsgCommon
import Debug.Trace
import qualified Data.Map as Map
import AnBxAst (AnBxType (..), TO (..), eqTypesStrict, eqTypes, agentDefaultType, AnBType (..))
import Data.List (foldl')


buildContext :: Protocol -> ProtType -> AnBContext
buildContext (_, types, _,_,_, _, _, _, _) prottype = types2context newContext types prottype

types2context :: AnBContext -> Types -> ProtType -> AnBContext
types2context ctx [] _ = ctx
types2context ctx ((t,ids):xs) PTAnBx = let
                                  vb = VarBind (BaseType t)
                                  ctx1 = foldl' (\x y -> case () of
                                                            -- AnBx default function signatures - if no explicit signature exist default one is added
                                                          _ | y == show AnBxPK && eqTypesStrict t (Function []) -> appendBinding x y (snd (pkFun AnBxPK))
                                                            | y == show AnBxSK && eqTypesStrict t (Function []) -> appendBinding x y (snd (pkFun AnBxSK))
                                                            | y == show AnBxHK && eqTypesStrict t (Function []) -> appendBinding x y (snd (pkFun AnBxHK))
                                                            | y == show AnBxHash && eqTypesStrict t (Function []) -> appendBinding x y (snd hashFun)
                                                            | y == show AnBxHmac && eqTypesStrict t (Function []) -> appendBinding x y (snd hmacFun)
                                                            | y == show AnBxBlind && eqTypesStrict t (Function []) -> appendBinding x y (snd blindFun)
                                                            -- functions  w signature
                                                            | otherwise -> appendBinding x y vb) ctx ids
                             in types2context ctx1 xs PTAnBx

types2context ctx ((t, ids): xs) PTAnB = let
    vb = VarBind (BaseType t)
    ctx1 = foldl' (\x y -> case t of 
                              PublicKey [] -> let -- add also the private key
                                                invK = show AnBxInv ++ y  
                                                invT = VarBind TPrivateKey
                                              in appendBinding (appendBinding x y vb) invK invT
                              _ -> appendBinding x y vb
                      ) ctx ids
  in types2context ctx1 xs PTAnB

newtype AnBContext = AnBContext (Map.Map String Binding) deriving (Eq,Show)

newContext :: AnBContext
newContext = AnBContext Map.empty

mapType :: AnBType -> Type
mapType (BaseType t) = t
mapType t = Custom (show t) []

defaultContext :: [a]
defaultContext = []
-- defaultContext = [(show AnBxZero,VarBind (BaseType Number {}))]      -- zero not yet allowed to be used explicitly in AnBx/AnB

-- AnBx default functions

pkFun :: AnBxPKeysFun -> (String,Binding)
pkFun pk = funSign (show pk) PubFun [BaseType agentDefaultType] (BaseType PublicKey {})
hashFun :: (String,Binding)
hashFun = funSign (show AnBxHash) PubFun [BaseType (Untyped [])] THash
hmacFun :: (String,Binding)
hmacFun = funSign (show AnBxHmac) PubFun [BaseType (Untyped []),BaseType (SymmetricKey [])] THMac
blindFun :: (String,Binding)
blindFun = funSign (show AnBxBlind) PubFun [BaseType agentDefaultType] (BaseType (PublicKey []))
xorFun = funSign (show AnBxXor) PubFun [BaseType (Number []),BaseType (Number [])] (BaseType (Number []))
xorFun :: (String,Binding)

funSign :: Ident -> PrivateFunction -> [AnBType] -> AnBType -> (String,Binding)
funSign id priv tx t = (id,VarBind (BaseType (Function [FunSign (map mapType tx,mapType t,priv)])))

compareTypes :: AnBType -> AnBType -> Bool
compareTypes (BaseType (Untyped _)) _ = True
compareTypes _ (BaseType (Untyped _)) = True
compareTypes (BaseType t1) (BaseType t2) = eqTypes t1 t2
compareTypes t1 t2 = t1==t2

compareTypesList :: [AnBType] -> [AnBType] -> Bool
compareTypesList [BaseType (Untyped _)] _ = True
compareTypesList _ [BaseType (Untyped _)] = True
compareTypesList t1 t2 = (length t1 == length t2) && all (uncurry compareTypes) (zip t1 t2)

appendBinding :: AnBContext -> String -> Binding -> AnBContext
appendBinding (AnBContext ns) n binding = case Map.lookup n ns of
                                         Nothing ->  AnBContext (Map.insert n binding ns)
                                         Just _ -> error ("appendBinding - TypeSystem (AnB) - symbol " ++ n ++ " already present in context " ++ show ns)

getIdentifiersByType :: AnBContext -> AnBType -> [String]
getIdentifiersByType (AnBContext ctx) targetType =
  Map.keys $ Map.filter matchesType ctx
  where
    -- Check if the binding's type matches the target type using compareTypes
    matchesType (VarBind anbType) = compareTypes anbType targetType

getTypeAndIdentifiersByType :: AnBContext -> AnBType -> [(AnBType, String)]
getTypeAndIdentifiersByType (AnBContext ctx) targetType =
  map extractTypeAndIdent $ filter matchesType (Map.toList ctx)
  where
    -- Check if the binding's type matches the target type using compareTypes
    matchesType (_, VarBind anbType) = compareTypes anbType targetType
    -- Extract (Type, Identifier) from a matching entry
    extractTypeAndIdent (ident, VarBind anbType) = (anbType, ident)

{- ---------------------
       BINDING
 ----------------------- -}

newtype Binding = VarBind AnBType
               deriving (Eq,Show)
--               deriving (Eq,Typeable,Data,Show)