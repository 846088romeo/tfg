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

module Java_TypeSystem_Context where

{- JContext used to implement de Bruijn indices, which are described in 
   chapter 6.  Each element also includes a Binding, so that we
   can record the type of the variable
 -}

import Java_TypeSystem_JType
import AnBxMsgCommon 
import qualified Data.Map as Map
import AnBAst (Protocol, Types, Type)
import AnBxAst (AnBxType(..), TO (..), isFunctionType)
import Data.List (foldl')

newtype JContext = JContext (Map.Map String Binding) deriving (Eq,Show)

buildJContext :: Protocol -> JContext
buildJContext (_, types,_, _,_, _, _, _, _) = types2context newContext types

newContext :: JContext
newContext = JContext defaultContext

defaultContext :: Map.Map String Binding
defaultContext = Map.singleton (show AnBxZero) (VarBind JNonce)           -- add zero symbol for xor

appendBinding :: JContext -> String -> Binding -> JContext
appendBinding (JContext ns) n binding = case Map.lookup n ns of
                                         Nothing ->  JContext (Map.insert n binding ns)
                                         Just _ -> error ("TypeSystem (J) - symbol " ++ n ++ " already present in context " ++ show ns)

getBindingByName :: JContext -> String -> (String, Binding)
getBindingByName (JContext ns) id = case Map.lookup id ns of
                                                Nothing ->  error ("TypeSystem (J) - symbol " ++ show id ++ " does not exist in " ++ show ns)
                                                Just x -> (id,x)

types2context :: JContext -> Types -> JContext
-- types2context ctx t | trace ("types2context\n\tcontext: " ++ show ctx ++ "\n\ttypes:" ++ show t) False = undefined
types2context ctx [] = ctx
types2context ctx (f@(Function to,ids):xs) = let
                                                 funsig = [x | (FunSign x) <- to]
                                                 priv = case to of
                                                                [] -> PubFun
                                                                [FunSign (_,_,p)] -> p
                                                                _ -> error ("unhandled type options: " ++ show f ++  " - opt: " ++ show to)
                                                 vb z = case funsig of
                                                                -- some built-in function    
                                                          [] -> if isPKFun z then VarBind (JFunction priv (JAgent,JPublicKey (Just (getKeyFun z))))
                                                                    else if isReserved z then
                                                                                    let fz = getReserved z in
                                                                                          case fz of
                                                                                            AnBxHash -> VarBind (JFunction priv (NEVarArgs,JHash))
                                                                                            AnBxHmac -> VarBind (JFunction priv (AnBxParams [NEVarArgs,JHmacKey],JHmac))
                                                                                            _ -> error (z ++ " is a reserved word")
                                                                            else VarBind (JFunction priv (NEVarArgs,JString))
                                                          fn -> let
                                                                  fn0 = [ (t1,t2) | (t1,t2,_) <- fn ]
                                                                  tn0 = map mapAnBAtomicTypes (fst (head fn0))
                                                                  tn = case tn0 of
                                                                            [x] -> x
                                                                            _ -> AnBxParams tn0
                                                                  t = mapAnBAtomicTypes (snd (head fn0))
                                                                in VarBind (JFunction priv (tn,t))
                                                 ctx1 = foldl' (\x y -> appendBinding x y (vb y)) ctx ids
                                          in types2context ctx1 xs

types2context ctx ((PublicKey opt,ids):xs) = let
                                                ctx1 = foldl' (\x y -> appendBinding x y (VarBind (mapAnBTypes (PublicKey opt,y)))) ctx ids
                                                -- add the private key if the public one is declared
                                                ctx2 = foldl' (\x y -> appendBinding x (show AnBxInv++y) (VarBind (JPrivateKey Nothing))) ctx1 ids
                                               in types2context ctx2 xs
types2context ctx ((t,ids):xs) = let
                                    ctx1 = foldl' (\x y -> appendBinding x y (VarBind (mapAnBTypes (t,y)))) ctx ids
                               in types2context ctx1 xs

-- Overridden by a specific type conventions if prefix is used

mapAnBAtomicTypes :: Type -> JType
mapAnBAtomicTypes t = case t of
                        Agent {}      -> JAgent
                        PublicKey _   -> JPublicKey Nothing
                        SymmetricKey _-> JSymmetricKey
                        SeqNumber _   -> JSeqNumber
                        Untyped _     -> JUntyped
                        Purpose _     -> JPurpose
                        Number _      -> JNonce -- jDefaultType
                        Custom t _    -> JUserDef t -- userdef
                        _                    -> error ("Unhandled type " ++ show t)

-- maps AnB Types including type conventions
mapAnBTypes :: (Type,Ident) -> JType
mapAnBTypes (t@(Number _),id)
                                | isVarofType Nonce id = JNonce
                                | isDHPar id || isVarofType DHG id = JDHBase
                                | isVarofType DHX id || isVarofType DHY id = JDHSecret
                                | isConstant id = JConstant (mapAnBAtomicTypes t)
                                -- | isVariable id = jDefaultType -- all vars are mapped as String if not specified elsewhere
                                | otherwise = mapAnBAtomicTypes t

mapAnBTypes (t@(SymmetricKey {}),id)
                                    | isVarofType HmacKey id = JHmacKey
                                    | otherwise = mapAnBAtomicTypes t           -- mapped to JSymmetricKey 
mapAnBTypes (t,id) | isFunctionType t = error ("there should be no reason at this stage to map " ++ id ++ " of type " ++ show t)
mapAnBTypes (t,_) = mapAnBAtomicTypes t

getIdentifiersByType :: JContext -> JType -> [String]
getIdentifiersByType (JContext ctx) targetType =
  Map.keys $ Map.filter matchesType ctx
  where
    -- Check if the binding's type matches the target type using compareTypes
    matchesType (VarBind anbType) = compareTypes anbType targetType

getIdentifiersByTypeStrict :: JContext -> JType -> [String]
getIdentifiersByTypeStrict (JContext ctx) targetType =
  Map.keys $ Map.filter matchesType ctx
  where
    -- Check if the binding's type matches the target type using compareTypes
    matchesType (VarBind anbType) = anbType == targetType    