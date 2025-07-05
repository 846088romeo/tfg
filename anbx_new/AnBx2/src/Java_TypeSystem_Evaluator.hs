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

 Copyright Ryan W. Porter
      for the portion of code adapted from Haskell ports of OCaml implementations for "Types and Programming Languages" (TAPL) by Benjamin C. Pierce, New BDS Licence)
      http://code.google.com/p/tapl-haskell/, 
-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "Use infix" #-}

module Java_TypeSystem_Evaluator (typeofTS,pkFunOfNExpression) where

import AnBxMsgCommon
import Java_TypeSystem_JType
import Java_TypeSystem_Context
import Debug.Trace
import Control.Monad.Writer

pkFunOfNExpression :: NExpression -> JContext -> Maybe AnBxPKeysFun
pkFunOfNExpression (NEPub _ pk) _ = pk
pkFunOfNExpression (NEPriv _ pk) _ = pk
pkFunOfNExpression e ctx = case typeofTS e ctx of
                                        JPrivateKey pk -> pk
                                        JPublicKey pk -> pk
                                        _ -> error ("pkFunOfNExpression - unexpected request for expression: " ++ show e)

{- ----------------------------
   TYPING
 ---------------------------- -}

typeErrorMsg :: String -> NExpression -> NExpression -> [JType] -> [JType] -> JContext -> String
typeErrorMsg s e term xs ts ctx = "JType - incompatible type error: " ++ s
                           ++ "\n\texpr: " ++ show e
                           ++ "\n\tterm: " ++ show term
                           ++ "\n\ttype(s): " ++ show xs ++
                             (if not (null ts) then "\n\texpected: " ++ show ts else "")
                             ++ "\n\tctx: " ++ show ctx

newtype Error = Error String deriving (Show)
type TC = Writer [Error]

typeofTSCatList :: [NExpression] -> JContext -> [JType]
typeofTSCatList xs ctx = map (\x -> fst(runWriter(typeofTSM x ctx))) xs

typeofTS :: NExpression -> JContext -> JType
typeofTS e ctx = fst(runWriter(typeofTSM e ctx))

typeofTSM :: NExpression -> JContext -> TC JType
-- typeofTSM term ctx | trace ("typeofTSM\n\tterm: " ++ show term ++ "\n\tcontext: " ++ show ctx) False = undefined 

typeofTSM (NEName (t,_)) _ = return t
typeofTSM (NEVar (t,_) _) _ = return t

typeofTSM (NEHash expr) ctx  = do 
                            !_ <- typeofTSM expr ctx  -- force to typecheck the expression
                            return JHash

typeofTSM term@(NEFun (JFunction _ (t1,t),f) expr@(NEVar _ e)) ctx = if n == 1 then  do  -- if a function is applied to a variable, check that arity is 1
                                                                                        t2 <- typeofTSM expr ctx
                                                                                        unless (compareTypes t1 t2 || compareTypes t1 JUntyped) $
                                                                                            tell [Error (typeErrorMsg ("wrong function arguments for function " ++ f ++ ": " ++ show t1 ++ " -> " ++ show t) expr term [t2] [t1] ctx)]
                                                                                        return t
                                                                                else error(typeErrorMsg ("wrong arguments arity (1 instead of " ++ show n ++ ") for function " ++ f ++ ": " ++ show t1 ++ " -> " ++ show t ) expr term [] [t1] ctx)
                                                                                where n = arityOfNExpression e
typeofTSM term@(NEFun (JFunction _ (t1,t),f) expr) ctx = do
                                                            t2 <- typeofTSM expr ctx
                                                            unless (compareTypes t1 t2 || compareTypes t1 JUntyped) $
                                                                tell [Error (typeErrorMsg ("wrong arguments for function " ++ f ++ ": " ++ show t1 ++ " -> " ++ show t) expr term [t2] [t1] ctx)]
                                                            return t
typeofTSM (NECat [x]) ctx = do 
                            typeofTSM x ctx

typeofTSM (NECat xs) ctx = return (AnBxParams (typeofTSCatList xs ctx))

typeofTSM term@(NEProj index arity e) ctx = case typeofTS e ctx of
                                                AnBxParams xs -> let
                                                                     len = length xs
                                                                     msgStr = "index/length incorrect in Proj function: " ++ show index ++ "/"++ show len ++ "\narity: " ++ show arity
                                                                 in do
                                                                        unless (elem index [1..len] && arity==len) $
                                                                            tell [Error (typeErrorMsg msgStr e term [typeofTS e ctx] [AnBxParams xs] ctx)]
                                                                        return (xs !! (index-1))
                                                _ -> error (typeErrorMsg "wrong argument type in Proj function" e term [] [] ctx)

typeofTSM term@(NEHmac e1 e2) ctx = do
                                       !_ <- typeofTSM e1 ctx
                                       t2 <- typeofTSM e2 ctx
                                       when (not (compareTypes t2 JHmacKey) || compareTypes t2 JDHSecKey || compareTypes t2 JSymmetricKey) $
                                            tell [Error (typeErrorMsg "expression in HMac must be a compatible HmacKey" e2 term [t2] [JHmacKey,JDHSecKey,JSymmetricKey] ctx)]
                                       return JHmac

typeofTSM term@(NESign e1 e2) ctx = do
                                        t1 <- typeofTSM e1 ctx
                                        t2 <- typeofTSM e2 ctx
                                        let pk = pkFunOfNExpression e2 ctx
                                        unless (compareTypes t2 (JPrivateKey pk)) $
                                            tell [Error (typeErrorMsg "wrong key type on NESign" e2 term [t2] [JPrivateKey pk] ctx)]
                                        unless (case pk of
                                                    Nothing -> True
                                                    Just pk -> elem pk pkiSigFunList) $
                                            tell [Error (typeErrorMsg "wrong key type on NESign" e2 term [t2] [JPrivateKey Nothing] ctx)]
                                        return (SignedObject t1)

typeofTSM term@(NEEnc e1 e2) ctx = do
                                        t1 <- typeofTSM e1 ctx
                                        t2 <- typeofTSM e2 ctx
                                        let pk = pkFunOfNExpression e2 ctx
                                        unless (compareTypes t2 (JPublicKey pk)) $
                                            tell [Error (typeErrorMsg "wrong key type on NEEnc" e2 term [t2] [JPublicKey pk] ctx)]
                                        unless (case pk of
                                                    Nothing -> True
                                                    Just pk -> elem pk pkiEncFunList) $
                                            tell [Error (typeErrorMsg "wrong key type on NEEnc" e2 term [t2] [JPublicKey Nothing] ctx)]
                                        return (SealedPair t1)

typeofTSM term@(NEEncS e1 e2) ctx = do
                                        t1 <- typeofTSM e1 ctx
                                        t2 <- typeofTSM e2 ctx
                                        unless (compareTypes t1 JSymmetricKey || compareTypes t1 JDHSecKey) $
                                            tell [error (typeErrorMsg "wrong key type on NEEncS" e2 term [t2] [JSymmetricKey,JDHSecKey] ctx)]
                                        return (SealedObject t1)

typeofTSM term@(NEDec e1 e2) ctx = do
                                        t1 <- typeofTSM e1 ctx
                                        t2 <- typeofTSM e2 ctx
                                        let pk = pkFunOfNExpression e2 ctx
                                        unless (compareTypes t1 (JPrivateKey pk)) $
                                            tell [Error (typeErrorMsg ("NEDec - expression must be a private key (sk) - pk: " ++ show pk) e2 term [t2] [JPrivateKey pk] ctx)]
                                        return (case t1 of
                                                    SealedPair t -> case pk of
                                                                            Nothing -> t
                                                                            Just sk -> if elem sk pkiEncFunList then t
                                                                                        else error (typeErrorMsg ("expression NEVerify must be a private key (sk) - pk: " ++ show pk) e2 term [t2] [JPublicKey pk] ctx)
                                                    _ -> error (typeErrorMsg "wrong decrypt type on NEDec" e1 term [t1] [SealedPair t1] ctx))

typeofTSM term@(NEDecS e1 e2) ctx = do
                                        t1 <- typeofTSM e1 ctx
                                        t2 <- typeofTSM e2 ctx
                                        unless (compareTypes t1 JSymmetricKey || compareTypes t1 JDHSecKey) $
                                            tell [Error (typeErrorMsg "NEDecS - expression  must be a symmetric key" e2 term [t2] [JSymmetricKey,JDHSecKey] ctx)]
                                        return (case t1 of
                                                SealedObject t -> t
                                                _ -> error (typeErrorMsg "wrong decrypt type on NEDecS" e1 term [t1] [SealedObject t1] ctx))

typeofTSM term@(NEVerify e1 e2) ctx = do
                                        t1 <- typeofTSM e1 ctx
                                        t2 <- typeofTSM e2 ctx
                                        let pk = pkFunOfNExpression e2 ctx
                                        unless (compareTypes t1 (JPublicKey pk)) $
                                            tell [Error (typeErrorMsg ("NEVerify - expression must be a public key (sk) - pk: " ++ show pk) e2 term [t2] [JPublicKey pk] ctx)]
                                        return (case t1 of
                                                    SignedObject t -> case pk of
                                                                            Nothing -> t
                                                                            Just sk -> if elem sk pkiSigFunList then t
                                                                                        else error (typeErrorMsg ("expression NEVerify expr must be a public key (sk) - pk: " ++ show pk) e2 term [t2] [JPublicKey pk] ctx)
                                                    _ -> error (typeErrorMsg "wrong decrypt type on NEVerify" e1 term [t1] [SignedObject t1] ctx))

typeofTSM term@(NEKap e1 e2) ctx = do
                                       t1 <- typeofTSM e1 ctx
                                       t2 <- typeofTSM e2 ctx
                                       unless (compareTypes t1 JDHBase) $
                                            tell [Error (typeErrorMsg "expression must be a (DH) base" e1 term [t1] [JDHBase] ctx)]
                                       unless (compareTypes t2 JDHSecret) $
                                            tell [Error (typeErrorMsg "expression must be a (DH) secret" e2 term [t2] [JDHSecret] ctx)]
                                       return JDHPubKey

typeofTSM term@(NEKas e1 e2) ctx = do
                                       t1 <- typeofTSM e1 ctx
                                       t2 <- typeofTSM e2 ctx
                                       unless (compareTypes t1 JDHPubKey) $
                                            tell [Error (typeErrorMsg "expression must be a (DH) public (half) key" e1 term [t1] [JDHPubKey] ctx)]
                                       unless (compareTypes t2 JDHSecret) $
                                            tell [Error (typeErrorMsg "expression must be a (DH) key pair" e2 term [t2] [JDHSecret] ctx)]
                                       return JDHSecKey

typeofTSM term@(NEXor e1 e2) ctx = do
                                       t1 <- typeofTSM e1 ctx
                                       t2 <- typeofTSM e2 ctx
                                       unless (compareTypes t1 JNonce) $
                                            tell [Error (typeErrorMsg "xor argument must be numeric" e1 term [t1] [JNonce] ctx)]
                                       unless (compareTypes t2 JNonce) $
                                            tell [Error (typeErrorMsg "xor argument must be numeric" e2 term [t2] [JNonce] ctx)]
                                       return JNonce

typeofTSM term@(NEPub e pk) ctx | exprIsPublicKey term = do 
                                            t <- typeofTSM e ctx
                                            unless (compareTypes t (JPublicKey pk)) $
                                                    tell [Error (typeErrorMsg ("NEPub - expression must be a public key - pk: " ++ show pk) e term [t] [JPublicKey pk] ctx)]
                                            return (JPublicKey pk)
typeofTSM term@(NEPriv e pk) ctx | exprIsPrivateKey term = do 
                                            t <- typeofTSM e ctx
                                            unless (compareTypes t (JPublicKey pk)) $
                                                tell [Error (typeErrorMsg ("NEPriv - expression must be a private key - pk: " ++ show pk) e term [t] [JPublicKey pk] ctx)]
                                            return (JPrivateKey pk)

typeofTSM term ctx = error (typeErrorMsg "unhandled expression type" term term [] [] ctx)


