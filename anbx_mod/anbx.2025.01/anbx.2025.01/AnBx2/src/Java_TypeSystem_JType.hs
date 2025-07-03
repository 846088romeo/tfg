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

{-# LANGUAGE DeriveDataTypeable #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "Use newtype instead of data" #-}
{-# LANGUAGE InstanceSigs #-}

module Java_TypeSystem_JType where
import AnBxMsgCommon
import Data.Typeable
import Data.Data
import Debug.Trace
import qualified Data.Set as Set
import Data.List (intercalate)
type StringSet = Set.Set String

type NEIdent = (JType,Ident)

compareNEIdent :: NEIdent -> NEIdent -> Ordering
compareNEIdent (JFunction _ _, id1) (JFunction _ _, id2) = compare id1 id2
compareNEIdent (t1, id1) (t2, id2) =
    case compare t1 t2 of
        EQ -> compare id1 id2
        ord -> ord

showNEIdent :: NEIdent -> String
showNEIdent (JPublicKey (Just pk),id) = show pk ++ "(" ++ id ++ ")"
showNEIdent (JPrivateKey (Just pk),id) = "inv" ++ "(" ++ show pk ++ "(" ++ id ++ ")"
showNEIdent (_,id) = id

showNEIdentList :: [NEIdent] -> String
showNEIdentList = intercalate "," . map showNEIdent

data NExpression =
        NEVar NEIdent NExpression                                   -- (type) varID expression
      | NEName NEIdent                                              
      | NECat [NExpression]
      | NEProj Int Int NExpression                                  -- index arity expression
      | NEEnc NExpression NExpression                               -- asymmetric               (Maybe AnBxPKeysFun)
      | NESign NExpression NExpression                              -- asymmetric               (Maybe AnBxPKeysFun)  
      | NEEncS NExpression NExpression                              -- symmetric            
      | NEDec NExpression NExpression                               -- asymmetric               (Maybe AnBxPKeysFun)
      | NEVerify NExpression NExpression                            -- asymmetric               (Maybe AnBxPKeysFun) 
      | NEDecS NExpression NExpression                              -- symmetric
      | NEPub NExpression (Maybe AnBxPKeysFun)                      -- expression ((Maybe AnBxPKeysFun))
      | NEPriv NExpression (Maybe AnBxPKeysFun)                     -- expression ((Maybe AnBxPKeysFun))
      | NEHash NExpression
      | NEHmac NExpression NExpression                              --  message, key
      | NEKap NExpression NExpression
      | NEKas NExpression NExpression
      | NEFun NEIdent NExpression                                   -- fun, message              String NExpression in NExpression
      | NEXor NExpression NExpression
      deriving (Ord)

instance Show NExpression where
        show :: NExpression -> String
        show (NEVar (t,name) _) = name -- ++ "[V:" ++ show t ++ "]" -- ++ "  [VAR: name:" ++name ++ " expr: " ++ show e ++"]  "
        show (NEName (t,name)) = name -- ++ "[N:" ++ show t ++ "]" -- ++ "  [NAME] "
        show (NECat []) = ""
        show (NECat [x]) = show x
        show (NECat (x:xs)) = "<" ++ show x  ++ foldr (\x y -> "," ++ show x ++ y ) "" xs ++ ">"
        show (NEEnc m n) = "enc("++ show m ++","++ show n ++ ")" -- ++ "[" ++ showPKFun pk ++ "]"  where pk = pkFunOfNExpression n newContext
        show (NESign m n) = "sign("++ show m ++","++ show n ++ ")" -- ++ "[" ++ showPKFun pk ++ "]" where pk = pkFunOfNExpression n newContext
        show (NEEncS m n) = "encS("++ show m ++","++ show n ++")"
        show (NEProj idx n m) = "proj["++ show idx ++ "/" ++ show n ++ "]["++ show m ++"]"
        show (NEDec m n) = "dec("++ show m ++","++ show n ++ ")" -- ++ "[" ++ showPKFun pk ++ "]" where pk = pkFunOfNExpression n newContext
        show (NEVerify m n) = "verify("++ show m ++","++ show n ++ ")" -- ++ "[" ++ showPKFun pk ++ "]"  where pk = pkFunOfNExpression n newContext
        show (NEDecS m n) = "decS("++ show m ++","++ show n ++")"
        show (NEPub m _) = show m
        show (NEPriv m _) = show AnBxInv ++ "(" ++  show m ++ ")"
        show (NEHash m) = show AnBxHash ++ "("++ show m ++")"
        show (NEHmac m n) = show AnBxHmac ++ "(["++ show m ++"],"++ show n ++")"
        show (NEKap m n) = show AnBxKap ++ "("++ show m ++","++ show n ++")"
        show (NEKas m n) = show AnBxKas ++ "("++ show m ++","++ show n ++")"
        show (NEFun (_,f) n) = f ++ "("++ show n ++")"
        show (NEXor m n) = show AnBxXor ++ "("++ show m ++","++ show n ++")"

instance Eq NExpression where
  (==) :: NExpression -> NExpression -> Bool
  -- (==) (NEVar (_,id1) _) (NEVar (_,id2) _) = id1==id2
  -- (==) (NEName (_,id1)) (NEName (_,id2)) = id1==id2
  (==) (NEVar id1 _) (NEVar id2 _) = id1==id2
  (==) (NEName id1) (NEName id2) = id1==id2
  (==) (NECat xs1) (NECat xs2) = xs1==xs2
  (==) (NEEnc e1 f1) (NEEnc e2 f2) = e1==e2 && f1==f2
  (==) (NESign e1 f1) (NESign e2 f2) = e1==e2 && f1==f2
  (==) (NEEncS e1 f1) (NEEncS e2 f2) = e1==e2 && f1==f2
  (==) (NEProj i1 j1 e1) (NEProj i2 j2 e2) = i1==i2 && j1==j2 && e1==e2
  (==) (NEDec e1 f1) (NEDec e2 f2) = e1==e2 && f1==f2
  (==) (NEVerify e1 f1) (NEVerify e2 f2) = e1==e2 && f1==f2
  (==) (NEDecS e1 f1) (NEDecS e2 f2) = e1==e2 && f1==f2
  (==) (NEPub e1 id1) (NEPub e2 id2) = e1==e2 && id1==id2
  (==) (NEPriv e1 id1) (NEPriv e2 id2) = e1==e2 && id1==id2
  (==) (NEHash e1) (NEHash e2) = e1==e2
  (==) (NEHmac e1 f1) (NEHmac e2 f2) = e1==e2 && f1==f2
  (==) (NEKap e1 f1) (NEKap e2 f2) = e1==e2 && f1==f2
  (==) (NEKas e1 f1) (NEKas e2 f2) = e1==e2 && f1==f2
  (==) (NEFun e1 f1) (NEFun e2 f2) = e1==e2 && f1==f2
  (==) (NEXor e1 f1) (NEXor e2 f2) = e1==e2 && f1==f2
  (==) _ _ = False

-- a specialised version used to generated variable ids
showVarName :: NExpression -> String
showVarName (NEVar (_,name) _) = name
showVarName (NEName (_,name)) = name
showVarName (NECat []) = ""
showVarName (NECat [x]) = showVarName x
showVarName (NECat (x:xs)) = "<" ++ showVarName x  ++ foldr (\x y -> "," ++ showVarName x ++ y ) "" xs ++ ">"
showVarName (NEEnc m n) = "enc("++ showVarName m ++","++ showVarName n ++ ")"
showVarName (NESign m n) = "sign("++ showVarName m ++","++ showVarName n ++ ")"
showVarName (NEEncS m n) = "encS("++ showVarName m ++","++ showVarName n ++")"
showVarName (NEProj idx n m) = "proj["++ show idx ++ "/" ++ show n ++ "]["++ showVarName m ++"]"
showVarName (NEDec m n) = "dec("++ showVarName m ++","++ showVarName n ++ ")"
showVarName (NEVerify m n) = "verify("++ showVarName m ++","++ showVarName n ++ ")"
showVarName (NEDecS m n) = "decS("++ showVarName m ++","++ showVarName n ++")"
showVarName (NEPub m _) = showVarName m
showVarName (NEPriv m _) = show AnBxInv ++ "(" ++ showVarName m ++ ")"
showVarName (NEHash m) = show AnBxHash ++ "("++ showVarName m ++")"
showVarName (NEHmac m n) = show AnBxHmac ++ "(["++ showVarName m ++"],"++ showVarName n ++")"
showVarName (NEKap m n) = show AnBxKap ++ "("++ showVarName m ++","++ showVarName n ++")"
showVarName (NEKas m n) = show AnBxKas ++ "("++ showVarName m ++","++ showVarName n ++")"
showVarName (NEFun (_,f) n) = f ++ "("++ showVarName n ++")"
showVarName (NEXor m n) = show AnBxXor ++ "("++ show m ++","++ show n ++")"

neXorZero :: NExpression
neXorZero = NEName (JNonce,show AnBxZero)

namesOfNExpression :: NExpression -> StringSet
namesOfNExpression ag@(NEName (_,n)) | exprIsAgent ag = Set.singleton n
namesOfNExpression (NEName _)  = Set.empty
namesOfNExpression (NEEnc m n) = Set.union (namesOfNExpression m) (namesOfNExpression n)
namesOfNExpression (NESign m n) = Set.union (namesOfNExpression m) (namesOfNExpression n)
namesOfNExpression (NEEncS m n) = Set.union (namesOfNExpression m) (namesOfNExpression n)
namesOfNExpression (NEPub m _) = namesOfNExpression m
namesOfNExpression (NEPriv m _) = namesOfNExpression m
namesOfNExpression (NEHash m) = namesOfNExpression m
namesOfNExpression (NEHmac m n) = Set.union (namesOfNExpression m) (namesOfNExpression n)
namesOfNExpression (NEKap m n) = Set.union (namesOfNExpression m) (namesOfNExpression n)
namesOfNExpression (NEKas m n) = Set.union (namesOfNExpression m) (namesOfNExpression n)
namesOfNExpression (NEFun (_,f) n) = Set.union (Set.singleton f) (namesOfNExpression n)
namesOfNExpression (NEXor m n) = Set.union (namesOfNExpression m) (namesOfNExpression n)
namesOfNExpression (NECat []) =  Set.empty
namesOfNExpression (NECat [x]) =  namesOfNExpression x
namesOfNExpression (NECat (x:xs)) =  Set.union (namesOfNExpression x) (namesOfNExpression (NECat xs))
namesOfNExpression e = error ("namesOfNExpression - unexpected term: " ++ show e)

nameOfGenerates :: NExpression -> String
nameOfGenerates (NEPub (NEName (_,id)) Nothing) = id                                  -- (Fresh) PublicKey 
nameOfGenerates (NEPriv (NEName (_,id)) Nothing) = show AnBxInv ++ id                 -- (Fresh) PrivateKey
nameOfGenerates (NEName (_,id)) = id
nameOfGenerates m = error ("nameOfGenerates not defined for: " ++ show m)

inverseNExpression :: NExpression -> NExpression
-- inverseNExpression m | trace ("inverseNExpression\n\tmessage: " ++ show m) False = undefined
inverseNExpression (NEPub m n) = NEPriv m n
inverseNExpression (NEPriv m n) = NEPub m n
inverseNExpression m = m

arityOfNExpression :: NExpression -> Int
-- arityOfNExpression e | trace ("arityOfNExpression\n\te: " ++ show e) False = undefined
arityOfNExpression (NECat xs) = length xs
arityOfNExpression (NEVar _ e) = arityOfNExpression e
arityOfNExpression _ = 1

sizeOfNExpression :: NExpression -> Int
sizeOfNExpression (NEVar _ _)  = 1
sizeOfNExpression (NEName _) = 1
sizeOfNExpression (NEPub m _)  = 1 + sizeOfNExpression m
sizeOfNExpression (NEPriv m _) = 1 + sizeOfNExpression m
sizeOfNExpression (NEHash m) = 1 + sizeOfNExpression m
sizeOfNExpression (NEHmac m n) = 1 + max (sizeOfNExpression m) (sizeOfNExpression n)
sizeOfNExpression (NEEnc m n) = 1 + max (sizeOfNExpression m) (sizeOfNExpression n)
sizeOfNExpression (NESign m n) = 1 + max (sizeOfNExpression m) (sizeOfNExpression n)
sizeOfNExpression (NEEncS m n) = 1 + max (sizeOfNExpression m) (sizeOfNExpression n)
sizeOfNExpression (NEDec m n) = 1 + max (sizeOfNExpression m) (sizeOfNExpression n)
sizeOfNExpression (NEVerify m n) = 1 + max (sizeOfNExpression m) (sizeOfNExpression n)
sizeOfNExpression (NEDecS m n) = 1 + max (sizeOfNExpression m) (sizeOfNExpression n)
sizeOfNExpression (NEKap m n) = 1 + max (sizeOfNExpression m) (sizeOfNExpression n)
sizeOfNExpression (NEKas m n) = 1 + max (sizeOfNExpression m) (sizeOfNExpression n)
sizeOfNExpression (NEFun _ n) = 1 + sizeOfNExpression n
sizeOfNExpression (NEXor m n) = 1 + max (sizeOfNExpression m) (sizeOfNExpression n)
sizeOfNExpression (NECat []) = 0
sizeOfNExpression (NECat [_]) = 1
sizeOfNExpression (NECat (x:xs)) =  1 + sizeOfNExpression x + sizeOfNExpression (NECat xs)
sizeOfNExpression (NEProj _ _ m) =  1 + sizeOfNExpression m

exprIsAgent :: NExpression -> Bool
exprIsAgent (NEName (JAgent,_)) = True
exprIsAgent _ = False

exprIsAgentKnown :: NExpression -> Bool
exprIsAgentKnown (NEName (JAgent,_)) = True
exprIsAgentKnown _ = False

agentOfNExpression :: NExpression -> Ident
agentOfNExpression ag@(NEName (_,id)) | exprIsAgent ag = id
agentOfNExpression e = error ("unexpected call of agentOfNExpression for expr: " ++ show e)

exprIsMessage :: NExpression -> Bool
exprIsMessage (NEName _) = True
exprIsMessage (NEEnc m n) = exprIsMessage m && exprIsMessage n
exprIsMessage (NESign m n) = exprIsMessage m && exprIsMessage n
exprIsMessage (NEEncS m n) = exprIsMessage m && exprIsMessage n
exprIsMessage (NEPub m _) = exprIsMessage m
exprIsMessage (NEPriv m _) = exprIsMessage m
exprIsMessage (NEHash m) = exprIsMessage m
exprIsMessage (NEHmac m n) = exprIsMessage m && exprIsMessage n
exprIsMessage (NEKap m n) = exprIsMessage m && exprIsMessage n
exprIsMessage (NEKas m n) = exprIsMessage m && exprIsMessage n
exprIsMessage (NEFun _ n) = exprIsMessage n
exprIsMessage (NEXor m n) = exprIsMessage m && exprIsMessage n
exprIsMessage (NECat []) = True
exprIsMessage (NECat xs) = all exprIsMessage xs
exprIsMessage _ = False    -- NEDec, verify or var expressions cannot be messages

exprIsConstantMessage:: NExpression -> Bool
exprIsConstantMessage (NEName (_,x)) = isConstant x
exprIsConstantMessage (NEEnc m n) = exprIsConstantMessage m && exprIsConstantMessage n
exprIsConstantMessage (NESign m n) = exprIsConstantMessage m && exprIsConstantMessage n
exprIsConstantMessage (NEEncS m n) = exprIsConstantMessage m && exprIsConstantMessage n
exprIsConstantMessage (NEPub m _) = exprIsConstantMessage m
exprIsConstantMessage (NEPriv m _) = exprIsConstantMessage m
exprIsConstantMessage (NEHash m) = exprIsConstantMessage m
exprIsConstantMessage (NEHmac m n) = exprIsConstantMessage m && exprIsConstantMessage n
exprIsConstantMessage (NEKap m n) = exprIsConstantMessage m && exprIsConstantMessage n
exprIsConstantMessage (NEKas m n) = exprIsConstantMessage m && exprIsConstantMessage n
exprIsConstantMessage (NEFun _ n) = exprIsConstantMessage n
exprIsConstantMessage (NEXor m n) = exprIsConstantMessage m && exprIsConstantMessage n
exprIsConstantMessage (NECat []) = True
exprIsConstantMessage (NECat xs) = all exprIsConstantMessage xs
exprIsConstantMessage _ = False   -- NEDec, verify or var expressions cannot be constant messages

exprContainsVar :: NExpression -> Bool
exprContainsVar (NEVar _ _) = True
exprContainsVar (NEName _) = False
exprContainsVar (NEEnc m n) = exprContainsVar m || exprContainsVar n
exprContainsVar (NESign m n) = exprContainsVar m || exprContainsVar n
exprContainsVar (NEEncS m n) = exprContainsVar m || exprContainsVar n
exprContainsVar (NEDec m n) = exprContainsVar m || exprContainsVar n
exprContainsVar (NEVerify m n) = exprContainsVar m || exprContainsVar n
exprContainsVar (NEDecS m n) = exprContainsVar m || exprContainsVar n
exprContainsVar (NEPub m _) = exprContainsVar m
exprContainsVar (NEPriv m _) = exprContainsVar m
exprContainsVar (NEHash m) = exprContainsVar m
exprContainsVar (NEHmac m n) = exprContainsVar m || exprContainsVar n
exprContainsVar (NEKap m n) = exprContainsVar m || exprContainsVar n
exprContainsVar (NEKas m n) = exprContainsVar m || exprContainsVar n
exprContainsVar (NEFun _ n) = exprContainsVar n
exprContainsVar (NEXor m n) = exprContainsVar m || exprContainsVar n
exprContainsVar (NECat []) = False
exprContainsVar (NECat xs) = any exprContainsVar xs
exprContainsVar (NEProj _ _ m) = exprContainsVar m

isKeyFromPKFun :: AnBxPKeysFun -> String -> Bool
isKeyFromPKFun pkf pk = isPKFun pk && isPKFunR pkf && getKeyFun pk == pkf

-- only these public key patterns are allowed
exprIsPublicKey :: NExpression -> Bool
exprIsPublicKey e
    | exprIsPublicKeyFresh e = True
    | exprIsPublicKeyAgentKnown e = True
    | exprIsPublicKeyAgentLearned e = True
    | otherwise = error ("Unexpected PublicKey format: " ++ show e)

-- only these Private key patterns are allowed
exprIsPrivateKey :: NExpression -> Bool
exprIsPrivateKey e
    | exprIsPrivateKeyFresh e = True
    | exprIsPrivateKeyAgentKnown e = True
    | exprIsPrivateKeyAgentLearned e = True
    | otherwise = error ("Unexpected PrivateKey format: " ++ show e)

-- freshly generated public key
exprIsPublicKeyFresh :: NExpression -> Bool
exprIsPublicKeyFresh (NEPub (NEName (JPublicKey Nothing,_)) Nothing) = True
exprIsPublicKeyFresh _ = False

-- public key from PKFun (pk) of known Agent (ag)
exprIsPublicKeyAgentKnown :: NExpression -> Bool 
exprIsPublicKeyAgentKnown (NEPub (NEFun (_,pk) ag) (Just pkf)) | exprIsAgentKnown ag && isKeyFromPKFun pkf pk = True
exprIsPublicKeyAgentKnown _ = False

-- public key from PKFun (pk) of learned agent expr
exprIsPublicKeyAgentLearned :: NExpression -> Bool 
exprIsPublicKeyAgentLearned (NEPub (NEFun (_,pk) _) (Just pkf)) | isKeyFromPKFun pkf pk = True
exprIsPublicKeyAgentLearned _ = False

-- freshly generated Private key
exprIsPrivateKeyFresh :: NExpression -> Bool
exprIsPrivateKeyFresh (NEPriv (NEName (JPublicKey Nothing,_)) Nothing) = True
exprIsPrivateKeyFresh _ = False

-- private key from PKFun (pk) of known Agent (ag)
exprIsPrivateKeyAgentKnown :: NExpression -> Bool 
exprIsPrivateKeyAgentKnown (NEPriv (NEFun (_,pk) ag) (Just pkf)) | exprIsAgentKnown ag && isKeyFromPKFun pkf pk = True
exprIsPrivateKeyAgentKnown _ = False

-- private key from PKFun (pk) of learned agent expr
exprIsPrivateKeyAgentLearned :: NExpression -> Bool 
exprIsPrivateKeyAgentLearned (NEPriv (NEFun (_,pk) _) (Just pkf)) | isKeyFromPKFun pkf pk = True
exprIsPrivateKeyAgentLearned _ = False

agentOfKey :: NExpression -> Ident
agentOfKey (NEPriv (NEFun _ (NEName (JAgent,ag))) (Just _)) = ag
agentOfKey (NEPub (NEFun _ (NEName (JAgent,ag))) (Just _)) = ag
agentOfKey e = error ("agentOfKey - unexpected request for: " ++ show e)

-- creation of public key expression
keyOfIdent :: Maybe AnBxPKeysFun -> Ident -> NExpression
keyOfIdent (Just pk) id = NEPub (NEFun (t,show pk) (NEName (JAgent, id))) (Just pk)
                            where t = JFunction PubFun (JAgent,JPublicKey (Just pk))
keyOfIdent Nothing id = NEPub (NEName (JPublicKey Nothing,id)) Nothing    

-- creation of private key expression
keyOfIdentPriv :: Maybe AnBxPKeysFun -> Ident -> NExpression
keyOfIdentPriv pk id = let
                          e = keyOfIdent pk id
                       in case e of 
                              NEPub e1 e2 ->  NEPriv e1 e2
                              _ -> error ("keyOfIdentPriv - unxpected request for: " ++ show e)


isSubExpr :: NExpression -> NExpression -> Bool
isSubExpr = isSubExprBase SEStd

isSubExprCSE :: NExpression -> NExpression -> Bool
isSubExprCSE = isSubExprBase SECSE

data SubExprType = SEStd | SECSE

-- base function for sub expression detection; usually the 2 pars functions are used
isSubExprBase :: SubExprType -> NExpression -> NExpression  -> Bool
-- isSubExprBase _ e f | trace ("isSubExprBase\n\te: " ++ show e ++ "\n\tf: " ++ show f) False = undefined
isSubExprBase set e f = (e==f) || case f of
                            NEVar _ _ -> False
                            NEName _-> False
                            NEEnc f1 f2 -> isSubExprBase set e f1  || isSubExprBase set e f2
                            NESign f1 f2 -> isSubExprBase set e f1  || isSubExprBase set e f2
                            NEEncS f1 f2 -> isSubExprBase set e f1 || isSubExprBase set e f2
                            NEDec f1 f2 -> isSubExprBase set e f1 || isSubExprBase set e f2
                            NEVerify f1 f2 -> isSubExprBase set e f1  || isSubExprBase set e f2
                            NEDecS f1 f2 -> isSubExprBase set e f1 || isSubExprBase set e f2
                            NEPub f _ -> case set of
                                            SECSE -> False
                                            SEStd -> isSubExprBase set e f
                            NEPriv f _ -> case set of
                                            SECSE -> False
                                            SEStd -> isSubExprBase set e f
                            NEHash f -> isSubExprBase set e f
                            NEHmac f1 f2 -> isSubExprBase set e f1 || isSubExprBase set e f2
                            NEKap f1 f2 -> case set of
                                            SECSE -> False
                                            SEStd -> isSubExprBase set e f1 || isSubExprBase set e f2
                            NEKas f1 f2 -> case set of
                                            SECSE -> False
                                            SEStd -> isSubExprBase set e f1 || isSubExprBase set e f2
                            NEFun _ f2 -> isSubExprBase set e f2
                            NEXor f1 f2 -> isSubExprBase set e f1 || isSubExprBase set e f2
                            NECat [] -> False
                            NECat xs -> any (isSubExprBase set e) xs
                            NEProj _ _ f1 -> isSubExprBase set e f1

nameOrVarOf :: NExpression -> NExpression
nameOrVarOf m@(NEVar _ _) = m
nameOrVarOf m@(NEName _) = m
nameOrVarOf (NEEnc m n) = case nameOrVarOf m of
                                        NEVar _ _ -> nameOrVarOf n
                                        m -> m
nameOrVarOf (NESign m n) = case nameOrVarOf m of
                                        NEVar _ _ -> nameOrVarOf n
                                        m -> m
nameOrVarOf (NEEncS m n) = case nameOrVarOf m of
                                        NEVar _ _ -> nameOrVarOf n
                                        m -> m

nameOrVarOf (NEDec m n) = case nameOrVarOf m of
                                        NEVar _ _ -> nameOrVarOf n
                                        m -> m
nameOrVarOf (NEVerify m n) = case nameOrVarOf m of
                                        NEVar _ _ -> nameOrVarOf n
                                        m -> m
nameOrVarOf (NEDecS m n) = case nameOrVarOf m of
                                        NEVar _ _ -> nameOrVarOf n
                                        m -> m
nameOrVarOf (NEPub m _) = nameOrVarOf m
nameOrVarOf (NEPriv m _) = nameOrVarOf m
nameOrVarOf (NEHash m) = nameOrVarOf m
nameOrVarOf (NEHmac m n) = case nameOrVarOf m of
                                                NEVar _ _ -> nameOrVarOf n
                                                m -> m
nameOrVarOf (NEKap m n) = case nameOrVarOf m of
                                                NEVar _ _ -> nameOrVarOf n
                                                m -> m
nameOrVarOf (NEKas m n) = case nameOrVarOf m of
                                                NEVar _ _ -> nameOrVarOf n
                                                m -> m
nameOrVarOf (NEFun _ n) = nameOrVarOf n
nameOrVarOf (NEXor m n) = case nameOrVarOf m of
                                                NEVar _ _ -> nameOrVarOf n
                                                m -> m
nameOrVarOf m@(NECat []) = error ("nameOrVarOf failed for message " ++ show m)
nameOrVarOf (NECat [x]) = nameOrVarOf x
nameOrVarOf (NECat (x:xs)) = case nameOrVarOf x of
                                                NEVar _ _ -> nameOrVarOf (NECat xs)
                                                x -> x
nameOrVarOf (NEProj _ _ m) = nameOrVarOf m


{- Contains data structures and printing functions for jtype -}

-- maps AnBx Types to Java Types
-- concrete types are declared in AstJavaCodeGenConfig.hs

data JType =
               JAgent
             | JString | JInt | JBool | JVoid
             | JSeqNumber | JNonce
             | JPublicKey (Maybe AnBxPKeysFun) | JPrivateKey (Maybe AnBxPKeysFun)
             | JKeyPair   -- used for fresh Private/Public key pairs 
             | JSymmetricKey
             | JHmacKey
             | JFunction PrivateFunction (JType, JType)
             | NEVarArgs
             | JObject | JConstant JType
             | JUntyped | JPurpose
             | JDHBase | JDHPubKey | JDHSecret | JDHSecKey
             | SealedPair JType
             | SignedObject JType
             | SealedObject JType
             | JHmac
             | JHash
             | AnBxParams [JType]
             | JAnBSession
             | JUserDef String               -- used to refer to specific types in Java code
        deriving (Eq,Typeable,Data,Show,Ord)

-- determine if a type is mapped to Number in AnB/OFMC
isTypeNonceAnB :: JType -> Bool
isTypeNonceAnB t = case t of
                    SealedPair _ -> True
                    SealedObject _ -> True
                    SignedObject _ -> True
                    JHmac -> True
                    JHash -> True
                    JSeqNumber -> True
                    JString -> True
                    _ -> False

showTypeError :: JType -> [a]
showTypeError t = error ("cannot show type " ++ show t)

varsOfNExpression :: NExpression -> Set.Set NEIdent
-- varsOfNExpression e  | trace ("varsOfNExpression: " ++ show e) False = undefined
varsOfNExpression e@(NEName (JPublicKey Nothing,_)) = error ("varsOfNExpression - unexpected expression " ++ show e) --Set.singleton n
varsOfNExpression e@(NEName (JPrivateKey Nothing,_)) = error ("varsOfNExpression - unexpected expression " ++ show e) -- Set.empty -- no need to add a name for freshly generated keys
-- varsOfNExpression (NEName (JPublicKey (Just _),_) (Just _)) = Set.empty -- no need to add a name for public/private keys
-- varsOfNExpression (NEName (JPrivateKey (Just _),_) (Just _)) = Set.empty
-- varsOfNExpression (NEName n@(JAgent,id) _) = if isHonest id then Set.empty else Set.singleton n
varsOfNExpression (NEName n) = Set.singleton n -- if isVarId id then Set.empty else Set.singleton n
varsOfNExpression (NEVar n _) = Set.singleton n
varsOfNExpression (NEEnc m n) = Set.union (varsOfNExpression m) (varsOfNExpression n)
varsOfNExpression (NEEncS m n) = Set.union (varsOfNExpression m) (varsOfNExpression n)
varsOfNExpression (NEDec m n) = Set.union (varsOfNExpression m) (varsOfNExpression n)
varsOfNExpression (NEDecS m n) = Set.union (varsOfNExpression m) (varsOfNExpression n)
varsOfNExpression (NESign m n) = Set.union (varsOfNExpression m) (varsOfNExpression n)
varsOfNExpression (NEVerify m n) = Set.union (varsOfNExpression m) (varsOfNExpression n)
varsOfNExpression (NEHash m) = varsOfNExpression m
varsOfNExpression (NEHmac m n) = Set.union (varsOfNExpression m) (varsOfNExpression n)
varsOfNExpression (NEKap m n) = Set.union (varsOfNExpression m) (varsOfNExpression n)
varsOfNExpression (NEKas m n) = Set.union (varsOfNExpression m) (varsOfNExpression n)
varsOfNExpression (NEFun _ m) = varsOfNExpression m
varsOfNExpression (NEXor m n) = Set.union (varsOfNExpression m) (varsOfNExpression n)
varsOfNExpression (NECat [x]) = varsOfNExpression x
varsOfNExpression (NECat (x : xs)) = Set.union (varsOfNExpression x) (varsOfNExpression (NECat xs))
varsOfNExpression (NEProj _ _ m) = varsOfNExpression m
varsOfNExpression _ = Set.empty

varAgentsOfNExpression :: NExpression -> [NEIdent]
-- varAgentsOfNExpression e  | trace ("varsAgentsOfNExpression: " ++ show e) False = undefined
varAgentsOfNExpression (NEName n@(JAgent,_)) = [n]
varAgentsOfNExpression (NEName _) = []
varAgentsOfNExpression (NEVar _ _) = []
varAgentsOfNExpression (NEEnc m n) = varAgentsOfNExpression m ++ varAgentsOfNExpression n
varAgentsOfNExpression (NEEncS m n) = varAgentsOfNExpression m ++ varAgentsOfNExpression n
varAgentsOfNExpression (NEDec m n) = varAgentsOfNExpression m ++ varAgentsOfNExpression n
varAgentsOfNExpression (NEDecS m n) = varAgentsOfNExpression m ++ varAgentsOfNExpression n
varAgentsOfNExpression (NESign m n) = varAgentsOfNExpression m ++ varAgentsOfNExpression n
varAgentsOfNExpression (NEVerify m n) = varAgentsOfNExpression m ++ varAgentsOfNExpression n
varAgentsOfNExpression (NEHash m) = varAgentsOfNExpression m
varAgentsOfNExpression (NEHmac m n) = varAgentsOfNExpression m ++ varAgentsOfNExpression n
varAgentsOfNExpression (NEKap m n) = varAgentsOfNExpression m ++ varAgentsOfNExpression n
varAgentsOfNExpression (NEKas m n) = varAgentsOfNExpression m ++ varAgentsOfNExpression n
varAgentsOfNExpression (NEFun _ m) = varAgentsOfNExpression m
varAgentsOfNExpression (NEXor m n) = varAgentsOfNExpression m ++ varAgentsOfNExpression n
varAgentsOfNExpression (NECat (x : xs)) = varAgentsOfNExpression x ++  varAgentsOfNExpression (NECat xs)
varAgentsOfNExpression (NEProj _ _ m) = varAgentsOfNExpression m
varAgentsOfNExpression _ = []

-- set some restriction on shareable expressions in Java: names or Functions with names parameters
isSharableNExpression :: NExpression -> Bool
isSharableNExpression (NEFun _ m) = isSharableNExpressionParameters m
isSharableNExpression (NEName _) = True
isSharableNExpression _ = False

isSharableNExpressionParameters :: NExpression -> Bool
isSharableNExpressionParameters (NEName _) = True
isSharableNExpressionParameters (NECat xs) = all isNENameExpr xs
isSharableNExpressionParameters _ = False

isNENameExpr :: NExpression -> Bool
isNENameExpr (NEName _) = True
isNENameExpr _ = False

-- here we define a specific function for comparing types, used for typechecking
-- instance Eq cannot be used because we need to consider formats with Msg

compareTypes :: JType -> JType -> Bool
-- compareTypes t1 t2 | trace ("compareTypes\n\tt1: " ++ show t1 ++ "\n\tt2: " ++ show t2) False = undefined 
compareTypes (JFunction _ (xs1,xs3)) (JFunction _ (xs2,xs4)) = compareTFormatsTypes xs1 xs2 && compareTFormatsTypes xs3 xs4
compareTypes (AnBxParams xs1) (AnBxParams xs2) = length xs1 == length xs2 && and (zipWith compareTFormatsTypes xs1 xs2)
compareTypes NEVarArgs _ = True                       -- if the expected type is NEVarArgs, everything is accepted
compareTypes t1 t2 = compareTFormatsTypes t1 t2

compareTFormatsTypes :: JType -> JType -> Bool
compareTFormatsTypes JNonce JString = True
compareTFormatsTypes JString JNonce = True
compareTFormatsTypes JNonce JSeqNumber = True
compareTFormatsTypes JSeqNumber JNonce = True
compareTFormatsTypes JSeqNumber JString = True
compareTFormatsTypes JString JSeqNumber = True
compareTFormatsTypes JNonce JHash = True
compareTFormatsTypes JHash JNonce = True
compareTFormatsTypes JSymmetricKey JDHSecKey = True
compareTFormatsTypes JDHSecKey JSymmetricKey = True
compareTFormatsTypes (JConstant t1) (JConstant t2) = compareTypes t1 t2  -- for constants compare the actual type
compareTFormatsTypes (JConstant t1) t2 = compareTypes t1 t2
compareTFormatsTypes t1 (JConstant t2) = compareTypes t1 t2
-- userdef types that are identical to other types are treated as equal
compareTFormatsTypes (JUserDef t1) (JUserDef t2)= t1 == t2
compareTFormatsTypes (JUserDef t1) t2 = t1 == show t2
compareTFormatsTypes t1 (JUserDef t2) = t2 == show t1
compareTFormatsTypes t1 t2 = t1==t2

-- needed to specify whether the use of the type (function) requires to reference the protocol session in Java
requiresSession :: JType -> Bool
requiresSession JSeqNumber = True
requiresSession JNonce = True
requiresSession (JPublicKey _) = True
requiresSession JSymmetricKey = True
requiresSession JHmacKey = True
requiresSession (JFunction _ (_, t)) = requiresSession t
requiresSession JDHBase = True
requiresSession JDHPubKey = True
requiresSession JDHSecret = True
requiresSession JDHSecKey = True
requiresSession (SealedPair _) = True
requiresSession (SignedObject _) = True
requiresSession (SealedObject _) = True
requiresSession JHmac = True
requiresSession JHash = True
requiresSession _ = False

{- ---------------------
       BINDING
 ----------------------- -}

data Binding = VarBind JType
               deriving (Eq,Typeable,Data,Show)
