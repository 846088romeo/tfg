{-

 AnBx Compiler and Code Generator


 Copyright 2011-2025 Paolo Modesti
 Copyright 2021 Rémi Garcia
 Copyright 2018-2025 SCM/SCDT/SCEDT, Teesside Universityy
 Copyright 2016-2018 School of Computer Science, University of Sunderland
 Copyright 2013-2015 School of Computing Science, Newcastle University
 Copyright 2011-2012 DAIS, Universita' Ca' Foscari Venezia
   
 This file is part of AnBx

 AnBx is free software: you can redistribute it and/or modify
 it under the Msgs of the GNU General Public License as published by
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
{-# LANGUAGE BangPatterns #-}

module AnBTypeSystem_Evaluator where

import AnBxMsgCommon
import AnBxMsg ( AnBxMsg (..))
import AnBAst
import AnBTypeSystem_Context
import Debug.Trace
import Control.Monad.Writer
import Data.Maybe
import qualified Data.Map as Map
import AnBxAst (AnBxType(..), TO (..), AnBType (..))

{- ----------------------------
   TYPING
 ---------------------------- -}

typeErrorMsg :: String -> Msg -> [AnBType] -> [AnBType] -> AnBContext -> String
typeErrorMsg s m xs ts ctx = "AnBType - incompatible type error: " ++ s ++
                             "\n\tMsg: " ++ show m ++
                             "\n\ttype(s): " ++ show xs ++
                             (if not (null ts) then "\n\texpected: " ++ show ts else "")
                             ++ "\n\tctx: " ++ show ctx

typeErrorArity :: String -> Int -> String -> String
typeErrorArity errormsg found expected = errormsg ++ "(wrong number of arguments: " ++ show found ++ "insted of " ++ expected ++")"

newtype Error = Error String deriving (Show)
type TC = Writer [Error]

typeofTSCatList :: [Msg] -> AnBContext -> [AnBType]
typeofTSCatList xs ctx = map (\x -> fst (runWriter (typeofTSM x ctx))) xs

typeofTS :: Msg -> AnBContext -> AnBType
typeofTS e ctx = fst (runWriter (typeofTSM e ctx))

typeofTSM :: Msg -> AnBContext -> TC AnBType
-- typeofTSM Msg ctx | trace ("typeofTSM (AnB)\n\tMsg: " ++ show Msg ++ "\n\tcontext: " ++ show ctx) False = undefined 

typeofTSM (Atom id) (AnBContext ns) = let
                                        bd = Map.lookup id ns
                                        (VarBind t) = case bd of
                                                        Just e -> e
                                                        Nothing -> error ("typeofTSM - TypeSystem (AnB) - identifier " ++ show id ++ " does not exist in " ++ show ns)
                                      in do
                                            when (isNothing bd) $
                                                tell [Error ("typeofTSM - TypeSystem (AnB) - identifier " ++ show id ++ " does not exist in " ++ show ns)]
                                            return t
typeofTSM m@(Comp Cat []) ctx = do
                                    tell  [Error (typeErrorMsg (typeErrorArity "TCat" 0 "1+" ) m [] [] ctx)]
                                    return (error ("error in " ++ show m))

typeofTSM (Comp Cat [x]) ctx = do
                                    typeofTSM x ctx

typeofTSM (Comp Cat xs) ctx = return (TCat (typeofTSCatList xs ctx))

typeofTSM m@(Comp Crypt []) ctx = do
                                    tell  [Error (typeErrorMsg (typeErrorArity "asymmetric encryption {...}K" 0 "2+") m [] [] ctx)]
                                    return (error ("error in " ++ show m))

typeofTSM m@(Comp Crypt [x]) ctx = do
                                    !_ <- typeofTSM x ctx
                                    tell  [Error (typeErrorMsg (typeErrorArity "asymmetric encryption {...}K" 1 "2+") m [] [] ctx)]
                                    return (error ("error in " ++ show m))

typeofTSM m@(Comp Crypt (x:xs)) ctx = do
                                    tx <- typeofTSM x ctx               -- key
                                    txs <- typeofTSM (Comp Cat xs) ctx  -- payload
                                    when (not (compareTypes tx (BaseType (PublicKey []))) && not (compareTypes tx TPrivateKey)) $
                                         tell [Error (typeErrorMsg ("asymmetric encryption {...}K (expected key of type " ++ show (BaseType (PublicKey [])) ++ " or " ++ show TPrivateKey ++ ")")  m [tx] [] ctx)]
                                    return (TCrypt txs)

typeofTSM m@(Comp Scrypt []) ctx = do
                                    tell  [Error (typeErrorMsg (typeErrorArity "symmetric encryption {|...|}K" 0 "2+") m [] [] ctx)]
                                    return (error ("error in " ++ show m))

typeofTSM m@(Comp Scrypt [x]) ctx = do
                                    !_ <- typeofTSM x ctx
                                    tell [Error (typeErrorMsg (typeErrorArity "symmetric encryption {|...|}K" 1 "2+") m [] [] ctx)]
                                    return (error ("error in " ++ show m))

typeofTSM m@(Comp Scrypt (x:xs)) ctx = do
                                    tx <- typeofTSM x ctx               -- key
                                    txs <- typeofTSM (Comp Cat xs) ctx  -- payload
                                    unless (compareTypes tx (BaseType (SymmetricKey []))) $
                                         tell [Error (typeErrorMsg "symmetric encryption {|...|}K" m [tx] [BaseType (SymmetricKey [])] ctx)]
                                    return (TScrypt txs)

typeofTSM m@(Comp Apply []) ctx = do
                                    tell  [Error (typeErrorMsg (typeErrorArity "apply function" 0 "1+") m [] [] ctx)]
                                    return (error ("error in " ++ show m))

typeofTSM m@(Comp Apply xs) ctx = let
                                    tx = typeofTSM (head xs) ctx
                                    t = fst (runWriter tx)
                                    errMsg = show t ++ " " ++ show (head xs)
                                  in case t of
                                        BaseType (Function [FunSign (t1,t2,_)]) -> do
                                           !_ <- typeofTSM (Comp Cat (tail xs)) ctx
                                           unless (compareTypesList t1' t3) $
                                                tell [Error (typeErrorMsg errMsg m t3 t1' ctx)]
                                           return (BaseType t2)
                                           where
                                            t1' = map BaseType t1
                                            t3  = case typeofTSCatList (tail xs) ctx of
                                                [TCat x] -> x
                                                x -> x
                                        BaseType (Function []) -> do    -- no type signature provided
                                                !_ <- typeofTSM (Comp Cat (tail xs)) ctx
                                                when True $
                                                    tell []
                                                -- return (BaseType Number [])
                                                return (BaseType (Untyped []))
                                        _ -> do
                                              !_ <- typeofTSM (Comp Cat (tail xs)) ctx
                                              when True $
                                                tell [Error (typeErrorMsg ("not a function type " ++ errMsg) m [t] [] ctx)]
                                              -- return (BaseType Number [])
                                              return (BaseType (Untyped []))

typeofTSM m@(Comp Inv [x]) ctx = do
                                    tx <- typeofTSM x ctx
                                    unless (compareTypes tx (BaseType (PublicKey []))) $
                                         tell [Error (typeErrorMsg (show AnBxInv) m [tx] [BaseType (PublicKey [])] ctx)]
                                    return TPrivateKey
typeofTSM m@(Comp Inv xs) ctx = do
                                 !_ <- typeofTSM (Comp Cat xs) ctx
                                 tell [Error (typeErrorMsg (typeErrorArity (show AnBxInv) (length xs) "1") m t [BaseType (PublicKey [])] ctx)]
                                 return TPrivateKey
                                 where
                                    t = typeofTSCatList xs ctx

-- DH
typeofTSM m@(Comp Exp [Comp Exp [g,x],y]) ctx = do
                                    tx <- typeofTSM x ctx
                                    ty <- typeofTSM y ctx
                                    tg <- typeofTSM g ctx
                                    unless (compareTypes tg (BaseType (Number [])) && compareTypes tx (BaseType (Number [])) && compareTypes tx (BaseType (Number []))) $
                                         tell [Error (typeErrorMsg (show AnBxExp) m [tg,tx,ty] [BaseType (Number []),BaseType (Number []),BaseType (Number [])] ctx)]
                                    return (BaseType (SymmetricKey []))
typeofTSM m@(Comp Exp [g,x]) ctx = do
                                    tx <- typeofTSM x ctx
                                    tg <- typeofTSM g ctx
                                    unless (compareTypes tg (BaseType (Number [])) && compareTypes tx (BaseType (Number []))) $
                                         tell [Error (typeErrorMsg (show AnBxExp) m [tg,tx] [BaseType (Number []),BaseType (Number [])] ctx)]
                                    return (BaseType (Number []))

typeofTSM m@(Comp Exp xs) ctx = do
                                 !_ <- typeofTSM (Comp Cat xs) ctx
                                 tell [Error (typeErrorMsg (typeErrorArity (show AnBxExp) (length xs) "2") m t [BaseType (Number []),BaseType (Number [])] ctx)]
                                 return (BaseType (Number []))
                                 where
                                    t = typeofTSCatList xs ctx
-- XOR
typeofTSM m@(Comp Xor [x,y]) ctx = do
                                   tx <- typeofTSM x ctx
                                   ty <- typeofTSM y ctx
                                   unless (compareTypes ty (BaseType (Number [])) && compareTypes tx (BaseType (Number []))) $
                                        tell [Error (typeErrorMsg (show AnBxXor) m [tx,ty] [] ctx)]
                                   return (BaseType (Number []))

typeofTSM m@(Comp Xor xs) ctx = do
                                 !_ <- typeofTSM (Comp Cat xs) ctx
                                 tell [Error (typeErrorMsg (typeErrorArity (show AnBxXor) (length xs) "2") m t [] ctx)]
                                 return (BaseType (Number []))
                                 where
                                    t = typeofTSCatList xs ctx

-- userdef (really used?)

typeofTSM m@(Comp (Userdef f) []) ctx = do
                                    tell  [Error (typeErrorMsg (typeErrorArity ("function " ++ f) 0 "1+") m [] [] ctx)]
                                    return (error ("error in " ++ show m))

typeofTSM m@(Comp (Userdef f) xs) ctx | f == show AnBxHash  = do
                                                                !_ <- typeofTSM (Comp Cat xs) ctx
                                                                return THash

                                      | f == show AnBxHmac = do
                                                                tx <- typeofTSM (head xs) ctx
                                                                !_ <- typeofTSM (Comp Cat (tail xs)) ctx
                                                                unless (compareTypes tx (BaseType (SymmetricKey []))) $
                                                                    tell [Error (typeErrorMsg "hmac(_,K)" m [tx] [BaseType (SymmetricKey [])] ctx)]
                                                                return THMac

                                      | otherwise = do
                                                        !_ <- typeofTSM (Comp Cat xs) ctx
                                                        return (BaseType (Number []))

typeofTSM (DigestHash msg) ctx = do 
                                    !_ <- typeofTSM msg ctx
                                    return THash
typeofTSM (DigestHmac msg id) ctx = do 
                                        !_ <- typeofTSM (Atom id) ctx
                                        !_ <- typeofTSM msg ctx
                                        return THMac

-- typeofTSM m _ = error $ patternMsgError m "typeofTSM (AnBType)"