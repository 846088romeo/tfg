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
{-# LANGUAGE StrictData #-}
{-# LANGUAGE InstanceSigs #-}

module AnBxMsg where

import AnBxMsgCommon

data AnBxMsg = Atom Ident
                | Comp Operator [AnBxMsg]
                | PrevSession AnBxMsg
                | DigestHash AnBxMsg
                | DigestHmac AnBxMsg Ident
               deriving (Eq,Ord)

instance Show AnBxMsg where show :: AnBxMsg -> String
                            show = ppMsg

isAnBMsg :: AnBxMsg -> Bool
isAnBMsg (Atom _) = True
isAnBMsg (Comp _ xs) = any isAnBMsg xs
isAnBMsg (DigestHash _) = False
isAnBMsg (DigestHmac _ _) = False

patternMsgError :: AnBxMsg -> String -> String
patternMsgError msg caller | isAnBMsg msg = caller ++ " - unhandled message: " ++ show msg
                           | otherwise = caller ++ " - expected message: " ++ show msg ++ "\n" ++ "at this stage, there should not be any " ++ show PTAnBx ++ " message extension"

syncMsgAst :: AnBxMsg
syncMsgAst = Atom syncMsg

-- | A folding operation on messages 
foldMsg :: (Ident -> a) -> (Operator -> [a] -> a) -> AnBxMsg -> a
foldMsg f _ (Atom a) = f a
foldMsg f g (Comp h xs) = g h (map (foldMsg f g) xs)
foldMsg f g (DigestHash x) = foldMsg f g x
foldMsg f g (DigestHmac x a) = g Cat (map (foldMsg f g) (x:[Atom a]))
-- foldMsg _ _ m = error ("unanble to foldMsg msg: " ++ show m)

-- | Identifiers (constants and variables) occuring in a given message
idents :: AnBxMsg -> [Ident]
idents = foldMsg return (const concat)

isAtom :: AnBxMsg -> Bool
isAtom (Atom _) = True
isAtom _ = False

isCat :: AnBxMsg -> Bool
isCat (Comp Cat _) = True
isCat _ = False

vars :: AnBxMsg -> [Ident]
vars = filter isVariable . idents

ppMsg :: AnBxMsg -> String
ppMsg (Atom x) = ppId x
ppMsg (Comp f xs) = case xs of
                        [] -> error ("ppMsg - empty list of arguments in Comp " ++ show f)
                        _ -> case f of
                                Cat -> ppMsgList xs
                                Apply -> if isAtype (head xs) && hideTypes then ppMsgList (tail xs)
                                                else ppMsg (head xs) ++ if head xs == Atom (show AnBxHmac) then case tail xs of
                                                                                                                        [Comp Cat mm@(m:_)] -> "(" ++ case m of
                                                                                                                                Comp Cat _ -> "(" ++ ppMsgList (init mm) ++ ")"
                                                                                                                                _ -> ppMsgList (init mm)
                                                                                                                            ++ "," ++ ppMsg (last mm) ++")"
                                                                                                                        _ -> "((" ++ ppMsgList (init(tail xs)) ++ ")," ++ ppMsg (last xs) ++")"
                                                                                                                    else "(" ++ ppMsgList (tail xs) ++ ")"
                                Crypt -> "{" ++ (ppMsg . head . tail) xs ++ "}" ++ ppMsg (head xs)
                                Scrypt -> "{|" ++ (ppMsg . head . tail) xs ++ "|}" ++ ppMsg (head xs)
                                Inv -> "inv(" ++ (ppMsg.head) xs ++ ")"
                                Exp -> "exp(" ++ ppMsgList xs ++ ")"
                                Xor -> "xor(" ++ ppMsgList xs ++ ")"
                                _ -> show f ++ "(" ++ ppMsgList xs ++ ")"
-- digests
ppMsg (DigestHash msg) = "[" ++ ppMsg msg ++ "]"
ppMsg (DigestHmac msg ident) = "[" ++ ppMsg msg ++ ":" ++ ident ++ "]"

--deCat :: AnBxMsg -> [AnBxMsg]
--deCat (Comp Cat ms) = ms
--deCat m = error ("deCAt applied to a non-Cat message "  ++ show m)

isAtype :: AnBxMsg -> Bool
isAtype (Atom x) = x `elem` typeNames
isAtype _ = False

isntFunction :: AnBxMsg -> Bool
isntFunction (Comp Apply (Atom "typeFun":_)) = False
isntFunction _ = True

ppMsgList :: [AnBxMsg] -> String
ppMsgList list = ppXList ppMsg "," list

firstorder :: AnBxMsg -> Bool
firstorder (Comp Apply [Atom "typeFun",_]) = False
firstorder _ = True
