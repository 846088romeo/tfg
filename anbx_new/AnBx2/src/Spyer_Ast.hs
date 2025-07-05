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

module Spyer_Ast where
import AnBxMsgCommon
import Spyer_Message
import Data.List ( intercalate, sort )
import Java_TypeSystem_JType
import Data.Containers.ListUtils (nubOrd)

data Exchange = XSend (String,String,NExpression) | XComment String
instance Show Exchange where
    show :: Exchange -> String
    show (XSend(a,b,m)) = a ++ " -> " ++ b ++ " : " ++ show m
    show (XComment s) = "(* " ++ s ++ " *)"

type NEShare = (ShareType,NEIdent,NExpression,[NEIdent])       -- share type, ident, expression (relevant only for abstractions), agents

data Declaration = DKnow (NEIdent,NExpression)                                    -- agent, expr
                 | DGenerates (NEIdent,NExpression)                               -- agent, expr
                 | DShare NEShare
               deriving (Eq)

instance Show Declaration where
    show :: Declaration -> String
    show (DKnow ((_,a),NEName (_,"hash"))) = "(* " ++ a ++ " know " ++ "hash" ++ " *)" -- hash is a reserved word in spyer
    show (DKnow ((_,a),m)) = a ++ " know " ++ show m
    show (DGenerates ((_,a),n)) =  a ++ " generates " ++ show n
    show (DShare (sh,(_,k),msg,ags)) = "private " ++ k ++ "     (* " ++ showNEIdentList ags ++ " " ++ show sh ++ " " ++ show msg ++ " *)"

type NEDeclaration = (String,[Declaration],NEquations) -- name,declaration,equations

type Narration = (NEDeclaration,[Exchange])

showDeclarationsCompact :: [Declaration] -> String
showDeclarationsCompact ds = let
                                     ag1 = [ a | DKnow (a,_) <- ds]
                                     ag2 = [ a | DGenerates (a,_) <- ds]
                                     agents = sort $ nubOrd (ag1 ++ ag2)
                                     ag_knows = map (\x -> (x,[ m | DKnow (a,m) <- ds, a == x])) agents
                                     ag_knows1 = [ x | x@(_,xs) <- ag_knows, not (null xs)]
                                     ag_generates = map (\x -> (x,[ m | DGenerates (a,m) <- ds, a == x])) agents
                                     ag_generates1 = [ x | x@(_,xs) <- ag_generates, not (null xs)]
                                     ag_share = [ x | x@(DShare _ ) <- ds]
                             in showDeclarationAgents ag_knows1 "knows" ++
                                showDeclarationAgents ag_generates1 "generates" ++
                                showDeclarations ag_share

showDeclarationAgent :: (NEIdent,[NExpression]) -> String -> String
showDeclarationAgent (_,[]) _ = ""
showDeclarationAgent ((_,a),xs) msg = a ++ " " ++ msg ++ ": " ++ intercalate "," (map show xs)

showDeclarationAgents :: [(NEIdent,[NExpression])] -> String -> String
showDeclarationAgents [] _ = ""
showDeclarationAgents ((_,[]):xs) msg = showDeclarationAgents xs msg
showDeclarationAgents (x:xs) msg = showDeclarationAgent x msg ++ "\n" ++ showDeclarationAgents xs msg

showDeclarations :: [Declaration] -> String
showDeclarations [] = ""
showDeclarations (d:ds) = show d ++ "\n" ++ showDeclarations ds

showExchanges :: [Exchange] -> String
showExchanges [] = ""
showExchanges (x:xs) = show x ++ "\n" ++ showExchanges xs

showNarration :: Narration -> String
showNarration ((protname,ds,es),xs) = "(* Protocol: " ++ protname ++ " *)" ++ "\n\n" ++
                                        (if null ds then "" else "(* Declarations *)\n" ++ showDeclarations ds ++ "\n") ++
                                        (if null es then "" else "(* Equations *)\n" ++ showEquations es ++ "\n") ++
                                        (if null xs then "" else "(* Actions *)\n" ++ showExchanges xs)
