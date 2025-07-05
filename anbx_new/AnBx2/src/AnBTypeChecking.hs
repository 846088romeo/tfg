
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

{-# LANGUAGE BangPatterns #-}
module AnBTypeChecking where

import AnBTypeSystem_Context
import AnBTypeSystem_Evaluator
import AnBAst
import Control.Monad.Writer
import Debug.Trace
import AnBxAst (AnBxChannelType (..), AnBxGoal (..), AnBxEquation (..))
import AnBxMsgCommon

typeCheckProtocol :: Protocol -> ProtType -> Protocol
typeCheckProtocol prot@(protocolname,types,definitions,equations,(ak,wk),shares,abstraction,actions,goals) prottype = let
                        ctx = buildContext prot prottype
                        !knowledge1 = (typeCheckKnowledgeAg ctx ak,typeCheckKnowledgeWh ctx wk)
                        !equations1 = map (typeCheckEquation ctx) equations
                        !actions1 = map (typeCheckAction ctx) actions
                        !goals1 = map (typeCheckGoal ctx) goals
                      in (protocolname,types,definitions,equations1,knowledge1,shares,abstraction,actions1,goals1)

typeCheckMsg :: a -> Msg -> AnBContext -> a
-- typeCheckMsg _ term ctx | trace ("typeCheckMsg\n\tterm: " ++ show term ++ "\n\tcontext: " ++ show ctx) False = undefined
typeCheckMsg a msg ctx = do
                            let (_, errs) = runWriter (typeofTSM msg ctx)
                            case errs of
                                [] -> a
                                _ -> error ("Errors:\n" ++ unlines (map fmt errs) ++ "Type check failed\n")
                                    where fmt (Error s) = s

typeCheckAction :: AnBContext -> Action -> Action
typeCheckAction _ a@((_,ActionComment _ _,_),_,_,_) = a
typeCheckAction ctx a@(_,msg,_,_) = typeCheckMsg a msg ctx

typeCheckEquation :: AnBContext -> AnBEquation  -> AnBEquation
typeCheckEquation ctx (Eqt msg1 msg2) = Eqt (typeCheckMsg msg1 msg1 ctx) (typeCheckMsg msg2 msg2 ctx)

typeCheckGoal :: AnBContext -> Goal -> Goal
typeCheckGoal ctx g@(ChGoal _ msg _) = typeCheckMsg g msg ctx
typeCheckGoal ctx g@(Secret msg _ _ _) = typeCheckMsg g msg ctx
typeCheckGoal ctx g@(Authentication _ _ msg _) = typeCheckMsg g msg ctx
typeCheckGoal ctx g@(WAuthentication _ _ msg _) = typeCheckMsg g msg ctx

typeCheckKnowledgeAg :: AnBContext -> [(Ident,[Msg])] -> [(Ident,[Msg])]
-- typeCheckKnowledgeAg ctx term | trace ("typeCheckKnowledgeAg\n\tterm: " ++ show term ++ "\n\tcontext: " ++ show ctx) False = undefined 
typeCheckKnowledgeAg _ [] = []
typeCheckKnowledgeAg ctx ((id,msgs):xs) = (id, map (\x -> typeCheckMsg x x ctx) msgs): typeCheckKnowledgeAg ctx xs

typeCheckKnowledgeWh :: AnBContext -> AnBKnowledgeWhere -> AnBKnowledgeWhere
typeCheckKnowledgeWh _ [] = []
typeCheckKnowledgeWh ctx ((msg1,msg2):xs) = (typeCheckMsg msg1 msg1 ctx,typeCheckMsg msg2 msg2 ctx) : typeCheckKnowledgeWh ctx xs
