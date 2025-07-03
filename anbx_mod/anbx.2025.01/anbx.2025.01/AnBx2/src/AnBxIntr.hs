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

module AnBxIntr where

import AnBxAst
import AnBAst (isVarId)
import AnBxDefinitions
import AnBxMain
import AnBxMsgCommon
import AnBxOnP
import AnBxMsg
import Data.List ((\\))
import Data.Containers.ListUtils (nubOrd)

buildAnBxIntr :: AnBxProtocol -> AnBxOnP -> Ident -> AnBxProtocol
buildAnBxIntr anbxprot anbxonp intr = let
                                    outtype = anbxouttype anbxonp
                                    anbxprot1 = mkAnB anbxprot anbxonp
                                    newprotname = getProtName anbxprot1 ++ (if outtype == AnBxIntr || outtype == AnBIntr then "_" ++ intr else "")
                                    anbxprot2 = renameProtocol anbxprot1 newprotname
                                    anbxprot3 = addAnBxIntr anbxprot2 anbxonp intr
                                 in anbxprot3

addAnBxIntr :: AnBxProtocol -> AnBxOnP -> Ident -> AnBxProtocol
addAnBxIntr ((protname,prottype),types,_,equations,(knowledge,wk),shares,abstraction,actions,goals) anbxonp intr = let
                                                                                                      optPubIntrK = anbxmitmpubknowledge anbxonp
                                                                                                      agents = getAgents types
                                                                                                      types1 = mapAnBxIntrTypes types intr optPubIntrK
                                                                                                      intrK = mapAnBxIntrKnowledge knowledge intr optPubIntrK
                                                                                                      wk1 = mapAnBxIntrKnowledgeWhere wk intr agents
                                                                                                      actions1 = mapAnBxIntrActions actions intr
                                                                                                      actions2 = if optPubIntrK then
                                                                                                                            let
                                                                                                                                (act0,act2) = partitionAction (actions1,[]) intr
                                                                                                                                -- insert the intruder action where  the initial knowledge is published
                                                                                                                                act1 = publishIntrK types intrK (firstPeer actions1)
                                                                                                                            in act0 ++ act1 ++ act2
                                                                                                                    else actions1
                                                                                                 in ((protname,prottype),types1,[],equations,(knowledge++[intrK],wk1),shares,abstraction,actions2,goals)

-- extract the functions identifiers from Types
functionsIDs :: AnBxTypes -> [Ident]
functionsIDs types = let
                        ids = [ fids | (AnBxAst.Function _,fids) <- types ]
                     in concat ids

-- divides the actions identifying the first one where intr is receiving a message
partitionAction :: (AnBxActions,AnBxActions) -> Ident -> (AnBxActions,AnBxActions)
partitionAction ([],_) _ = ([],[])
partitionAction ([x],__) _ = ([x],[])
partitionAction (x@((_,_,(id,_,_)),_,_,_):xs,xs0) intr = if id == intr then ([x],xs)
                                                                       else ([x] ++ fst (partitionAction (xs,[]) intr),xs0 ++ snd (partitionAction (xs,[]) intr))


publishIntrK :: AnBxTypes -> (Ident,[AnBxMsg]) -> AnBxPeer -> AnBxActions
publishIntrK types (intr,msgs) _ = let
                                        pi = ident2AnBxPeer intr
                                        fids = functionsIDs types
                                        msgs1 = msgs \\ ids2Msgs fids
                                        a1 = ((pi,Insecure,pi),msglist2msg msgs1,Nothing,Nothing)
                                   in [a1]

mapAnBxIntrTypes :: AnBxTypes -> Ident -> Bool -> AnBxTypes
mapAnBxIntrTypes types intr optPubIntrK = let
                                                types1 = if optPubIntrK then initTypes (AnBxAst.Number []) [syncMsg] AnBxAst.eqTypesStrict AnBxAst.elemTypes types
                                                                        else types
                                          in types1 ++ [(AnBxAst.Agent False False [] NoCert,[intr])]

mapAnBxIntrKnowledge :: AnBxKnowledgeAgents -> Ident -> Bool -> (Ident,[AnBxMsg])
mapAnBxIntrKnowledge knowledge intr optPubIntrK = let
                                            -- function to substitute agent id with intruder id
                                            subst a msgs  = map (\x -> AnBxDefinitions.substVar x (a,intr)) msgs
                                            knowledgeVarAgents = [ x | x@(a,_) <- knowledge, isVarId a ]
                                            -- applies the substitution a -> i for every message and concatenate (for VarAgents)
                                            i = concatMap (\(a,msgs) -> subst a msgs) knowledgeVarAgents
                                            -- new intr knowledge
                                            ids = if optPubIntrK then [intr,syncMsg] else [intr]
                                            intrK = (intr, nubOrd (ids2Msgs ids ++ i))
                                      in intrK

mapAnBxIntrKnowledgeWhere :: AnBxKnowledgeWhere -> Ident -> [Ident] -> AnBxKnowledgeWhere
mapAnBxIntrKnowledgeWhere wk intr agents = nubOrd (wk ++ map (\x -> (Atom x,Atom intr)) varagents)
                                                    where
                                                        varagents = [ x | x <- agents, isVarId x ]

mapAnBxIntrActions :: AnBxActions -> Ident -> AnBxActions
mapAnBxIntrActions actions intr = concatMap ( \x -> mapAnBxIntrAction x intr) actions

mapAnBxIntrAction :: AnBxAction -> Ident -> AnBxActions
mapAnBxIntrAction ((p1,ct@Insecure,p2),msg,msg1,msg2) intr = let
                                                        pi = ident2AnBxPeer intr
                                                        a1 = ((p1,ct,pi),msg,msg1,msg2)
                                                        a2 = ((pi,ct,p2),msg,msg1,msg2)
                                                    in [a1,a2]
mapAnBxIntrAction a _ = [a]
