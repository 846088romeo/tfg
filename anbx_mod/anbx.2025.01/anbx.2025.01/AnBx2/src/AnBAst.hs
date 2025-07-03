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
{-

Partly derived from
Open Source Fixedpoint Model-Checker version 2020

(C) Copyright Sebastian Moedersheim 2003,2020
(C) Copyright Paolo Modesti 2012
(C) Copyright Nicklas Bo Jensen 2012
(C) Copyright IBM Corp. 2009
(C) Copyright ETH Zurich (Swiss Federal Institute of Technology) 2003,2007

All Rights Reserved.

-}

{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "Use infix" #-}

module AnBAst where

import Data.Char
import Data.List ( (\\), intercalate )
import AnBxMsgCommon
import AnBxOnP
--import Debug.Trace
import qualified Data.Map as Map
import AnBxAst (AnBxType(..),TO (..), AnBxChannel, AnBxAction, AnBxChannelType (..), AnBxGoal (..), AnBxProtocol, AnBxEquation (Eqt), isAgentType, isFunctionType, inMsg, AnBxPeer, peerIsPseudo, AnBxKnowledge, AnBxKnowledgeAgents, AnBxKnowledgeWhere, AnBxTypes, AnBxAbstraction, AnBxShare, getActiveAgents)
import AnBxMsg (AnBxMsg(..), patternMsgError)
import Data.Containers.ListUtils (nubOrd)

-- | The type @Protocol@ is the type for the result of the AnB-Parser,
-- i.e. the topmost structure of the Abstract Syntax Tree (AST)

type Protocol = AnBxProtocol
type Type = AnBxType

-- data types for attack trace reconstuction
type SubjectiveImpersonations = Map.Map Ident (Map.Map Ident Ident)
type OFMCAttackImpersonationsAndProt =  Maybe (SubjectiveImpersonations,Protocol,[Int],Maybe Msg)

-- | A type declaration consist of a type and a list of identifiers
-- (constants or variables) that have that type
type Types = AnBxTypes

type AnBKnowledgeAgents = AnBxKnowledgeAgents
type AnBKnowledgeWhere = AnBxKnowledgeWhere

-- | A knowledge declaration consists of an identifier for a role
-- (constant or variable; should be of type Agent!) and a list of
-- messages that this role initially knows. The variables in that
-- knowledge should always be of type Agent; this is not checked now,
-- however. NEW: Additionally, we have a set of pairs of messages that
-- express inequalities of terms in the instantiation of the
-- knowledge. One can use this for instance to express with A/=B that
-- the roles A and B must be played by different agents.

type Knowledge = AnBxKnowledge

-- | A peer is the endpoint of a channel (i.e. sender or
-- receiver). The identifier is the real name (according to the
-- specification), the bool says whether this agent is
-- pseudonymous. The third is the pseudonym in case the agent is
-- pseudonymous.

type Peer = AnBxPeer

-- | A channel is characterized by a sender and receiver peer, and by
-- a channel type, e.g.  @ ((A,False,Nothing),Secure,(B,True,PKB)) @

type Channel = AnBxChannel

-- | An action consists of a channel (sender, channeltype, receiver)
-- and a message being sent. Additionally, there are two optional
-- message terms for modeling zero-knowledge protocols, namely a
-- pattern for the receiver, and a message that the sender must know

type Action = AnBxAction

-- | List of actions
type Actions = [Action]
  --- every action has the form 
  --- sender, channeltype, receiver, transmitted message, 
  --- and two optional message terms for zero-knowledge, namely a pattern 
  --- for the receiver, and a message that the sender must know

type ChannelType = AnBxChannelType

realChannelType :: ChannelType -> Bool
realChannelType (ActionComment _ _) = False
realChannelType _= True

type GoalComment = String
type Goal = AnBxGoal
type Goals = [Goal]

-- map an authentication goal to a channel goal, as IF deal with channels goals only for Authentication
mapGoal2Channel :: Goal -> Goal
mapGoal2Channel (Authentication p2 p1 msg comment) = ChGoal (p1,FreshAuthentic,p2) msg comment
mapGoal2Channel (WAuthentication p2 p1 msg comment) = ChGoal (p1,Authentic,p2) msg comment
mapGoal2Channel g = g

-- map authentication goals to channel goals
mapGoals2Channels :: Goals -> Goals
mapGoals2Channels = map mapGoal2Channel

mapProtocol2AnBIF :: Protocol -> Protocol
mapProtocol2AnBIF (protname,types,definitions,knowledge,equations,shares,abstractions,actions,goals) = (protname,types,definitions,knowledge,equations,shares,abstractions,mapAction2AnBIF actions,mapGoals2Channels goals)

-- map channel type to types handled by IF
mapChannelType2AnBIF :: ChannelType -> ChannelType
mapChannelType2AnBIF (Sharing SHAgree) = Secure
mapChannelType2AnBIF (Sharing SHAgreeInsecurely) = Insecure
mapChannelType2AnBIF ct = ct

-- map actions to channel type handled by IF
mapAction2AnBIF :: Actions -> Actions
mapAction2AnBIF actions = map (\((a,ct,b),msg1,msg2,msg3) -> ((a,mapChannelType2AnBIF ct,b),msg1,msg2,msg3)) actions0
                            where
                            actions0 = dropAction2AnBIF actions

-- drop comment actions as they are not required for IF translation
dropAction2AnBIF :: Actions -> Actions
dropAction2AnBIF actions = [ a | a@((_,ct,_),_,_,_) <- actions, realChannelType ct]

-- | For the annotation of abstractions: to express that a variable
-- (identifier) should be abstracted into a given term. This
-- represents replacing in the entire description all occurrences of
-- that variable with that term.

type Msg = AnBxMsg
type Abstraction = AnBxAbstraction
type AnBShare = AnBxShare
type AnBShares = [AnBShare]
type AnBEquation = AnBxEquation
type AnBEquations = [AnBEquation]
type AnBEqTheory = (Types,AnBEquations)

protHasEquations :: Protocol -> Bool
protHasEquations (_,_,_,_,equations,_,_,_,_) = not $ null equations

listActionPeersPred :: Actions -> (Peer -> Bool) -> [Peer]
listActionPeersPred actions pred =
    [peer | ((sender, _, receiver), _, _, _) <- actions, peer <- [sender, receiver], pred peer]

listGoalPeersPred :: [Goal] -> (Peer -> Bool) -> [Peer]
listGoalPeersPred goals pred =
    [peer | goal <- goals, peer <- extractPeers goal, pred peer]
  where
    extractPeers (ChGoal (sender, _, receiver) _ _) = [sender, receiver]
    extractPeers (Secret _ peers _ _) = peers
    extractPeers (Authentication initiator responder _ _) = [initiator, responder]
    extractPeers (WAuthentication initiator responder _ _) = [initiator, responder]

listPeerPred :: Protocol -> (Peer -> Bool) -> [Peer]
listPeerPred (_, _, _, _, _, _, _, actions, goals) pred = nubOrd $ listActionPeersPred actions pred ++ listGoalPeersPred goals pred

protocolHasPseudo :: Protocol -> Bool
protocolHasPseudo prot = null (listPeerPred prot peerIsPseudo)

actionIsComment :: Action -> Bool
actionIsComment ((_,ActionComment _ _,_),_,_,_) = True
actionIsComment _ = False

-- find the first agent using an ident (sharing are not considered)
firstAgent :: Ident -> Actions -> OutType -> Maybe Ident
--firstAgent id a | trace("firstAgent\n\tid: " ++ id ++ "\n\ta: " ++ show a) False = undefined
firstAgent _ [] _ = Nothing
firstAgent id ((( (_,_,_),Sharing sh,(_,_,_)),msg,_,_):xs) out | sh==SHShare || not (isOutTypePV out) = if inMsg msg id then Nothing else firstAgent id xs out
firstAgent id ((( (a,_,_),_,(_,_,_)),msg,_,_):xs) out = if inMsg msg id then Just a else firstAgent id xs out


-- here we consider messages in preshared knowledge
isCompShared :: Msg -> AnBShares -> Maybe ShareType
-- isCompShared msg shares | trace("isCompShared\n\tmsg: " ++ show msg ++ "\n\tshares: " ++ show shares) False = undefined
isCompShared (Atom _) [] = Nothing
isCompShared msg@(Atom _) ((sh,_,msgs):xs) = if elem msg msgs then Just sh else isCompShared msg xs
isCompShared (Comp _ _) [] = Nothing
isCompShared msg@(Comp _ _) ((sh,_,msgs):xs) = if elem msg msgs then Just sh else isCompShared msg xs
isCompShared msg _ = error $ patternMsgError msg "isCompShared"

-- list of agents in a message
spMsg2Agents :: Msg -> Types -> [Ident]
spMsg2Agents msg types = [ x | x <- agents, inMsg msg x ]
                                    where
                                agents = concat [ ids | (t,ids) <- types, isAgentType t]

spMsg2Ident :: Msg -> Ident
spMsg2Ident (Atom m) = m
spMsg2Ident (Comp _ xs) = let
                            ids = concatMap spMsg2Ident xs
                            hd = toUpper . head $ ids
                          in hd : tail ids
spMsg2Ident m = error $ patternMsgError m "spMsg2Ident"

isPrivFun :: Ident -> Types -> Bool
isPrivFun id types = elem id ([concat x | (Function [FunSign (_, _, PrivFun)], x) <- types])

isHonest :: Ident -> Bool
isHonest id = isLower (head id)

isVarId :: Ident -> Bool
isVarId id = isUpper (head id)

-- returns the type of an identifier
id2Type :: Ident -> Types -> Type
id2Type _ [] = Untyped []
id2Type id ((t,ls):xs) = if elem id ls then t else id2Type id xs

-- list of identifiers in a message
spMsg2Idents :: Msg -> Types -> [Ident]
spMsg2Idents msg types = [ x | x <- idents, inMsg msg x ]
                                    where
                                        idents = concat [ ids | (_,ids) <- types ]

-- list of identifiers in a message of specific type
spMsg2IdentsType :: Msg -> Types -> (Type -> Bool) -> [Ident]
spMsg2IdentsType msg types ismytype = [ x | x <- idents, inMsg msg x ]
                                    where
                                        idents = concat [ ids | (t,ids) <- types, ismytype t]

-- list functions in equations
eqFunctionsAnB :: Protocol -> [Ident]
eqFunctionsAnB (_,_,_,[],_,_,_,_,_) = []
eqFunctionsAnB (_,types,_,equations,_,_,_,_,_) = nubOrd ([ f | eq <- equations, f <- eq2Fun eq types])

-- list of identifiers in a message, not functions
spMsg2IdentsNoFun :: Msg -> Types -> [Ident]
spMsg2IdentsNoFun msg types = [ x | x <- idents, inMsg msg x ]
                                    where
                                        idents = concat [ ids | (t,ids) <- types, not (isFunctionType t)]

-- list functions identifiers in an equation
eq2Fun :: AnBEquation -> Types -> [Ident]
eq2Fun (Eqt msg1 msg2) types = nubOrd ((spMsg2Idents msg1 types ++ spMsg2Idents msg2 types) \\ (spMsg2IdentsNoFun msg1 types ++ spMsg2IdentsNoFun msg2 types))

-- Function to compute the number of production rule applications required to derive the message
countRuleApplications :: Msg -> Int
countRuleApplications (Atom _) = 0
countRuleApplications (Comp _ msgs) = 1 + sum (map countRuleApplications msgs)
countRuleApplications msg = error $ patternMsgError msg "countRuleApplications"

-- same for terms where crypto is applied
countCryptRuleApplications :: Msg -> Int
countCryptRuleApplications (Comp Crypt msgs) = 1 + sum (map countCryptRuleApplications msgs)
countCryptRuleApplications (Comp Scrypt msgs) = 1 + sum (map countCryptRuleApplications msgs)
countCryptRuleApplications _ = 0

-- Function to compute the depth of the derivation tree
-- i.e. the number of rule applications from the start symbol to the message
computeDepth :: Msg -> Int
computeDepth (Atom _) = 0
computeDepth (Comp _ msgs) = 1 + maximum (map computeDepth msgs)
computeDepth msg = error $ patternMsgError msg "computeDepth"

-- same for terms where crypto is applied
computeCryptDepth :: Msg -> Int
computeCryptDepth (Comp Crypt msgs) = 1 + maximum (map computeCryptDepth msgs)
computeCryptDepth (Comp Scrypt msgs) = 1 + maximum (map computeCryptDepth msgs)
computeCryptDepth _ = 0

actions2Msgs :: Actions -> [Msg]
actions2Msgs = map (\(_,msg,_,_) -> msg)

-- fields hearder for AnBStatsCSV
csvFieldNames :: String
csvFieldNames = "protocol,agents,agents.const,agents.var,steps,rule.applications,crypto.rule.applications,term.depth,crypto.term.depth,goals,goals.bullet,goals.secret,goals.auth,goals.wauth"

showStatList :: [Int] -> String
showStatList list = "- Total: " ++ show (sum list) ++ " - Min: " ++ show (minimum list) ++ " - Max: " ++ show (maximum list) ++ " - List: " ++ show list

showAnBStats :: Protocol -> OutType -> String
showAnBStats ((protname,_),_,_,_,_,_,_,actions,goals) outtype =
    let
        aa = getActiveAgents actions
        ca = [ x | x <- aa, isHonest x]
        naa = length aa
        nca = length ca
        nva = naa - nca
        activeactions = [a | a <- actions, not (actionIsComment a)]
        msgs = actions2Msgs activeactions
        steps = length activeactions
        ruleAppList = map countRuleApplications msgs
        depthList = map computeDepth msgs
        cryptRuleAppList = map countCryptRuleApplications msgs
        cryptDepthList = map computeCryptDepth msgs
        nGoals = length goals
        nGoalsBullet = length [ g | g@(ChGoal {}) <-  goals]
        nGoalsSecret = length [ g | g@(Secret {}) <-  goals]
        nGoalsAuth = length [ g | g@(Authentication {}) <-  goals]
        nGoalsWAuth = length [ g | g@(WAuthentication {}) <-  goals]
    in case outtype of
         AnBStats ->
                "Protocol: " ++ protname ++ "\n" ++
                "Number of Agents: " ++ show naa ++ " - Const: " ++ show nca ++ " - Var: " ++ show nva ++ "\n" ++
                "Number of Steps: " ++ show steps  ++ "\n" ++
                "Rule applications " ++ showStatList ruleAppList ++ "\n" ++
                "Crypto Rule applications " ++ showStatList cryptRuleAppList ++ "\n" ++
                "Term depth " ++ showStatList depthList ++ "\n" ++
                "Crypto term depth " ++ showStatList cryptDepthList ++ "\n" ++
                "Number of Goals: " ++ show nGoals ++ " - Bullet: " ++ show nGoalsBullet ++ " - Secret: " ++ show nGoalsSecret ++ " - Auth: " ++ show  nGoalsAuth ++ " - WAuth: " ++ show nGoalsWAuth ++ "\n\n"
         AnBStatsCSV ->  csvFieldNames ++ "\n" ++ protname ++ "," ++ show naa ++ "," ++ show nca ++ "," ++ show nva ++ "," ++ show steps  ++ ","
                                               ++ showQuotedList ruleAppList  ++ "," ++ showQuotedList cryptRuleAppList  ++ ","
                                               ++ showQuotedList depthList ++ "," ++ showQuotedList cryptDepthList ++ ","
                                               ++ show nGoals ++ "," ++ show nGoalsBullet ++ "," ++ show nGoalsSecret ++ "," ++ show nGoalsAuth ++ "," ++ show nGoalsWAuth
         _ -> error ("AnB Statistics underfined for output type: " ++ show outtype)

showQuotedList :: Show a => [a] -> String
showQuotedList xs = "\"" ++ intercalate "," (map show xs)  ++ "\""

-- Extracts constants from a protocol, excluding active agents and function names
constOfProt :: Protocol -> [Ident]
constOfProt (_, types, _, _, _,_, _, actions, _) =
    let
        -- Extract identifiers that are not of type Agent or Function
        nonAgentFunctionConstants = concat [ x | (t, x) <- types , not (isAgentType t || isFunctionType t)]

        -- Extract agent identifiers that are not actively involved in actions
        inactiveAgents = concatMap (filter (\id -> not (agentInActions id actions))) [x | (t, x) <- types, isAgentType t]

        -- Combine the two lists and filter only constants
        constants = filter isConstant (nonAgentFunctionConstants ++ inactiveAgents)
    in
        constants

-- check if an agent id is doing an action in the protocol
agentInActions :: Ident -> Actions -> Bool
agentInActions _ [] = False
agentInActions a (x : xs) = agentInAction a x || agentInActions a xs

agentInAction :: Ident -> Action -> Bool
agentInAction id (((a, _, _), _, (b, _, _)), _, _, _) = id == a || id == b
