{-

 AnBx Compiler and Code Generator

 Copyright 2011-2025 Paolo Modesti
 Copyright 2021-2025 Rémi Garcia
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
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "Use infix" #-}

module Spyer_Execnarr where
import           AnB2NExpression (Execnarr, Fact (GuessableSecretGoal, Request, SecretGoal, Seen, Witness, Wrequest), getIdent, MapSK, NAction (NACheck, NAComment, NAEmit, NAEmitReplay, NAGoal, NANew, NAReceive), printMapSK, stepOfNAction, agentOfNAction,trMsg, agent2NExpression, trEquations, agent2NEIdent, id2NEIdent)
import           AnB2Spyer       (trAnB2ExecnarrKnowledge)
import           AnBAst          (Actions, AnBShares, Goals, Msg, Peer, Protocol, Types, OFMCAttackImpersonationsAndProt, Goal)
import           AnBxShow        (showIdents, showAction,showSimpleGoal)
import           AnBxMsgCommon   (Ident, isVariable, syncMsg,ShareType (SHShare,SHAgree,SHAgreeInsecurely))
import           AnBxOnP         (cmdRelaxGoalsOtherAgentKnow,isOutTypePV,AnBxOnP(relaxGoalsOtherAgentKnow, nogoals, anbxouttype),OutType (AnB, AnBIntr), cmdAnBExecCheck, anbxmitm)
import           Data.Maybe      (fromJust, fromMaybe)
import           Data.List       ((\\), find, foldl')
import           Spyer_Ast       (Declaration (DGenerates, DKnow, DShare))
import           Spyer_Knowledge (addKnowledge, irreducibles, rep,analysisStepEq,knAdd,inSynthesis)
import           Spyer_Message   (KnowledgeMap, namesOfKnowlegde, NEquations, Formula (FAnd,FSingle), Atom (FNotEq,FWff), showKnowledgeMap)
import           Spyer_Common    (setChoose)
import qualified Data.Map as Map
import qualified Data.Set as Set
import Data.Containers.ListUtils (nubOrd)
import Data.Tuple.Utils (fst3,snd3,thd3)
import AnBxMsg ( AnBxMsg (..))
import AnBxAst ( AnBxGoal(..), AnBxChannelType (..), peer2Ident, getSender, getReceiver, ident2Peer, getActiveAgents, peer2Agent, unwrapMsg, AnBxMsgWrapper(..))


-- import AnBTypeSystem_Evaluator (typeofTS)
import Java_TypeSystem_Context ( JContext, buildJContext, getIdentifiersByTypeStrict )
import Java_TypeSystem_Evaluator ( typeofTS )
import Java_TypeSystem_JType

getKappa :: MapSK -> String -> JContext -> KnowledgeMap
getKappa kappa a ctx = if not (Map.member a kappa) then Map.singleton (agent2NExpression a ctx) (Set.singleton (agent2NExpression a ctx)) else fromJust (Map.lookup a kappa)

updateKappa :: MapSK -> String -> KnowledgeMap -> MapSK
updateKappa kappa a ka = let
                              kappa1 = Map.delete a kappa
                              kappa2 = Map.insert a ka kappa1
                         in kappa2

namesOfKappa :: MapSK -> StringSet
-- namesOfKappa kappa | trace ("namesOfKappa\n\tknowledge: " ++ printMapSK kappa) False = undefined
namesOfKappa = Map.foldr (Set.union . namesOfKnowlegde) Set.empty

newVar :: Int -> String
newVar next_var = "R" ++ show next_var

-- mapping goals to steps
type MapGoals = Map.Map (String, String) (Maybe Int)      -- agent, goalid -> step -- when the agent can compose the message of the given goal, use mkID

-- | Update MapGoals only if the entry does not exist or its value is Nothing
updateMapGoals :: MapGoals -> String -> Goal -> Msg -> JContext -> Int -> MapGoals
updateMapGoals mapGoals agent goal msg ctx step=
    let
        -- Generate the unique identifier for the goal using mkID
        goalID = mkID goal msg ctx

        -- Key for the MapGoals entry
        key = (agent, goalID)
    in
        -- Use Map.alter to conditionally update the entry
        Map.alter updateIfNothingOrMissing key mapGoals
  where
    -- Helper function to update only if the current value is Nothing or missing
    updateIfNothingOrMissing :: Maybe (Maybe Int) -> Maybe (Maybe Int)
    updateIfNothingOrMissing currentValue =
        case currentValue of
            Nothing         -> Just (Just step)  -- Add a new entry
            Just Nothing    -> Just (Just step)  -- Update an existing entry with Nothing
            Just (Just _)   -> currentValue      -- Keep the existing value

-- Initialize MapGoals with all goals from a protocol
initMapGoals :: [Goal] -> JContext-> MapGoals
initMapGoals goals ctx =
    let
        -- Extract all (agent, goalID) pairs from the list of goals using the updated goalToMapKeys
        goalEntries = concatMap (\goal -> goalToMapKeys goal ctx) goals

        -- Initialize MapGoals with all entries set to Nothing
    in  Map.fromList [(key, Nothing) | key <- goalEntries]

-- Helper function to extract all (agent, goalID) pairs from a goal
goalToMapKeys :: Goal -> JContext -> [(String, String)]
goalToMapKeys g@(ChGoal (p1, _, p2) _ _) ctx =
    let msg = messageOfGoal g
    in [(peer2Ident p1, mkID g msg ctx), (peer2Ident p2, mkID g msg ctx)]

goalToMapKeys g@(Secret _ peers _ _) ctx =
    let msg = messageOfGoal g
    in [(peer2Ident peer, mkID g msg ctx) | peer <- peers]

goalToMapKeys g@(Authentication p1 p2 _ _) ctx =
    let msg = messageOfGoal g
    in [(peer2Ident p1, mkID g msg ctx), (peer2Ident p2, mkID g msg ctx)]

goalToMapKeys g@(WAuthentication p1 p2 _ _) ctx =
    let msg = messageOfGoal g
    in [(peer2Ident p1, mkID g msg ctx), (peer2Ident p2, mkID g msg ctx)]

-- | Update MapGoals based on whether the message in a goal can be synthesised
updateGoalsWithSynthesis :: Int -> MapSK -> MapGoals -> Goal -> JContext -> NEquations -> AnBxOnP -> MapGoals
updateGoalsWithSynthesis step kappa mapGoals goal ctx equations opt =
    let
        -- Extract agents involved in the goal using the updated goalToMapKeys
        agents = map fst (goalToMapKeys goal ctx)

        -- Update MapGoals for each agent
        updateForAgent :: MapGoals -> String -> MapGoals
        updateForAgent currentMap agent =
            let
                -- Check if the message can be synthesised by the agent
                msg = messageOfGoal goal
                canSynthesise = isSynMsg agent kappa msg ctx equations opt
            in
                if canSynthesise
                then updateMapGoals currentMap agent goal msg ctx step
                else currentMap
    in
        -- Fold over all agents in the goal to apply updates
        foldl' updateForAgent mapGoals agents


-- | Update MapGoals for a list of goals based on whether the message in each goal can be synthesised
updateMapGoalsList :: Int -> MapSK -> MapGoals -> [Goal] -> JContext -> NEquations -> AnBxOnP -> MapGoals
updateMapGoalsList step kappa mapGoals goals ctx equations opt =
    -- Use foldl' to apply updateGoalsWithSynthesis to each goal in the list
    foldl' (updateSingleGoal step kappa ctx equations opt) mapGoals goals
  where
    -- Helper function to apply updateGoalsWithSynthesis to a single goal
    updateSingleGoal :: Int -> MapSK -> JContext -> NEquations -> AnBxOnP -> MapGoals -> Goal -> MapGoals
    updateSingleGoal step kappa ctx equations opt currentMap goal =
        updateGoalsWithSynthesis step kappa currentMap goal ctx equations opt

-- | Get the corresponding value in MapGoals for a given agent and goal
getMapGoalForAgent :: String -> Goal -> Msg -> JContext -> MapGoals -> Maybe (Maybe Int)
getMapGoalForAgent agent goal msg ctx mapgoals =
    let
        -- Generate the unique identifier for the goal using mkID
        goalID = mkID goal msg ctx

        -- Key for the MapGoals entry
        key = (agent, goalID)
    in
        -- Lookup the value associated with the key in MapGoals
        Map.lookup key mapgoals

messageOfGoal :: Goal -> Msg
messageOfGoal (ChGoal _ msg _) = msg
messageOfGoal (Secret msg _ _ _) = msg
messageOfGoal (Authentication _ _ msg _) = msg
messageOfGoal (WAuthentication _ _ msg _) = msg

type SeenSQN = [(String,String)]    -- Agent, Ident

errorInSynthesis :: Ident -> NExpression -> KnowledgeMap -> NEquations -> String
errorInSynthesis agent message knowledge equations = "\tagent " ++ agent ++ " cannot synthesise the message\n\tmessage: " ++ show message ++ "\n\tknowledge: " ++ showKnowledgeMap knowledge ++ if null equations then "" else "\n\tequations: " ++ show equations

-- Protocol compilation
compileAnB2ExecnarrKnow :: (Int,StringSet,MapSK,StringSet) -> (JContext,Types,AnBShares,[Declaration],[Declaration],NEquations,Actions,Goals,Goals,SeenSQN) -> MapGoals -> EVNumbers -> AnBxOnP -> OutType -> (Execnarr,MapSK,MapGoals)
-- compileAnB2ExecnarrKnow (step,privnames,kappa,gennames) (_,_,_,_,decl,equations,a,g1,g2,sg) mapgoals _ _ | trace ("\ncompileAnB2ExecnarrKnow - step: " ++ show step ++ "\n" ++ "gennames: " ++ showIdents (Set.toList gennames) ++ "\nprivnames: " ++ showIdents (Set.toList privnames) ++ "\nknowledge:\n" ++ printMapSK kappa ++ "decl: " ++ show decl ++ "\nequations: " ++ show equations ++ "\nActions:\n" ++ showActions a ++ "\nGoals Sender: " ++ showSimpleGoals g1 ++ "\nGoals Receiver: " ++ showSimpleGoals g2 ++ "\nSeen: " ++ show sg ++ "\nMapGoals: " ++ show mapgoals) False = undefined

-- no actions - no goals (on both sides) to process 
compileAnB2ExecnarrKnow (_,_,kappa,_) (_,_,_,_,_,_,[],[],[],_) mapgoals _ _ _ = ([],kappa,mapgoals)

-- comments
compileAnB2ExecnarrKnow context@(next_var,_,_,_) (ctx,types,sh,[],decl,equations,((_,ActionComment _ s,_),_,_,_):xs,goalsS,goalsR,seenSQN) mapgoals evn opt out = let
                                                                                                                                       (xnarr,newKappa,newMapGoals) = compileAnB2ExecnarrKnow context (ctx,types,sh,[],decl,equations,xs,goalsS,goalsR,seenSQN) mapgoals evn opt out
                                                                                                                                   in  (NAComment (next_var,s):xnarr,newKappa,newMapGoals)

-- knowledge/declarations
compileAnB2ExecnarrKnow (next_var,privnames,kappa,gennames) (ctx,types,sh,DKnow ((_,a),m):ds,decl,equations,xs,goalsS,goalsR,seenSQN) mapgoals evn opt out =
               let s = Set.intersection (namesOfNExpression m) gennames in
                        if Set.null s then
                                let
                                        ka1 = getKappa kappa a ctx
                                        ka2 = knAdd m (Set.singleton m) ka1 equations ctx opt
                                        ka3 = rep (irreducibles ka2 equations ctx opt) equations ctx opt
                                        newKappa = updateKappa kappa a ka3
                                in compileAnB2ExecnarrKnow (next_var,privnames,newKappa,gennames) (ctx,types,sh,ds,decl,equations,xs,goalsS,goalsR,seenSQN) mapgoals evn opt out
                        else error ("cannot compile AnB to ExecNarr - message " ++ show m ++ " contains generated names, for example: " ++ setChoose s)

compileAnB2ExecnarrKnow (next_var,privnames,kappa,gennames) (ctx,types,sh,DGenerates ((_,a),n):ds,decl,equations,xs,goalsS,goalsR,seenSQN) mapgoals evn opt out =
                let
                    all_names = Set.unions [privnames,gennames,namesOfKappa kappa]
                    ng = nameOfGenerates n
                     in if not (Set.member ng all_names) then
                                let
                                        ka1 = getKappa kappa a ctx
                                        ka2 = knAdd n (Set.singleton n) ka1 equations ctx opt
                                        ka3 = rep (irreducibles ka2 equations ctx opt) equations ctx opt
                                        newKappa = updateKappa kappa a ka3
                                        gennames1 = Set.insert ng gennames
                                        (xnarr,newKappa1,newMapGoals) = compileAnB2ExecnarrKnow (next_var,privnames,newKappa,gennames1) (ctx,types,sh,ds,decl,equations,xs,goalsS,goalsR,seenSQN) mapgoals evn opt out
                                in (NANew (next_var, a,id2NEIdent ng ctx):xnarr,newKappa1,newMapGoals)
                        else error ("cannot compile AnB to ExecNarr - " ++ ng ++ " cannot be freshly generated.")

compileAnB2ExecnarrKnow (next_var,privnames,kappa,gennames) (ctx,types,sh,DShare (_,(_,k),_,_):ds,decl,equations,xs,goalsS,goalsR,seenSQN) mapgoals evn opt out =
               let all_names = Set.unions [privnames,gennames,namesOfKappa kappa] in
                 if not (Set.member k all_names) then
                        let
                            privnames1 = Set.insert k privnames
                            (xnarr,newKappa,newMapGoals) = compileAnB2ExecnarrKnow (next_var,privnames1,kappa,gennames) (ctx,types,sh,ds,decl,equations,xs,goalsS,goalsR,seenSQN) mapgoals evn opt out
                        in (xnarr,newKappa,newMapGoals)         -- skip Share declarations
                else error ("cannot compile AnB to ExecNarr - " ++ k ++ " cannot be a private name.")

-- actions 

-- no actions left, at this stage only secrecy goals should be here, no authentication goals, unless they trivially fail
compileAnB2ExecnarrKnow (next_var,_,kappa,_) (ctx,types,sh,[],_,equations,[],g:gs,_,_) mapgoals evn opt out = let
                                                                                                (msg,agentList) = msgAgentsOfGoal g
                                                                                                -- check all agents can synthetise the message
                                                                                                execnarrComputed = execnarrComp next_var kappa (ctx,types,sh,equations,gs) g msg agentList mapgoals evn opt out True
                                                                                             in case g of -- process secrecy goals
                                                                                                Secret {} -> execnarrComputed
                                                                                                ChGoal (_,Insecure,_) _ _ -> execnarrComputed
                                                                                                _ -> error (errorGoalSynMsg g kappa mapgoals out) -- execnarrComputed

-- no actions left, all goals processed on the sender side, this is the receiver side, only authentication goals on receiver side
compileAnB2ExecnarrKnow (next_var,_,kappa,_) (ctx,types,sh,[],_,equations,[],[],g:goalsR,_) mapgoals evn opt out = let
                                                                                                    (msg,agentList) = msgAgentsOfGoal g
                                                                                                    -- check all agents can synthetise the message
                                                                                                    execnarrComputed = execnarrComp next_var kappa (ctx,types,sh,equations,goalsR) g msg agentList mapgoals evn opt out False
                                                                                                  in case g of
                                                                                                    -- no secrecy goals allow at this stage 
                                                                                                    Secret {} -> error ("cannot compile AnB to ExecNarr - this goal should have been already processed at this stage: " ++ errorMsgGoalKnowledgeEquations g kappa equations)
                                                                                                    ChGoal (_,Insecure,_) _ _ -> error ("cannot compile AnB to ExecNarr - this goal should have been already processed at this stage: " ++ errorMsgGoalKnowledgeEquations g kappa equations)
                                                                                                    _ -> if relaxGoalsOtherAgentKnow opt then execnarrComputed else error (errorGoalSynMsg g kappa mapgoals out)

-- processing list of actions
compileAnB2ExecnarrKnow context@(next_var,privnames,kappa,gennames) (ctx,types,sh,[],decl,equations,x@(((a,_,_),channeltype,(b,_,_)),msgw,_,_):xs,goalsS,goalsR,seenSQN) mapgoals evn@(_,endEvnrAuth,endEvnrSecr) opt out
                        -- share actions (simply ignored as shares are processed in AnB and later in the compilation chain, except for ProVerif output)
                        | channeltype == Sharing SHShare || ((channeltype == Sharing SHAgree || channeltype == Sharing SHAgreeInsecurely) && not (isOutTypePV out)) = compileAnB2ExecnarrKnow context (ctx,types,sh,[],decl,equations,xs,goalsS,goalsR,seenSQN) mapgoals evn opt out
                        -- standard actions
                        | otherwise =
                            let (msg,_) = unwrapMsg msgw
                        in if next_var==0 && msg == Atom syncMsg then
                            -- skip first empty action if any
                            compileAnB2ExecnarrKnow context (ctx,types,sh,[],decl,equations,xs,goalsS,goalsR,seenSQN) mapgoals evn opt out
                        else
                            let
                                (msg,_) = unwrapMsg msgw
                                -- a (sender), b (receiver)
                                m = trMsg msg ctx                  -- translate the AnB message to NExpression
                                ka0 = getKappa kappa a ctx                  -- get knowledge for sender
                                ka = analysisStepEq ka0 equations ctx opt   -- run equation-based analysis step on the knowledge 
                            in case (inSynthesis ka (agent2NExpression b ctx) equations, inSynthesis ka m equations ctx opt) of       -- check if sender can syntesise message m, check also the recipient name but it not really used at the moment
                                            -- sender cannot synthesise message
                                            (_,Nothing) -> error ("agent " ++ a ++  " cannot compile AnB to ExecNarr - in action: " ++ showAction x ++ "\n" ++ errorInSynthesis a m ka equations)
                                            (_,Just em) -> let x = newVar next_var in
                                                                                let -- compile the action
                                                                                    kappa1 = updateKappa kappa a ka
                                                                                    t = typeofTS m ctx    -- computes the type of the variable to be added to the knowledge
                                                                                    -- update knowledge for a 
                                                                                    (kb,phi) = addKnowledge (m,NEVar (t,x) em) (getKappa kappa1 b ctx) equations ctx opt -- add the received message to b's knowledge and updates the knowledge
                                                                                    newKappa = updateKappa kappa1 b kb                                       -- update knowledge for b
                                                                                    -- update the goals map
                                                                                    mapgoals1 = updateMapGoalsList next_var newKappa mapgoals goalsS ctx equations opt
                                                                                    ((gS1,gS2),(gR1,gR2)) = goals2filter a b goalsS goalsR newKappa ctx equations opt     -- process applicable (gS1,gR1) / non applicable goals (gS2,gR2) for sender/receiver
                                                                                    acts_be = concatMap (\x -> beginEvents next_var endEvnrSecr newKappa x ctx equations mapgoals opt) gS1     -- compute begin events for applicable goals
                                                                                    acts_ee = concatMap (\x -> endEvents endEvnrAuth next_var newKappa x ctx equations mapgoals opt RelaxKnowAgentFalse) gR1 -- compute end events for applicable goals
                                                                                    na = agent2NEIdent a ctx
                                                                                    nb = agent2NEIdent b ctx
                                                                                    acts1 = case msgw of
                                                                                        PlainMsg _ ->
                                                                                            [NAEmit (next_var, a, (na, channeltype, nb), agent2NExpression b ctx, em),
                                                                                            NAReceive (next_var, b, (nb, channeltype, na), NEVar (t, x) em)]
                                                                                        ReplayMsg _ ->
                                                                                            [NAEmitReplay (next_var, a, (na, channeltype, nb), agent2NExpression b ctx, em),
                                                                                            NAReceive (next_var, b, (nb, channeltype, na), NEVar (t, x) em)]           -- add send and receive actions
                                                                                    (acts2,seenSQN1) = seenEvents next_var b newKappa ctx equations seenSQN decl opt                                     -- generate seen events for sequence numbers   
                                                                                    acts3 = [NACheck (next_var,b,phi)]                                                                                   -- generate the checks on reception
                                                                                    (acts4,newKappa1,newMapGoals) = compileAnB2ExecnarrKnow (next_var + 1,privnames,newKappa,gennames) (ctx,types,sh,[],decl,equations,xs,gS2,gR2,seenSQN1) mapgoals1 evn opt out   -- compute the rest of the narration
                                                                                in (acts_be ++ acts1 ++ acts2 ++ acts3 ++ acts4 ++ acts_ee,newKappa1,newMapGoals)       -- full narration computed with end events at the end
                                                                            -- in error (show em)


execnarrComp ::  Int -> MapSK -> (JContext,Types,AnBShares,NEquations,[Goal]) -> Goal -> Msg -> [String] -> MapGoals -> EVNumbers -> AnBxOnP -> OutType -> Bool -> ([NAction],MapSK,MapGoals)
-- execnarrComp step kappa  (_,_,equations,gs) g _ _ mapgoals _ _ _ | trace ("\nexecnarrComp - step: " ++ show step ++ "\n" ++ "\nknowledge:\n" ++ printMapSK kappa ++ "\nequations: " ++ show equations ++ "\nGoal: " ++ showSimpleGoal g ++ "\nGoals: " ++ showSimpleGoals gs ++ "\nMapGoals: " ++ show mapgoals) False = undefined

execnarrComp next_var kappa (ctx,types,sh,equations,gs) g msg agentList mapgoals evn@(_,_,endEvnrSecr) opt out dropBeginEvents = if all (\x -> isSynMsg x kappa msg ctx equations opt) agentList then
                                                                                                                                        let
                                                                                                                                            relax = if relaxGoalsOtherAgentKnow opt then RelaxKnowAgentTrue else RelaxKnowAgentFalse
                                                                                                                                            be = if dropBeginEvents then beginEvents next_var endEvnrSecr kappa g ctx equations mapgoals opt else []
                                                                                                                                            ee = endEvents endEvnrSecr next_var kappa g ctx equations mapgoals opt relax
                                                                                                                                            -- no need to recompute the knowledge as it cannot be extended at this stage
                                                                                                                                            (xn,_,newMapGoals) = case gs of
                                                                                                                                                                [] -> ([],kappa,mapgoals)
                                                                                                                                                                [g1] -> execnarrComp next_var kappa (ctx,types,sh,equations,[]) g1 msg agentList mapgoals evn opt out dropBeginEvents
                                                                                                                                                                g1:gs1 -> execnarrComp next_var kappa (ctx,types,sh,equations,gs1) g1 msg agentList mapgoals evn opt out dropBeginEvents
                                                                                                                                            xnarr = if null xn then nubOrd (be ++ ee) else nubOrd be ++ xn ++ nubOrd ee
                                                                                                                                        in (xnarr,kappa,newMapGoals)
                                                                                                                                    else let
                                                                                                                                            agentFail = [ a | a <- agentList, not (isSynMsg a kappa msg ctx equations opt)]
                                                                                                                                            in error ("agent(s) " ++ showIdents agentFail ++ " cannot synthesize the message in goal: " ++ errorMsgGoalKnowledgeEquations g kappa equations ++ "dropBeginEvents: " ++ show dropBeginEvents)
errorGoalSynMsg :: Goal -> MapSK -> MapGoals -> OutType -> String
errorGoalSynMsg g kappa mapgoals out = "unexpected goal at this stage: " ++ showSimpleGoal g
                    ++ "\n\t" ++ "- check if sender and receiver in the goal are coherent with actions"
                    ++ "\n\t" ++ "- for authentication goals consider if the receiver knows the identity/pseudonym of the other agent"
                    ++ "\n\t" ++ "  run with " ++ cmdRelaxGoalsOtherAgentKnow ++ " to relax the above requirement"
                    ++ (if out == AnB || out == AnBIntr then  "\n\t" ++ "  or with " ++ cmdAnBExecCheck ++ " option, to enable compilation to " ++ show AnB else "")
                    ++ "\n\t" ++ (if isOutTypePV out then "  use carefully, as this may lead to ill-formed ProVerif protocols " else "")
                    ++ "\nknowledge:\n" ++ printMapSK kappa
                    ++ "\nmapgoals:\n" ++ show mapgoals

errorMsgGoalKnowledgeEquations :: Goal -> MapSK -> NEquations -> String
errorMsgGoalKnowledgeEquations g kappa equations = showSimpleGoal g ++ "\nknowledge:\n" ++ printMapSK kappa ++ (if null equations then "" else "\nequations: " ++ show equations) ++ "\n"

-- unhandled channel type
-- compileAnB2ExecnarrKnow _ (_,_,[],_,((ch,_,_,_):_),_,_,_) _ _ = error ("cannot translate channel " ++ showChannel ch)

-- partition the goals between applicable and not applicable at the current stage

goals2filter :: String -> String -> Goals -> Goals -> MapSK -> JContext -> NEquations -> AnBxOnP -> ((Goals,Goals),(Goals,Goals))
-- goals2filter a b g1 g2 _ _ _ _ _ | trace ("goals2filter\n\tsender (" ++ a ++ "): " ++ showSimpleGoals g1 ++ "\n\treceiver (" ++ b ++ "):" ++ showSimpleGoals g2) False = undefined
goals2filter a b goalsS goalsR kappa ctx equations opt = let
                                     gsS = [ x | x <- goalsS , isSynGoalSender a b x kappa ctx equations opt]
                                     gsR = [ x | x <- goalsR , isSynGoalReceiver a b x kappa ctx equations opt]
                                 in  ((gsS,goalsS \\ gsS),(gsR,goalsR \\ gsR))

skipChGoal :: Bool
skipChGoal = False -- default = False 

skipConfidentialChGoal :: Bool
skipConfidentialChGoal = False  -- default = False

-- secGoalEnd :: Bool
-- secGoalEnd = False   -- default = False

-- check if a goal is applicable at the current stage to the Sender                                 
isSynGoalSender :: String -> String -> Goal -> MapSK -> JContext -> NEquations -> AnBxOnP -> Bool
-- isSynGoalSender a _ g kappa _ _ _ _ | trace ("isSynGoalSender - agent: " ++ a ++ " - goal: " ++ showSimpleGoal g ++ "\n\tK(" ++ a ++ "): " ++ showKnowledgeMap (getKappa kappa a)) False = undefined
isSynGoalSender _ _ Secret {} _ _ _ _  = False          -- if secrecy goals are tested at the end
-- isSynGoalSender a _ (Secret msg _ _ _) kappa ctx equations opt = isSynMsg a kappa msg ctx equations opt && secGoalEnd
isSynGoalSender a _ (ChGoal ch@(_,channelType,_) msg _) kappa ctx equations opt | channelType == Confidential || channelType == Insecure = a == getSender ch && isSynMsg a kappa msg ctx equations opt
                                                                                     | otherwise = a == getSender ch && isSynMsg a kappa msg ctx equations opt && isSynMsg a kappa (Atom (getReceiver ch)) ctx equations opt

-- stricter version where the sender of an authentication goal must known the recipient, unless relaxGoalsOtherAgentKnow is set to True
isSynGoalSender a _ (WAuthentication p1 p2 msg _) kappa ctx equations opt = a == peer2Ident p2 && isSynMsg a kappa msg ctx equations opt && isSynMsg a kappa (peer2Agent p1) ctx equations opt
isSynGoalSender a _ (Authentication p1 p2 msg _) kappa ctx equations opt = a == peer2Ident p2 && isSynMsg a kappa msg ctx equations opt && isSynMsg a kappa (peer2Agent p1) ctx equations opt

-- check if a goal is applicable at the current stage to the Receiver
isSynGoalReceiver :: String -> String -> Goal -> MapSK -> JContext -> NEquations -> AnBxOnP -> Bool
-- isSynGoalReceiver _ b g kappa _ _ _ _ | trace ("isSynGoalReceiver - agent: " ++ b ++ " - goal: " ++ showSimpleGoal g ++ "\n\t" ++ showKnowledgeMap (getKappa kappa b)) False = undefined
isSynGoalReceiver _ _ Secret {} _ _ _ _ = False          -- if secrecy goals are tested at the end 
-- isSynGoalReceiver _ b (Secret msg _ _ _) kappa ctx equations opt = isSynMsg b kappa msg ctx equations opt && secGoalEnd
isSynGoalReceiver _ b (ChGoal ch@(_,channelType,_) msg _) kappa ctx equations opt | channelType == Confidential || channelType == Insecure = b == getReceiver ch && isSynMsg b kappa msg ctx equations opt
                                                                                       | otherwise = b == getReceiver ch && isSynMsg b kappa msg ctx equations opt && isSynMsg b kappa (Atom (getSender ch)) ctx equations opt

-- stricter version where the receiver of an authentication goal must known the sender, unless relaxGoalsOtherAgentKnow is set to True 
isSynGoalReceiver _ b (WAuthentication p1 p2 msg _) kappa ctx equations opt = b == peer2Ident p1 && isSynMsg b kappa msg ctx equations opt && isSynMsg b kappa (peer2Agent p2) ctx equations opt
isSynGoalReceiver _ b (Authentication p1 p2 msg _) kappa ctx equations opt = b == peer2Ident p1 && isSynMsg b kappa msg ctx equations opt && isSynMsg b kappa (peer2Agent p2) ctx equations opt


msgAgentsOfGoal :: Goal -> (Msg,[Ident])
-- msgAgentsOfGoal g  | trace ("msgAgentsOfGoal\n\tgoal: " ++ showSimpleGoal g) False = undefined
msgAgentsOfGoal (Secret msg peers _ _) = (msg,agentList)
                                                 where agentList = map peer2Ident peers;
msgAgentsOfGoal (ChGoal ch msg _) = (msg,agentList)
                                                 where
                                                      p1 = getSender ch;
                                                      p2 = getReceiver ch;
                                                      agentList = [p1,p2];
msgAgentsOfGoal (WAuthentication p1 p2 msg _) = (msg,agentList)
                                                 where
                                                      agentList = map peer2Ident [p1,p2];
msgAgentsOfGoal (Authentication p1 p2 msg _) = (msg,agentList)
                                                 where
                                                      agentList = map peer2Ident [p1,p2];

-- check if a msg can be synthesised at the current stage
isSynMsg :: String -> MapSK -> Msg -> JContext -> NEquations -> AnBxOnP -> Bool
-- isSynMsg agent kappa msg _ _ _  | trace ("isSynMsg - agent: " ++ agent ++ " - msg: " ++ show (trMsg msg ctx) ++ "\n\tK(" ++ agent ++ "): " ++ showKnowledgeMap (getKappa kappa agent)) False = undefined
isSynMsg agent kappa msg ctx equations opt = let
                                                        m = trMsg msg ctx
                                                        ka = getKappa kappa agent ctx
                                                  in case inSynthesis ka m equations ctx opt of
                                                                    Nothing -> False
                                                                    Just _ -> True

-- computes the expression for goal 
synMsgGoal :: String -> MapSK -> Msg -> JContext -> NEquations -> Goal -> AnBxOnP -> Int -> String -> NExpression
-- synMsgGoal agent kappa msg ctx _ goal _ step stage | trace ("synMsgGoal\n\tstep: " ++ show step ++ " - agent: " ++ show agent ++ " - stage: " ++ stage ++ " - goal: " ++ showSimpleGoal goal ++ "\n\tK(" ++ agent ++ "): " ++ showKnowledgeMap (getKappa kappa agent) ++ "\n\tmsg: " ++ show (trMsg msg ctx)) False = undefined
synMsgGoal agent kappa msg ctx equations goal opt step stage  = let
                                                                m = trMsg msg ctx
                                                                ka = getKappa kappa agent ctx
                                                          in case inSynthesis ka m equations ctx opt of
                                                                    Nothing -> error ("step: " ++ show step ++ " - agent: " ++ show agent ++ " - stage: " ++ stage ++ " - goal: " ++ showSimpleGoal goal ++ "\n" ++ errorInSynthesis agent m ka equations)
                                                                    Just e -> e
-- seen events
mkSeenEvent :: Int -> String -> NExpression -> Peer -> JContext -> NAction
mkSeenEvent int var expr agent ctx = NAGoal (int,peer2Ident agent,Seen,"_" ++ var ++ "_" ++ peer2Ident agent,expr,[(peer2Ident agent,peer2AgentNE agent ctx)],False,int) -- bool ==> side conditions (False because of interest only of the receiving agent)

seenEvents :: Int -> String -> MapSK -> JContext -> NEquations -> SeenSQN -> [Declaration] -> AnBxOnP -> ([NAction],SeenSQN)
seenEvents int agent kappa ctx equations seenSQN decl opt = let
                                                    alreadySeen = [ id  | (ag,id) <- seenSQN, ag==agent]
                                                    generated = [ id | DGenerates((_,ag),NEName (_,id)) <- decl,  ag == agent ]
                                                    sqndef = getIdentifiersByTypeStrict ctx JSeqNumber
                                                    sqn = (sqndef \\ alreadySeen) \\ generated
                                                    sqnsyn = [ x | x <- sqn, isSynMsg agent kappa (Atom x) ctx equations opt, isVariable x] -- sqn var syntetisable 
                                                  in case sqnsyn of
                                                        [] -> ([],seenSQN)
                                                        (x:_) -> let
                                                                events1 = [mkSeenEvent int x (synSeenExpr agent kappa (Atom x) ctx equations opt) (ident2Peer agent) ctx]
                                                                seen1 = [(agent,x)]
                                                                (events2,seen2) = seenEvents int agent kappa ctx equations (seenSQN ++ seen1) decl opt
                                                             in (events1 ++ events2, seen2)
                                                             -- error ("\nx: " ++ x ++ "\nev1: " ++ show events1 ++ "\nev2: " ++ show events2 ++ "\nsn: " ++ show (nubOrd(seenSQN ++ seen1 ++ seen2)))

synSeenExpr :: String -> MapSK -> Msg -> JContext -> NEquations -> AnBxOnP -> NExpression
synSeenExpr agent kappa msg ctx equations opt = let
                                                    m = trMsg msg ctx
                                                    ka = getKappa kappa agent ctx
                                                in case inSynthesis ka m equations ctx opt of
                                                        Nothing -> error ("in seen: " ++ "\n" ++ errorInSynthesis agent m ka equations)
                                                        Just e -> e

-- | Generate a unique ID for the event, including goal-specific details and event labels
mkID :: Goal -> Msg -> JContext -> String
mkID goal msg ctx =
    mkGoalID goal ++ getIdent msg ctx ++ "_" ++ filter (/=' ') (unwords eventLabel)
        where
        -- Create the eventLabel based on the type of goal
        eventLabel = case goal of
            -- For goals with two agents
            Authentication p1 p2 _ _ -> map peer2Ident [p1,p2]
            WAuthentication p1 p2 _ _ -> map peer2Ident [p1,p2]
            ChGoal (p1,Confidential,p2) _ _ -> map peer2Ident [p1,p2]
            ChGoal (p1,_,p2) _ _ -> map peer2Ident [p2,p1]      -- inverted order to match auth goals
            -- For goals with multiple peers 
            Secret _ peers _ _ -> map peer2Ident peers

mkGoalID :: Goal -> String
mkGoalID (Secret _ _ True _ ) = "w"
mkGoalID Secret {} = ""
mkGoalID ch@(ChGoal (_,Sharing _,_) _ _) = error ("channel goal unsupported" ++ show ch)
mkGoalID ch@(ChGoal (_,ActionComment _ _,_) _ _) = error ("channel goal unsupported" ++ show ch)
mkGoalID (ChGoal (_,ch@Confidential,_) _ _) = "chgoal_" ++ show ch ++ "_"       
mkGoalID (ChGoal (_,ch,_) _ _) = "_chgoal_" ++ show ch ++ "_"
mkGoalID WAuthentication {} = "_wauth_"
mkGoalID Authentication {} = "_auth_"

peer2NExpression :: KnowledgeMap -> Peer -> NEquations -> JContext -> AnBxOnP -> NExpression
peer2NExpression ka (a,_,_) equations ctx opt = case inSynthesis ka (agent2NExpression a ctx) equations ctx opt of
                                Just em -> em
                                Nothing -> error ("Agent " ++ a ++ " is unknown\nknowledge: " ++ showKnowledgeMap ka)

peer2AgentNE :: Peer -> JContext -> NExpression
peer2AgentNE (a,_,_) ctx = agent2NExpression a ctx

data RelaxKnowAgent = RelaxKnowAgentTrue | RelaxKnowAgentFalse
                            deriving (Eq)

effectiveStep :: Int -> String -> Goal -> Msg -> JContext -> MapGoals -> Int
effectiveStep currentstep x g msg ctx mapgoals = case getMapGoalForAgent x g msg ctx mapgoals of
            Nothing -> error $ "Missing entry for agent: " ++ x ++ "\n" ++
                        "goal: " ++ show g ++ "\n" ++
                        "msg: " ++ show msg ++ "\n" ++
                        "in mapgoals: " ++ show mapgoals
            Just result -> Data.Maybe.fromMaybe currentstep result

-- relax can be true only after last action is processed
-- generate goal events
endEvents :: Int -> Int -> MapSK -> Goal -> JContext -> NEquations -> MapGoals -> AnBxOnP -> RelaxKnowAgent -> [NAction]
endEvents s currentstep kappa g@(Secret msg peers guess _) ctx equations mapgoals opt _ = map (\x -> let
                                                                                        -- this is stronger condition that each agent knows all other agents of the secrecy set 
                                                                                        -- agentListExpr = map (\y -> (y,synMsgGoal x kappa (Atom y) ctx g)) agentList
                                                                                        agentListExpr = map (\y -> (y, agent2NExpression y ctx)) agentList
                                                                                        e = synMsgGoal x kappa msg ctx equations g opt (es x) "endEvents/g"
                                                                                        sideCond = ifhonest x agentList agentListExpr
                                                                                     in NAGoal (s,x, if guess then GuessableSecretGoal else SecretGoal, ids, e, agentListExpr, sideCond, es x)) agentList
                                                                                where
                                                                                    agentList = map peer2Ident peers
                                                                                    ids = mkID g msg ctx
                                                                                    es x = effectiveStep currentstep x g msg ctx mapgoals

endEvents _ _ _  (ChGoal (_,Confidential,_) _ _) _ _ _ _ _ = []

endEvents s currentstep kappa g@(ChGoal (p2,ct,p1) msg _) ctx equations mapgoals opt relax = [NAGoal (s,p,event,ids,e,agentListExpr,sideCond,es p)]
                                                 where
                                                      p = peer2Ident p1
                                                      event = case ct of
                                                                FreshSecure -> Request
                                                                FreshAuthentic -> Request
                                                                _  -> Wrequest
                                                      agentList = map peer2Ident (if relax==RelaxKnowAgentTrue then (if isSynMsg p kappa (Atom (peer2Ident p2)) ctx equations opt then [p1,p2] else [p1]) else [p1,p2])
                                                      ids = mkID g msg ctx
                                                      e = synMsgGoal p kappa msg ctx equations g opt (es p) "endEvents/e"
                                                      agentListExpr = map (\x -> if ct==Insecure && isSynMsg x kappa (Atom x) ctx equations opt
                                                                                            then (x,agent2NExpression x ctx)
                                                                                            else (x,synMsgGoal p kappa (Atom x) ctx equations g opt (es x) "endEvents/agl")) agentList
                                                      sideCond = ifhonest p agentList agentListExpr
                                                      es x = effectiveStep currentstep x g msg ctx mapgoals

endEvents s currentstep kappa g@(WAuthentication p1 p2 msg _) ctx equations mapgoals opt relax = [NAGoal (s,p,Wrequest,ids,e,agentListExpr,sideCond,es p)]
                                                 where
                                                      p = peer2Ident p1
                                                      agentList = map peer2Ident (if relax==RelaxKnowAgentTrue then (if isSynMsg p kappa (Atom (peer2Ident p2)) ctx equations opt then [p1,p2] else [p1]) else [p1,p2])
                                                      ids = mkID g msg ctx
                                                      e = synMsgGoal p kappa msg ctx equations g opt (es p) "endEvents/e"
                                                      agentListExpr = map (\x -> (x,synMsgGoal p kappa (Atom x) ctx equations g opt (es x) "endEvents/agl")) agentList
                                                      sideCond = ifhonest p agentList agentListExpr
                                                      es x = effectiveStep currentstep x g msg ctx mapgoals

endEvents s currentstep kappa g@(Authentication p1 p2 msg _) ctx equations mapgoals opt relax = [NAGoal (s,p,Request,ids,e,agentListExpr,sideCond,es p)]
                                                where
                                                      p = peer2Ident p1
                                                      agentList = map peer2Ident (if relax==RelaxKnowAgentTrue then (if isSynMsg p kappa (Atom (peer2Ident p2)) ctx equations opt then [p1,p2] else [p1]) else [p1,p2])
                                                      ids = mkID g msg ctx
                                                      e = synMsgGoal p kappa msg ctx equations g opt (es p) "endEvents/e"
                                                      agentListExpr = map (\x -> (x,synMsgGoal p kappa (Atom x) ctx equations g opt (es x) "endEvents/agl")) agentList
                                                      sideCond = ifhonest p agentList agentListExpr
                                                      es x = effectiveStep currentstep x g msg ctx mapgoals

beginEvents :: Int -> Int -> MapSK -> Goal -> JContext -> NEquations -> MapGoals -> AnBxOnP -> [NAction]
beginEvents _ _ _  Secret {} _ _ _ _= []

-- this implements confidential channel goals A ->* B: Msg 
-- it generates an event on the sender side rather than on the receiver side    
beginEvents s endEvnrSecr kappa g@(ChGoal (p1@(a,_,_),Confidential,p2@(b,_,_)) msg _) ctx equations mapgoals opt= [NAGoal (endEvnrSecr,p, SecretGoal, ids, synMsgGoal p kappa msg ctx equations g opt s "beginEvents/g",agentListExpr,sideCond,s) | not (skipConfidentialChGoal || skipChGoal)]
                                                                            where
                                                                                  p = peer2Ident p1  -- sender
                                                                                  agentList = map peer2Ident (if isSynMsg a kappa (Atom b) ctx equations opt then [p1,p2] else [p1]) -- check if receiver is known by sender
                                                                                  agentListExpr = map (\x -> (x,synMsgGoal p kappa (Atom x) ctx equations g opt (es x) "beginEvents/agl")) agentList
                                                                                  ids = mkID g msg ctx
                                                                                  sideCond = ifhonest p agentList agentListExpr
                                                                                  es x = effectiveStep s x g msg ctx mapgoals

beginEvents s endEvnrSecr kappa g@(ChGoal (p2,ct,p1) msg par) ctx equations mapgoals opt = NAGoal (s,p,Witness,ids,e,agentListExpr,False,s) : confGoal
                                                            where
                                                                p = peer2Ident p2
                                                                agentList = map peer2Ident [p1,p2]
                                                                ids = mkID g msg ctx
                                                                e = synMsgGoal p kappa msg ctx equations g opt s "beginEvents/e"
                                                                agentListExpr = map (\x -> if ct==Insecure && isSynMsg x kappa (Atom x) ctx equations opt
                                                                                            then (x,agent2NExpression x ctx)
                                                                                            else (x,synMsgGoal p kappa (Atom x) ctx equations g opt s "beginEvents/agl")) agentList
                                                                -- secure: authentic + confidential
                                                                confGoal = if ct == FreshSecure || ct == Secure then beginEvents s endEvnrSecr kappa (ChGoal (p2,Confidential,p1) msg par) ctx equations mapgoals opt else []

beginEvents s _ kappa g@(WAuthentication p1 p2 msg _) ctx equations mapgoals opt = [NAGoal (s,p,Witness,ids,e,agentListExpr,False,s)]
                                                            where
                                                                p = peer2Ident p2
                                                                agentList = map peer2Ident [p1,p2]
                                                                ids = mkID g msg ctx
                                                                e = synMsgGoal p kappa msg ctx equations g opt s "beginEvents/e"
                                                                agentListExpr = map (\x -> (x,synMsgGoal p kappa (Atom x) ctx equations g opt (es x) "beginEvents/agl")) agentList
                                                                es x = effectiveStep s x g msg ctx mapgoals

beginEvents s _ kappa g@(Authentication p1 p2 msg _) ctx equations mapgoals opt = [NAGoal (s,p,Witness,ids,e,agentListExpr,False,s)]
                                                            where
                                                                p = peer2Ident p2
                                                                agentList = [p1,p2]
                                                                agentListExpr = map (\x -> (peer2Ident x,peer2AgentNE x ctx)) agentList
                                                                ids = mkID g msg ctx
                                                                e = synMsgGoal p kappa msg ctx equations g opt (es p) "beginEvents/e"
                                                                es x = effectiveStep s x g msg ctx mapgoals
-- compute execnarr and knowledge map

-- event step for annotation 
 -- @(beginEvnr,endEvnrAuth,endEvnrSecr)
type EVNumbers = (Int,Int,Int)

evnOfProt :: Actions -> EVNumbers
evnOfProt actions = (beginEvnrDefault,evNumber steps, evNumber steps)    
                        where steps = length actions

beginEvnrDefault :: Int
beginEvnrDefault = 0

evNumber :: Int -> Int
evNumber n | n > 0 = (div (n + 1) 100 + 1) * 100 - 1
           | otherwise = error ("evNumber - wrong nunber of steps" ++ show n)

execnarrKnowOfProt :: Protocol -> AnBxOnP -> (Execnarr,MapSK,MapGoals)
-- execnarrKnowOfProt (_,_,(_,_),_,_,_,actions,goals) _ | trace  ("\nexecnarrKnowOfProt\n\ta: " ++ show (head actions) ++ "\n\tgoals: " ++ showSimpleGoals goals) False = undefined
execnarrKnowOfProt prot@(_,types,_,anbequations,(_,wh),shares,_,actions,goals) anbxopt = (xnarr,kappa,mapgoals)
                        where
                            ctx = buildJContext prot 
                            xnarr = nubOrd . sortExecNarr . cleanExecNarr $ (wh_actions ctx ++ narr)
                            newmapgoals = initMapGoals goals ctx
                            goals2ver = if ng then [] else goals
                            evn = evnOfProt actions
                            (narr,kappa,mapgoals) = compileAnB2ExecnarrKnow (0,Set.empty,Map.empty,Set.empty) (ctx,types,shares,decs,decs,equations,actions,goals2ver,goals2ver,[]) newmapgoals evn anbxopt out
                            ng = nogoals anbxopt
                            out = anbxouttype anbxopt
                            decs = trAnB2ExecnarrKnowledge prot ctx anbxopt
                            wh_actions = where2notEq wh
                            equations = trEquations anbequations types ctx

-- compute execnarr
execnarrOfProt :: Protocol -> OFMCAttackImpersonationsAndProt -> AnBxOnP -> Execnarr
-- execnarrOfProt (_,_,(_,_),_,_,_,actions,goals) trImpsAndProt _ | trace  ("\nexecnarrOfProt\n\tActions: " ++ showAction (head actions) ++ "\n\tGoals: " ++ showSimpleGoals goals ++ "\n\ttrImpsAndProt: " ++ show trImpsAndProt)  False = undefined
execnarrOfProt prot trImpsAndProt anbxopt =
  let
    origNarr = fst3 (execnarrKnowOfProt prot anbxopt)
  in case trImpsAndProt of
       Just (_,trProt,trActsIdx,toprint) -> mergeHonestAndTraceExecNarrs origNarr trProt trActsIdx toprint anbxopt
       Nothing -> origNarr

-- compute knowledge map
knowOfProt :: Protocol -> AnBxOnP -> MapSK
knowOfProt prot anbxopt = snd3 (execnarrKnowOfProt prot anbxopt)

-- compute mapGoals (agent,goalID) -> step 
mapgoalsOfProt :: Protocol -> AnBxOnP -> MapGoals
mapgoalsOfProt prot anbxopt = thd3 (execnarrKnowOfProt prot anbxopt)

----------------------------------------------------------------------------------------------------------
-- attack trace reconstruction functions

mergeHonestAndTraceExecNarrs :: Execnarr -> Protocol -> [Int] -> Maybe Msg -> AnBxOnP -> Execnarr
-- mergeHonestAndTraceExecNarrs passiveIntrNarr trProt@(trname,trtypes,trkn,treqs,trsh,trabs,tracts,trgoals) trActsIdx intrMsgToPrint options | trace  ("mergeHonestAndTraceExecNarrs" ++ show intrMsgToPrint) False = undefined
mergeHonestAndTraceExecNarrs passiveIntrNarr (trname,trtypes,trdefs,treqs,trkn,trsh,trabs,tracts,trgoals) trActsIdx intrMsgToPrint options =
  let
    activeAgs = Set.fromList (getActiveAgents tracts)
    intrName = anbxmitm options
    alignedTrProt = (trname,trtypes,trdefs,treqs,trkn,trsh,trabs,alignTraceActionsWithPassive tracts trActsIdx beginEvnrDefault intrName,trgoals)
    ctx = buildJContext alignedTrProt
    narrWithIntrActions = injectIntrActionsInPassiveExecNarr passiveIntrNarr (execnarrOfProt alignedTrProt Nothing (options{nogoals=True})) trActsIdx activeAgs intrName
    equations = trEquations treqs trtypes ctx
    narrWithAddedIntrWff = case intrMsgToPrint of
                             Just toPrint ->  let
                                                m = trMsg toPrint ctx                                           -- translate the AnB message to NExpression
                                                ka0 = getKappa (knowOfProt alignedTrProt options) intrName ctx  -- get knowledge for sender
                                                ka = analysisStepEq ka0 equations ctx options                   -- run equation-based analysis step on the knowledge
                                              in case inSynthesis ka m equations ctx options of
                                                   Nothing -> error (intrName ++ " cannot synthesize the term " ++ show m ++ " at the end of its actions")
                                                   Just em -> case find (\a -> case a of
                                                                                NACheck (_,n,FSingle (FWff ex)) -> n==intrName && ex==em
                                                                                NACheck (_,n,FAnd phi) -> n==intrName && Set.member (FWff em) phi
                                                                                _ -> False) narrWithIntrActions of
                                                                Just _ -> narrWithIntrActions
                                                                Nothing -> case trActsIdx of
                                                                             [] -> error "mergeHonestAndTraceExecNarrs: trace intruder action indexes list is empty"
                                                                             _ -> narrWithIntrActions ++ [NACheck (last trActsIdx,intrName,FSingle (FWff em))]
                             Nothing -> narrWithIntrActions
  in narrWithAddedIntrWff

alignTraceActionsWithPassive:: Actions -> [Int] -> Int -> String -> Actions
alignTraceActionsWithPassive [] _ _ _ = []
alignTraceActionsWithPassive (((_,ActionComment _ _,_),_,_,_):tractxs) trActsIdx currIdx intrName = alignTraceActionsWithPassive tractxs  trActsIdx currIdx intrName
alignTraceActionsWithPassive tr [] _ _ = tr
alignTraceActionsWithPassive activeActs@(tract:tractxs) trActsIdx@(trIdx:trIdxs) currIdx intrName =
  if currIdx==trIdx then
    tract : alignTraceActionsWithPassive tractxs trIdxs (currIdx+1) intrName
  else
    ((ident2Peer intrName,Insecure,ident2Peer intrName),(PlainMsg (Atom intrName)),Nothing,Nothing)
     : alignTraceActionsWithPassive activeActs trActsIdx (currIdx+1) intrName -- add Intr->Intr:Intr fillers to ensure proper step numbering of the trace actions

injectIntrActionsInPassiveExecNarr:: Execnarr -> Execnarr -> [Int] -> Set.Set Ident -> String -> Execnarr
injectIntrActionsInPassiveExecNarr [] _ _ _ _ = []
injectIntrActionsInPassiveExecNarr passiveNarr (n@(NANew _):anxs) trActsIdx activeAgs intrName | agentOfNAction n == Just intrName =
                                                n : injectIntrActionsInPassiveExecNarr passiveNarr anxs trActsIdx activeAgs intrName
injectIntrActionsInPassiveExecNarr passiveNarr@(pn:pnxs) activeNarr trActsIdx activeAgs intrName =
  let pnrest = injectIntrActionsInPassiveExecNarr pnxs activeNarr trActsIdx activeAgs intrName
  in case agentOfNAction pn of
       Just ag | ag==intrName -> case (activeNarr,trActsIdx) of
                                  (an:anxs,tridx:tridxs) -> let pnstep = stepOfNAction pn
                                                            in if tridx < pnstep then injectIntrActionsInPassiveExecNarr passiveNarr activeNarr tridxs activeAgs intrName
                                                               else if tridx > pnstep then pnrest
                                                               else if agentOfNAction an/=Just intrName || tridx > stepOfNAction an then
                                                                      injectIntrActionsInPassiveExecNarr passiveNarr anxs trActsIdx activeAgs intrName
                                                               else an : injectIntrActionsInPassiveExecNarr pnxs anxs trActsIdx activeAgs intrName
                                  _ -> injectIntrActionsInPassiveExecNarr pnxs activeNarr trActsIdx activeAgs intrName
               | Set.member ag activeAgs -> pn : pnrest
       _ -> pnrest

----------------------------------------------------------------------------------------------------------

-- compute bool for side condition (if an agent list in an goal annotation, contains a variable agent name)
ifhonest :: Ident -> [Ident] -> [(Ident,NExpression)] -> Bool
-- ifhonest a agents agsExpr | trace ("\nifhonest\n\ta: " ++ a ++ "\n\tagents: " ++ show agents  ++ "\n\tagsExpr: " ++ show agsExpr ) False = undefined
ifhonest a agents agsExpr = let -- find all the pairs (agent, expression) in goal, except agent a and constant agents
                                                    hh = [ x | x@(ag,_) <- agsExpr, a /= ag, elem ag agents, isVariable ag]
                                                in case hh of
                                                    [] -> False
                                                    _ -> True

-- put secrecy goals at the end of protocol
-- put request annotation at the end
-- events with side conditions after those without
-- this matters when generating ProVerif code

sortExecNarr :: Execnarr -> Execnarr
sortExecNarr xs= let
                    secretsWithoutSideCond = [ g | g@(NAGoal (_,_,SecretGoal,_,_,_,False,_)) <- xs] ++ [ g | g@(NAGoal (_,_,GuessableSecretGoal,_,_,_,False,_)) <- xs]
                    secretsWithSideCond = [ g | g@(NAGoal (_,_,SecretGoal,_,_,_,True,_)) <- xs] ++ [ g | g@(NAGoal (_,_,GuessableSecretGoal,_,_,_,True,_)) <- xs]
                    requestsWithoutSideCond = [ g | g@(NAGoal (_,_,Wrequest,_,_,_,False,_)) <- xs] ++ [ g | g@(NAGoal (_,_,Request ,_,_,_,False,_)) <- xs]
                    requestsWithSideCond = [ g | g@(NAGoal (_,_,Wrequest,_,_,_,True,_)) <- xs] ++ [ g | g@(NAGoal (_,_,Request ,_,_,_,True,_)) <- xs]
                    xs2 = requestsWithoutSideCond ++ secretsWithoutSideCond ++ requestsWithSideCond ++ secretsWithSideCond
                    xs1 = xs \\ xs2
                 in xs1 ++ xs2

wh2a :: Ident -> Ident -> JContext -> NAction
wh2a id1 id2 ctx = NACheck (0,id1,FAnd (Set.singleton (FNotEq (agent2NExpression id1 ctx,agent2NExpression id2 ctx))))

where2notEq :: [(Msg,Msg)] -> JContext -> Execnarr
where2notEq [] _ = []
where2notEq ((Atom id1,Atom id2):xs) ctx = [wh2a id1 id2 ctx,wh2a id2 id1 ctx] ++ where2notEq xs ctx
where2notEq xs _ = error ("unexpected expression in where clause: " ++ show xs)

-- clean formulas
cleanExecNarr :: Execnarr -> Execnarr
cleanExecNarr [] = []
cleanExecNarr (NACheck (step,a,phi):xs) = NACheck (step,a,phi) : cleanExecNarr (cleanFormulas (a,phi) xs)
cleanExecNarr (x:xs) = x : cleanExecNarr xs

cleanFormulas :: (String,Formula) -> [NAction] -> [NAction]
cleanFormulas _ [] = []
cleanFormulas (a,phi@(FAnd ats)) (x:xs) = case x of
                                                NACheck(step,b,FAnd ats1) -> if a == b then NACheck (step,b,FAnd (Set.difference ats1 ats)) : cleanFormulas (a,phi) xs else x : cleanFormulas (a,phi) xs
                                                _ -> x : cleanFormulas (a,phi) xs
cleanFormulas _ x = x           -- single checks -- not present here!

------------------

errorMsgGoalAttackTrace :: Goal -> String -> String
errorMsgGoalAttackTrace goal str = "the goal cannot be processed as " ++ str ++ " knows the message" ++ "\nGoal: " ++ showSimpleGoal goal

-- returns a peer if the peer (1st option) or the intruder (2nd option) can synthesise msg
newPeerTraceGoal :: Goal -> Peer -> MapSK -> Msg -> String -> JContext -> NEquations -> AnBxOnP -> Peer
newPeerTraceGoal g peer@(a,_,_) kappa msg intr ctx equations opt
                                                                | isSynMsg a kappa msg ctx equations opt = peer
                                                                | isSynMsg intr kappa msg ctx equations opt = ident2Peer intr
                                                                | otherwise = error (errorMsgGoalAttackTrace g ("neither " ++ a ++ " or " ++ intr))

-- applies the goal transformation to all goals of the protocol
protAttackTraceGoals :: Protocol -> String -> AnBxOnP -> Protocol
protAttackTraceGoals prot@(name,types,definitions,anbequations,knowledge,shares,abstractions,actions,goals) intr opt = let
                                                                                                                ctx = buildJContext prot -- PTAnB
                                                                                                                equations = trEquations anbequations types ctx
                                                                                                                prot1 = (name,types,definitions,anbequations,knowledge,shares,abstractions,actions,[])
                                                                                                                -- computes the knowledge of agents, no goals are checked or required
                                                                                                                kappa = knowOfProt prot1 opt
                                                                                                                newGoals = map (\x -> goalAttackTrace x kappa intr ctx equations opt) goals
                                                                                                                prot2 = (name,types,definitions,anbequations,knowledge,shares,abstractions,actions,newGoals)
                                                                                                           in prot2

-- applies the transformation of goals based on the rules described in the paper
goalAttackTrace :: Goal -> MapSK -> String -> JContext -> NEquations -> AnBxOnP -> Goal
goalAttackTrace g@(Secret msg peers guess goalcomment) kappa _ ctx equations opt = if null newPeers then error (errorMsgGoalAttackTrace g "no agent")
                                                                                                    else Secret msg newPeers guess goalcomment
                                                                                                        where   -- agents that can be syntesise the message in the secrecy set
                                                                                                            newPeers = [ p | p@(a,_,_) <- peers, isSynMsg a kappa msg ctx equations opt]

-- if p2 (sender) cannot syntesise msg, p2 is replaced by the intruder
goalAttackTrace g@(WAuthentication p1 p2 msg goalcomment) kappa intr ctx equations opt = WAuthentication p1 newPeer msg goalcomment
                                                                                                where
                                                                                                    newPeer = newPeerTraceGoal g p2 kappa msg intr ctx equations opt

goalAttackTrace g@(Authentication p1 p2 msg goalcomment) kappa intr ctx equations opt = Authentication p1 newPeer msg goalcomment
                                                                                                where
                                                                                                    newPeer = newPeerTraceGoal g p2 kappa msg intr ctx equations opt

-- channel goals 
goalAttackTrace g@(ChGoal (p1,ct,p2) msg par) kappa intr ctx equations opt = ChGoal (newPeer,ct,p2) msg par
                                                                                                where
                                                                                                   newPeer = newPeerTraceGoal g p1 kappa msg intr ctx equations opt
