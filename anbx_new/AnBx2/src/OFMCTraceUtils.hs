{-

 AnBx Compiler and Code Generator

 Copyright 2021-2025 Rémi Garcia
 Copyright 2021-2025 Paolo Modesti
 Copyright SCM/SCDT/SCEDT, Teesside University

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

module OFMCTraceUtils where
import OFMCTraceParser
import OFMCTraceLexer
import AnBxMsgCommon
import AnBTypeSystem_Context
import AnBTypeSystem_Evaluator
import Control.Monad.Writer
import AnBAst
import AnBxAst
import AnBxMain
import Data.List ( find, elemIndex, stripPrefix )
import Data.Maybe
import Data.Either
import Data.List.Split
import Data.Char (toUpper)
import JavaCodeGenConfig
import AnB2NExpression
import Spyer_Execnarr
import Spyer_Message
import AnBxOnP
import qualified Data.Map as M
import qualified Data.Set as S
import Java_TypeSystem_Context
import AnBxMsg ( AnBxMsg (Comp,Atom), patternMsgError)
import AnBxShow (showActions,showAction, showSimpleGoal)
import Data.Containers.ListUtils (nubOrd)


-- map of agent real name to alias xXX in trace, how far it has gone in the protocol and knowledge at this step
type OFMCStateKnowledge = M.Map Ident (Ident,Int,[Msg])

-- subjectivity in format: key: alias , values: all agents substituted by alias
type SubjectiveAgents = M.Map Ident (S.Set Ident)


-- those keys are present in the trace to encrypt a message and make bullet semantics explicit, or simply to act as intruder keys
intrKeysSubsts:: M.Map Msg Msg
intrKeysSubsts = M.fromList [(Atom "authChCr",Atom (show AnBxSK)),(Atom "confChCr",Atom (show AnBxPK))]

getTrace:: String -> (Actions,[Msg])
getTrace inputstr = let trace = case splitOn "ATTACK TRACE:\n" inputstr of
                                  (_:trst:_) -> let rstStr =  "% Reached State:"
                                                in case splitOn rstStr trst of
                                                          (tr:st:_) -> case splitOn "i can" tr of
                                                                         (tracts:_) -> tracts ++ rstStr ++ st
                                                                         _ -> tr ++ rstStr ++ st
                                                          _ -> "Could not find a reached state in the ofmc attack trace"
                                  _ -> error "Unrecognised ofmc attack format: did not find 'ATTACK TRACE'"
                        (catUnfixed,rchSt) = ofmctraceparser . OFMCTraceLexer.alexScanTokens $ trace
                        catFixed = map (\(ch,msg,patt,sendknow) -> (ch,fixCat msg, fixCatMaybe patt,fixCatMaybe sendknow)) catUnfixed
                    in (catFixed,rchSt)

fixCatMaybe:: Maybe Msg -> Maybe Msg
fixCatMaybe msg = case msg of
                    Just m -> Just (fixCat m)
                    Nothing -> Nothing

-- replace aliased expressions in trace and format protocol
getNamedTrace :: String -> Protocol -> ProtType -> AnBxOnP -> (Protocol,Knowledge,[Int],Maybe Msg)
getNamedTrace tracetext prot@(protName,types,definitions,anbeqs,(know,wh),_,abst,unfilteredacts,goals) ptype anbxopt =
  if length goals /= 1 then error singleGoalsErrMsg  -- only protocols with single goals are supported at the moment
  else
  let
    ctx = buildContext prot ptype
    (trace,reached) = getTrace tracetext
    protActs = filter isEffectiveAction unfilteredacts
    agsOwnInfos = getKnowledgesFromState reached
    intrName = anbxmitm anbxopt
    objectiveAgsSubsts = M.insert (Atom iname) (Atom intrName) (M.foldrWithKey (\ag (alias,_,_) acc -> M.insert (Atom alias) (Atom ag) acc) M.empty agsOwnInfos)
    honestKnow = (filter (\(ag,_) -> ag /= intrName) know,wh)
    subjAliases = subjectiveAliasesInProt agsOwnInfos honestKnow
    subjAgsSubsts = M.foldrWithKey (\alias subj acc -> M.insert (Atom alias) (Atom (subjToId alias subj intrName)) acc) M.empty subjAliases
    agsSubsts = M.union objectiveAgsSubsts subjAgsSubsts
    namedtrace = replaceActsVars agsSubsts trace
    --subjAgsDecls = ((Agent False False []), M.foldr (\(Atom name) acc -> name:acc) [] subjAgsSubsts)
    subjectiveKn = getHonestAgentsSubjectiveKnowledge honestKnow agsOwnInfos agsSubsts
    (mirrorPassiveActs,forgedTypes,trHonestKnowSec@(trHonestKnow,trWh),trActs,actsIndexes) = mergeTraceActions subjectiveKn protActs namedtrace agsOwnInfos types ctx intrName --forgedTypes are new ids for what is forged by intr
    intrKnow = getIntrKnow honestKnow types intrName
    traceKnow = (intrKnow:trHonestKnow,trWh)
    traceProt = (protName,types++forgedTypes,[],anbeqs,traceKnow,[],abst,trActs,goals)
    (newgoals,intrMsgToPrint) = rewriteGoals mirrorPassiveActs traceProt anbxopt {nogoals=True}
  in ((protName,types++forgedTypes,definitions,anbeqs,(intrKnow: map (\(a,ts) -> case find (\(a2,_) -> a==a2) know of
                                                                Nothing -> error ("getNamedTrace: could not find knowledge for agent " ++ a ++ " in original knowledge:\n"++show know)
                                                                Just (_,ts2) -> (a, nubOrd (ts++ts2)))
                                                    trHonestKnow ,trWh),
       [],abst,trActs,newgoals), trHonestKnowSec, actsIndexes,intrMsgToPrint)--(subjAgsDecls:forgedTypes,intrKnow,trKnow, trActs,actsIndexes)

isEffectiveAction:: Action -> Bool
isEffectiveAction ((_,ActionComment _ _,_),_,_,_) = False
isEffectiveAction ((_,Sharing SHShare,_),_,_,_) = False
isEffectiveAction _ = True

getHonestAgentsSubjectiveKnowledge:: Knowledge -> OFMCStateKnowledge -> M.Map Msg Msg -> Knowledge
getHonestAgentsSubjectiveKnowledge kn@([],_) _ _ = kn
getHonestAgentsSubjectiveKnowledge ((ag,kn):knxs,wh) stKnow agsSubs =
  case M.lookup ag stKnow of
    Just (_,_,stkn) -> let
                         (restkn,restwh) = getHonestAgentsSubjectiveKnowledge (knxs,wh) stKnow agsSubs
                         selfIdx = elemIndex (Atom ag) kn -- we assume the knowledge is deduplicated since we are using the result of compileAnBx
                       in ((ag, case selfIdx of
                                  Just idx -> let (before,after) = splitAt idx (reverse (map (replaceMsgs agsSubs) (take (length kn - 1) stkn))) in before ++ Atom ag:after
                                  Nothing -> reverse (map (replaceMsgs agsSubs) (take (length kn) stkn)) ++ [Atom ag]) --add at the end to maintain order in original knowledge
                          : restkn, restwh)
    Nothing -> error ("Agent "++ag++" is not recorded in reached state. Recording is "++show stKnow)

-- Agent alias is the first parameter: state_rAgent(alias,stepnum,...). The rest is the initial knowledge of the agent
getKnowledgesFromState:: [Msg] -> OFMCStateKnowledge
getKnowledgesFromState ((Comp Apply ((Atom fun):[Comp Cat ((Atom selfalias):(Atom stepnum):stateknow)])):stxs) =
                  let rest = getKnowledgesFromState stxs
                  in case stripPrefix "state_r" fun of
                       Just ag -> M.insert ag (selfalias, read stepnum, init stateknow) rest -- the last variable in stateknow is the session number
                       Nothing -> rest
getKnowledgesFromState (_:stxs) = getKnowledgesFromState stxs
getKnowledgesFromState [] = M.empty

subjToId:: Ident -> S.Set Ident -> String -> Ident
--subjToId alias subj = (intercalate "_" (S.toList subj))++"_"++ alias
subjToId _ _ intrName = intrName

subjectiveAliasesInProt:: OFMCStateKnowledge -> Knowledge -> SubjectiveAgents
subjectiveAliasesInProt stKnows (kns,_) =
      let selfAliases = S.insert iname (M.foldr (\(al,_,_) acc -> S.insert al acc) S.empty stKnows)
      in M.unionsWith S.union
                (map (\(ag,kn) -> let stkn = case M.lookup ag stKnows of
                                               Just (_,_,stk) -> stk
                                               Nothing -> error ("Agent " ++ ag ++ " is not recorded in reached state. Recording is " ++ show stKnows)
                                  in subjectiveAliasesFromStateKnow stkn (ag, reverse kn) selfAliases) --to compare with ofmc state knowledge which comes reversed
                       kns)

-- returns for each xXX subjective agent: which agents it represents in the given agent's knowledge
subjectiveAliasesFromStateKnow:: [Msg] -> (Ident,[Msg]) -> S.Set Ident -> M.Map Ident (S.Set Ident)
subjectiveAliasesFromStateKnow _ (_,[]) _ = M.empty
subjectiveAliasesFromStateKnow [] _ _ = M.empty
subjectiveAliasesFromStateKnow stateknow@(st:stxs) (ag,(Atom initk):kxs) selfAliases =
  if initk==ag then subjectiveAliasesFromStateKnow stateknow (ag,kxs) selfAliases --skip if self in knowledge
  else case st of
        Atom stk -> let restSubj = subjectiveAliasesFromStateKnow stxs (ag,kxs) selfAliases
                    in if stk /= initk && S.notMember stk selfAliases then --subjective alias, only for agents
                         M.insertWith S.union stk (S.singleton initk) restSubj
                       else restSubj
        _ -> error ("Knowledge of agent "++ag++": "++initk++" could not be found in reached state. "++ show st++" is found at this position in reached state.")
subjectiveAliasesFromStateKnow (_:stxs) (ag,(Comp _ _):kxs) selfAliases = subjectiveAliasesFromStateKnow stxs (ag,kxs) selfAliases
subjectiveAliasesFromStateKnow _ (_,msg:_) _ = error $ patternMsgError msg "subjectiveAliasesFromStateKnow" 

replaceActsVars:: M.Map Msg Msg -> Actions -> Actions
replaceActsVars substs acts = map (\(ch,msg,patt,sendknow) -> (replaceChannelVar substs ch, replaceMsgs substs msg, patt, sendknow)) acts

replaceChannelVar:: M.Map Msg Msg -> Channel -> Channel
replaceChannelVar substs ch = let replsend = case M.lookup (Atom (getSender ch)) substs of
                                               Just (Atom name) -> setSender ch name
                                               _ -> ch
                              in case M.lookup (Atom (getReceiver replsend)) substs of
                                   Just (Atom name) -> setReceiver replsend name
                                   _ -> replsend

replaceMsgs:: M.Map Msg Msg -> Msg -> Msg
replaceMsgs substs msg = case M.lookup msg substs of
                           Just name -> name
                           Nothing -> case msg of
                                        Atom _ -> msg
                                        Comp op msgs -> Comp op (map (replaceMsgs substs) msgs)
                                        _ -> error $ patternMsgError msg "replaceMsgs"

getIntrKnow:: Knowledge -> Types -> String -> (Ident,[Msg])
getIntrKnow (agsknow,_) types intrName = let
                                           intrkn = S.fromList (Atom intrName:
                                             concatMap (\(ag,msgs) -> if isConstant ag then [] -- constant agents have a non-extractible knowledge and i cannot impersonate them
                                                                      else mapMaybe (\m -> case m of
                                                                                             Atom x -> if x/=ag then Just m else Nothing -- litterals are known as-is
                                                                                             Comp _ _ -> Just (replaceMsgs (M.singleton (Atom ag) (Atom intrName)) m)
                                                                                             _ -> error $ patternMsgError m "getIntrKnow")
                                                                                     msgs)
                                                          agsknow)
                                           withDHBase = case declOfID dhPar types of
                                                          Just (Number _,_) -> S.insert (Atom dhPar) intrkn
                                                          _ -> intrkn
                                         in (intrName,S.toList withDHBase)


splitWithIntrAnB:: Protocol -> String -> Protocol
splitWithIntrAnB ((ptname,pt),types,defs,eqs,kn,_,abst,acts,goals) intrName =
  ((ptname++attackTraceSuffix,pt),types,defs,eqs,kn,[],abst,foldr (\(ch,msg,patt,sendknow) acc ->
                                                             (setReceiver ch intrName,msg,patt,sendknow)
                                                           : (setSender ch intrName,msg,patt,sendknow) : acc) [] acts, goals)

-- returns index of nth action with given agent as sender or nth with it as receiver and n-1 previous as sender
idxOfnthActOfAgent:: (Ident,Int) -> Actions -> Int -> Maybe Int
idxOfnthActOfAgent _ [] _ = Nothing
idxOfnthActOfAgent (ag,stepsToGo) ((actch,_,_,_):actxs) tempindex =
                                      if stepsToGo < 1 then Nothing
                                      else let isSender = getSender actch == ag
                                           in if stepsToGo == 1 && isSender then Just tempindex
                                              else let
                                                     remainingSteps = if isSender then stepsToGo-1 else stepsToGo
                                                     indexrest = idxOfnthActOfAgent (ag,remainingSteps) actxs (tempindex+1)
                                                   in case indexrest of
                                                       Just idx -> Just idx
                                                       Nothing -> if getReceiver actch == ag then Just tempindex else Nothing

getOrigsWhenForged:: S.Set Ident -> Msg -> Msg -> M.Map Ident Msg
getOrigsWhenForged declaredIds (Comp pop (pmsg:pmsgxs)) (Comp trop (trmsg:trmsgxs)) | pop==trop =
                                                            M.union (getOrigsWhenForged declaredIds pmsg trmsg) (getOrigsWhenForged declaredIds (Comp Cat pmsgxs) (Comp Cat trmsgxs))
getOrigsWhenForged declaredIds m (Atom trid) = if S.notMember trid declaredIds then M.singleton trid m else M.empty
getOrigsWhenForged _ _ _ = M.empty

-- for an ident: returns the uppercase necessary declarations and the expression it should be replaced by.
getForgeryInfos:: S.Set Ident -> (Actions,Actions) -> AnBContext -> String -> M.Map Ident (Types,Msg)
getForgeryInfos _ ([],_) _ _ = M.empty
getForgeryInfos _ (_,[]) _ _ = M.empty
getForgeryInfos declaredIds (pt,((_,ActionComment _ _,_),_,_,_):trxs) ctx intrName = getForgeryInfos declaredIds (pt,trxs) ctx intrName
getForgeryInfos declaredIds ((_,ptmsg,_,_):ptxs,(_,trmsg,_,_):trxs) ctx intrName =
  M.union (getForgeryInfos declaredIds (ptxs,trxs) ctx intrName) (M.mapWithKey (\alias orig -> getStructuredForgery (toUpper (head alias):tail alias) orig ctx intrName)
                                                                      (getOrigsWhenForged declaredIds ptmsg trmsg))

-- restores the original structure when a non-Atom expression is replaced by a single alias. Useful for type and buffer-size fooling.
-- if it replaces a ciphertext, then the cipher is given by ofmc as something that cannot be decrypted by the receiver. We generate dummy values then.
getStructuredForgery :: Ident -> Msg -> AnBContext -> String -> (Types,Msg)
getStructuredForgery alias orig ctx intrName =
  let keyName al = al++"_Key"
  in case orig of
       Comp Cat msgs -> let
                          msgsSize = length msgs
                          vnames = if msgsSize>1 then map (\idx -> alias++"_" ++ show idx) [1..msgsSize] else [alias]
                          (types,exprs) = foldr (\(name,msg) (acct,acce)-> let (t,e) = getStructuredForgery name msg ctx intrName
                                                                           in (t++acct, e:acce))
                                          ([],[]) (zip vnames msgs)
                        in (types, Comp Cat exprs)
       Comp Apply ((Atom fun):_) | fun==show AnBxHash -> ([(Number [],[alias])], Comp Apply (Atom fun:[Atom alias]))
                                 | fun==show AnBxHmac -> ([(Number [],[alias]),(SymmetricKey [],[keyName alias])],
                                                          Comp Apply (Atom fun:[Atom alias, Atom (keyName alias)]))
       Comp cr [_,msgs] | cr==Crypt || cr==Scrypt -> let (forgedTypes,forgedMsgs) = getStructuredForgery alias (Comp Cat [msgs]) ctx intrName
                                                     in ((if cr==Crypt then PublicKey [] else SymmetricKey [], [keyName alias]):forgedTypes,
                                                         Comp cr [Atom (keyName alias), forgedMsgs])
       Comp Exp [Atom base,expo] | base==dhPar ->  let aliasWithDH = case expo of
                                                                           Atom e | isVarofType DHX e -> prefixDHX++alias
                                                                                  | isVarofType DHY e -> prefixDHY++alias
                                                                           _ -> alias
                                                       in ([(Number [],[aliasWithDH])], Comp Exp [Atom base,Atom aliasWithDH])
       Comp Inv _ -> ([(PublicKey [], [alias])], Comp Inv [Atom alias])
       _ -> case fst (runWriter (typeofTSM orig ctx)) of
              BaseType (Agent {}) -> ([], Atom intrName)
              BaseType t -> ([(t,[alias])],Atom alias)
              _ -> ([(Number [], [alias])], Atom alias)

-- channel type and pseudonyms are supposed to already be set as original protocol specification
normalizeChannelMsg:: Action -> Action
normalizeChannelMsg ((sender@(_,sisps,_),chtype,recv), msg,patt,sendknow) =
      let trimmedMsg = if sisps && chtype /= Confidential then
                         case msg of
                           Comp Cat [_,m] -> m
                           Comp Cat (_:ms) -> Comp Cat ms
                           _ -> error (show msg++"\nNon confidential pseudonymous channels are supposed to contain a pseudonym and then the actual message")
                       else msg
      in ((sender,Insecure,recv), replaceMsgs intrKeysSubsts trimmedMsg,patt,sendknow)

-- Takes reversed actions: pattern matching starts from last possible trace action. Returns well-formatted reversed actions
-- From the moment the trace begins, channels will be the ones found in the trace. Additional forwarding is discarded
-- It does not replace the messages with the intruder ones.
getMirroringProtAndTrace:: Actions -> Actions -> Int -> (Actions,Actions, [Int])
getMirroringProtAndTrace pt [] _ = ([],map mkActComment pt,[])
getMirroringProtAndTrace [] (tr:_) _ = error ("No action to match trace action " ++ showAction tr)
getMirroringProtAndTrace (ac@(ptch,ptmsg,_,_):actxs) trArr@((trch,trmsg,patt,sendknow):trxs) actIdx =
              if getSender trch == getSender ptch && getReceiver trch == getReceiver ptch then
                let
                    (ptRest,trRest,idxRest) = getMirroringProtAndTrace actxs trxs (actIdx-1)
                    normalizedTrAct@(_,normalizedtrMsg,_,_) = normalizeChannelMsg (ptch,trmsg,patt,sendknow)
                    withOrigComment = if normalizedtrMsg/=ptmsg then normalizedTrAct:[mkActComment ac] else [normalizedTrAct]
                in (ac:ptRest, withOrigComment++trRest, actIdx:idxRest)
              else let (ptRest,trRest,idxRest) = getMirroringProtAndTrace actxs trArr (actIdx-1) --action is irrelevant to the attack
                   in (ptRest,mkActComment ac:trRest,idxRest)


declOfID:: Ident -> Types -> Maybe (Type,[Ident])
declOfID ident types = find (\(_,decls) -> elem ident decls) types

mkActComment :: Action -> Action
mkActComment ac = ((ident2Peer nullPeerName,ActionComment CTAnBx (showAction ac),ident2Peer nullPeerName),Atom syncMsg,Nothing,Nothing)

-- Protocol actions list will be split protocol actions for Dolev-Yao: A->B - A->Intr Intr->B
-- returns actions in original protocol with a trace counterpart, trace additional types, subjective knowledge, actions, and trace action indexes wrt the passive acts
mergeTraceActions:: Knowledge -> Actions -> Actions -> OFMCStateKnowledge -> Types -> AnBContext -> String -> (Actions,Types,Knowledge,Actions,[Int])
mergeTraceActions (kn,wh) acts tr agKnows types ctx intrName =
  let
    realTraceActs = filter (\(ch,_,_,_) -> not (getSender ch == intrName && getReceiver ch == intrName)) tr -- trim i -> i from ofmc output
    reversedTrace = reverse realTraceActs
    lastTracedAg = let
                     (lastCh,_,_,_) = head reversedTrace
                     sender = getSender lastCh
                   in if sender/=intrName then sender else getReceiver lastCh
    reachedStepofLastTrAg = case M.lookup lastTracedAg agKnows of
                              Just (_,step,_) -> step
                              Nothing -> error ("Agent "++lastTracedAg++" could not be found in state info:\n"++show agKnows)
    lastSubstableActIdx = case idxOfnthActOfAgent (lastTracedAg,reachedStepofLastTrAg) acts 0 of
                            Just idx -> idx
                            Nothing -> error ("Could not find action "++show reachedStepofLastTrAg++" for agent "++lastTracedAg)
    (protSubstable,protAfterTrace) = splitAt (lastSubstableActIdx+1) acts
    reversedProt = reverse protSubstable
    (mirrorPt,mirrorTr,actsIndexes) = let (p,t,nums) = getMirroringProtAndTrace reversedProt reversedTrace lastSubstableActIdx
                                      in (reverse p,reverse t, reverse nums) --operate on non reversed lists for type inference because intr can swap variables mid-protocol
    declaredIds = S.fromList [ ids | (_, items) <- types, ids <- items]
    forgeryInfos = getForgeryInfos declaredIds (mirrorPt,mirrorTr) ctx intrName
    forgedSubsts =  M.foldrWithKey (\alias (_,subst) acc -> M.insert (Atom alias) subst acc )  M.empty forgeryInfos
    withforgedTrace = replaceActsVars forgedSubsts mirrorTr
    subjKnow = (kn,wh)--(map (\(a,k) -> (a,k++[(Atom pseudonymFun)])) kn, wh)
    typesForForged = M.toList (M.foldr (\(todecls,_) acc -> foldr (\(t,ids) localacc -> M.insertWith (\x y -> concat [x,y]) t ids localacc) acc todecls) M.empty forgeryInfos) --group ids by type
  in
    (mirrorPt,typesForForged, subjKnow, withforgedTrace ++ map mkActComment protAfterTrace,actsIndexes)

-- Order of terms must be maintained between original and trace knowledges. Unequal Atoms are agents because other constants are well known
getImpersonationsForOneAgent:: Ident -> [Msg] -> [Msg] -> M.Map Ident Ident
getImpersonationsForOneAgent _ [] _ = M.empty
getImpersonationsForOneAgent ag (_:_) [] = error ("Original initial knowledge of agent " ++ ag ++ "is longer than its initial trace knowledge")
getImpersonationsForOneAgent ag ((Atom origmsg):orignkxs) ((Atom trmsg):trknxs) = if origmsg /= trmsg then M.insert (rolePrefix++origmsg) (rolePrefix++trmsg) rest else rest
                                                                                  where rest = getImpersonationsForOneAgent ag orignkxs trknxs
getImpersonationsForOneAgent ag ((Comp _ _):orignkxs) ((Comp _ _):trknxs) = getImpersonationsForOneAgent ag orignkxs trknxs
getImpersonationsForOneAgent ag origkn trkn = error ("Mismatching original and trace initial knowledges of agent "++ ag ++":\n" ++ show origkn ++ "\n"++ show trkn)

getSubjectiveImpersonations:: Knowledge -> Knowledge -> String -> SubjectiveImpersonations
getSubjectiveImpersonations ([],_) _  _ = M.empty
getSubjectiveImpersonations _ ([],_) _ = M.empty
getSubjectiveImpersonations origkn@((origag,_):origknxs,origwh) trkn@((trag,_):trknxs,trwh) intrName
   | trag == intrName = getSubjectiveImpersonations origkn (trknxs,trwh) intrName
   | origag == intrName = getSubjectiveImpersonations (origknxs,origwh) trkn intrName
   | origag /= trag = error ("Knowledge sections in original protocol and trace reconstruction should be in the same order\n Orig: Agent " ++ origag ++ " , Trace: Agent "++trag)
getSubjectiveImpersonations ((ag,origKnMsgs):origknxs,origwh) ((_,trKnMsgs):trknxs,trwh) intrName =
  let
    rest = getSubjectiveImpersonations (origknxs,origwh) (trknxs,trwh) intrName
    current = getImpersonationsForOneAgent ag origKnMsgs trKnMsgs
  in if M.null current then rest
     else M.insert (rolePrefix++ag) current rest

rewriteGoals:: Actions -> Protocol -> AnBxOnP -> (Goals, Maybe Msg)
rewriteGoals passiveActs trProt@(_,types,_,anbequations,_,_,_,_,[goal]) anbxopt =
    let 
        ctx1 = buildJContext trProt
        (newgoal,intrMsgToPrint) = rewriteGoalMsg goal passiveActs trProt (knowOfProt trProt anbxopt) (trEquations anbequations types ctx1) ctx1 anbxopt
    in ([newgoal],intrMsgToPrint)
rewriteGoals _ _ _ = error singleGoalsErrMsg

singleGoalsErrMsg :: String
singleGoalsErrMsg = "Goal rewriting for ofmc trace reconstruction is only supported for a single goal"

-- takes the searched expression, the original protocol action message, and the trace action message. Returns its counterpart from a given agent's point of view
getOrigFromHonestAgPovActionMsg:: Msg -> Msg -> Msg -> (String,MapSK) -> NEquations -> JContext -> AnBxOnP -> Maybe Msg
getOrigFromHonestAgPovActionMsg targetmsg ptmsg trmsg (ag,kn) neqs ctx opts | targetmsg==ptmsg = if isSynMsg ag kn trmsg ctx neqs opts then Just trmsg
                                                                                                           else Nothing
getOrigFromHonestAgPovActionMsg targetmsg (Comp Scrypt pt) (Comp Scrypt tr@[trkey,_]) (ag,kn) neqs ctx opts =
    if isSynMsg ag kn trkey ctx neqs opts then
      getOrigFromHonestAgPovActionMsg targetmsg (Comp Cat pt) (Comp Cat tr) (ag,kn) neqs ctx opts
    else Nothing
getOrigFromHonestAgPovActionMsg targetmsg (Comp Crypt pt) (Comp Crypt tr@[trkey,_]) (ag,kn) neqs ctx opts =
    let keyToDecrypt = case trkey of
                         Comp Inv [pubkey] -> pubkey
                         pubkey -> Comp Inv [pubkey]
    in if isSynMsg ag kn keyToDecrypt ctx neqs opts || isSynMsg ag kn (Comp Cat tr) ctx neqs opts then
         getOrigFromHonestAgPovActionMsg targetmsg (Comp Cat pt) (Comp Cat tr) (ag,kn) neqs ctx opts
       else Nothing
getOrigFromHonestAgPovActionMsg targetmsg (Comp pop (ptmsg:ptmsgxs)) (Comp trop (trmsg:trmsgxs)) kn neqs ctx opts | pop==trop =
    case getOrigFromHonestAgPovActionMsg targetmsg ptmsg trmsg kn neqs ctx opts of
      Just orig -> Just orig
      Nothing -> getOrigFromHonestAgPovActionMsg targetmsg (Comp Cat ptmsgxs) (Comp Cat trmsgxs) kn neqs ctx opts
getOrigFromHonestAgPovActionMsg _ _ _ _ _ _ _ = Nothing

-- the actions must be matching passive intruder protocol and trace actions, where only the agent's send/receive actions are present
getOrigFromHonestAgPovActions:: Msg -> (Actions,Actions) -> (String,MapSK) -> NEquations -> JContext -> AnBxOnP -> Maybe Msg
getOrigFromHonestAgPovActions _ ([],[]) _ _ _ _  = Nothing
getOrigFromHonestAgPovActions _ (ptact:_,[]) _ _ _ _ = error ("No trace action to match action: " ++ showAction ptact ++ " when trying to rewrite goals during ofmc trace reconstruction")
getOrigFromHonestAgPovActions _ ([],tract:_) _ _ _ _ = error ("No action to match trace action: " ++ showAction tract ++ " when trying to rewrite goals during ofmc trace reconstruction")
getOrigFromHonestAgPovActions targetmsg ((_,ptmsg,_,_):ptactsxs,(_,trmsg,_,_):tractsxs) kn neqs ctx opts =
    case getOrigFromHonestAgPovActionMsg targetmsg ptmsg trmsg kn neqs ctx opts of
      Just msg -> Just msg
      Nothing -> getOrigFromHonestAgPovActions targetmsg (ptactsxs,tractsxs) kn neqs ctx opts

-- returns the error message for the first non-composable terminal term, or the Msg
getOrigFromHonestAgPovMsg:: Msg -> (Actions,Actions) -> (String,MapSK) -> NEquations -> JContext -> AnBxOnP -> Either String Msg
getOrigFromHonestAgPovMsg targetmsg (ptacts,tracts) kn@(peer,_) neqs ctx opts =
  case getOrigFromHonestAgPovActions targetmsg (ptacts,tracts) kn neqs ctx opts of
    Just m -> Right m
    Nothing -> case targetmsg of -- if the message does not appear as-is, see if it is composable
                 Atom failedTarget -> Left ("Terminal term " ++ failedTarget ++ " could not be associated with a trace counterpart from " ++ peer ++ "'s point of view during OFMC trace reconstruction goal rewriting. Trace actions involving " ++ peer ++ " are:\n" ++ showActions tracts)
                 Comp op terms -> let newmsg = map (\t -> getOrigFromHonestAgPovMsg t (ptacts,tracts) kn neqs ctx opts) terms
                                  in case find isLeft newmsg of
                                       Just err -> err
                                       Nothing -> Right (Comp op (rights newmsg))
                 _ -> error $ patternMsgError targetmsg "getOrigFromHonestAgPovMsg"  

-- passive actions must be the matching counterparts of trace actions
rewriteGoalMsg:: Goal -> Actions -> Protocol -> MapSK -> NEquations -> JContext -> AnBxOnP -> (Goal, Maybe Msg)
rewriteGoalMsg goal passiveActs (_,_,_,_,_,_,_,trActs,_) know neqs ctx anbxopt =
  let
    effectiveTrActs = filter isEffectiveAction trActs
    filterActsByAg ag = let predAg (ch, _, _, _) = getSender ch == ag || getReceiver ch == ag
                        in (filter predAg passiveActs, filter predAg effectiveTrActs)
    secrecyGoalMsgSearch peers msg = case peers of
                                       ((pname,_,_):otherpeers) -> case getOrigFromHonestAgPovMsg msg (filterActsByAg pname) (pname,know) neqs ctx anbxopt of
                                                                     Right m -> m
                                                                     Left _ -> secrecyGoalMsgSearch otherpeers msg
                                       [] -> error ("None of the agents specified in the secrecy goal can compose a trace counterpart for " ++ show msg ++ " during OFMC trace reconstruction goal rewriting. Trace actions are:\n" ++ showActions trActs)
    authGoalMsgSearch (peerName,_,_) msg = case getOrigFromHonestAgPovMsg msg (filterActsByAg peerName) (peerName,know) neqs ctx anbxopt of
                                             Right m -> m
                                             Left err -> error err
    isKnownByActiveAgent ag msg = ag `elem` getActiveAgents trActs && isSynMsg ag know msg ctx neqs anbxopt
    substitutePeer peer@(peerName,_,_) msg = if isKnownByActiveAgent peerName msg then peer
                                             else ident2Peer (anbxmitm anbxopt)
    goalComment = showSimpleGoal
   in case goal of
        ChGoal channel msg _ -> let
                                  (newChannel,newmsg,intrMsgToPrint) =
                                    case channel of
                                      (ini,chtype,recv) | chtype `elem` [Authentic,FreshAuthentic] -> let trmsg = authGoalMsgSearch recv msg
                                                                                                                     in ((substitutePeer ini trmsg,chtype,recv),trmsg, Nothing)
                                                         | chtype == Confidential -> let trmsg = secrecyGoalMsgSearch [ini] msg
                                                                                            in ((ini,chtype,substitutePeer recv trmsg),trmsg, Just trmsg)
                                                         | chtype `elem` [Secure,FreshSecure] -> error ("Cannot rewrite secure bullet channel goals in OFMC goal reconstruction. Please split the goal "++ showSimpleGoal goal ++ " into authentic (*->) and confidential (->*) pieces.")
                                      _ ->  (channel,msg, Nothing)
                                in (ChGoal newChannel newmsg (goalComment goal), intrMsgToPrint)
        Secret msg peers guessable _ -> let newmsg = secrecyGoalMsgSearch peers msg
                                        in (Secret newmsg (filter (\(pname,_,_) -> isKnownByActiveAgent pname newmsg) peers) guessable (goalComment goal), Just newmsg)
        WAuthentication ini resp msg _ -> let newmsg = authGoalMsgSearch ini msg
                                           in (WAuthentication ini (substitutePeer resp newmsg) newmsg (goalComment goal), Nothing)
        Authentication ini resp msg _ -> let newmsg = authGoalMsgSearch ini msg
                                          in (Authentication ini (substitutePeer resp newmsg) newmsg (goalComment goal), Nothing)
