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
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "Use infix" #-}
{-# HLINT ignore "Avoid lambda using `infix`" #-}

module AnBxMain (trAnB,mkAnB,renameProtocol,getProtName,getExt,getAgents,firstPeer,msglist2msg,initTypes,trAnB2AnBx,fixCat,setCertifiedAgents,replicateAnBx) where

import           AnBxAst
import           AnBxDefinitions
import           AnBxImplementation
import           AnBxMsg
import           AnBxMsgCommon
import           AnBxOnP
import           AnBxShow
import           AnBAst
import Data.List ( (\\), intercalate, intersect, nubBy, sort )
import Data.Containers.ListUtils (nubOrd)
import Debug.Trace
import qualified Data.Maybe
import AnBTypeChecking (typeCheckProtocol)
import AnB2NExecnarr (trProt2Execnarr)
-----------------------------------------
-- used in AnBxParser
setCertifiedAgents :: AnBxTypes -> ProtType -> AnBxTypes
setCertifiedAgents types prottype =
  let
    certified :: [Ident]
    certified = if null ca || prottype == PTAnBx then ca else error errMsg
        where
            ca = concatMap (\(t, ids) -> case t of
                                          AnBxAst.Agent _ _ _ Cert -> ids
                                          _ -> []) types
            errMsg = "cannot have certified agents " ++ showIdents ca ++ " in a protocol of type " ++ show prottype ++ " - use type " ++ show PTAnBx ++ " instead"

    -- Remove certified agents from non-certified declarations
    removeCertified :: (AnBxType, [Ident]) -> (AnBxType, [Ident])
    removeCertified (t@(AnBxAst.Agent _ _ _ NoCert), ids) = (t, filter (`notElem` certified) ids) 
    removeCertified xs = xs

    uniqueTypes = map removeCertified types
  in uniqueTypes

---------------------- make AnB ---------------------------
-- main function to translate from AnBx to AnB, also see trAnB for finalisation
mkAnB :: AnBxProtocol -> AnBxOnP -> AnBxProtocol
mkAnB protocol options =
    let (protocolname@(_,prottype),types,definitions,equations,(knowledge,wk),shares,abstraction,actions,goals) = protocol
        ------------------ set some options  ------------
        implType = anbximpltype options
        -- useTagsif2cif = False
        useTagsif2cif = anbxif2cif options                      -- should be True only for debug     
        useTags = case implType of
                        AANB  -> True                           -- tags are mandatory on Annotated AnB
                        _ -> anbxusetags options
        ------------------ set certified agents and returns lists -----------
        agents = getAgents types
        certified = getCertifiedAgents types
        nt0 = types
        ------------------ add initial global types only AnBx ------------
        nt1 = case prottype of
                     PTAnBx -> let
                                    nt1a = initTypes (AnBxAst.SeqNumber []) initSeqNumbers AnBxAst.eqTypesStrict AnBxAst.elemTypes .
                                           initTypes (AnBxAst.Number []) (initNumbers implType useTags useTagsif2cif) AnBxAst.eqTypesStrict AnBxAst.elemTypes $ nt0
                                    nt1b = initTypedFunctions (initFunctionsTyped implType useTagsif2cif) nt1a
                               in nt1b
                     _ -> nt0
        ------------- add global initial knowledge only AnBx ----------
        nk1 = case prottype of
                     PTAnBx -> initKnowledges agents (\_ -> ids2Msgs (initFunctions implType useTagsif2cif)) .
                               initKnowledges agents (\_ -> ids2Msgs (initNumbers implType useTags useTagsif2cif)) .
                               initKnowledges certified initCertifiedPeer .
                               initKnowledges agents (\x -> initPeer x implType useTagsif2cif) $ knowledge
                     _ -> knowledge

        (ntEq,nkEq,eqEq) = mkEqTheories buildInEqTheories (nt1,nk1,equations)
        ------------ expand bullet channels to AnBx channels ----------
        actions0 = mkAnBxActionsExpandBullet nk1 certified actions options prottype
        pkfuncfg = if anbxexpandbullets options then stdPKcfg else chexpPKcfg
        ------------ apply definitions ----------
        definitions1 = reverse (fst (ckDefs (mkDef definitions definitions,types2idents nt1)))
        actions1 = mkDef definitions1 actions0
        shares1 = nubOrd $ mkDef definitions1 shares
        goals1 = nubOrd $ mkDef definitions1 goals
        nk2 = mkDef definitions1 nkEq
        equations1 = nubOrd $ mkDef definitions1 eqEq -- definitions may duplicate some equations, same for goals and shares
        ---------- make initial knowledge (shares) ---------
        -- automatically detect shares in the knowledge
        (nk3a,shares2a) = if noshareguess options then (nk2,shares1) else mkSharesKnowledge nk2 shares1 True
        nt2 = mkShareTypes shares2a ntEq options
        nk4a = mkShareKnowledge shares2a nk3a options
        -- recheck if the previous 2 instructions have added any new shared (agree) info - automatically detect shares in the knowledge
        (nk4,shares2) = if noshareguess options then (nk4a,shares2a) else mkSharesKnowledge nk4a shares2a False
        -----------------------------------------
        -- (nk3,shares2) = if noshareguess options then (nk2,shares1) else mkSharesKnowledge nk2 shares1
        -- nt2 = mkShareTypes shares2 ntEq options
        -- nk4 = mkShareKnowledge shares2 nk3 options
        -----------------------------------------
        ---------- make initial actions (agree/shares) ---------
        actions2 = mkShareActions [ x | x@(SHShare,_,_) <- shares2] actions1 ++ actions1
        actions3 = mkShareActions [ x | x@(SHAgree,_,_) <- shares2] actions2 ++ actions2
        actions4 = mkShareActions [ x | x@(SHAgreeInsecurely,_,_) <- shares2] actions3 ++ actions3
        ----------- expand agree channels to AnBx channels ----------
        actions5 = mkAnBxActionsExpandBullet nk4 certified actions4 options prottype
        ------------ make hash/hmac ----------
        goals2 =  goals1
        dt =  digesttype options
        hmacmaps = mkHmacs actions5 [] 1 nt1 dt
        nk5 = mkDigestKnowledge nk4 t hmacmaps dt
        nt3 = initTypes (AnBxAst.SymmetricKey []) [x | (_,x,_,_) <- hmacmaps] AnBxAst.eqTypesStrict AnBxAst.elemTypes nt2
        goals3 = mkDigestGoals goals2 nt3 hmacmaps dt
        ------------- add comments to goals ----
        goals4 = commentGoals goals goals3
        ------------ compilation ----------
        (nt4,nk6,action5,_,_) = mkActions nt3 nk5 actions5 nullStatus certified 1 implType pkfuncfg useTags hmacmaps [] dt
        ----------- tag protocol for ProVerif termination ---
        (nt5,nk7,action6) = if pvTagFunTT options then applyPVTagFunTT nt4 nk6 action5 else (nt4,nk6,action5)
        ----------- some cleaning -------
        t = mkCleanTypes nt5
         ----------- check types ----------
        actions7 = ckActions action6 t
        goals5 = ckGoals goals4 t
        nk8 = if anbknowcheck options then sanityCheckKnowledge agents nk7 else nk7
        anbxprotocol = (protocolname,t,definitions1,equations1,(nk8,wk),shares2,abstraction,actions7,goals5)
     in anbxprotocol

     -- in error("\n" ++ showShares shares2 ++ "\n" ++ showKnowledgeAgents nk4 ++ "\n" ++ showTypes nt2)

        -- not needed at the moment
        -- nonCertifiedAgreeAgents = if anbxexpandagree options then nubOrd (concat [ agents | (SHAgree,agents,_) <- shares2]) \\ certified else []
        -- nt99 = concatMap (setCertifiedAgent nonCertifiedAgreeAgents) nt2

sanityCheckKnowledge :: [Ident] -> AnBxKnowledgeAgents -> AnBxKnowledgeAgents
sanityCheckKnowledge agents k = let
                                    agentsOfKnowledge = [ a | (a,xs) <- k, xs/=[]]
                                    orphans = agents \\ agentsOfKnowledge
                                in if null orphans then k else error ("Initial knowledge of agent(s) " ++ show orphans ++ " not specified")

-- reconstruct shares from knowledge 
mkSharesKnowledge :: AnBxKnowledgeAgents -> AnBxShares -> Bool -> (AnBxKnowledgeAgents,AnBxShares)
-- mkSharesKnowledge k sh _ | trace ("mkSharesKnowledge\nk " ++ showKnowledgeAgents k ++ "\nsh" ++ showShares sh) False = undefined
mkSharesKnowledge k sh removeExistingMsg = let
                                        -- pairs of knowledge
                                        kpairs = [(a,b) | a  <- k, b <-k, a/=b]
                                        -- the intersection for each pair
                                        kpairIntersect = map (\((ag1,k1),(ag2,k2)) -> (ag1,ag2, [ x | x <- intersect k1 k2, isSharable x, mkShareSanityCheck [ag1,ag2] k])) kpairs
                                        -- non empty intersections
                                        kpairIntersectNotEmpty = [ x | x@(_,_,k) <- kpairIntersect, k/=[] ]
                                        -- what could be shared
                                        kpairIntersectNotEmptyShares = nubBy eqShare kpairIntersectNotEmpty
                                        -- the new shares, but no check that agents know each other
                                        newShares = nubOrd (sh ++ map ( \(ag1,ag2,msgs) -> (SHShare,[ag1,ag2],msgs)) kpairIntersectNotEmptyShares)
                                        -- remove shared value from agents' knowledge to avoid duplication
                                        newKnowkedge = if removeExistingMsg then map (\x -> updateAgentKnowledge x newShares) k else k
                                    in (newKnowkedge,newShares)

isSharable :: AnBxMsg -> Bool
isSharable (Comp _ _) = True
isSharable (AnBxMsg.DigestHash _) = True
isSharable (AnBxMsg.DigestHmac _ _) = True
isSharable _ = False

updateAgentKnowledge :: (String,[AnBxMsg]) -> [(ShareType,[String],[AnBxMsg])]  -> (String,[AnBxMsg])
updateAgentKnowledge (agent,msgs) ((SHShare,agents,msgs1):_) = if elem agent agents then (agent, msgs \\ msgs1) else (agent,msgs)
updateAgentKnowledge (agent,msgs) ((_,_,_):xs) = updateAgentKnowledge (agent,msgs) xs
updateAgentKnowledge (agent,msgs) [] = (agent,msgs)

-- share statement comparison
eqShare :: (String,String,[AnBxMsg]) -> (String,String,[AnBxMsg]) -> Bool
eqShare (ag1,ag2,msgs1) (ag3,ag4,msgs2) = msgs1 == msgs2 && (ag1==ag3 && ag2==ag4 || ag1==ag4 && ag2==ag3)


-- specific function tag, used for tagging protocols
funTag :: Ident -> Ident
funTag f = "tag" ++ f

applyPVTagFunTT :: AnBxTypes -> AnBxKnowledgeAgents -> AnBxActions -> (AnBxTypes,AnBxKnowledgeAgents,AnBxActions)
applyPVTagFunTT t k a = let
                            funTT = findTTFuncions t
                        in if null funTT then (t,k,a) else
                                    let
                                        tags = map funTag funTT
                                        ids = getIds t isNumberType
                                        clashingTags = intersect tags ids
                                    in if clashingTags /= [] then
                                                error ("can not tag protocol as some identifiers already exist: " ++ intercalate "," clashingTags ++ "\nPlease rename the duplicated identifiers")
                                        else let
                                                -- add tags to Types
                                                typedTags = [(AnBxAst.Number [],tags)]
                                                idTags = map Atom tags
                                                t1 = t ++ typedTags
                                                -- add tags to agents's knowledge
                                                k1 = map (\(a,ids) -> (a,nubOrd (ids++idTags))) k
                                                -- for every function occurence replace f with tagf,f
                                                defs = map  (\x -> Def (Comp Apply [Atom x,Atom "X"]) (Comp Cat [Atom (funTag x),Comp Apply [Atom x,Atom "X"]])) funTT
                                                a1 = mkDef defs a
                                             in (t1,k1,a1)
--                                                                    error ("pvTagFunTT option not implemented yet " 
--                                                                        ++ "\n\tfunTT: " ++ show funTT 
--                                                                        ++ "\n\ttags: " ++ show tags
--                                                                        ++ "\n\tTypes:\n " ++ showTypes t1 
--                                                                        ++ "\n\tKnowledge:\n" ++ showKnowledges (k1,[])
--                                                                        ++ "\n\tDefinitions:\n" ++ showDefinitions defs
--                                                                        ++ "\n\ta: " ++ show a1)

-- identifies functions where domain and codomain are the same (endofunction)
findTTFuncions :: AnBxTypes -> [Ident]
findTTFuncions [] = []
findTTFuncions ((AnBxAst.Function [AnBxAst.FunSign ([t1],t2,_)],fids):xs) = (if AnBxAst.eqTypes t1 t2 then fids else []) ++ findTTFuncions xs
findTTFuncions (_:xs) = findTTFuncions xs

errorBulletChannelExpansionMsg :: String
errorBulletChannelExpansionMsg = "bullet channel expansion is available only for AnBx protocols\n" ++ "change protocol interpretation to AnBx by removing AnB after protocol name or changing it to AnBx"

-- translates AnB bullet channels to AnBx channels for further expansion
mkAnBxActionsExpandBullet :: AnBxKnowledgeAgents -> [Ident] -> AnBxActions -> AnBxOnP -> ProtType -> AnBxActions
mkAnBxActionsExpandBullet knowledge certified actions options prottype | anbxexpandbullets options = case prottype of
                                                                                                    PTAnBx -> map (mkAnBxActionExpandBullet knowledge certified options) actions
                                                                                                    _ -> error errorBulletChannelExpansionMsg
                                                             | anbxexpandagree options = map (mkAnBxActionExpandBullet knowledge certified options) actions
                                                             | otherwise = actions

mkAnBxActionExpandBullet :: AnBxKnowledgeAgents -> [Ident] -> AnBxOnP -> AnBxAction -> AnBxAction
-- mkAnBxActionExpandBullet _ _ _ a | trace ("mkAnBxActionExpandBullet\n\taction: " ++ show a ++ "\n") False = undefined
mkAnBxActionExpandBullet _ _ options a@((peer1,AnBxAst.Authentic,peer2@(id,_,_)),msg,msg1,msg2) = if anbxexpandbullets options then ((peer1,BMChannelTypeTriple Std peer1 [id] nullPeer,peer2),msg,msg1,msg2) else a         -- A -> B,(A|B|-)
mkAnBxActionExpandBullet _ _ options a@((peer1,AnBxAst.FreshAuthentic,peer2@(id,_,_)),msg,msg1,msg2) = if anbxexpandbullets options then ((peer1,BMChannelTypeTriple Fresh peer1 [id] nullPeer,peer2),msg,msg1,msg2) else a  -- A -> B,@(A|B|-)
mkAnBxActionExpandBullet _ _ options a@((peer1,AnBxAst.Confidential,peer2),msg,msg1,msg2) = if anbxexpandbullets options then ((peer1,BMChannelTypeTriple Std nullPeer nullVers peer2,peer2),msg,msg1,msg2) else a           -- A -> B,(-|-|B)
mkAnBxActionExpandBullet _ _ options a@((peer1,AnBxAst.Secure,peer2@(id,_,_)),msg,msg1,msg2) = if anbxexpandbullets options then  ((peer1,BMChannelTypeTriple Std peer1 [id] peer2,peer2),msg,msg1,msg2) else a              -- A -> B,(A|B|B)
mkAnBxActionExpandBullet _ _ options a@((peer1,AnBxAst.FreshSecure,peer2@(id,_,_)),msg,msg1,msg2) = if anbxexpandbullets options then ((peer1,BMChannelTypeTriple Fresh peer1 [id] peer2,peer2),msg,msg1,msg2) else a        -- A -> B,@(A|B|B)

mkAnBxActionExpandBullet ka certified options a@((peer1@(id1,_,_),AnBxAst.Sharing SHAgree,peer2@(id2,_,_)),msg,msg1,msg2) = if anbxexpandagree options then -- expands agree action for attack trace reconstruction
                                                                                                                                let -- expansion with agreed sharing function
                                                                                                                                    ids = [id1,id2]
                                                                                                                                    msgAgreed = agreedSecureMsg msg ids
                                                                                                                                    ka1 = knowledgeOfAgent ka id1
                                                                                                                                    ka2 = knowledgeOfAgent ka id2
                                                                                                                                    shKey = shAgreeKey ids
                                                                                                                                in if elem shKey ka1 && elem shKey ka2 then   -- check is key in is agents' knowledge
                                                                                                                                    -- ((peer1,AnBxAst.Sharing SHAgree,peer2),msgAgreed,msg1,msg2)
                                                                                                                                    ((peer1,BMChannelTypeTriple Std nullPeer nullVers nullPeer,peer2),msgAgreed,msg1,msg2)
                                                                                                                                    else error ("mkAnBxActionExpandBullet - key " ++ show shKey ++ " is not shared between agents " ++ showIdents ids ++
                                                                                                                                               "\n\taction: " ++ showAction a ++
                                                                                                                                               "\n\tknowledge:\n" ++ showKnowledgeAgents ka)
                                                                                                                                -- expansion with AnBx functions
                                                                                                                                -- if elem id1 certified && elem id2 certified then
                                                                                                                                --       ((peer1,BMChannelTypeTriple Std peer1 [id2] peer2,peer2),msg,msg1,msg2)                -- A -> B,(A|B|B)
                                                                                                                                --       else ((peer1,BMChannelTypeTriple Std nullPeer nullVers nullPeer,peer2),msg,msg1,msg2)  -- A -> B,(-|-|-)
                                                                                                                         else a
mkAnBxActionExpandBullet _ _ options a@((peer1,AnBxAst.Sharing SHAgreeInsecurely,peer2),msg,msg1,msg2) = if anbxexpandagree options then -- expands agree action for attack trace reconstruction
                                                                                                                                        ((peer1,BMChannelTypeTriple Std nullPeer nullVers nullPeer,peer2),msg,msg1,msg2)   -- A -> B,(-|-|-)
                                                                                                                                      else a
mkAnBxActionExpandBullet _ _ _ a = a

agreedSecureMsg :: AnBxMsg -> [Ident] -> AnBxMsg
agreedSecureMsg msg ids = Comp Scrypt [shAgreeKey ids, msgagreed]
                                where
                                    msgagreed = Comp Cat (map Atom ids ++ [msg])

shAgreeKey :: [Ident] -> AnBxMsg
shAgreeKey ids = Comp Apply (keyfun : keyargs)
                                where
                                        keyfun = Atom (show AnBxShAgree)
                                        keyargs = [Comp Cat (map Atom ids1)]
                                        ids1 = sort ids         -- to make sure the same key is always used, regardless the direction of communication

-- add comments to goals, if different from the original
commentGoals :: AnBxGoals -> AnBxGoals -> AnBxGoals
commentGoals [] _ = []
commentGoals _ [] = []
commentGoals (x:xs) (y:ys) = let
                                ng = if x==y then [x] else [addCommentGoal y (showGoal x)]
                             in ng ++ commentGoals xs ys

addCommentGoal :: AnBxGoal -> String -> AnBxGoal
addCommentGoal (ChGoal channel msg _) comment = ChGoal channel msg comment
addCommentGoal (Secret msg peers bool _) comment = Secret msg peers bool comment
addCommentGoal (Authentication peerFrom peerTo msg _) comment = Authentication peerFrom peerTo msg comment
addCommentGoal (WAuthentication peerFrom peerTo msg _) comment = WAuthentication peerFrom peerTo msg comment

firstPeer :: AnBxActions -> AnBxPeer
-- firstPeer xs | trace ("firstPeer\nactions: " ++ show xs ++ "\n") False = undefined
firstPeer xs = let
                    actions = dropActionComments xs
               in case actions of
                    [] -> error "firstPeer: empty action list"
                    _ -> let ((p,_,_),_,_,_) = head (dropActionComments xs) in p

lastPeer :: AnBxActions -> AnBxPeer
-- lastPeer xs | trace ("lastPeer\nactions: " ++ show xs ++ "\n") False = undefined
lastPeer xs = let
                    actions = dropActionComments xs
               in case actions of
                    [] -> error "lastPeer: empty action list"
                    _ -> let ((_,_,p),_,_,_) = last (dropActionComments xs) in p

sh2Type :: AnBxShare -> ShareType
sh2Type (sh,_,_) = sh

sh2Ids :: AnBxShare -> [Ident]
sh2Ids (_,ids,_) = ids

sh2Msgs :: AnBxShare -> [AnBxMsg]
sh2Msgs (_,_,msgs) = msgs

knowAgent :: AnBxKnowledgeAgent -> Ident -> Bool
knowAgent (_,[]) _ = False
knowAgent (id,(Atom a):xs) agent | a==agent = True
                                 | otherwise = knowAgent (id,xs) agent
knowAgent (id,_:xs) agent = knowAgent (id,xs) agent

knowAgents :: AnBxKnowledgeAgent -> [Ident] -> Bool
knowAgents k = all (knowAgent k)

knowledgeOfAgents :: AnBxKnowledgeAgents -> [Ident] -> AnBxKnowledgeAgents
knowledgeOfAgents k ids = [ x | x@(id,_) <- k, elem id ids]

knowledgeOfAgent :: AnBxKnowledgeAgents -> Ident -> [AnBxMsg]
knowledgeOfAgent k id = concat [ msgs | (id1,msgs) <- k, id == id1]

addSync2Types :: Types -> Types
addSync2Types t = initTypes (AnBxAst.Number []) [syncMsg] AnBxAst.eqTypesStrict AnBxAst.elemTypes t

mkShareTypes :: AnBxShares -> AnBxTypes -> AnBxOnP -> AnBxTypes
mkShareTypes [] t _ = t
-- only agree shares require definition of sync message and agree sharing function
mkShareTypes [(SHAgree,_,_)] t options = let
                                            t1 = addSync2Types t
                                            t2 = if anbxexpandagree options then initTypedFunctions agreeFun t1 else t1
                                         in nubOrd t2
mkShareTypes [(SHAgreeInsecurely,_,_)] t _ = addSync2Types t
mkShareTypes [_] t _ = t
mkShareTypes (x:xs) t options = mkShareTypes xs t1 options
                                where t1 = mkShareTypes [x] t options

-- check if agents (ids) know each other 
mkShareSanityCheck :: [String] -> AnBxKnowledgeAgents -> Bool
mkShareSanityCheck ids k = all (\x -> knowAgents x ids) (knowledgeOfAgents k ids)

mkShareKnowledge :: AnBxShares -> AnBxKnowledgeAgents -> AnBxOnP -> AnBxKnowledgeAgents
mkShareKnowledge [] k _ = k
mkShareKnowledge [(SHShare,ids,msgs)] k _ = if mkShareSanityCheck ids k    -- check if agents know each other
                                                 then initKnowledges ids (const msgs) k
                                                 else error ("Some of the agents (" ++ showIdents ids ++ ") does not know each other" ++
                                                             "\n\twhen sharing " ++ showMsgs msgs ++
                                                             "\n\tPlease check the Knowledge:" ++
                                                             "\n" ++ showKnowledgeAgents k)
                                                             -- "\n" ++ showAstList k showKnowledgeAgent ";\n")
mkShareKnowledge [(SHAgree,ids,_)] k options = let
                                                    k1 = initKnowledges ids (const [syncMsgAst]) k
                                                    k2 = if anbxexpandagree options then initKnowledges ids (const [shAgreeKey ids]) k1 else k1
                                               in k2
mkShareKnowledge [(SHAgreeInsecurely,ids,_)] k _ = initKnowledges ids (const [syncMsgAst]) k
mkShareKnowledge (x:xs) k options = mkShareKnowledge xs k1 options
                                where k1 = mkShareKnowledge [x] k options

mkShareActions :: AnBxShares -> AnBxActions -> AnBxActions
-- mkShareActions xs _ | trace ("mkShareActions\n\tshare actions: " ++ show xs ++ "\n") False = undefined
mkShareActions [] _ = []
mkShareActions [x@(sh@shType,_,_)] a | shType==SHAgree || shType==SHAgreeInsecurely = let
                                                                                        p1 = firstPeer a
                                                                                        as1 = mkShareAction x
                                                                                        p2 = lastPeer as1
                                                                                        as2 = [syncActionSh sh p2 p1 | p2 /= p1]
                                                                                      in as1 ++ as2
mkShareActions (x@(sh@shType,_,_):xs) a | shType==SHAgree || shType==SHAgreeInsecurely = let
                                                                                            p1 = firstPeer a
                                                                                            as1 = mkShareAction x
                                                                                            p2@(id2,_,_) = lastPeer as1
                                                                                            -- see if p2 in the next list, and put p2 in top of the list
                                                                                            -- to avoid syncActions
                                                                                            ids2 = sh2Ids (head xs)
                                                                                            xs1 = if elem id2 ids2 then (sh2Type (head xs),id2 : [x | x <-ids2, x/=id2],sh2Msgs (head xs)) : tail xs else xs
                                                                                            p3 = ident2AnBxPeer (head (sh2Ids (head xs1)))  -- first peer of the next list
                                                                                            as2 = [syncActionSh sh p2 p3 | p3 /= p2]
                                                                                            as3 = mkShareActions xs1 a
                                                                                            p4 = lastPeer as3
                                                                                            as4 = [syncActionSh sh p4 p1 | p4 /= p1]
                                                                                         in as1 ++ as2 ++ as3 ++ as4
mkShareActions ((SHShare,_,_):xs) a = mkShareActions xs a
mkShareActions xs _ = error ("Unexpected share or agree action at this stage: " ++ show xs)

-- mkShareActions (x@(SHShare,_,_):xs) a = mkShareAction x ++ mkShareActions xs a  

mkShareAction :: AnBxShare -> AnBxActions
-- mkShareAction x | trace ("mkShareAction\n\tshare action: " ++ show x ++ "\n") False = undefined
mkShareAction (_,[],_) = []
mkShareAction (_,[_],_) = []
mkShareAction (sh,[id, id'],msgs) = [shareAction sh (ident2AnBxPeer id) (ident2AnBxPeer id') (msglist2msg msgs)]
mkShareAction (sh,id:id':ids,msgs) = shareAction sh (ident2AnBxPeer id) (ident2AnBxPeer id') (msglist2msg msgs) : mkShareAction (sh,id':ids,msgs)

msglist2msg :: [AnBxMsg] -> AnBxMsg
msglist2msg [] = syncMsgAst
msglist2msg msgs = Comp Cat msgs

-- remove unused types
mkCleanTypes :: AnBxTypes -> AnBxTypes
mkCleanTypes [] =[]
mkCleanTypes (x@(_,identlist):xs) = ([x | identlist /= []]) ++ mkCleanTypes xs

initNumbers :: ImplType -> Bool -> Bool -> [Ident]
-- initNumbers impltype useTags useTagsif2cif
-- first boolean is true if tag are used
initNumbers _ True _ = syncMsg : tags
initNumbers CIF False True = syncMsg : tags
initNumbers _ False _ = [syncMsg]

initSeqNumbers :: [Ident]
initSeqNumbers = []

initPeer :: Ident -> ImplType -> Bool -> [AnBxMsg]
initPeer ident AANB _ = map (\pk -> Comp Inv [Comp Apply [Atom (show pk),Atom ident]]) [AnBxBlind]
initPeer ident CIF True = map (\pk -> Comp Inv [Comp Apply [Atom (show pk),Atom ident]]) [AnBxBlind]
initPeer _ _ _ = []

initCertifiedPeer :: Ident -> [AnBxMsg]
initCertifiedPeer ident = map (\pk -> Comp Inv [Comp Apply [Atom (show pk),Atom ident]]) pkiFunList

-- get protocol name
getProtName :: AnBxProtocol -> String
getProtName ((protName,_),_,_,_,_,_,_,_,_) = protName

-- rename protocol to newName
renameProtocol :: AnBxProtocol -> String -> AnBxProtocol
renameProtocol ((_,protType),anbxTypes,anbxDefinitions,anbxEquations,anbxKnowledge,anbxShares,anbxAbstraction,anbxActions,anbxGoals) newName =
                        ((newName,protType),anbxTypes,anbxDefinitions,anbxEquations,anbxKnowledge,anbxShares,anbxAbstraction,anbxActions,anbxGoals)

getExt :: OutType -> String
getExt outtype = case outtype of
                        AnBx -> "AnBx"
                        AnB ->"AnB"
                        AnBEqTheory -> "thy"
                        AnBIF -> "if"
                        AnBIntr ->"AnB"
                        AnBxIntr -> "AnBx"
                        AnBLatex -> "tex"
                        AnBxLatex -> "tex"
                        Spyer -> "spyer"
                        Execnarr -> "exna"
                        OptExecnarr -> "oxna"
                        TypedOptExecnarr -> "txna"
                        TypedOptExecnarrDocker -> "txna"
                        SPI -> "spi"
                        VDM -> "vdmsl"
                        VDMTest -> "vdmsl"
                        _ -> if isOutTypePV outtype then "pv"
                            else if isOutTypeJava outtype then "java"
                            else error ("unhandled file extension for output type: " ++ show outtype)

------------ Translate AnBx2AnB ------------

trAnB :: AnBxProtocol -> AnBxOnP -> IO Protocol
trAnB protocol opt = do
    let ((protocolname, prottype), types, _, equations, knowledge, shares, abstraction, actions, goals) = protocol
        out = anbxouttype opt
        prot1 = ((protocolname, PTAnB), types, [], equations, knowledge, shares, abstraction, actions, goals)
        prot2 = if noprivatekeygoals opt then prot1 else protPrivate2Goals prot1 out
        prot3 = if guessprivatefunctions opt then privateFunctions prot2 else prot2
        prot4 = if anbtypecheck opt then typeCheckProtocol prot3 prottype else prot3

    if anbexeccheck opt && isOutAnB out
        then do
            !_ <- trProt2Execnarr prot4 Nothing opt  -- ejecutabilidad check
            return prot4
        else return prot4

privateFunctions :: Protocol -> Protocol
privateFunctions (protocolname,types,declarations,equations,knowledge,shares,abstraction,actions,goals) =
    (protocolname,types1,declarations,equations,knowledge,shares,abstraction,actions,goals)
        where
            types1 = findPrivateFunctions knowledge types

findPrivateFunctions :: Knowledge -> Types -> Types
findPrivateFunctions k t = t1 -- error ("prv: " ++ show prv ++ "\n" ++ "\n" ++ "t1: " ++ show t1)
                                where
                                    t1 = makeFunctionPrivate t prv
                                    prv = getFunctionsIds t \\ getIdsFromKnowledge k        -- find the private functions  (not included as "atom" in any knowledge or PublicFunction by definition)

makeFunctionPrivate :: Types -> [Ident] -> Types
makeFunctionPrivate t [] = t
makeFunctionPrivate [] _ = []
makeFunctionPrivate ((Function [FunSign (t1,t2,p)],fids):xs) prv = -- error ("pub: " ++ show pubT ++ " - " ++ "priv: " ++ show prvT  ++ " - " ++ "prv: " ++ show prv) 
                                                            newx ++ makeFunctionPrivate xs prv
                                                                where
                                                                    newx = map (\x -> (Function [FunSign (t1,t2,PrivFun)],[x])) prvT ++ map (\x -> case p of
                                                                                                                                                      PrivFun -> (Function [FunSign (t1,t2,PrivFun)],[x])
                                                                                                                                                      _ -> (Function [FunSign (t1,t2,PubFun)],[x])) pubT
                                                                    prvT = intersect prv fids       -- private functions
                                                                    pubT = fids \\ prvT             -- public functions

makeFunctionPrivate (x:xs) ids = x : makeFunctionPrivate xs ids

-- get all functions ids from type declaration
getFunctionsIds :: Types -> [Ident]
getFunctionsIds [] = []
getFunctionsIds ((Function _,ids):xs) = ids ++ getFunctionsIds xs
getFunctionsIds (_:xs) = getFunctionsIds xs

-- get all ids declared in initial knowledge
getIdsFromKnowledge :: Knowledge -> [Ident]
getIdsFromKnowledge ([],_) = []
getIdsFromKnowledge ((_,msgs):xs,kw) = [ x | (Atom x) <- msgs ] ++ getIdsFromKnowledge (xs,kw)

-- compute secrecy goals from Private section
protPrivate2Goals :: Protocol -> OutType -> Protocol
protPrivate2Goals (name, types, definitiopns, equations,knowledge,shares, abstractions, actions, goals) out =
                        (name, types, definitiopns, equations,knowledge,shares, abstractions, actions, goals1)
                        -- error ("private:" ++ show (getActiveAgents actions))
                                                      where
                                    private = mkPrivateAgent knowledge (getActiveAgents actions)   -- generate private key goals only for active agents
                                    goalsInv = map (\(ids,msg) -> secGoal msg ids) private
                                    goals1 = nubOrd (goals ++ goalsInv ++ private2GoalPrivateKeys types actions out)

private2GoalPrivateKeys :: Types -> Actions -> OutType -> Goals
private2GoalPrivateKeys types a out = let
                                    publicKeys = getIds types isPublicKeyType
                                    -- get only variables, and key used
                                    publicKeysVar = [ pk | pk <- publicKeys, isVariable pk, firstAgent pk a out /= Nothing]
                                  in map (\x -> private2GoalPrivateKey x a out) publicKeysVar

private2GoalPrivateKey :: Ident -> Actions -> OutType -> Goal
private2GoalPrivateKey pk a out = let
                                agent = firstAgent pk a out
                              in case agent of
                                Nothing -> error ("private2goal privatekey pk: " ++ show pk ++ " - a: " ++ show a)
                                Just ag -> secGoal (Comp Inv [Atom pk]) [ag]

-- [ident]: list of active agents in the protocol 
mkPrivateAgent :: Knowledge -> [Ident] -> [([Ident],Msg)]
mkPrivateAgent ([],_) _ = []
mkPrivateAgent ((id,msgs):xs,wh) ids = [([id], x) | elem id ids, x@(Comp Inv _) <- msgs] ++ mkPrivateAgent (xs,wh) ids

secGoal :: Msg -> [Ident] -> Goal
secGoal msg [] = error ("no peers specfied in goal for msg: " ++ show msg)
secGoal msg [x] = Secret msg [(x, False, Nothing)] False ""
secGoal msg agents = Secret msg (map (\ x -> (x, False, Nothing)) agents) False ""

-- equations --------------

mkEqTheory :: AnBxEqTheory -> (AnBxTypes,AnBxKnowledgeAgents,AnBxEquations) -> (AnBxTypes,AnBxKnowledgeAgents,AnBxEquations)
mkEqTheory (thTypes,thEquations) (types,knowledgeAgents,equations) = (nubOrd (types ++ thTypes), k1, nubOrd (equations ++ thEquations))
                                                            where
                                                                    k1 = map (\(ag,msgs) -> (ag,msgs ++ nubOrd (ids2Msgs (getTypeIds thTypes)))) knowledgeAgents

-- add the equational theories to the protocol: type declaration, agents' knowledge and equations

mkEqTheories :: [AnBxEqTheory] -> (AnBxTypes,AnBxKnowledgeAgents,AnBxEquations) -> (AnBxTypes,AnBxKnowledgeAgents,AnBxEquations)
mkEqTheories theories (types,knowledge,equations) = (types1,knowledge1,equations2)
                                                       where
                                                            (types1,knowledge1,equations1) = foldr mkEqTheory (types,knowledge,equations) theories
                                                            equations2 = map (checkEquation types) equations1
relaxAllIDVar :: Bool
relaxAllIDVar = True

checkEquation :: AnBxTypes -> AnBxEquation ->  AnBxEquation
checkEquation types eq@(AnBxAst.Eqt msg1 msg2) = if cond then eq else error ("All identifiers in this equation declaration must be variables: " ++ showEquation eq
                                                                              ++ "\nidentifiers: " ++ intercalate "," ids ++ "\nconstants: " ++ intercalate "," consts)
                                                        where
                                                            cond = relaxAllIDVar || all isVariable ids
                                                            consts = filter (not . isVariable) ids
                                                            ids = nubOrd (msgs2IdsNoFun msg1 types ++ msgs2IdsNoFun msg2 types)

-- get all ids from type declaration
getTypeIds :: AnBxTypes -> [Ident]
getTypeIds [] = []
getTypeIds xs = concatMap snd xs

---------------------------------------------------
-- translate AnB2AnBx


trAnB2AnBx :: Maybe ProtType -> Protocol -> AnBxProtocol
trAnB2AnBx protType protocol =
    let
        pType = Data.Maybe.fromMaybe PTAnB protType
        ((protocolname,_), types, _, equations, knowledge, shares, abstraction, actions, goals) = protocol
        actions1 = dropActionShares actions  -- actions shares are dropped as they can be recompiled in AnBx 
        dropShares = False
        shares1 = if dropShares then [] else shares  -- shares are dropped as they can be recomputed
        prot1 = ((protocolname,pType), types, [], equations, knowledge, shares1, abstraction, actions1 , goals)
    in prot1

---- replicate actions n times (n = anbxreplicate) ---

replicateAnBx :: AnBxProtocol -> AnBxOnP -> AnBxProtocol
replicateAnBx prot opt = let
                            ((protname,prottype),types,definitions,equations,(knag,knwh),shares,abstraction,actions,goals) = prot
                            n = anbxreplicate opt
                            p1 = firstPeer actions
                            p2 = lastPeer actions
                            ids = [peer2Ident p1, peer2Ident p2]
                            types1 = if p1==p2 then types else addSync2Types types
                            knag1 = if p1==p2 then knag else initKnowledges ids (const [syncMsgAst]) knag                -- add sync
                            protname1 = protname ++ "_x" ++ show n
                            actions0 = if p1==p2 then actions else actions ++ [syncActionSh SHAgreeInsecurely p2 p1]     -- add sync
                            actions1 | n > minAnBxReplicate = concat (replicate n actions0)
                                     | n == minAnBxReplicate = error ("-out:AnBx requires a valid " ++ cmdAnBxReplicate ++ " parameter: n > " ++ show minAnBxReplicate)
                                     | otherwise = error ("replicateAnBx - invalid value n: " ++ show n ++ ", must be n > " ++ show minAnBxReplicate)       
                         in ((protname1,prottype),types1,definitions,equations,(knag1,knwh),shares,abstraction,actions1,goals)
