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

module AnBxImplementation where

import           AnBxAst
import           AnBxImplementationCIF
import           AnBxMsg
import           AnBxMsgCommon
import           AnBxOnP
import           AnBxShow
import           Data.Char
import Data.List ( (\\), union )
import Data.Containers.ListUtils (nubOrd)
import           Debug.Trace


type AnBxStepImpl = ([(AnBxType,Ident)],[Ident],AnBxActions,NonceStore)
-- new (Type,ident), idents to add to all agents, protocolsteps@(a,msg,b), NonceStore

whichForward :: AnBxChannel -> AnBxChannel -> ForwardMode
-- forward modes (no fresh)
whichForward channel@(peerFrom, BMChannelTypeTriple Forward peerAF _ peerST,peerTo) previous@(_,BMChannelTypeTriple prevmode prevpeerAF _ prevpeerST,_) =
        if peerAF == prevpeerAF && peerAF /= peerFrom && peerFrom /= peerTo && prevmode /= Forward then
                        if isNullPeer peerST then
                                Sighted
                        else
                                if peerST /= prevpeerST then
                                        SightedSecret
                                else
                                        if peerST == prevpeerST && peerST == peerTo && prevmode == Std then
                                                Blind
                                        else
                                                error (peerErrorForward channel previous)
        else error (peerErrorForward channel previous)

-- fresh forward modes
-- AnBx 2.0
whichForward channel@(peerFrom, BMChannelTypeTriple ForwardFresh peerAF _ peerST,peerTo) previous@(_,BMChannelTypeTriple prevmode prevpeerAF _ prevpeerST,_) =
        if peerAF == prevpeerAF && peerAF /= peerFrom && peerFrom /= peerTo && prevmode /= Forward then
                        if isNullPeer peerST then
                                FreshSighted
                        else
                                if peerST /= prevpeerST then
                                        FreshSightedSecret
                                else
                                         error (peerErrorForward channel previous)
        else error (peerErrorForward channel previous)

whichForward channel previous = error (peerErrorForward channel previous)

newNum :: String -> Int -> String
newNum str int = str ++ show int

type ActionStatus = (AnBxChannel,AnBxMsg)

nullStatus :: (AnBxChannel,AnBxMsg)
nullStatus =  (nullChannel,Atom "")

nullChannel :: AnBxChannel
nullChannel = (nullPeer,Insecure,nullPeer)

plainChannel :: AnBxPeer -> AnBxPeer -> AnBxChannel
plainChannel p1 p2  = (p1,Insecure,p2)

syncAction :: AnBxPeer -> AnBxPeer -> AnBxAction
syncAction p1 p2 = (plainChannel p1 p2, syncMsgAst,Nothing,Nothing)

syncActionSh :: ShareType -> AnBxPeer -> AnBxPeer -> AnBxAction
syncActionSh sh p1 p2 = shareAction sh p1 p2 syncMsgAst

shareChannel :: ShareType -> AnBxPeer -> AnBxPeer -> AnBxChannel
shareChannel sh p1 p2  = (p1,Sharing sh,p2)

shareAction :: ShareType -> AnBxPeer -> AnBxPeer -> AnBxMsg -> AnBxAction
shareAction sh p1 p2 msg = (shareChannel sh p1 p2, msg,Nothing,Nothing)

peerErrorNoCert :: AnBxPeer -> AnBxChannel -> String
peerErrorNoCert peer channel = "\n\n" ++ "Peer " ++ showPeer peer ++ " must be certified on channel\n\n" ++ showChannel channel ++ "\n\n"

peerErrorForward :: AnBxChannel ->  AnBxChannel -> String
peerErrorForward channel previous = "\n\n" ++ "Incompatible forward mode in channel sequence\n\n" ++ showChannel previous ++ " " ++ showChannel channel ++ "\n\n"

peerErrorMode :: AnBxChannel -> String
peerErrorMode channel@(_,ct,_) = "\n\n" ++ "Incompatible mode in channel\n\n" ++ showChannel channel ++ "\n\n" ++ "Double check if the forwarding mode ^" ++ showChannelType ct ++ " should be enabled" ++ "\n\n"

--------------------------------- notation conversion  -----------
cvPair2Triple :: AnBxAction -> AnBxAction
cvPair2Triple ((a@(ida,_,_),BMChannelTypePair bmode orig dest@(iddest,_,_) ,b@(idb,_,_)),m1,m2,m3) =
        if isNullPeer orig then
                ((a,BMChannelTypeTriple bmode orig [nullPeerName] dest ,b),m1,m2,m3)
        else
                case bmode of
                        Forward -> ((a,BMChannelTypeTriple bmode orig [ida] dest ,b),m1,m2,m3)
                        ForwardFresh -> ((a,BMChannelTypeTriple bmode orig [ida] dest ,b),m1,m2,m3)
                        _ -> if isNullPeer dest then
                                        ((a,BMChannelTypeTriple bmode orig [idb] dest ,b),m1,m2,m3)
                                else
                                        ((a,BMChannelTypeTriple bmode orig [iddest] dest ,b),m1,m2,m3)
cvPair2Triple act = act

------------------------- Channel Mapping -----------------------
ch2impl :: AnBxChannel -> ActionStatus -> [Ident] -> AnBxChImpl
-- ch2impl ch@(_,chmode,_) actionstatus certified | trace ("ch2impl\n\tch: " ++ showChannel ch ++ "\n\tchmode: " ++ show chmode ++ "\n\tactionstatus: " ++ show actionstatus ++ "\n\tcertified: " ++ show certified) False = undefined
----------------------- standard modes --------------------------
ch2impl channel@(peerFrom, BMChannelTypeTriple Std peerAF vers peerST, peerTo) _ certified
            | isNullPeer peerAF && isNullPeer peerST && peerFrom /= peerTo = Plain peerFrom peerTo
            -- FromA channel
            | peerFrom == peerAF && not (isNullPeer peerFrom) && isNullPeer peerST && peerFrom /= peerTo = if isPeerMemberOf peerAF certified then
                                                                                                                    FromA peerAF vers peerTo
                                                                                                                else error (peerErrorNoCert peerFrom channel)
            -- SecretForC
            | not (isNullPeer peerST) && isNullPeer peerAF && peerFrom /= peerTo = if isPeerMemberOf peerST certified then
                                                                                                SecretForC peerFrom peerTo peerST
                                                                                        else error (peerErrorNoCert peerST channel)
            -- FromASecretForC
            | peerFrom == peerAF && not (isNullPeer peerFrom) && not (isNullPeer peerST) && peerFrom /= peerST = if isPeerMemberOf peerFrom certified then
                                                                                                                        if isPeerMemberOf peerST certified then
                                                                                                                                FromASecretForC peerFrom vers peerTo peerST
                                                                                                                        else error (peerErrorNoCert peerST channel)
                                                                                                                else error (peerErrorNoCert peerFrom channel)
            | otherwise = error (peerErrorMode channel)

----------------------- fresh modes --------------------------
ch2impl channel@(peerFrom, BMChannelTypeTriple Fresh peerAF vers peerST, peerTo) _ certified
            | peerFrom == peerAF && not (isNullPeer peerFrom) && isNullPeer peerST = if isPeerMemberOf peerFrom certified then
                                                                                if isPeerMemberOf peerTo certified then
                                                                                        FreshFromA peerFrom vers peerTo
                                                                                else FreshFromAWithDH peerFrom vers peerTo
                                                                        else error (peerErrorNoCert peerFrom channel)

            | peerFrom == peerAF && peerTo == peerST && not (isNullPeer peerFrom) && not (isNullPeer peerTo) = if isPeerMemberOf peerFrom certified then
                                                                                                                        if isPeerMemberOf peerTo certified then
                                                                                                                                FreshFromASecretForB peerFrom vers peerTo
                                                                                                                        else
                                                                                                                                error (peerErrorNoCert peerTo channel)
                                                                                                             else error (peerErrorNoCert peerFrom channel)
            | otherwise = error (peerErrorMode channel)

----------------------- forward modes --------------------------
ch2impl channel@(peerFrom, BMChannelTypeTriple Forward _ vers _, peerTo) (previous@(_,BMChannelTypeTriple mode prevpeerAF _ _,_),_) certified =
        case whichForward channel previous of
                Blind -> ForwardBlind peerFrom vers peerTo peerTo
                Sighted ->      if mode==Fresh then
                                        ForwardSighted prevpeerAF vers peerFrom peerTo True
                                else
                                        ForwardSighted prevpeerAF vers peerFrom peerTo False

                SightedSecret -> if isPeerMemberOf peerTo certified then
                                                       if mode==Fresh then
                                                                ForwardSightedSecret prevpeerAF vers peerFrom peerTo True
                                                       else
                                                                ForwardSightedSecret prevpeerAF vers peerFrom peerTo False
                                        else
                                                error (peerErrorNoCert peerTo channel)
                _ -> error (peerErrorNoCert peerTo channel)

-- AnB 2.0 --------------- Forward Fresh Modes ---------------
ch2impl channel@(peerFrom, BMChannelTypeTriple ForwardFresh _ vers _, peerTo) (previous@(_,BMChannelTypeTriple _ prevpeerAF _ _,_),_) certified =
        case whichForward channel previous of
                FreshSighted -> if isPeerMemberOf peerTo certified then
                                                ForwardFreshSighted prevpeerAF vers peerFrom peerTo
                                          else
                                                ForwardFreshSightedWithDH prevpeerAF vers peerFrom peerTo

                FreshSightedSecret -> if isPeerMemberOf peerTo certified then
                                                       ForwardFreshSightedSecret prevpeerAF vers peerFrom peerTo
                                            else
                                                        error (peerErrorNoCert peerTo channel)
                _ -> error (peerErrorNoCert peerTo channel)

ch2impl (peerFrom,channelType, peerTo) _ _ = error ("unhandled channel type " ++ show peerFrom ++ " " ++ show channelType ++ " " ++ show peerTo)
-- ch2impl (peerFrom,channelType, peerTo) _ _ = AnBStandard peerFrom peerTo channelType

mkAnBxAction :: AnBxPeer -> AnBxChannelType -> AnBxPeer -> AnBxMsg -> [AnBxMsg] -> AnBxAction
mkAnBxAction a ch b msg k = ((a,ch,b),appendDigestKeys msg k,Nothing,Nothing)

--- find hmacs to apply in actions ----
                    -- (msg,key,orig,dest)
type HmacMapping = (AnBxMsg,Ident,AnBxPeer,AnBxPeer)

mkHmac ::  AnBxMsg -> Ident -> AnBxMsg
mkHmac msg k = Comp Apply [Atom (show AnBxHmac),Comp Cat [msg,Atom k]]

findHmac :: AnBxMsg -> AnBxTypes -> [AnBxMsg]
findHmac _ [] = []
findHmac (Atom _ ) _ = []
findHmac (Comp _ xs) types = nubOrd (concatMap (\x -> findHmac x types) xs)
findHmac (DigestHash m) types = findHmac m types
findHmac m@(DigestHmac msg id) types = if elem id (getCertifiedAgents types)
                                                                        then [m]
                                                                        else error ("cannot create a secure digest of "++ show msg ++ " for the uncertified agent " ++ id)

-- build the hmac mappping list 
mkHmacs ::  AnBxActions -> [HmacMapping] ->  Int -> AnBxTypes ->  DigestType -> [HmacMapping]
-- mkHmacs _ maps int _ _ | trace ("mkHmacs\n\tint: " ++ show int ++ "\n\tmaps: " ++ show maps ++ "\n") False = undefined
mkHmacs [] maps _ _ _ = maps
mkHmacs (x:xs) maps int types dt = let
                                        ((a,_,_),msg,_,_) = x
                                        hs = findHmac msg types
                                        currhs = [ x | (x,_,_,_) <- maps]
                                        -- newhs  = newElem hs currhs
                                        newhs = hs \\ currhs
                                        newmaps = case dt of
                                            DTExpanded -> [(m,newHmacKey int id msg,a,ident2AnBxPeer id) | m@(DigestHmac msg id) <- newhs]
                                            DTAbstract -> []
                                       in mkHmacs xs (newmaps ++ maps) (int+1) types dt

newHmacKey :: Int -> Ident -> AnBxMsg -> String
newHmacKey int id msg = newNum prefixHK int ++ id ++ mkMsg2HmacKey (show msg)

mkMsg2HmacKey :: String -> String
mkMsg2HmacKey msg = [ x | x <- msg, isAlpha x || isDigit x]

-- hmac digests are compiled in the implementation 
mkDigestActions :: AnBxActions  -> AnBxTypes -> [HmacMapping] -> DigestType -> AnBxActions
mkDigestActions xs types hmacmaps dt  = map (\x-> mkDigestAction x types hmacmaps dt) xs

mkDigestAction :: AnBxAction -> AnBxTypes -> [HmacMapping] -> DigestType -> AnBxAction
mkDigestAction (ch,msg1,msg2,msg3) types hmacmaps dt = let
                                                          (m,k) = mkDigestMsgAction (ch,msg1,Nothing,Nothing) types hmacmaps False dt
                                                       in case k of
                                                             [] -> (ch,m,msg2,msg3)
                                                             _ -> (ch,Comp Cat [m, Comp Cat k],msg2,msg3)

mkDigestKnowledge :: AnBxKnowledgeAgents  -> AnBxTypes -> [HmacMapping] -> DigestType -> AnBxKnowledgeAgents
mkDigestKnowledge xs types hmacmaps dt = map (\(x,msgs) -> (x,map (\m -> mkDigestMsg m types hmacmaps True dt) msgs)) xs

appendDigestKeys :: AnBxMsg -> [AnBxMsg] -> AnBxMsg
appendDigestKeys m [] = m
appendDigestKeys m [k] = Comp Cat [m, k]
appendDigestKeys m k = Comp Cat (m : k)

-- this adds the messages used to pass the hmac key to the recipient (it returns the expanded digest, plus optional messages)
mkDigestMsgAction ::  AnBxAction -> AnBxTypes -> [HmacMapping] -> Bool -> DigestType -> (AnBxMsg,[AnBxMsg])
-- mkDigestMsgAction action types maps _ _ | trace ("mkDigestMsgAction\n\tmsg: " ++ show action ++ "\n\tmaps: " ++ show maps ++ "\n") False = undefined
mkDigestMsgAction (_,Atom id,_,_) _ _ _ _ = (Atom id,[])
mkDigestMsgAction (ch,Comp op xs,_,_) types maps inhash dt = let
                                                             m = map (\x -> mkDigestMsgAction (ch,x,Nothing,Nothing) types maps inhash dt) xs
                                                             msg = [fst x | x <- m]
                                                             keys = concat ([snd x | x <- m])
                                                          in fixCatPair (Comp op msg, nubOrd keys)
mkDigestMsgAction (ch,DigestHash msg,_,_) types maps _ dt = let
                                                             (m,k) = mkDigestMsgAction (ch,msg,Nothing,Nothing) types maps True dt
                                                         in fixCatPair (Comp Apply [Atom (show AnBxHash),m],k)
mkDigestMsgAction (ch,DigestHmac msg id,_,_) types maps inhash DTAbstract = let
                                                                              (msg1,_) = mkDigestMsgAction (ch,msg,Nothing,Nothing) types maps inhash DTAbstract
                                                                              hmacMsg = mkHmac msg1 id
                                                                          in fixCatPair (hmacMsg,[]) -- hmac(msg,A)
mkDigestMsgAction (ch,m@(DigestHmac msg id),_,_) types maps inhash DTExpanded = let
                                                                                  ((_,_,_),h) = getKey m maps
                                                                                  (msg1,k) = mkDigestMsgAction (ch,msg,Nothing,Nothing) types maps inhash DTExpanded
                                                                                  key = Comp Apply [Atom (show pkHMacFun),Atom id]
                                                                                  encKey = Comp Crypt [key,Atom h]
                                                                                  hmacMsg = mkHmac msg1 h
                                                                                  stnd = (Comp Cat [hmacMsg,encKey], k)
                                                                          in fixCatPair (if inhash then (hmacMsg,k) else stnd)

mkDigestMsg ::  AnBxMsg -> AnBxTypes -> [HmacMapping] -> Bool -> DigestType -> AnBxMsg
-- mkDigestMsg msg types maps _ _ | trace ("mkDigestMsg\n\tmsg: " ++ show msg ++ "\n\tmaps: " ++ show maps ++ "\n") False = undefined
mkDigestMsg (Atom id) _ _ _ _ = Atom id
mkDigestMsg (Comp op xs) types maps inhash dt = Comp op (map (\x -> mkDigestMsg x types maps inhash dt) xs)
mkDigestMsg (DigestHash msg) types maps _ dt = Comp Apply [Atom (show AnBxHash),mkDigestMsg msg types maps True dt]  --- hash(msg)  -- set inhash->True
mkDigestMsg (DigestHmac msg id) types maps inhash DTAbstract = let
                                                                          msg1 = mkDigestMsg msg types maps inhash DTAbstract
                                                                          hmacMsg = mkHmac msg1 id
                                                                      in hmacMsg -- (msg,A)
mkDigestMsg m@(DigestHmac msg _) types maps inhash DTExpanded = let
                                                                          (_,h) = getKey m maps
                                                                          msg1 = mkDigestMsg msg types maps inhash DTExpanded
                                                                          hmacMsg = mkHmac msg1 h
                                                                       in hmacMsg

mkDigestGoals :: AnBxGoals -> AnBxTypes -> [HmacMapping] -> DigestType -> AnBxGoals
mkDigestGoals xs types maps dt = map (\x-> mkDigestGoal x types maps dt) xs

mkDigestGoal :: AnBxGoal -> AnBxTypes -> [HmacMapping] -> DigestType -> AnBxGoal
mkDigestGoal (ChGoal ch msg comment) types maps dt = ChGoal ch (mkDigestMsg msg types maps False dt) comment
mkDigestGoal (Secret msg peers bool comment) types maps dt = Secret (mkDigestMsg msg types maps False dt) peers bool comment
mkDigestGoal (Authentication p1 p2 msg comment) types maps dt = Authentication p1 p2 (mkDigestMsg msg types maps False dt) comment
mkDigestGoal (WAuthentication p1 p2 msg comment) types maps dt = WAuthentication p1 p2 (mkDigestMsg msg types maps False dt) comment

getKey :: AnBxMsg ->  [HmacMapping] -> (AnBxPeer,Ident)
-- getKey msg maps | trace ("getKey\n\tmsg: " ++ show msg ++ "\n\tmaps: " ++ show maps ++ "\n") False = undefined
getKey msg [] = error ("hmac key not found for msg: " ++ show msg)
getKey msg ((m,k,a,_):xs) = if msg==m then (a,k) else getKey msg xs

----------- Protocol Compilation  --------------

mkCommentAction :: AnBxAction -> ComType -> AnBxAction
mkCommentAction action ct = mkAnBxAction nullPeer (ActionComment ct (showAction action)) nullPeer syncMsgAst []

mkCommentActions :: AnBxActions -> ComType -> AnBxActions
mkCommentActions [] _ = []
mkCommentActions [x] ct = [mkCommentAction x ct,x]
mkCommentActions (x:xs) ct = mkCommentActions [x] ct ++ mkCommentActions xs ct

mkActions :: AnBxTypes -> AnBxKnowledgeAgents -> AnBxActions -> ActionStatus -> [Ident] -> Int -> ImplType -> AnBxPKeyFunCfg -> Bool -> [HmacMapping] -> NonceStore -> DigestType -> (AnBxTypes,AnBxKnowledgeAgents,AnBxActions,ActionStatus,NonceStore)
mkActions types knowledge [] _ _ _ _ _ _ _ ns _ = (types,knowledge,[],nullStatus,ns)
mkActions types knowledge (action:actions) status certified int impltype pkcfg usetags hmacmaps ns dt =
        let
                action1 = cvPair2Triple action
                action2 = action1
                --case impltype of
                --                        CIF -> mkActionCIF action1
                --                        CIF2 -> mkActionCIF action1
                --                        CIF3 -> mkActionCIF action1
                --                        AANB -> mkActionCIF action1
                --                        _ -> action1
                (t,k,a,s,ns1) = mkAction types knowledge (cvPair2Triple action2) status certified int impltype pkcfg usetags hmacmaps ns dt
                (tt,kk,aa,ss,ns2) = mkActions t k actions s certified (int+1) impltype pkcfg usetags hmacmaps ns1 dt
       in (tt,kk,a++aa,ss,ns2)

mkAction :: AnBxTypes -> AnBxKnowledgeAgents -> AnBxAction -> ActionStatus -> [Ident] -> Int -> ImplType -> AnBxPKeyFunCfg -> Bool -> [HmacMapping] -> NonceStore -> DigestType -> (AnBxTypes, AnBxKnowledgeAgents,AnBxActions,ActionStatus,NonceStore)
mkAction types knowledge action@((_,BMChannelTypeTriple {},_),_,_,_) status@(_,prevmsg) certified int impltype pkcfg usetags hmacmaps ns dt =
                        let
                                (ch,msg,_,_) = action
                                ci :: AnBxChImpl
                                ci = ch2impl ch status certified
                                msg1 = case ci of
                                                ForwardBlind {} -> prevmsg
                                                _ -> msg
                                -- reference msg index, for forward mode
                                -- previous message, should be generalised to match any previous message
                                refint = int - 1
                                (td,sk,sa,ns1) = protSpecification ch ci impltype pkcfg usetags msg1 int refint ns certified t hmacmaps dt
                                st = [ x | (Number _,x) <- td ]
                                sn = [ x | (SeqNumber _,x) <- td ]
                                sp = [ x | (PublicKey _,x) <- td ]
                                ss = [ x | (SymmetricKey _,x) <- td ]
                                sf = [ x | (Function _,x) <- td ]
                                t = initTypes (Number []) st eqTypesStrict elemTypes .
                                    initTypes (SeqNumber []) sn eqTypesStrict elemTypes .
                                    initTypes (PublicKey []) sp eqTypesStrict elemTypes .
                                    initTypes (SymmetricKey []) ss eqTypesStrict elemTypes .
                                    initTypes (Function []) sf eqTypesStrict elemTypes $ types
                                agents = getActiveAgents sa
                                -- add to each agent involved in the exchange the necessary knowledge
                                k = if null sk then knowledge else initKnowledges agents (const (ids2Msgs sk)) knowledge
                                -- apply hash/hmac (hmacs already applied) to actions
                                sa1 = mkDigestActions sa t hmacmaps dt
                                -- sa1 = sa
                                -- extract last msg sent - for forward mode)
                                -- should be generalised the get the refint message
                                (_,m,_,_) = last sa1
                                s = (ch,m)
                                a0 = mkCommentAction action CTAnBx
                                -- sa2 = mkCommentActions sa1 CTAnB
                        -- in error ("m: " ++ show m)
                        -- in error ("Agents: " ++ show agents)
                        -- in (t,k,[a0]++sa2,s,ns1)
                        in (t,k,a0 : sa1,s,ns1)
mkAction types knowledge action status _ _ _ _ _ hmacmaps ns dt = let -- apply mkDigest
                                                                    (ch,_,msg1,msg2) = action
                                                                    (msg3,k) = mkDigestMsgAction action types hmacmaps False dt
                                                                    msg4 = case k of
                                                                            [] -> msg3
                                                                            [x] -> Comp Cat [msg3,x]
                                                                            _ -> Comp Cat (msg3 : k)
                                                                in (types,knowledge,[(ch,msg4,msg1,msg2)],status,ns)

-- preserveCat = [show AnBxHmac]
fixCat :: AnBxMsg -> AnBxMsg
-- fixCat m | trace ("fixCat\n\tmsg: " ++ show m) False = undefined
fixCat m@(Atom _) = m
fixCat m@(Comp Apply []) = error $ patternMsgError m "fixCat"
fixCat m@(Comp Apply xs) | head xs == Atom (show AnBxHmac) = let
                                                                errorMsg m xs = "fixCat - term " ++ show m ++ " does not seem well-formed for function " ++ show (head xs) ++ "\n" ++ "check Arity (2) and type signature"
                                                             in Comp Apply (head xs :
                                                                                 case tail xs of
                                                                                    [Comp Cat []] -> error $ errorMsg m xs
                                                                                    -- if the first parameter is Cat, flatten
                                                                                    [Comp Cat [Comp Cat [msg],k]] -> [Comp Cat [fixCat msg, fixCat k]]
                                                                                    [Comp Cat [msg,k]] -> [Comp Cat [fixCat msg, fixCat k]]
                                                                                    -- last element is the key, as the cat expression has been flatten
                                                                                    [Comp Cat xs] -> [Comp Cat [msg,k]] 
                                                                                                                where msg = Comp Cat (init xs)
                                                                                                                      k = last xs
                                                                                    _  -> error $ errorMsg m xs)
                         | otherwise = Comp Apply (map fixCat xs)
fixCat (Comp Cat [x]) = fixCat x
fixCat (Comp Cat xs) = Comp Cat (foldr (\x ys -> fixCats (fixCat x) ++ ys) [] xs)
fixCat (Comp op xs) = Comp op (map fixCat xs)
fixCat (DigestHash m) = DigestHash (fixCat m)
fixCat (DigestHmac m id) = DigestHmac (fixCat m) id

fixCats :: AnBxMsg -> [AnBxMsg]
----fixCats expr | trace ("fixCats\n\texpr " ++ show expr) False = undefined
fixCats (Comp Cat xs) = xs
fixCats x = [x]

fixCatPair :: (AnBxMsg,[AnBxMsg]) -> (AnBxMsg,[AnBxMsg])
fixCatPair (msg,msgs) = (fixCat msg, map fixCat msgs)

-- types manipulation

initTypes :: AnBxType -> [Ident] -> (AnBxType -> AnBxType -> Bool) -> (AnBxType -> [AnBxType] -> Bool) -> [(AnBxType,[Ident])] -> [(AnBxType,[Ident])]
-- initTypes type2add identlist f types | trace ("initTypes\n\ttype: " ++ "\n\tids: " ++ show identlist) False = undefined
initTypes _ [] _ _ types = types
initTypes type2add (id:ids) eq elemtype types = if elem id (identsOfType type2add types) then initTypes type2add ids eq elemtype types
                                                                                         else initTypes type2add ids eq elemtype types ++ [(type2add,[id])]

initType :: (AnBxType,[Ident]) -> AnBxType -> [Ident] -> (AnBxType -> AnBxType -> Bool) -> (AnBxType,[Ident])
initType (t,idents) _ [] _ = (t, idents)
initType (t,idents) type2add identlist eq | eq t type2add = (t, union idents identlist)
                                          | otherwise = (t,idents)

initTypedFunctions :: [(AnBxType, [Ident])] -> [(AnBxType, [Ident])] -> [(AnBxType, [Ident])]
initTypedFunctions [] types = types
initTypedFunctions ((t, ids):rest) types = initTypedFunctions rest (initTypes t ids eqTypesStrict elemTypes types)


-------------- check definitions messages, actions and goals form missing types ------------------------

ckDefs2 :: AnBxDefinitions -> AnBxTypes -> AnBxDefinitions
ckDefs2 defs types =
                    let
                        idents = nubOrd (defs2idents defs ++ types2idents types)
                    in map (\x -> ckDef x idents) defs

ckDefs :: (AnBxDefinitions,[Ident]) -> (AnBxDefinitions,[Ident])
ckDefs ([],ids) = ([],ids)
ckDefs ([def],ids) = ([ckDef def ids],nubOrd (ids++defs2idents [def]))
ckDefs (def:defs,ids) = let
                            (def1,ids1) = ckDefs ([def],ids)
                        in (def1 ++ fst (ckDefs (defs,nubOrd (ids ++ ids1))), nubOrd (ids ++ ids1 ++ defs2idents defs))

ckDef :: AnBxDefinition -> [Ident] -> AnBxDefinition
ckDef (Def msg1@(Comp Apply [Atom _, Comp Cat xs]) msg2) idents = Def msg1 (ckTypeMsg msg2 (idents ++ concatMap AnBxMsg.idents xs))
ckDef (Def msg1@(Comp Apply [Atom _, Atom id]) msg2) idents = Def msg1 (ckTypeMsg msg2 (idents++[id]))
ckDef (Def msg1@(Comp Apply [Atom _, _]) msg2) _ = error ("ill-formed definition: " ++ show msg1 ++ ": " ++ show msg2 )
ckDef (Def msg1 msg2) idents = Def msg1 (ckTypeMsg msg2 idents)

ckGoal :: AnBxGoal -> AnBxTypes -> AnBxGoal
-- ckGoal goal _ | trace ("ckGoal\n\tgkoal: " ++ show goal) False = undefined
ckGoal (ChGoal ch msg comment) types = ChGoal ch (ckMsg msg types) comment
ckGoal (Secret msg peers bool comment) types = Secret (ckMsg msg types) peers bool comment
ckGoal (Authentication p1 p2 msg comment) types = Authentication p1 p2 (ckMsg msg types) comment
ckGoal (WAuthentication p1 p2 msg comment) types = WAuthentication p1 p2 (ckMsg msg types) comment

ckGoals :: AnBxGoals -> AnBxTypes -> AnBxGoals
ckGoals [] _ = []
ckGoals _ [] = error "No type information in order to check actions"
ckGoals goals types = map (\x -> ckGoal x types) goals

ckMsg :: AnBxMsg -> AnBxTypes -> AnBxMsg
ckMsg msg types = ckTypeMsg msg (types2idents types)

ckTypeMsg :: AnBxMsg -> [Ident] -> AnBxMsg
ckTypeMsg msg idents = if ckIdents (AnBxMsg.idents msg) idents ("Msg:\t" ++ show msg)
                        then fixCat msg
                        else error ("type error (ckTypeMsg) msg: " ++ show msg)

ckActions :: AnBxActions -> AnBxTypes -> AnBxActions
ckActions [] _ = []
ckActions _ [] = error "No type information in order to check actions"
ckActions actions types = map (\x -> ckAction x types) actions

ckAction :: AnBxAction -> AnBxTypes -> AnBxAction
ckAction action types = ckTypeAction action (types2idents types)

ckTypeAction :: AnBxAction -> [Ident] ->  AnBxAction
-- ckTypeAction action _ | trace ("ckTypeAction\n\taction: " ++ show action) False = undefined
ckTypeAction action@((_,ActionComment _ _,_),_,_,_) _ = action
ckTypeAction action@(ch@((p1,_,_),_,(p2,_,_)),msg,msg1,msg2) idents =
        let
                errormsg = "Action:\t" ++ showAction action
                n_msg = if ckIdents (AnBxMsg.idents msg) idents errormsg then msg else error ("type error (ckTypeAction) msg: " ++ show msg ++ "\nchannel: " ++ show ch)
                n_ch = if ckIdent p1 idents errormsg && ckIdent p2 idents errormsg then ch else error ("type error (ckTypeAction) channel: " ++ show ch ++ "\nmsg: " ++ show msg)
        in (n_ch,n_msg,msg1,msg2)

ckIdents ::  [Ident] -> [Ident] -> String -> Bool
ckIdents [] _ _ = error "No action to check"
ckIdents _ [] _ = error "No type information available to check actions"
ckIdents [i] idents errormsg = ckIdent i idents errormsg
ckIdents (i:is) idents errormsg = ckIdent i idents errormsg && ckIdents is idents errormsg

ckIdent :: Ident -> [Ident] -> String -> Bool
ckIdent ident [] errormsg = error ("No identifiers:\t" ++ ident ++ "\n" ++ errormsg)
ckIdent ident idents errormsg = elem ident idents || error ("Missing identifier:\t" ++ ident ++ "\n" ++ "Idents:\t" ++ showIdents idents ++ "\n" ++ errormsg)

types2idents :: AnBxTypes -> [Ident]
types2idents [] = []
types2idents [(_,idents)] = idents
types2idents ((_,idents):ts) = union (types2idents ts) (idents ++ [show AnBxInv,show AnBxExp, show AnBxXor,show AnBxZero])

defs2idents :: AnBxDefinitions -> [Ident]
defs2idents = concatMap def2idents

def2idents :: AnBxDefinition -> [Ident]
def2idents (Def (Atom id) _) = [id]
def2idents (Def (Comp Apply ((Atom id):_)) _) = [id]
def2idents _ = []

data BasicOp =    OpSign AnBxMsg Ident [Ident] Tag ConcatPos
                | OpTag AnBxMsg Tag
                | OpCrypt AnBxMsg Ident Tag
                | OpScrypt AnBxMsg AnBxMsg Tag
                | OpSignCrypt AnBxMsg Ident [Ident] Ident Tag ConcatPos
                | OpSignScrypt AnBxMsg Ident [Ident] AnBxMsg Tag ConcatPos
                | OpHybridScrypt AnBxMsg Ident AnBxMsg Tag
                | OpHybridSignScrypt AnBxMsg Ident [Ident] Ident AnBxMsg Tag ConcatPos
                | OpHash AnBxMsg
                | OpHmac AnBxMsg Ident
                | OpDHGX Ident
                | OpDHGXY Ident Ident
                | OpInvPKI AnBxPKeysFun Ident
                | OpPKI AnBxPKeysFun Ident
                | OpBlind AnBxMsg Ident Tag
                | OpBlindFun Ident
                | OpAAnBList Ident [Ident] AnBxMsg
                | OpAAnBListN Ident [Ident] AnBxMsg Ident
                deriving (Eq,Show)

mkOp :: BasicOp -> AnBxPKeyFunCfg -> AnBxMsg
-- mkOp op | trace ("mkOp\n\top: " ++ show op) False = undefined
mkOp (OpTag msg tag) _ =  concatId2Msg CPLeft (showTagMsg tag) msg
mkOp (OpSign msg agent vers tag cPos) cfg@(_,sk,_) = Comp Crypt [mkOp (OpInvPKI sk agent) cfg,concatMsgs2Msg cPos (ids2Msgs (showTagMsg tag : vers)) msg]
mkOp (OpCrypt msg agent tag) cfg@(pk,_,_) = Comp Crypt [mkOp (OpPKI pk agent) cfg,concatMsgs2Msg CPLeft (ids2Msgs [showTagMsg tag]) msg]
mkOp (OpScrypt msg key tag) _ = Comp Scrypt [key,concatMsgs2Msg CPLeft (ids2Msgs [showTagMsg tag]) msg]
mkOp (OpSignCrypt msg agent1 vers agent2 tag cPos) cfg = mkOp (OpCrypt (mkOp (OpSign msg agent1 vers tag cPos) cfg) agent2 NoTag) cfg
mkOp (OpSignScrypt msg agent vers key tag cPos) cfg = mkOp (OpScrypt (mkOp (OpSign msg agent vers tag cPos) cfg) key NoTag) cfg
mkOp (OpHybridScrypt msg agent key tag) cfg = Comp Cat [mkOp (OpCrypt key agent NoTag) cfg, mkOp (OpScrypt msg key tag) cfg]
mkOp (OpHybridSignScrypt msg agent1 vers agent2 key tag cPos) cfg = Comp Cat [mkOp (OpCrypt key agent2 NoTag) cfg,mkOp (OpSignScrypt msg agent1 vers key tag cPos) cfg]
mkOp (OpHash msg) _ = DigestHash msg
mkOp (OpHmac msg id) _ = DigestHmac msg id
mkOp (OpDHGX x) _ =  Comp Exp [Atom dhPar,Atom x]
mkOp (OpDHGXY x y) cfg = Comp Exp [mkOp (OpDHGX y) cfg,Atom x]
mkOp (OpInvPKI pk a) cfg = Comp Inv [mkOp (OpPKI pk a) cfg]
mkOp (OpPKI pk a) _ = Comp Apply [Atom (show pk), Atom a]
mkOp (OpBlind msg agent tag) cfg = Comp Cat [Atom (showTagMsg tag), Comp Crypt [mkOp (OpBlindFun agent) cfg,msg]]
mkOp (OpBlindFun agent) _ = Comp Apply [Atom (show AnBxBlind), Atom agent]
mkOp (OpAAnBList agent vers msg) _ = concatIds2Msg CPLeft (agent : vers) msg
mkOp (OpAAnBListN agent vers msg nonce) _ = concatIds2Msg CPLeft ([agent] ++ vers ++ [nonce]) msg

concatMsgs2Msg ::  ConcatPos -> [AnBxMsg] -> AnBxMsg -> AnBxMsg
-- concatMsgs2Msg _ mx msg | trace ("concatMsgs2Msg\n\tmx: " ++ show mx ++ "\n\tmsg: " ++ show msg) False = undefined
concatMsgs2Msg _ [] msg = msg
concatMsgs2Msg CPRight mx (Comp Cat msg) = Comp Cat (msg ++ mx)
concatMsgs2Msg _ mx (Comp Cat msg) = Comp Cat (mx ++ msg)
concatMsgs2Msg CPRight mx msg = Comp Cat (msg : mx)
concatMsgs2Msg _ mx msg = Comp Cat (mx ++ [msg])

concatId2Msg :: ConcatPos -> Ident -> AnBxMsg -> AnBxMsg
-- concatId2Msg _ id msg | trace ("concatId2Msg\n\tid: " ++ show id ++ "\n\tmsg: " ++ show msg) False = undefined
concatId2Msg pos id msg = concatMsgs2Msg pos [Atom id] msg

concatIds2Msg :: ConcatPos -> [Ident] -> AnBxMsg -> AnBxMsg
-- concatIds2Msg _ ids msg | trace ("concastIds2Msg\n\tid: " ++ show ids ++ "\n\tmsg: " ++ show msg) False = undefined
concatIds2Msg pos ids msg = concatMsgs2Msg pos (ids2Msgs ids) msg


-------- protocol specification --------- Actions,Types -----------------

--- returns Key,Nonce,Knowledege,[NExpression]
protSpecification :: AnBxChannel -> AnBxChImpl -> ImplType -> AnBxPKeyFunCfg -> Bool -> AnBxMsg -> Int -> Int -> NonceStore -> [Ident] -> AnBxTypes -> [HmacMapping] -> DigestType -> AnBxStepImpl
-- protSpecification ch@(p1,chmode,p2) chImpl impltype pkcfg usetags msg0 int refint ns certified types hmacmaps dt | trace ("protSpecification\n\tch: " ++ showChannel ch ++ " " ++ show msg0 ++ "\n\tchImpl: " ++ show chImpl ++ "\n\timpltype: " ++ show impltype) False = undefined
protSpecification ch@(p1,_,p2) chImpl impltype pkcfg usetags msg0 int refint ns certified types hmacmaps dt =
        let
                  ---------- init Nonces,Numbers, Keys, ...
                  n = newNum prefixNonce int
                  x = newNum prefixDHX int
                  y = newNum prefixDHY int
                  k = newNum prefixKey int
                  sqn = newNum prefixSQN int
                  cPos = step2Pos int
                  (msg,hmks) = mkDigestMsgAction (ch,msg0,Nothing,Nothing) types hmacmaps False dt
                  (_,chmode,_) = mkAnBxChannelCIF ch  -- remove forward as the implementation is the same for Std and Fresh modes, except for ForwardBlind. That is why ForwardBlind is tested first in AANB and CIF*
        in case impltype of
                AANB -> case chImpl of
                                ForwardBlind {} -> let -- ForwardBlind just requires to push the message ahead
                                                        m1 = msg
                                                        a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                    in ([],[],[a1],ns)
                                _ -> case chmode of
                                        -- Plain
                                        BMChannelTypeTriple Std ap vers bp | (ap==nullPeer) && (bp==nullPeer) && (vers==nullVers) -> let
                                                                                                                                        t1 = insertTag Ptag usetags
                                                                                                                                        m1 = mkOp (OpTag msg t1) pkcfg
                                                                                                                                        a1  = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                     in ([],[],[a1],ns)
                                        -- Secret For
                                        BMChannelTypeTriple Std ap vers bp@(b,_,_) | (ap==nullPeer) && (vers==nullVers) -> if not (isPeerMemberOf bp certified) then error (peerErrorNoCert bp ch) else
                                                                                                                                                                       let
                                                                                                                                                                           t1 = insertTag Ctag usetags
                                                                                                                                                                           m1 = mkOp (OpBlind msg b t1) pkcfg
                                                                                                                                                                           a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                       in ([],[],[a1],ns)

                                        -- From
                                        BMChannelTypeTriple Std ap@(a,_,_) vers bp | (bp==nullPeer) && (vers/=nullVers) -> if not (isPeerMemberOf ap certified) then error (peerErrorNoCert ap ch) else
                                                                                                                                                                         case getNonceFromStore (a,vers,msg0) ns of
                                                                                                                                                                                Nothing ->
                                                                                                                                                                                        let
                                                                                                                                                                                             t1 = insertTag Atag usetags
                                                                                                                                                                                             m1 = mkOp (OpTag (mkOp (OpAAnBList a vers msg) pkcfg) t1) pkcfg
                                                                                                                                                                                             a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                                         in ([],[],[a1],ns)
                                                                                                                                                                                Just (nds,_) -> if ap==p1 then (let
                                                                                                                                                                                                                    t1 = insertTag Atag usetags
                                                                                                                                                                                                                    m1 = mkOp (OpTag (mkOp (OpAAnBList a vers msg) pkcfg) t1) pkcfg
                                                                                                                                                                                                                    a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                                                            in ([],[],[a1],ns)) else (let
                                                                                                                                                                                                                                                  t1 = insertTag Atag usetags
                                                                                                                                                                                                                                                  m1 = mkOp (OpTag (mkOp (OpAAnBListN a vers msg nds) pkcfg) t1) pkcfg
                                                                                                                                                                                                                                                  a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                                                                                          in ([],[],[a1],ns))
                                        -- From + Secret
                                        BMChannelTypeTriple Std ap@(a,_,_) vers bp@(b,_,_) | vers/=nullVers -> if not (isPeerMemberOf bp certified) then error (peerErrorNoCert bp ch) else
                                                                                                                                       if not (isPeerMemberOf ap certified) then error (peerErrorNoCert ap ch) else
                                                                                                                                                                      case getNonceFromStore (a,vers,msg0) ns of
                                                                                                                                                                              Nothing ->
                                                                                                                                                                                      let
                                                                                                                                                                                           t1 = insertTag Stag usetags
                                                                                                                                                                                           m1 = mkOp (OpBlind (mkOp (OpAAnBList a vers msg) pkcfg) b t1) pkcfg
                                                                                                                                                                                           a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                                       in ([],[],[a1],ns)
                                                                                                                                                                              Just (nds,_) -> (let
                                                                                                                                                                                                   t1 = insertTag Stag usetags
                                                                                                                                                                                                   m1 = mkOp (OpBlind (mkOp (OpAAnBListN a vers msg nds) pkcfg) b t1) pkcfg
                                                                                                                                                                                                   a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                                           in ([],[],[a1],ns))

                                        -- Fresh From
                                        BMChannelTypeTriple Fresh ap@(a,_,_) vers bp | (bp==nullPeer) && (vers/=nullVers) -> if not (isPeerMemberOf ap certified) then error (peerErrorNoCert ap ch) else
                                                                                                                                                                         case getNonceFromStore (a,vers,msg0) ns of
                                                                                                                                                                                Nothing ->
                                                                                                                                                                                        let
                                                                                                                                                                                             t1 = insertTag Fatag usetags
                                                                                                                                                                                             ns1 = addNonceToStore (a,vers,msg0,sqn,cPos) ns
                                                                                                                                                                                             m1 = mkOp (OpTag (mkOp (OpAAnBListN a vers msg sqn) pkcfg) t1) pkcfg
                                                                                                                                                                                             a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                                         in ([(SeqNumber [],sqn)],[],[a1],ns1)
                                                                                                                                                                                Just (nds,_) -> (let
                                                                                                                                                                                                     t1 = insertTag Fatag usetags
                                                                                                                                                                                                     m1 = mkOp (OpTag (mkOp (OpAAnBListN a vers msg nds) pkcfg) t1) pkcfg
                                                                                                                                                                                                     a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                                             in ([],[],[a1],ns))
                                        -- Fresh From + Secret
                                        BMChannelTypeTriple Fresh ap@(a,_,_) vers bp@(b,_,_) | vers/=nullVers -> if not (isPeerMemberOf bp certified) then error (peerErrorNoCert bp ch) else
                                                                                                                                         if not (isPeerMemberOf ap certified) then error (peerErrorNoCert ap ch) else
                                                                                                                                                                        case getNonceFromStore (a,vers,msg0) ns of
                                                                                                                                                                                Nothing ->
                                                                                                                                                                                        let
                                                                                                                                                                                             t1 = insertTag Fstag usetags
                                                                                                                                                                                             ns1 = addNonceToStore (a,vers,msg0,sqn,cPos) ns
                                                                                                                                                                                             m1 = mkOp (OpBlind (mkOp (OpAAnBListN a vers msg sqn) pkcfg) b t1) pkcfg
                                                                                                                                                                                             a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                                             in ([(SeqNumber [],sqn)],[],[a1],ns1)
                                                                                                                                                                                Just (nds,_) -> (let
                                                                                                                                                                                                     t1 = insertTag Fstag usetags
                                                                                                                                                                                                     m1 = mkOp (OpBlind (mkOp (OpAAnBListN a vers msg nds) pkcfg) b t1) pkcfg
                                                                                                                                                                                                     a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                                             in ([],[],[a1],ns))
                                        ch -> error (show ch ++ " not implemented")

                -- sequence numbers for freshness
                CIF  -> case chImpl of
                                ForwardBlind {} -> let
                                                        m1 = msg
                                                        a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                    in ([],[],[a1],ns)
                                _ -> case chmode of
                                        -- Plain
                                        BMChannelTypeTriple Std ap vers bp | (ap==nullPeer) && (bp==nullPeer) && (vers==nullVers) -> ([],[],[mkAnBxAction p1 Insecure p2 msg hmks],ns)

                                        -- Secret For
                                        BMChannelTypeTriple Std ap vers bp@(b,_,_) | (ap==nullPeer) && (vers==nullVers) -> if not (isPeerMemberOf bp certified) then error (peerErrorNoCert bp ch) else
                                                                                                                                                                       let
                                                                                                                                                                           t1 = insertTag Ctag usetags
                                                                                                                                                                           m1 = mkOp (OpCrypt msg b t1) pkcfg
                                                                                                                                                                           a1  = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                       in ([],[],[a1],ns)

                                        -- From
                                        BMChannelTypeTriple Std ap@(a,_,_) vers bp | (bp==nullPeer) && (vers/=nullVers) -> if not (isPeerMemberOf ap certified) then error (peerErrorNoCert ap ch) else
                                                                                                                                                                         case getNonceFromStore (a,vers,msg0) ns of
                                                                                                                                                                                Nothing ->
                                                                                                                                                                                        let
                                                                                                                                                                                            -- standard signature, no SQN involved, use standard position CPLeft
                                                                                                                                                                                             t1 = insertTag Atag usetags
                                                                                                                                                                                             m1 = mkOp (OpSign msg a vers t1 CPLeft) pkcfg
                                                                                                                                                                                             a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                                         in ([],[],[a1],ns)
                                                                                                                                                                                Just (nds,ndsPos) -> if ap==p1 then (let
                                                                                                                                                                                                                        -- if a SQN is involved, then use the SQN stored position
                                                                                                                                                                                                                        -- in this case the originator is sending the message
                                                                                                                                                                                                                        t1 = insertTag Atag usetags
                                                                                                                                                                                                                        m1 = mkOp (OpSign msg a vers t1 ndsPos) pkcfg
                                                                                                                                                                                                                        a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                                                                    in ([],[],[a1],ns)) else (let
                                                                                                                                                                                                                                -- if a SQN is involved, then use the SQN stored position
                                                                                                                                                                                                                                -- in this case it is a forwarded message as ap/=p1
                                                                                                                                                                                                                                                  t1 = insertTag Atag usetags
                                                                                                                                                                                                                                                  m1 = mkOp (OpSign (concatId2Msg ndsPos nds msg) a vers t1 ndsPos) pkcfg
                                                                                                                                                                                                                                                  a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                                                                                          in ([],[],[a1],ns))
                                        -- From + Secret
                                        BMChannelTypeTriple Std ap@(a,_,_) vers bp@(b,_,_) | vers/=nullVers -> if not (isPeerMemberOf bp certified) then error (peerErrorNoCert bp ch) else
                                                                                                                                         if not (isPeerMemberOf ap certified) then error (peerErrorNoCert ap ch) else
                                                                                                                                                                        case getNonceFromStore (a,vers,msg0) ns of
                                                                                                                                                                                Nothing ->
                                                                                                                                                                                        let
                                                                                                                                                                                             t1 = insertTag Stag usetags
                                                                                                                                                                                             m1 = mkOp (OpSignCrypt msg a vers b t1 CPLeft) pkcfg
                                                                                                                                                                                             a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                                         in ([],[],[a1],ns)
                                                                                                                                                                                Just (nds,ndsPos) -> if ap==p1 then (let
                                                                                                                                                                                                                        t1 = insertTag Stag usetags
                                                                                                                                                                                                                        m1 = mkOp (OpSignCrypt msg a vers b t1 ndsPos) pkcfg
                                                                                                                                                                                                                        a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                                                                    in ([],[],[a1],ns)) else (let
                                                                                                                                                                                                                                                  t1 = insertTag Stag usetags
                                                                                                                                                                                                                                                  m1 = mkOp (OpSignCrypt (concatId2Msg ndsPos nds msg) a vers b t1 ndsPos) pkcfg
                                                                                                                                                                                                                                                  a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                                                                                          in ([],[],[a1],ns))

                                        -- Fresh From
                                        BMChannelTypeTriple Fresh ap@(a,_,_) vers bp | (bp==nullPeer) && (vers/=nullVers) -> if not (isPeerMemberOf ap certified) then error (peerErrorNoCert ap ch) else
                                                                                                                                                                         case getNonceFromStore (a,vers,msg0) ns of
                                                                                                                                                                                Nothing ->
                                                                                                                                                                                        let
                                                                                                                                                                                             t1 = insertTag Atag usetags
                                                                                                                                                                                             ns1 = addNonceToStore (a,vers,msg0,sqn,cPos) ns
                                                                                                                                                                                             m1 = mkOp (OpSign (concatId2Msg cPos sqn msg) a vers t1 cPos) pkcfg
                                                                                                                                                                                             a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                                         in ([(SeqNumber [],sqn)],[],[a1],ns1)
                                                                                                                                                                                Just (nds,ndsPos) -> (let
                                                                                                                                                                                                     t1 = insertTag Atag usetags
                                                                                                                                                                                                     m1 = mkOp (OpSign (concatId2Msg ndsPos nds msg) a vers t1 ndsPos) pkcfg
                                                                                                                                                                                                     a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                                             in ([],[],[a1],ns))
                                        -- Fresh From + Secret
                                        BMChannelTypeTriple Fresh ap@(a,_,_) vers bp@(b,_,_) | vers/=nullVers -> if not (isPeerMemberOf bp certified) then error (peerErrorNoCert bp ch) else
                                                                                                                                         if not (isPeerMemberOf ap certified) then error (peerErrorNoCert ap ch) else
                                                                                                                                                                        case getNonceFromStore (a,vers,msg0) ns of
                                                                                                                                                                                Nothing ->
                                                                                                                                                                                        let
                                                                                                                                                                                             t1 = insertTag Stag usetags
                                                                                                                                                                                             ns1 = addNonceToStore (a,vers,msg0,sqn,cPos) ns
                                                                                                                                                                                             m1 = mkOp (OpSignCrypt (concatId2Msg cPos sqn msg) a vers b t1 cPos) pkcfg
                                                                                                                                                                                             a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                                         in ([(SeqNumber [],sqn)],[],[a1],ns1)
                                                                                                                                                                                Just (nds,ndsPos) -> (let
                                                                                                                                                                                                     t1 = insertTag Stag usetags
                                                                                                                                                                                                     m1 = mkOp (OpSignCrypt (concatId2Msg ndsPos nds msg) a vers b t1 ndsPos) pkcfg
                                                                                                                                                                                                     a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                                                                                                                                                             in ([],[],[a1],ns))
                                        ch -> error (show ch ++ " not implemented")

                -- challange response for freshness
                CIF2  -> let
                            chmode_ccm = CCM2 in
                         case chImpl of
                                ForwardBlind {} -> let
                                                        m1 = msg
                                                        a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                    in ([],[],[a1],ns)
                                _ -> case chmode of

                                        BMChannelTypeTriple Std _ _ _ -> protSpecification ch chImpl CIF pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                        -- ForwardFreshSighted
                                        BMChannelTypeTriple Fresh ap vers bp | (bp==nullPeer) && (vers/=nullVers) && (p1/=ap) -> if not (isPeerMemberOf ap certified) then error (peerErrorNoCert ap ch) else
                                                                                                                                                                         protSpecification ch (ForwardFreshSighted ap vers p1 p2) chmode_ccm pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                        -- Fresh From
                                        BMChannelTypeTriple Fresh ap vers bp | (bp==nullPeer) && (vers/=nullVers) -> if not (isPeerMemberOf ap certified) then error (peerErrorNoCert ap ch) else
                                                                                                                                                                         protSpecification ch (FreshFromA ap vers p2) chmode_ccm pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                        -- ForwardFreshSightedSecret
                                        BMChannelTypeTriple Fresh ap vers bp | (vers/=nullVers) && (p1/=ap) -> if not (isPeerMemberOf bp certified) then error (peerErrorNoCert bp ch) else
                                                                                                                                         if not (isPeerMemberOf ap certified) then error (peerErrorNoCert ap ch) else
                                                                                                                                                                        protSpecification ch (ForwardFreshSightedSecret ap vers p1 p2) chmode_ccm pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                        -- Fresh From + Secret
                                        BMChannelTypeTriple Fresh ap vers bp | vers/=nullVers -> if not (isPeerMemberOf bp certified) then error (peerErrorNoCert bp ch) else
                                                                                                                                         if not (isPeerMemberOf ap certified) then error (peerErrorNoCert ap ch) else
                                                                                                                                                                        protSpecification ch (FreshFromASecretForB ap vers bp) chmode_ccm pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                        ch -> error (show ch ++ " not implemented")
         -- challange response (DH) for freshness
                CIF3  -> let
                            chmode_ccm = CCM4
                         in case chImpl of
                                ForwardBlind {} -> let
                                                        m1 = msg
                                                        a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                                    in ([],[],[a1],ns)
                                _ -> case chmode of
                                        BMChannelTypeTriple Std _ _ _ -> protSpecification ch chImpl CIF pkcfg usetags msg0 int refint ns certified types hmacmaps dt

--                                      -- ForwardFreshSighted
                                        BMChannelTypeTriple Fresh ap vers bp | (bp==nullPeer) && (vers/=nullVers) && (p1/=ap) -> if not (isPeerMemberOf ap certified) then error (peerErrorNoCert ap ch) else
                                                                                                                                                                         protSpecification ch (ForwardFreshSightedWithDH ap vers p1 p2) chmode_ccm pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                        -- Fresh From
                                        BMChannelTypeTriple Fresh ap vers bp | (bp==nullPeer) && (vers/=nullVers) -> if not (isPeerMemberOf ap certified) then error (peerErrorNoCert ap ch) else
                                                                                                                                                                         protSpecification ch (FreshFromAWithDH ap vers p2) chmode_ccm pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                        -- ForwardFreshSightedSecret
                                        BMChannelTypeTriple Fresh ap vers bp | (vers/=nullVers) && (p1/=ap) -> if not (isPeerMemberOf bp certified) then error (peerErrorNoCert bp ch) else
                                                                                                                                         if not (isPeerMemberOf ap certified) then error (peerErrorNoCert ap ch) else
                                                                                                                                                                        protSpecification ch (ForwardFreshSightedSecret ap vers p1 p2) chmode_ccm pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                        -- Fresh From + Secret
                                        BMChannelTypeTriple Fresh ap vers bp | vers/=nullVers -> if not (isPeerMemberOf bp certified) then error (peerErrorNoCert bp ch) else
                                                                                                                                       if not (isPeerMemberOf ap certified) then error (peerErrorNoCert ap ch) else
                                                                                                                                                                      protSpecification ch (FreshFromASecretForB ap vers bp) chmode_ccm pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                        ch -> error (show ch ++ " not implemented")
                -- Basic CCM impl w SQN
                CCM -> case chImpl of

                                Plain _ _ -> ([],[],[mkAnBxAction p1 Insecure p2 msg hmks],ns)

                                FromA (a,_,_) vers _ ->
                                        let
                                                t1 = insertTag Atag usetags
                                                m1 = mkOp (OpSign msg a vers t1 CPLeft) pkcfg
                                                a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                        in ([],[],[a1],ns)

                                ---------- 3 peers ------------

                                SecretForC _ _ (c,_,_) ->
                                        let
                                                t1 = insertTag Ctag usetags
                                                m1 = mkOp (OpCrypt msg c t1) pkcfg
                                                a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                        in ([],[],[a1],ns)

                                FromASecretForC (a,_,_) vers _ (c,_,_)  ->
                                        let
                                                t1 = insertTag Atag usetags
                                                m1 = mkOp (OpSignCrypt msg a vers c t1 CPLeft) pkcfg
                                                a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                        in ([],[],[a1],ns)

                                ---------- fresh -------------

                                FreshFromA (a,_,_) vers _ ->
                                        let
                                                t1 = insertTag Fatag usetags
                                                m1 = mkOp (OpSign (concatId2Msg cPos sqn msg) a vers t1 CPLeft) pkcfg
                                                a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                        in ([(SeqNumber [],sqn)],[],[a1],ns)

                                FreshFromAWithDH ap vers bp -> protSpecification ch (FreshFromA ap vers bp) impltype pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                FreshFromASecretForB (a,_,_) vers (b,_,_) ->
                                        let
                                                t1 = insertTag Fatag usetags
                                                m1 = mkOp (OpSignCrypt (concatId2Msg cPos sqn msg) a vers b t1 CPLeft) pkcfg
                                                a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                        in ([(SeqNumber [],sqn)],[],[a1],ns)

                                ----------------- forward --------------

                                ForwardSighted (a,_,_) vers bp cp prevFresh ->
                                        let
                                                --' prevFresh should be only considered if freshness is done with SQN
                                                sqn = newNum prefixSQN refint
                                                t1 = insertTag Fatag usetags
                                                m1 = if prevFresh then mkOp (OpSign (concatId2Msg cPos sqn msg) a vers t1 CPLeft) pkcfg else mkOp (OpSign msg a vers t1 CPLeft) pkcfg
                                                a1 = mkAnBxAction bp Insecure cp m1 hmks
                                        in ([],[],[a1],ns)

                                ForwardSightedSecret  (a,_,_) vers bp cp@(c,_,_) prevFresh ->
                                        let
                                                sqn = newNum prefixSQN refint
                                                m1 = if prevFresh then mkOp (OpSignCrypt (concatId2Msg cPos sqn msg) a vers c (insertTag Fatag usetags) CPLeft) pkcfg else mkOp (OpSignCrypt msg a vers c (insertTag Atag usetags) CPLeft) pkcfg
                                                a1 = mkAnBxAction bp Insecure cp m1 hmks
                                        in ([],[],[a1],ns)

                                ForwardBlind {} ->
                                        let
                                                m1 = msg
                                                a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                        in ([],[],[a1],ns)

                                ----------------- fresh forward --------------

                                ForwardFreshSighted (a,_,_) vers bp cp ->
                                        let
                                                -- resuse the sqn of a previous exchange
                                                sqn = newNum prefixSQN refint
                                                t1 = insertTag Fatag usetags
                                                m1 = mkOp (OpSign (concatId2Msg cPos sqn msg) a vers t1 CPLeft) pkcfg
                                                a1 = mkAnBxAction bp Insecure cp m1 hmks
                                        in ([],[],[a1],ns)

                                ForwardFreshSightedWithDH ap vers bp cp -> protSpecification ch (ForwardFreshSighted ap vers bp cp) impltype pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                ForwardFreshSightedSecret (a,_,_) vers bp cp@(c,_,_) ->
                                        let
                                                -- resuse the sqn of a previous exchange
                                                sqn = newNum prefixSQN refint
                                                t1 = insertTag Fatag usetags
                                                m1 = mkOp (OpSignCrypt (concatId2Msg cPos sqn msg) a vers c t1 CPLeft) pkcfg
                                                a1 = mkAnBxAction bp Insecure cp m1 hmks
                                        in ([],[],[a1],ns)

                -- CCM w. challange response / separation of fresh proof and authenticity

                CCM2 -> case chImpl of

                                Plain {} -> protSpecification ch chImpl CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                FromA {} -> protSpecification ch chImpl CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                ---------- 3 peers ------------

                                SecretForC {} -> protSpecification ch chImpl CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                FromASecretForC {} -> protSpecification ch chImpl CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                ---------- fresh -------------

                                FreshFromA (a,_,_) vers (b,_,_) ->
                                        let
                                                m1 = Atom a
                                                a1 = mkAnBxAction p1 Insecure p2 m1 []
                                                m2 = mkOp (OpCrypt (Comp Cat [Atom n,Atom b]) a NoTag) pkcfg
                                                a2 = mkAnBxAction p2 Insecure p1 m2 []
                                                t3 = insertTag Atag usetags
                                                m3 = mkOp (OpSign msg a vers t3 CPLeft) pkcfg
                                                a3 = mkAnBxAction p1 Insecure p2 m3 []
                                                a4 = syncAction p2 p1
                                                t5 = insertTag Fatag usetags
                                                m5 = mkOp (OpSign (concatId2Msg cPos n (mkOp (OpHash msg) pkcfg)) a vers t5 CPLeft) pkcfg
                                                a5 = mkAnBxAction p1 Insecure p2 m5 hmks
                                        in ([(Number [],n)],[],[a1,a2,a3,a4,a5],ns)

                                FreshFromAWithDH ap vers bp  -> protSpecification ch (FreshFromA ap vers bp) impltype pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                FreshFromASecretForB (a,_,_) vers (b,_,_) ->
                                        let
                                                m1 = Atom a
                                                a1 = mkAnBxAction p1 Insecure p2 m1 []
                                                m2 = mkOp (OpCrypt (Comp Cat [Atom n,Atom b]) a NoTag) pkcfg
                                                a2 = mkAnBxAction p2 Insecure p1 m2 []
                                                t3 = insertTag Atag usetags
                                                m3 = mkOp (OpSignCrypt msg a vers b t3 CPLeft) pkcfg
                                                a3 = mkAnBxAction p1 Insecure p2 m3 []
                                                a4 = syncAction p2 p1
                                                t5 = insertTag Fstag usetags
                                                m5 = mkOp (OpSignCrypt (concatId2Msg cPos n (mkOp (OpHash msg) pkcfg)) a vers b t5 CPLeft) pkcfg
                                                a5 = mkAnBxAction p1 Insecure p2 m5 hmks
                                        in ([(Number [],n)],[],[a1,a2,a3,a4,a5],ns)

                                ----------------- forward --------------

                                ForwardSighted ap vers bp cp _ -> protSpecification ch (ForwardSighted ap vers bp cp False) CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                ForwardSightedSecret ap vers bp cp _ -> protSpecification ch (ForwardSightedSecret ap vers bp cp False) CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                ForwardBlind {} -> protSpecification ch chImpl CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                ----------------- fresh forward --------------

                                ForwardFreshSighted ap@(a,_,_) vers bp cp@(c,_,_) ->
                                        let
                                                t1 = insertTag Atag usetags
                                                m1 = mkOp (OpSign msg a vers t1 CPLeft) pkcfg
                                                a1 = mkAnBxAction bp Insecure cp m1 []
                                                m2 = mkOp (OpCrypt (Comp Cat [Atom c,Atom n]) a NoTag) pkcfg
                                                a2 = mkAnBxAction cp Insecure bp m2 []
                                                m3 = m2
                                                t3 = insertTag Fatag usetags
                                                a3 = mkAnBxAction bp Insecure ap m3 []
                                                m4 = mkOp (OpSign (concatId2Msg cPos n (mkOp (OpHash msg) pkcfg)) a vers t3 CPLeft) pkcfg
                                                a4 = mkAnBxAction ap Insecure bp m4 []
                                                m5 = m4
                                                a5 = mkAnBxAction bp Insecure cp m5 hmks
                                        in ([(Number [],n)],[],[a1,a2,a3,a4,a5],ns)

                                ForwardFreshSightedWithDH ap vers bp cp -> protSpecification ch (ForwardFreshSighted ap vers bp cp) impltype pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                ForwardFreshSightedSecret ap@(a,_,_) vers bp cp@(c,_,_) ->
                                        let
                                               t1 = insertTag Atag usetags
                                               m1 = mkOp (OpSignCrypt msg a vers c t1 CPLeft) pkcfg
                                               a1 = mkAnBxAction bp Insecure cp m1 []
                                               m2 = mkOp (OpCrypt (Comp Cat [Atom c,Atom n]) a NoTag) pkcfg
                                               a2 = mkAnBxAction cp Insecure bp m2 []
                                               m3 = m2
                                               a3 = mkAnBxAction bp Insecure ap m3 []
                                               t4 = insertTag Fstag usetags
                                               m4 = mkOp (OpSignCrypt (concatId2Msg cPos n (mkOp (OpHash msg) pkcfg)) a vers c t4 CPLeft) pkcfg
                                               a4 = mkAnBxAction ap Insecure bp m4 []
                                               m5 = m4
                                               a5 = mkAnBxAction bp Insecure cp m5 hmks
                                        in ([(Number [],n)],[],[a1,a2,a3,a4,a5],ns)

                -- CCM w SQN and Hybrid crypto
                CCM3 -> case chImpl of

                                Plain {} -> protSpecification ch chImpl CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                FromA {} -> protSpecification ch chImpl CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                ---------- 3 peers ------------

                                SecretForC _ _ (c,_,_) ->
                                        let
                                                t1 = insertTag Fatag usetags
                                                m1 = mkOp (OpHybridScrypt msg c (Atom k) t1)  pkcfg        -- "({"++k++"}pk("++c++"),{|"++insertTag(Ctag)++msg++"|}"++k++")"
                                                a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                        in ([(SymmetricKey [],k)],[],[a1],ns)

                                FromASecretForC (a,_,_) vers _ (c,_,_)  ->
                                        let
                                                t1 = insertTag Atag usetags
                                                m1 = mkOp (OpHybridSignScrypt msg a vers c (Atom k) t1 CPLeft) pkcfg     --  "({"++k++"}pk("++c++"),{|{"++insertTag(Atag)++ (showIdents vers) ++","++msg++"}inv(sk("++a++"))|}"++k++")"
                                                a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                        in ([(SymmetricKey [],k)],[],[a1],ns)

                                ---------- fresh -------------

                                FreshFromA {}-> protSpecification ch chImpl CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                FreshFromAWithDH ap vers bp  -> protSpecification ch (FreshFromA ap vers bp) impltype pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                FreshFromASecretForB (a,_,_) vers (b,_,_) ->
                                        let
                                                t1 = insertTag Fatag usetags
                                                m1 = mkOp (OpHybridSignScrypt (concatId2Msg cPos sqn msg) a vers b (Atom k) t1 CPLeft) pkcfg         --"({"++k++"}pk("++b++"),{|{"++insertTag(Fatag)++sqn++","++ (showIdents vers) ++","++msg++"}inv(sk( "++a++"))|}"++k++")"
                                                a1 = mkAnBxAction p1 Insecure p2 m1 hmks
                                        in ([(SeqNumber [], sqn),(SymmetricKey [],k)],[],[a1],ns)

                                         ----------------- forward --------------

                                ForwardSighted {} -> protSpecification ch chImpl CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                ForwardSightedSecret (a,_,_) vers bp@(b,_,_) cp prevFresh ->
                                        let
                                                sqn = newNum prefixSQN refint
                                                m1 = if prevFresh then mkOp (OpHybridSignScrypt (concatId2Msg cPos sqn msg) a vers b (Atom k) (insertTag Fatag usetags) CPLeft) pkcfg else mkOp (OpHybridSignScrypt msg a vers b (Atom k) (insertTag Atag usetags) CPLeft) pkcfg
                                                a1 = mkAnBxAction bp Insecure cp m1 hmks
                                        in ([(SymmetricKey [],k)],[],[a1],ns)

                                ForwardBlind {} -> protSpecification ch chImpl CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                ----------------- fresh forward --------------

                                ForwardFreshSighted {} -> protSpecification ch chImpl CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                ForwardFreshSightedWithDH ap vers bp cp -> protSpecification ch (ForwardFreshSighted ap vers bp cp) impltype pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                ForwardFreshSightedSecret (a,_,_) vers bp cp@(c,_,_) ->
                                        let
                                                -- resuse the key of a previous exchange
                                                -- k = newNum "K" refint
                                                sqn = newNum prefixSQN refint
                                                t1 = insertTag Fatag usetags
                                                m1 = mkOp (OpHybridSignScrypt (concatId2Msg cPos sqn msg) a vers c (Atom k) t1 CPLeft) pkcfg --"({"++k++"}pk("++c++"),{|{"++insertTag(Fatag)++sqn++","++ (showIdents vers) ++","++msg++"}inv(sk("++a++"))|}"++k++")"
                                                a1 = mkAnBxAction bp Insecure cp m1 hmks
                                        in ([(SymmetricKey [],k)],[],[a1],ns)

                 -- challange response. diffie-hellman - nohybrid

                CCM4 -> case chImpl of

                                Plain {} -> protSpecification ch chImpl CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                FromA {} -> protSpecification ch chImpl CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                ---------- 3 peers ------------

                                SecretForC {} -> protSpecification ch chImpl CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                FromASecretForC {} -> protSpecification ch chImpl CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                ---------- fresh -------------

                                FreshFromA ap vers bp -> protSpecification ch chImpl1 CCM4 pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                                                            where chImpl1 = FreshFromAWithDH ap vers bp

                                FreshFromAWithDH (a,_,_) vers _ ->
                                        let
                                                g = dhPar
                                                m1 = mkOp (OpDHGX x) pkcfg
                                                a1 = mkAnBxAction p1 Insecure p2 m1 []
                                                m2 = mkOp (OpCrypt (Comp Cat ([mkOp (OpDHGX y) pkcfg, Atom n] ++ showIdentsMsg vers)) a NoTag) pkcfg
                                                a2 = mkAnBxAction p2 Insecure p1 m2 []
                                                m3 = Comp Cat [mkOp (OpScrypt (concatId2Msg cPos n (mkOp (OpHash (mkOp (OpSign msg a vers NoTag CPLeft) pkcfg)) pkcfg)) (mkOp (OpDHGXY x y) pkcfg) (insertTag Fatag usetags)) pkcfg,mkOp (OpSign msg a vers (insertTag Atag usetags) CPLeft) pkcfg]

                                                a3 = mkAnBxAction p1 Insecure p2 m3 hmks
                                        in ([(Number [], n),(Number [], x),(Number [], y),(Number [], g)],[g],[a1,a2,a3],ns)

                                FreshFromASecretForB  (a,_,_) vers (b,_,_) ->
                                        let
                                                g = dhPar
                                                m1 = mkOp (OpDHGX x) pkcfg
                                                a1 = mkAnBxAction p1 Insecure p2 m1 []
                                                m2 = mkOp (OpCrypt (Comp Cat ([mkOp (OpDHGX y) pkcfg, Atom n] ++ showIdentsMsg vers)) a NoTag) pkcfg
                                                a2 = mkAnBxAction p2 Insecure p1 m2 []
                                                m3 = Comp Cat [mkOp (OpScrypt (concatId2Msg cPos n (mkOp (OpHash (mkOp (OpSign msg a vers NoTag CPLeft) pkcfg)) pkcfg)) (mkOp (OpDHGXY x y) pkcfg) (insertTag Fatag usetags)) pkcfg,mkOp (OpSignCrypt msg a vers b (insertTag Atag usetags) CPLeft) pkcfg]
                                                a3 = mkAnBxAction p1 Insecure p2 m3 hmks
                                        in ([(Number [], n),(Number [], x),(Number [], y),(Number [], g)],[g],[a1,a2,a3],ns)

                                ----------------- forward --------------

                                ForwardSighted {} -> protSpecification ch chImpl CCM2 pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                ForwardSightedSecret  ap vers bp cp _ -> protSpecification ch (ForwardSightedSecret ap vers bp cp False) CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                ForwardBlind {} -> protSpecification ch chImpl CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                ----------------- fresh forward --------------

                                ForwardFreshSighted ap vers bp cp -> protSpecification ch chImpl1 CCM4 pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                                                            where chImpl1 = ForwardFreshSightedWithDH ap vers bp cp

                                ForwardFreshSightedWithDH ap@(a,_,_) vers bp cp@(c,_,_) ->
                                        let
                                                g = dhPar
                                                t1 = insertTag Atag usetags
                                                m1 = mkOp (OpSign msg a vers t1 CPLeft) pkcfg
                                                a1 = mkAnBxAction bp Insecure cp m1 []
                                                m2 = Atom c
                                                a2 = mkAnBxAction cp Insecure ap m2 []
                                                m3 = mkOp (OpDHGX x) pkcfg
                                                a3 = mkAnBxAction ap Insecure cp m3 []
                                                m4 = mkOp (OpCrypt (Comp Cat ([mkOp (OpDHGX y) pkcfg, Atom n] ++ showIdentsMsg vers)) a NoTag) pkcfg
                                                a4 = mkAnBxAction cp Insecure ap m4 []
                                                t5 = insertTag Fatag usetags
                                                m5 = mkOp (OpScrypt (concatId2Msg cPos n (mkOp (OpHash (mkOp (OpSign msg a vers NoTag CPLeft) pkcfg)) pkcfg)) (mkOp (OpDHGXY x y) pkcfg) t5) pkcfg
                                                a5 = mkAnBxAction ap Insecure cp m5 hmks
                                        in ([(Number [], n),(Number [], x),(Number [], y),(Number [], g)],[g],[a1,a2,a3,a4,a5],ns)

                                ForwardFreshSightedSecret ap@(a,_,_) vers bp cp@(c,_,_) ->
                                                          let
                                                g = dhPar
                                                t1 = insertTag Atag usetags
                                                m1 = mkOp (OpSignCrypt msg a vers c t1 CPLeft) pkcfg
                                                a1 = mkAnBxAction bp Insecure cp m1 []
                                                m2 = Atom c
                                                a2 = mkAnBxAction cp Insecure ap m2 []
                                                m3 = mkOp (OpDHGX x) pkcfg
                                                a3 = mkAnBxAction ap Insecure cp m3 []
                                                m4 = mkOp (OpCrypt (Comp Cat ([mkOp (OpDHGX y) pkcfg, Atom n] ++ showIdentsMsg vers)) a NoTag) pkcfg
                                                a4 = mkAnBxAction cp Insecure ap m4 []
                                                t5 = insertTag Fatag usetags
                                                m5 = mkOp (OpScrypt (concatId2Msg cPos n (mkOp (OpHash (mkOp (OpSign msg a vers NoTag CPLeft) pkcfg)) pkcfg)) (mkOp (OpDHGXY x y) pkcfg) t5) pkcfg
                                                a5 = mkAnBxAction ap Insecure cp m5 hmks
                                        in ([(Number [], n),(Number [], x),(Number [], y),(Number [], g)],[g],[a1,a2,a3,a4,a5],ns)

                 -- engineering - ARSPA-WITS
                 -- hybrid. challange response. diffie-hellman

                APP -> case chImpl of

                                Plain {} -> protSpecification ch chImpl CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                FromA {} -> protSpecification ch chImpl CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                ---------- 3 peers ------------

                                SecretForC {}-> protSpecification ch chImpl CCM3 pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                FromASecretForC {} -> protSpecification ch chImpl CCM3 pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                ---------- fresh -------------

                                FreshFromA (a,_,_) vers (b,_,_)  ->
                                        let
                                                m1 = Atom a
                                                a1 = mkAnBxAction p1 Insecure p2 m1 []
                                                m2 = mkOp (OpCrypt (Comp Cat [Atom n,Atom b]) a NoTag) pkcfg
                                                a2 = mkAnBxAction p2 Insecure p1 m2 []
                                                m3 = Comp Cat [mkOp (OpCrypt (concatId2Msg cPos n (mkOp (OpHash (mkOp (OpSign msg a vers NoTag CPLeft) pkcfg)) pkcfg)) b (insertTag Fatag usetags)) pkcfg,mkOp (OpSign msg a vers (insertTag Atag usetags) CPLeft) pkcfg]
                                                a3 = mkAnBxAction p1 Insecure p2 m3 hmks
                                        in ([(Number [],n)],[],[a1,a2,a3],ns)

                                FreshFromAWithDH (a,_,_) vers _ ->
                                        let
                                                g = dhPar
                                                m1 = mkOp (OpDHGX x) pkcfg
                                                a1 = mkAnBxAction p1 Insecure p2 m1 []
                                                m2 = mkOp (OpCrypt (Comp Cat ([mkOp (OpDHGX y) pkcfg, Atom n] ++ showIdentsMsg vers)) a NoTag) pkcfg
                                                a2 = mkAnBxAction p2 Insecure p1 m2 []
                                                m3 = Comp Cat [mkOp (OpScrypt (concatId2Msg cPos n (mkOp (OpHash (mkOp (OpSign msg a vers NoTag CPLeft) pkcfg)) pkcfg)) (mkOp (OpDHGXY x y) pkcfg) (insertTag Fatag usetags)) pkcfg,mkOp (OpSign msg a vers (insertTag Atag usetags) CPLeft) pkcfg]
                                                a3 = mkAnBxAction p1 Insecure p2 m3 hmks
                                        in ([(Number [], n),(Number [], x),(Number [], y),(Number [], g)],[g],[a1,a2,a3],ns)

                                FreshFromASecretForB (a,_,_) vers (b,_,_) ->
                                        let
                                                 m1 = Atom a
                                                 a1 = mkAnBxAction p1 Insecure p2 m1 []
                                                 m2 = mkOp (OpCrypt (Comp Cat [Atom n,Atom b]) a NoTag) pkcfg
                                                 a2 = mkAnBxAction p2 Insecure p1 m2 []
                                                 -- USE HYBRID ENCRYPTION
                                                 m3 = Comp Cat [mkOp (OpCrypt (concatId2Msg cPos n (Atom k)) b (insertTag Fatag usetags)) pkcfg, mkOp (OpSignScrypt msg a vers (Atom k) (insertTag Atag usetags) CPLeft) pkcfg]

                                                 a3 = mkAnBxAction p1 Insecure p2 m3 hmks
                                        in ([(Number [],n),(SymmetricKey [],k)],[],[a1,a2,a3],ns)

                                ----------------- forward --------------

                                ForwardSighted {} -> protSpecification ch chImpl CCM2 pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                ForwardSightedSecret  ap vers bp cp _ -> protSpecification ch (ForwardSightedSecret ap vers bp cp False) CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt
                                ForwardBlind {} -> protSpecification ch chImpl CCM pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                ----------------- fresh forward --------------

                                ForwardFreshSighted {}  -> protSpecification ch chImpl CCM2 pkcfg usetags msg0 int refint ns certified types hmacmaps dt

                                ForwardFreshSightedWithDH ap@(a,_,_) vers bp cp@(c,_,_) ->
                                        let
                                                g = dhPar
                                                t1 = insertTag Atag usetags
                                                m1 = mkOp (OpSign msg a vers t1 CPLeft) pkcfg
                                                a1 = mkAnBxAction bp Insecure cp m1 []
                                                m2 = Atom c
                                                a2 = mkAnBxAction cp Insecure ap m2 []
                                                m3 = mkOp (OpDHGX x) pkcfg
                                                a3 = mkAnBxAction ap Insecure cp m3 []
                                                m4 = mkOp (OpCrypt (Comp Cat ([mkOp (OpDHGX y) pkcfg, Atom n] ++ showIdentsMsg vers)) a NoTag) pkcfg
                                                a4 = mkAnBxAction cp Insecure ap m4 []
                                                t5 = insertTag Fatag usetags
                                                m5 = mkOp (OpScrypt (concatId2Msg cPos n (mkOp (OpHash (mkOp (OpSign msg a vers NoTag CPLeft) pkcfg)) pkcfg)) (mkOp (OpDHGXY x y) pkcfg) t5) pkcfg
                                                a5 = mkAnBxAction ap Insecure cp m5 hmks
                                        in ([(Number [], n),(Number [], x),(Number [], y),(Number [], g)],[g],[a1,a2,a3,a4,a5],ns)

                                ForwardFreshSightedSecret ap@(a,_,_) vers bp cp@(c,_,_) ->
                                        let
                                               t1 = insertTag Atag usetags
                                               m1 = mkOp (OpHybridSignScrypt msg a vers c (Atom k) t1 CPLeft) pkcfg
                                               a1 = mkAnBxAction bp Insecure cp m1 []
                                               m2 = mkOp (OpCrypt (Comp Cat [Atom n,Atom c]) a NoTag) pkcfg
                                               a2 = mkAnBxAction cp Insecure bp m2 []
                                               m3 = m2
                                               a3 = mkAnBxAction bp Insecure ap m3 []
                                               t4 = insertTag Fstag usetags
                                               m4 = mkOp (OpSignCrypt (Comp Cat [Atom c,Atom n,mkOp (OpHash msg) pkcfg]) a vers c t4 CPLeft) pkcfg
                                               a4 = mkAnBxAction ap Insecure bp m4 []
                                               m5 = m4
                                               a5 = mkAnBxAction bp Insecure cp m5 hmks
                                        in ([(Number [], n),(SymmetricKey [],k)],[],[a1,a2,a3,a4,a5],ns)
