{-

N.B. Experimental AnB to IF translation
Please report errors and suggestions to: p.modesti@tees.ac.uk

Copyright 2023-2025 Paolo Modesti

Code adapted from the Translator.hs file of the
Open Source Fixedpoint Model-Checker version 2022

(C) Copyright Sebastian Moedersheim 2003,2022
(C) Copyright Jakub Janaszkiewicz 2022
(C) Copyright Paolo Modesti 2012
(C) Copyright Nicklas Bo Jensen 2012
(C) Copyright IBM Corp. 2009
(C) Copyright ETH Zurich (Swiss Federal Institute of Technology) 2003,2007

All Rights Reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

- Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

- Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

- Neither the name of the ETH Zuerich, IBM, nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

-}

-- modified OFMC code, most changes are tagged as "<paolo-eq>" "</paolo-eq>"
-- changes enabled when eqHack is True
-- also allows for a strictier interpretation of the AnB where clause, 
-- that consider the global view of the protocol, rather then individual agents' view

{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "Use infix" #-}
{-# HLINT ignore "Avoid lambda using `infix`" #-}
{-# LANGUAGE InstanceSigs #-}

module AnB2IF_Translator where
import AnB2IF_Common
    ( AnBOnP(eqnoexec, outt, noowngoal, numSess, typed,
                     if2cif),
      OutputType(Isa, Pretty, IF) )
import AnB2IF_LMsg (LMsg)
import AnB2IF_Msg (Substitution, analysis, ppMsgListOFMC, ppMsgOFMC)
import AnB2IF_MsgPat (mkname, initialState, lversion, receiveLMsg, receiveMsg, sendMsg, synthesisPattern, ProtocolState)
import AnBAst
    ( Msg,
      Action,
      Peer,
      Knowledge,
      Types,
      Protocol,
      eqFunctionsAnB,
      mapProtocol2AnBIF, ChannelType, Type)
import AnBxOnP ( AnBxOnP(ifsessions,ifstrictwhere) )
import AnBxMsgCommon
    ( Operator(Userdef, Scrypt, Xor, Crypt, Inv, Apply, Cat),
      Ident,
      isVariable,
      ppXList,
      ppId,
      ppIdList,
      replace )
import Data.List ( (\\), intersect, isPrefixOf, nubBy )
import Data.Containers.ListUtils (nubOrd)
import Data.Maybe ( fromJust, fromMaybe, isNothing )
import Debug.Trace (trace)
import AnBxShow (showEquation, showSimpleGoal)
import AnBShow (showAnB, showAnBOutputHeader, AnBHeaderType(AnBHTIF))
import AnBxMsg ( AnBxMsg (Comp,Atom), patternMsgError, isAtom, idents, vars, isntFunction)
import AnBxAst (AnBxGoal (..), AnBxType (..), AnBxChannelType (..), isPublicKeyType, isSeqNumberType, unwrapMsg)
import qualified Data.Bifunctor

--------- Facts, Rules, and the Translation State ---------------

data Fact
  = State Ident [LMsg]
  | FPState Ident [Msg]
  | Iknows Msg
  | Fact Ident [Msg]
  deriving (Eq, Show, Ord)

type Rule = ([Fact], Eqs, [Ident], [Fact])

lhs :: (a, b, c) -> a
lhs (l, _, _) = l

rhs :: (a, b, c) -> c
rhs (_, _, r) = r

frv :: (a, b, c) -> b
frv (_, f, _) = f

identsF :: Fact -> [Ident]
identsF (State _ _) = error "identsF of state undefined"
identsF (FPState _ msgs) = nubOrd (concatMap idents msgs)
identsF (Iknows msg) = nubOrd (idents msg)
identsF (Fact _ msgs) = nubOrd (concatMap idents msgs)

identsFL :: (Foldable t) => t Fact -> [Ident]
identsFL m = nubOrd (concatMap identsF m)

type Rule' = (Rule, ProtocolState, ProtocolState)
type Eqs = [(Msg, Msg)]
type Role = (Ident, [Rule'])

data ProtocolTranslationState = PTS
  { protocol :: Protocol,
    options :: AnBOnP,
    roles :: [Role],
    rules :: [Rule],
    initial :: String
  }

-- enable/disable display of AnB protocol in debug messages
showProtInPTS :: Bool
showProtInPTS = False

instance Show ProtocolTranslationState where
    show :: ProtocolTranslationState -> String
    show pts = (if showProtInPTS then showAnB (protocol pts) else "") ++ "\n" ++ "Roles: " ++ show (roles pts) ++ "\n" ++ "Rules: " ++ show (rules pts) ++ "\n" ++ "Initials: " ++ show (initial pts) ++ "\n"
-- <paolo-eq>

showIFHeaderComments :: Protocol -> AnBxOnP -> String
showIFHeaderComments (_,_,_,equations,_,_,_,_,goals) options = "% Sessions: " ++ show (ifsessions options) ++ "\n" ++
                                                                    (if null equations then "" else "% Equations:" ++ "\n" ++
                                                                                          concatMap (\x -> "%\t" ++ showEquation x ++ "\n") equations) ++
                                                                    (if null goals then "" else "% Goals:" ++ "\n" ++
                                                                                          concatMap (\x -> "%\t" ++ showSimpleGoal x ++ "\n") goals)

mkIF :: Protocol -> AnBOnP -> AnBxOnP -> String
mkIF protocol@((protName,_),_,_,_,_,_,_,_,_) args options =
     let
        protocol1 = mapProtocol2AnBIF protocol
        headerStr = showAnBOutputHeader protName AnBHTIF options ++ showIFHeaderComments protocol options
     in
    headerStr ++ "\n" ++
  (( case outt args of
        IF -> (\x -> x ++ endstr (noowngoal args)) . ruleList args    -- endstr = attackstates. ruleList is for SQN
        t -> error (show t ++ " unsupported")
    )
      . addInit (eqFunsIF protocol) (ifstrictwhere options)  -- add init section, which depends from the number of sessions. Functions used in equations are not printed (see printTypes function)
      . addGoals        -- add goals annotations: secrets, witness, wrequest, request, ...
      . rulesAddSteps   -- add step number to the state, e.g. state_rA(A,SID,0,XshkAB,succ,pre,B)
      . createRules     -- created the transition rules from actions
  ) (mkPTS protocol1 args)

mkPTS :: Protocol -> AnBOnP -> ProtocolTranslationState
mkPTS protocol options = PTS {protocol = protocol, options = options, roles = [], rules = [], initial = ""}

-- substitute the application of equation functions with terms with Userdef _ that can be handled by equational theories
-- moreover such functions should not be declared in the init section (see printTypes function)
mkEqMsg :: [Ident] -> Msg -> Msg
-- mkEqMsg eqFuns msg | trace ("mkEqMsg\n\tmsg: " ++ show msg ++ "\n\teqFuns: " ++ show eqFuns) False = undefined
mkEqMsg eqFuns msg@(Comp Apply (Atom x : xs)) = if elem x eqFuns then Comp (Userdef x) (map (mkEqMsg eqFuns) xs) else msg
mkEqMsg _ msg = msg

mkEqLMsg :: [Ident] -> LMsg -> LMsg
mkEqLMsg eqFuns (msg1, msg2) = (mkEqMsg eqFuns msg1, mkEqMsg eqFuns msg2)

mkEqFact :: [Ident] -> Fact -> Fact
-- mkEqFact eqFuns msg | trace ("mkEqFact\n\tmsg: " ++ show msg ++ "\n\teqFuns: " ++ show eqFuns) False = undefined
mkEqFact eqFuns (State ident xs) = State ident (map (mkEqLMsg eqFuns) xs)
mkEqFact eqFuns (FPState ident xs) = FPState ident (map (mkEqMsg eqFuns) xs)
mkEqFact eqFuns (Iknows msg) = Iknows (mkEqMsg eqFuns msg)
mkEqFact eqFuns (Fact ident xs) = Fact ident (map (mkEqMsg eqFuns) xs)

mkRuleEq :: [Ident] -> Rule -> Rule
mkRuleEq eqFuns (l, eq, f, r) =
  let l1 = map (mkEqFact eqFuns) l
      r1 = map (mkEqFact eqFuns) r
   in (l1, eq, f, r1)

-- </paolo-eq>

---- Translation Stage 1: Creating Rules
----------------------------------------

createRules :: ProtocolTranslationState -> ProtocolTranslationState
-- createRules pts | trace ("createRules\n" ++ show pts) False = undefined
createRules pts =
  let p@(_, types, _, _, knowledge,_, _, actions, _) = protocol pts
      frMsg = fresh p
      pks = concatMap snd (filter (\(x, _) -> isPublicKeyType x) types)
      -- roles =
      --  ( snd
      --      . head
      --      . filter (\x -> case fst x of Agent {} -> True; _ -> False)
      --  )
      --    types
  in -- <paolo-eq>
      pts {rules = manageRules 0 frMsg (\x -> initialState (lookupL x knowledge)) actions pks (eqnoexec (options pts))}
     -- </paolo-eq>

manageRules :: Int -> [Ident] -> (Ident -> ProtocolState) -> [Action] -> [Ident] -> Bool -> [Rule]
manageRules step fresh states actions pks eqHack =
  -- <paolo-eq>
  --- about step number (=list index + 1)
  --- initially 0: there is no incoming message
  --- finally (length actions): there is no outgoing message
  let ((_, _, b, min, _, _), (b', _, _, mout, _, _)) 
        | step == length actions = (toJust (Just (last actions)), toJust Nothing)
        | step == 0 = (toJust Nothing, toJust (Just (head actions)))
        | otherwise = (toJust (Just (actions !! (step - 1))), toJust (Just (actions !! step)))
      thisfresh = case mout of
                    Nothing -> []
                    Just (_, _, _, mout', _) -> intersect fresh (idents mout')
      freshpks = intersect pks thisfresh
      ub
        | isNothing b = fromMaybe (error ("Undefined Receiver in step" ++ show step)) b'
        | isNothing b' = fromJust b
        | b /= b' = error ("Receiver: " ++ show b ++ " and Sender/NextMsg is " ++ show b')
        | otherwise = fromJust b
      (rule, state') = createRule thisfresh freshpks ub (states ub) min mout eqHack       -- <paolo-eq>
   in
      rule  : (if step == length actions then [] else manageRules (step + 1) (fresh \\ thisfresh) (\x -> if x == ub then state' else states x) actions pks eqHack)
      -- </paolo-eq>

-- <paolo-eq>

-- IF built-in functions used in standard equational theories
builtInEqFuns :: [String]
builtInEqFuns = ["inv", "crypt", "scrypt", "fst", "snd", "pair", "inve", "exp", "kap", "kep", "e", "xor", "skey_", "commit1", "commit2", "bind", "open", "commitment", "halfkey", "fullkey"]

-- identify custom functions used in the equations declaration
eqFunsIF :: Protocol -> [Ident]
eqFunsIF protocol = eqFunctionsAnB protocol \\ builtInEqFuns

-- patched version
msgHasEqFuns :: Msg -> Ident -> Bool
msgHasEqFuns (Atom id) f = id == f
msgHasEqFuns (Comp _ xs) f = any (\x -> msgHasEqFuns x f) xs
msgHasEqFuns msg _ = error $ patternMsgError msg "msgHasEqFuns" 


sendMsg1 :: Msg -> ProtocolState -> ProtocolState
sendMsg1 msg state =
  case synthesisPattern state msg of
    Nothing -> state ++ [(msg, msg)] -- returns a message anyway, it assumes that it can be done if executability of protocol has been been checked with Eq theories
    Just p -> state ++ [(msg, p)]

synthesisPattern1 :: ProtocolState -> Msg -> Bool -> [Ident] -> Maybe Msg
-- synthesisPattern1 _ msg eqHack eqFuns | trace ("synthesisPattern1\n\tmsg: " ++ ppMsgOFMC Pretty msg ++ " - " ++ "eqHack: " ++ show eqHack ++ " - " ++ "eqFuns: " ++ show eqFuns) False = undefined
synthesisPattern1 state msg _ [] = synthesisPattern state msg
synthesisPattern1 state msg False _ = synthesisPattern state msg
synthesisPattern1 state msg True _ = case synthesisPattern state msg of
                                                    Nothing -> Just (Comp Apply [Atom "CheckHERE", msg]) -- print a warning in IF code, to make OFMC stop if verification is unreliable 
                                                    Just m -> Just m
-- </paolo-eq>

createRule :: [Ident] -> [Ident] -> Ident -> ProtocolState -> Maybe (Peer, ChannelType, Peer, Msg, Maybe Msg) -> Maybe (Peer, ChannelType, Peer, Msg, Maybe Msg) -> Bool -> (Rule, ProtocolState)
-- createRule fresh freshpks role state incomin outgoin eqHack  | trace ("createRule\n\tfresh: " ++ show fresh ++ "\n\tfreshpks: " ++ show freshpks ++ "\n\trole: " ++ show role ++ "\n\tstate: " ++ show state ++ "\n\tincomin: " ++ show incomin ++ "\n\toutoing: " ++ show outgoin) False = undefined
createRule fresh freshpks role state incomin outgoin eqHack =
  let (state1, msg1) =
        case incomin of
          Nothing -> (state, Atom "i")
          Just (sender, ct, receiver, recm, Nothing) ->
            let st = receiveMsg recm state
             in (st, chtrafo False sender ct receiver (snd (last st)))
          Just (sender, ct, receiver, recm, Just recmp) ->
            let st = receiveLMsg (recm, recmp) state
             in (st, chtrafo False sender ct receiver (snd (last st)))
      (state2, msg2) =
        case outgoin of
          Nothing -> (state1, Atom "i")
          Just (sender, ct, receiver, sndm, _) ->
            -- <paolo-eq>
            let state1' = peertrafo receiver msg1 state1
                state2 = (state1' ++ map (\x -> (Atom x, Atom x)) fresh ++ map (\x -> (Comp Inv [Atom x], Comp Inv [Atom x])) freshpks)
                st = if eqHack then sendMsg1 sndm state2 else sendMsg sndm state2
             in (st, chtrafo True sender ct receiver (snd (last st)))
   in       -- </paolo-eq>
      ((State role ((nubBy eqSnd
                        . (\x -> (Atom role, Atom role) : (x ++ [(Atom "SID", Atom "SID")]))
                        . take (length state)) state1)
            : ([Iknows msg1 | msg1 /= Atom "i"]),
          [],
          fresh,
          State role ((nubBy eqSnd
                            . (\x -> (Atom role, Atom role) : (x ++ [(Atom "SID", Atom "SID")]))) state2)
            : ([Iknows msg2 | msg2 /= Atom "i"])
        ),
        state2
      )

eqSnd :: (Eq a1) => (a2, a1) -> (a3, a1) -> Bool
eqSnd (_, a) (_, b) = a == b

isAgent :: Type -> Bool
isAgent (Agent {}) = True
isAgent _ = False

gettype :: Types -> Ident -> Type
gettype types id =
  let typedec = map fst $ filter (elem id . snd) types
   in if null typedec
        then error $ id ++ " has no declared type."
        else
          if length typedec > 1
            then error $ id ++ " has conflicting type declarations: " ++ show typedec
            else head typedec

fresh :: Protocol -> [Ident]
fresh (_, types, _,  _, (knowl, _),_ , _, actions, _) =
  let longterm = nubOrd $ concatMap (concatMap idents . snd) knowl
      all = nubOrd $ concatMap 
        (\(_, msgw, _, _) ->
          let (m, _) = unwrapMsg msgw
          in idents m)
        actions
      --- here we don't count sender/receiver names (can't be fresh)
      fresh = nubOrd (all \\ longterm)
      longterm_fresh = filter (not . isAgent . gettype types) (filter isVariable longterm)
      const_fresh = filter (not . isVariable) fresh
   in if const_fresh /= []
        then error $ "Error: the following constant(s) are not contained in initial knowledge of any role: " ++ ppIdList const_fresh
        else
          if longterm_fresh /= []
            then error $ "Error: the following variable(s) occur in the initial knowledge but are not of type agent: " ++ ppIdList longterm_fresh
            else fresh

toJust :: Maybe Action -> (Maybe Ident, ChannelType, Maybe Ident, Maybe (Peer, ChannelType, Peer, Msg, Maybe Msg), Maybe Msg, Maybe Msg)
toJust Nothing = (Nothing, Secure, Nothing, Nothing, Nothing, Nothing)
toJust (Just ((sp@(a, _, _), ct, rp@(b, _, _)), msgw, mp, zk)) = 
  let (m, _) = unwrapMsg msgw
  in (Just a, Secure, Just b, Just (sp, ct, rp, m, mp), mp, zk)

---------- Channel Transformation ---------
chtrafo :: Bool -> Peer -> ChannelType -> Peer -> Msg -> Msg
chtrafo _ (_, _, Just _) _ _ msg = error ("Not yet implemented: custom pseudos in protocol. Msg: " ++ ppMsgOFMC Pretty msg)
chtrafo _ _ _(_, _, Just _) msg = error ("Not yet implemented: custom pseudos in protocol. Msg: " ++ ppMsgOFMC Pretty msg)
chtrafo isSender sp@(sender, psender, Nothing) ct rp@(receiver, preceiver, Nothing) msg =
  case ct of
    Insecure -> if psender
                            then
                                let
                                    id = if isSender then peerToMsgKnwn sp else peerToMsgUKnwn sp
                                in Comp Cat [id, msg]
                            else msg
    Authentic ->
      if psender
        then
          let
                id = if isSender then peerToMsgKnwn sp else peerToMsgUKnwn sp
          in Comp Cat [ id, Comp Crypt [ Comp Inv [ Comp Apply [Atom "authChCr", id]], msg]]
        else Comp Crypt [Comp Inv [Comp Apply [Atom "authChCr", Atom sender]], msg]
    Confidential ->
      if preceiver
        then
          let id = if isSender
                        then peerToMsgUKnwn rp
                        else peerToMsgKnwn rp
           in Comp Crypt [Comp Apply [Atom "confChCr", id], msg]
        else Comp Crypt [Comp Apply [Atom "confChCr", Atom receiver], msg]
    Secure ->
      if psender
        then
          let ids = if isSender
                        then peerToMsgKnwn sp
                        else peerToMsgUKnwn sp
           in if preceiver
                then error "Secure channel with mutual pseudonymity..."
                else
                  Comp Cat [ ids, Comp Scrypt [ Comp Apply [ Atom "secChCr", Comp Cat [ ids, Atom receiver ]], msg]]
        else
          if preceiver
            then
               let idr = if isSender
                            then peerToMsgUKnwn rp
                            else peerToMsgKnwn rp
               in Comp Scrypt [Comp Apply [ Atom "secChCr", Comp Cat [ Atom sender, idr]], msg]
            else
              Comp Scrypt [ Comp Apply [Atom "secChCr", Comp Cat [Atom sender, Atom receiver]], msg ]
    _ -> error ("chtrafo - unhandled channel type " ++ show ct)

peertrafo :: Peer -> Msg -> ProtocolState -> ProtocolState
peertrafo (_, _, Just _) inmsg _ = error ("Not yet implemented: alternative pseudos in protocol. Msg: " ++ ppMsgOFMC Pretty inmsg)
peertrafo (_, ispseudo, Nothing) inmsg protostate =
  let pseus = (nubOrd . filter (isPrefixOf "Pseudonym") . idents) inmsg
   in if length pseus > 1
        then error ("Too much pseudo in inmsgs=" ++ show inmsg ++ " namely " ++ show pseus)
        else
          if null pseus
            then
              if ispseudo
                then error ("Contact pseudo!" ++ show inmsg)
                else protostate
            else
              let [pseu] = pseus
               in if Atom pseu `elem` map snd protostate
                    then protostate
                    else protostate ++ [(Atom pseu, Atom pseu)]

peerToMsgKnwn :: Peer -> Msg
peerToMsgKnwn (a, False, _) = Atom a
peerToMsgKnwn (a, True, Nothing) = Comp Apply [Atom "pseudonym", Atom a]
peerToMsgKnwn (_, True, Just _) = error "N/A"

peerToMsgUKnwn :: Peer -> Msg
peerToMsgUKnwn (a, False, _) = Atom a
peerToMsgUKnwn (a, True, Nothing) = Atom ("Pseudonym" ++ a)
peerToMsgUKnwn (_, True, Just _) = error "N/A"

lookupL :: Ident -> Knowledge -> [Msg]
lookupL x ([], _) = error ("Initial knowledge of role " ++ show x ++ " not specified.")
lookupL x ((y, k) : ys, ineq) = if x == y then k else lookupL x (ys, ineq)

----- Translation Stage 2: add steps
------------------------------------

rulesAddSteps :: ProtocolTranslationState -> ProtocolTranslationState
-- rulesAddSteps pts| trace ("rulesAddSteps\n" ++ show pts) False = undefined
rulesAddSteps pts =
  let counter inc (State role (player : ids)) (facts, db) =
        ( State role (player : ((\x -> (x, x)) . Atom . show) (db role) : ids) : facts,
          \x -> if x == role then db role + inc else db x
        )
      counter _ fact (facts, db) = (fact : facts, db)
      adds [] _ = []
      adds ((l, [], f, r) : xs) db =
        let (l', db') = foldr (counter 1) ([], db) l
            (r', db'') = foldr (counter 0) ([], db') r
         in (l', [], f, r') : adds xs db''
      adds rules _ = error ("unhandled case in adds" ++ "\nrules: " ++ show rules)
   in pts {rules = adds (rules pts) (const 0)}

---- Translation Stage 3: adding goals
---------------------------------------

addGoals :: ProtocolTranslationState -> ProtocolTranslationState
-- addGoals pts | trace ("addGoals\n" ++ show pts) False = undefined
addGoals pts =
  let rs = rules pts
      eqHackOpt = eqnoexec (options pts)
      eqFuns = eqFunsIF (protocol pts)
      eqHack = not (null eqFuns) && eqHackOpt -- No need to hack if there are no functions used in equations
   in if lversion
        then pts
        else
          let
              (_, _, _, _, _,_, _, _, goals) = protocol pts
              folder (ChGoal (speer@(sender, _, _), channeltype, rpeer@(receiver, _, _)) msg _) rs =
                let (i, pattern) = findFirstKnow rs sender msg 1 eqHack eqFuns -- <paolo-eq>
                    pre = take (i - 1) rs
                    post = drop (i - 1) rs
                    hp@(l, [], f, r) = postRules post rs "addGoals: rs empty list" eqHack  -- <paolo-eq>
                    newfacts = ([Fact "secret" [ pattern, goalpeer False rpeer hp] | channeltype == Secure || channeltype == Confidential || channeltype == FreshSecure])
                            ++ ([Fact "witness" [ goalpeer
                                                  True -- peerToMsgKnwn
                                                  speer hp,
                                                goalpeer
                                                  False -- peerToMsgUKnwn
                                                  rpeer hp,
                                                mkPurpose ( Comp Cat [ goalpeer True rpeer hp2, goalpeer False speer hp2, msg]), pattern] | channeltype == Secure || channeltype == Authentic || channeltype == FreshAuthentic || channeltype == FreshSecure]
                           )
                    tp = tailRules post eqHack -- <paolo-eq>
                    rs' = pre ++ [(l, [], f, newfacts ++ r)] ++ tp
                    (i2, pat) = findLastKnow rs' receiver msg 1 Nothing eqHack eqFuns -- <paolo-eq>
                    pre2 = take (i2 - 1) rs'
                    post2 = drop (i2 - 1) rs'
                    hp2@(l2, [], f2, r2) = postRules post2 rs' "addGoals: rs' empty list" eqHack  -- <paolo-eq>
                    newfacts' =
                      ( if channeltype == FreshSecure || channeltype == FreshAuthentic
                          then [Fact "request" [ goalpeer
                                                    True -- peerToMsgKnwn
                                                    rpeer
                                                    hp2,
                                                goalpeer
                                                    False -- peerToMsgUKnwn
                                                    speer
                                                    hp2,
                                                    mkPurpose (Comp Cat [ goalpeer True rpeer hp2, goalpeer False speer hp2, msg]), pat, Atom "SID"]]
                          else
                            ([Fact "wrequest" [ goalpeer
                                                  True -- peerToMsgKnwn
                                                  rpeer (head post2),
                                                goalpeer
                                                  False -- peerToMsgUKnwn
                                                  speer (head post2),
                                                  mkPurpose ( Comp Cat [ goalpeer True rpeer hp2, goalpeer False speer hp2, msg ]), pat] | channeltype == Secure || channeltype == Authentic])
                      )
                    tp2 = tailRules post2 eqHack  -- <paolo-eq>   
                    rs2' = pre2 ++ [(l2, [], f2, newfacts' ++ r2)] ++ tp2
                 in rs2'
              folder (Secret msg peers b comment) rs = foldr (folder2 (Secret msg peers b comment)) rs peers
              folder g _ = error ("addGoals:folder - unhandled goal: " ++ show g)
              folder2 (Secret msg (peers :: [Peer]) False _) (peer@(pee, _, _) :: Peer) rs =
                let (i, pattern) = findLastKnow rs pee msg 1 Nothing eqHack eqFuns
                    pre = take (i - 1) rs
                    post = drop (i - 1) rs
                    hp@(l, [], f, r) = postRules post rs "addGoals: rs empty list" eqHack  -- <paolo-eq>      
                    secrecyset = Comp Apply [Atom "secrecyset", Comp Cat [goalpeer False peer hp, Atom "SID", mkPurpose msg]]
                    newfacts =
                      ( Fact "secrets" [pattern, secrecyset]
                          : [ Fact --- was: Atom ("secrecyset(SID)")]):
                                "contains"
                                [ secrecyset, -- was: Atom "secrecyset(SID)",
                                  goalpeer False p hp ] | p <- peers ]
                      )
                    tp = tailRules post eqHack  -- <paolo-eq> 
                    rs' = pre ++ [(l, [], f, newfacts ++ r)] ++ tp
                 in rs'
              -- new stuff: guessable secret (when flag of Secret... is true):
              folder2 (Secret msg (peers :: [Peer]) True _) (peer@(pee, _, _) :: Peer) rs =
                updateAllContain rs pee msg 1 peer peers
              folder2 g _ _ = error ("addGoals: folder2 - unhandled goal: " ++ show g)
           in pts {rules = foldr folder rs goals}

-- <paolo-eq>
-- return a rule, even if first argument is empty
postRules :: [Rule] -> [Rule] -> String -> Bool -> Rule
-- postRules post rs _ eqHack | trace ("postRules\n\tpost:" ++ show post ++ "\n\trs: " ++ show rs ++ "\n\teqHack: " ++ show eqHack) False = undefined
postRules [] [] errMsg True = error errMsg
postRules [] rs _ True = last rs
postRules post _ _ _ = head post

-- simply return an empty tail list
tailRules :: [Rule] -> Bool -> [Rule]
-- tailRules post eqHack | trace ("tailRules\n\tpost:" ++ show post ++ "\n\teqHack: " ++ show eqHack) False = undefined
tailRules [] True = []
tailRules post _ = tail post
-- </paolo-eq>

-- postRules :: [Rule] -> [Rule] -> String -> Bool -> Rule
-- postRules post rs _ eqHack | trace ("postRules\n\tpost:" ++ show post ++ "\n\trs: " ++ show rs ++ "\n\teqHack: " ++ show eqHack) False = undefined
-- postRules post rs errMsg eqHack = if eqHack then case post of          -- <paolo-eq>
--                                                [] -> case rs of 
--                                                        [] -> error errMsg
--                                                        _ -> last rs
--                                                _ -> head post
--                                            else head post  

-- tailRules :: [Rule] -> Bool -> [Rule]
-- tailRules post eqHack | trace ("tailRules\n\tpost:" ++ show post ++ "\n\teqHack: " ++ show eqHack) False = undefined
-- tailRules post eqHack = if eqHack then case post of          -- <paolo-eq>
--                                            [] -> [] 
--                                            _ -> tail post
--                                  else tail post 

mkPurpose :: Msg -> Msg
mkPurpose m = Comp Apply [Atom "typePurpose", let (Atom s) = mkname m in (Atom $ "p" ++ tail s)]

---mkPurpose (Atom m) = Comp Apply [Atom "typePurpose", Atom ("purpose"++m)]
---mkPurpose m = Comp Apply [Atom "typePurpose", Atom "purpose"]

goalpeer :: Bool -> Peer -> Rule -> Msg
goalpeer _ (a, False, Nothing) (_, [], _, _) = Atom a
goalpeer isKnown (a, True, Nothing) _ =
  if isKnown
    then Comp Apply [Atom "pseudonym", Atom a]
    else Atom ("Pseudonym" ++ a)
goalpeer _ (_, True, Just msg) (_, _, _, r) =
  let (State _ msgs) = head r
   in if msg `elem` map snd msgs
        then msg
        else
          let msg' = mkname msg
           in if msg' `elem` map snd msgs
                then msg'
                else error "Pseudo not found!"
goalpeer _ p r  = error ("goalpeer - unhandled peer " ++ show p ++ " in " ++ show r)

getKnow :: [Fact] -> Ident -> Maybe [LMsg]
-- getKnow facts ident | trace ("getKnow\n" ++ "Facts: " ++ show facts ++ "\nIdent: " ++ ident)  False = undefined
getKnow [] _ = Nothing
getKnow ((State player know) : facts) ident = if player == ident then Just know else getKnow facts ident
getKnow (_:fs) ident = getKnow fs ident

getSent :: [Fact] -> [Msg]
-- getSent facts | trace ("getSent\n" ++ "Facts: " ++ show facts)  False = undefined
getSent [] = []
getSent ((Iknows m) : fs) = m : getSent fs
getSent (_ : fs) = getSent fs

findFirstKnow :: [Rule] -> Ident -> Msg -> Int -> Bool -> [Ident] -> (Int, Msg)
-- findFirstKnow rules ident msg i eqHack eqFuns | trace ("findFirstKnow\n\t" ++ "Rules: " ++ show rules ++ "\n\tIdent: " ++ ident ++ "\n\tMsg: " ++ show msg ++ "\n\ti: " ++ show i ++ "\n\teqHack: " ++ show eqHack ++ "\n\teqFuns: " ++ show eqFuns)  False = undefined

-- apparently this is not needed, as we can wait for findLastKnow
-- findFirstKnow [] ident msg i eqHack _ = if eqHack then (i, msg) else error (ppMsgOFMC Pretty msg ++ " is never known by " ++ ppId ident)

findFirstKnow ((_, [], _, r) : rules) ident msg i eqHack eqFuns = case getKnow r ident of
                                                                            Nothing -> findFirstKnow rules ident msg (i + 1) eqHack eqFuns
                                                                            Just know -> maybe (findFirstKnow rules ident msg (i + 1) eqHack eqFuns) (\x -> (i, x)) (synthesisPattern know msg)
findFirstKnow rules ident msg int eqHack eqFuns = error ("findFirstKnow - unhandled case\n" ++
                                                                                        "rules:" ++ show rules ++
                                                                                        "\nident: " ++ ident ++
                                                                                        "\nmsg: " ++ show msg ++
                                                                                        "\ni: " ++ show int ++
                                                                                        "\neqHack: " ++ show eqHack ++
                                                                                        "\neqFuns: " ++ show eqFuns)

findLastKnow :: [Rule] -> Ident -> Msg -> Int -> Maybe (Int, Msg) -> Bool -> [Ident] -> (Int, Msg)
-- findLastKnow rules ident msg i maybe_n_pat eqHack eqFuns | trace ("findLastKnow\n\t" ++ "Rules: " ++ show (length rules) ++ "\n\tIdent: " ++ ident ++ "\n\tMsg: " ++ show msg ++ "\n\ti: " ++ show i ++ "\n\tnpat: " ++ show maybe_n_pat ++ "\n\teqHack: " ++ show eqHack ++ "\n\teqFuns: " ++ show eqFuns)  False = undefined

-- with eqHack enabled, it delegates the decision to addGoals function if no more rules are available. if msg is composable the hack should work
findLastKnow [] ident msg i Nothing eqHack _ = if eqHack then (i, msg) else error (ppMsgOFMC Pretty msg ++ " is never known by " ++ ppId ident)

findLastKnow [] _ _ _ (Just (n, pat)) _ _ = (n, pat)
findLastKnow ((_, [], _, r) : rules) ident msg i maybe_n_pat eqHack eqFuns = case getKnow r ident of
                                                                                        Nothing -> findLastKnow rules ident msg (i + 1) maybe_n_pat eqHack eqFuns
                                                                                        Just know -> maybe
                                                                                            (findLastKnow rules ident msg (i + 1) maybe_n_pat eqHack eqFuns)
                                                                                            (\x -> findLastKnow rules ident msg (i + 1) (Just (i, x)) eqHack eqFuns)
                                                                                            (synthesisPattern know msg)
findLastKnow rules ident msg i maybe_n_pat eqHack eqFuns = error ("findLastKnow - unhandled case\n" ++
                                                                                        "rules:" ++ show rules ++
                                                                                        "\nident: " ++ ident ++
                                                                                        "\nmsg: " ++ show msg ++
                                                                                        "\ni: " ++ show i ++
                                                                                        "\nnpat: " ++ show maybe_n_pat ++
                                                                                        "\neqHack: " ++ show eqHack ++
                                                                                        "\neqFuns: " ++ show eqFuns)

updateAllContain :: [Rule] -> Ident -> Msg -> Int -> Peer -> [Peer] -> [Rule]
updateAllContain [] _ _ _ _ _ = []
updateAllContain ((l, [], f, r) : rules) ident msg i peer peers =
  ( case getKnow r ident of -- is this a rule for the specified peer ident?
      Nothing -> (l, [], f, r) -- no
      Just know ->
        -- yes, the local knowledge is know
        case filter (\(x, _) -> x == msg) know of -- check for msg in the patterns
          [] -> (l, [], f, r) -- not there, so skip
          ((_, m) : _) ->
            -- the concrete message is m, see if that is contained in the sent messages
            -- let ms = filter (hasSubterm m) $ getSent r
            let sent = getSent r
                -- ms0 = map (replaceST (Atom "guessPW") m) sent
                ms = concatMap (supertopcheckerbunny m) sent -- ms0 \\ sent
                secrecyset =
                  Comp
                    Apply
                    [ Atom "guessSecrecyset",
                      Comp Cat [goalpeer False peer (l, [], f, r), Atom "SID", mkPurpose msg]
                    ]
                newfacts =
                  if null ms
                    then []
                    else
                      [Fact "guessChal" [m, secrecyset] | m <- ms]
                          ++ [ Fact "contains" [secrecyset, goalpeer False p (l, [], f, r)] | p <- peers]
             in (l, [], f, r ++ newfacts)
  )
    : updateAllContain rules ident msg (i + 1) peer peers
updateAllContain _ _ _ _ _ _ = error "unhandled case in updateAllContain"

guessPW :: Msg
guessPW = Atom "guessPW"

supertopcheckerbunny :: Msg -> Msg -> [Msg]
-- stcb pw m  -- for a guessable password and a message that may contain it,
-- return all those messages that would constitute a successful guessing attack on m, replacing pw by guessPW
supertopcheckerbunny pw t =
  case t of
    (Comp Scrypt [k, m]) ->
      let k' = replaceST guessPW pw k
          m' = replaceST guessPW pw m
       in if k' /= k
            then [k']
            else ([Comp Scrypt [k', m'] | m' /= m])
    (Comp Cat [m1, m2]) ->
      let m1' = replaceST guessPW pw m1
          m2' = replaceST guessPW pw m2
       in if m1 /= m1'
            then [m1']
            else ([m2' | m2 /= m2'])
    (Comp Xor _) -> error "Guessing for XOR not implemented"
    _ ->
      let t' = replaceST guessPW pw t
       in ([t' | t' /= t])

replaceST :: Msg -> Msg -> Msg -> Msg
-- replaceST r s t = t[s->r]
replaceST r s t =
  if s == t
    then r
    else case t of
      Comp f ms -> Comp f $ map (replaceST r s) ms
      _ -> t

hasSubterm :: Msg -> Msg -> Bool
hasSubterm m1 m2 = m1 == m2 || case m2 of
                                    Comp _ ms -> any (hasSubterm m1) ms
                                    _ -> False

subtermList :: Msg -> [Msg] -> Bool
subtermList m = any (subterm m)

subterm :: Msg -> Msg -> Bool
subterm m1 m2 = (m1 == m2) || (case m2 of
                    Atom _ -> False
                    Comp _ xs -> subtermList m1 xs
                    _ -> error $ patternMsgError m2 "subterm")

--- Stage 4: Adding the initial state
-------------------------------------

addInit :: [Ident] -> Bool -> ProtocolTranslationState -> ProtocolTranslationState
-- addInit pts| trace ("addInit\n" ++ show pts) False = undefined
addInit eqFuns ifstrictwhere pts =
  let (_,typdec,_,_,knowledge, _, _, _, _) = protocol pts
      args = options pts
      absInit = getinitials knowledge
      jn = numSess args
      n :: Int
      n = fromMaybe (error "Unbounded sessions currently not supported.") jn
      (_, ineq) = knowledge
      (facts0, honest, _, agents0, ik0, ineq') = instantiate ifstrictwhere n absInit ineq 
      facts =
        facts0
          ++ ik0
          ++ getCrypto agents0
      agents = (++) ["i", "A", "B"] agents0
   in pts
        { initial =
            ( if typed args
                then
                   "section types:\n"
                      ++ ppIdList agents
                      ++ ",AnB_A,AnB_B:agent\n"
                      ++ printTypes eqFuns typdec
                      ++ "\n"
               else ""
            )
              ++ "section inits:\n"
              ++ " initial_state init1 :=\n"
              ++ ppFactList IF facts
              ++ concatMap (\x -> " & " ++ ppId x ++ "/=i") honest
              ++ concatMap (\(s, t) -> " & " ++ ppMsgOFMC IF s ++ "/=" ++ ppMsgOFMC IF t) ineq'
              ++ "\n\n"
              ++ "section rules:\n"
        }

getCrypto :: [Ident] -> [Fact]
getCrypto agents =
  map Iknows
    ( Atom "confChCr"
        : Atom "authChCr"
        : Comp Inv [Comp Apply [Atom "authChCr", Atom "i"]]
        : Comp Inv [Comp Apply [Atom "confChCr", Atom "i"]]
        : [ Comp Apply [Atom "secChCr", Comp Cat [Atom "i", Atom other]] | other <- agents \\ ["i"]]
            ++ [ Comp Apply [Atom "secChCr", Comp Cat [Atom other, Atom "i"]] | other <- agents \\ ["i"]]
            ++ [ Comp Apply [Atom "secChCr", Comp Cat [Atom "i", Comp Apply [Atom "pseudonym", Comp Cat [Atom other]]]] | other <- agents \\ ["i"]]
            ++ [ Comp Apply [Atom "secChCr", Comp Cat [Comp Apply [Atom "pseudonym", Comp Cat [Atom other]], Atom "i"]] | other <- agents \\ ["i"]]
    )

printTypes :: [Ident] -> Types -> String
printTypes eqFuns =
  let f (Agent {}, ids) = ppIdList ids ++ ":agent\n"
      f (Number _, ids) = ppIdList ids ++ ":text\n"
      f (SeqNumber _, _) = ""
      f (PublicKey _, ids) = ppIdList ids ++ ":public_key\n"
      f (SymmetricKey _, ids) = ppIdList ids ++ ":symmetric_key\n"
      f (Function _, ids) = let
                                ids1 = ids \\ eqFuns     -- do not print functions used in equations
                            in case ids1 of
                                [] -> ""
                                _ -> ppIdList ids1 ++ ":function\n"
      f (Custom x _, ids) = ppIdList ids ++ ":t_" ++ x ++ "\n"
      f (Untyped _, _) = ""
      f _ = ""
   in concatMap f

getIK0 :: [Fact] -> [Fact]
getIK0 states =
  let f (Atom a) =
        if isVariable a && (a /= "SID")
          then Atom "i"
          else Atom a
      f (Comp o as) = Comp o (map f as)
      f msg = error $ patternMsgError msg "getIK0"  
   in (map (Iknows . f)
          . nubOrd
          . concatMap getMsgs
          . filter (\(State role _) -> isVariable role)
      )
        states

getMsgs :: Fact -> [Msg]
getMsgs (State _ msgs) = map snd msgs
getMsgs (FPState _ msgs) = msgs
getMsgs (Iknows msg) = [msg]
getMsgs (Fact _ msgs) = msgs

getinitials :: Knowledge -> [Fact]
getinitials = map (\(x, y) -> State x (map (\z -> (z, z)) (Atom x : Atom "0" : ((analysis y \\ [Atom x]) ++ [Atom "SID"])))) . fst

instantiate :: Bool -> Int -> [Fact] -> [(Msg, Msg)] -> ([Fact], [Ident], [[Ident]], [Ident], [Fact], [(Msg, Msg)])
instantiate ifstrictwhere n states ineq =
  let nstates = zip states [1 ..]
      inst0 i n (State role msgs) =
        let f (Atom a) =
              if isVariable a && (a /= "SID")
                then Atom (a ++ show i ++ show n)
                else Atom a
            f (Comp o as) = Comp o (map f as)
            f msg = error $ patternMsgError msg "instantiate - inst0"  
            varcheck = nubOrd (concatMap (vars . snd) msgs) \\ nubOrd (filter isVariable (map (\(Atom x) -> x) (filter isAtom (map snd msgs))))
         in if null varcheck
              then insSid n (State role (map (Data.Bifunctor.bimap f f) msgs))
              else
                error ( "Currently not supported:\n " ++ " role " ++ role ++ " does not know " ++ show varcheck ++ "\n"
                      ++ " but functions of " ++  show varcheck  ++ "\n.")
      inst0 _ _ _ = error "uhnandled inst0"
      ik0 i n (State role msgs) =
        let f (Atom a) =
              if isVariable a && (a /= "SID")
                then
                  if a == role
                    then Atom "i"
                    else Atom (a ++ show i ++ show n)
                else Atom a
            f (Comp o as) = Comp o (map f as)
            f msg = error $ patternMsgError msg "instantiate - ik0"  
         in if isVariable role
              then map ((Iknows . f) . snd) msgs
              else []
      ik0 _ _ _ = error "uhnandled ik0"
      ik = nubOrd (concat [ik0 i k f | k <- [1 .. n], (f, i) <- nstates])
      insSid i (State r m) = State r (init m ++ [(\x -> (x, x)) (Atom (show (2 * i)))])
      insSid _ _ = error ""
      instfacts = [inst0 i k f | k <- [1 .. n], (f, i) <- nstates]
      {-
      instineq0 i n (s, t) =
        let f (Atom a) =
              if isVariable a && (a /= "SID")
                then Atom (a ++ show i ++ show n)
                else Atom a
            f (Comp o as) = Comp o (map f as)
         in (f s, f t)
      instineq = [instineq0s i k e | k <- [1 .. n], (_, i) <- nstates, e <- ineq] 
      -} 
      -- <paolo-eq>
      -- implements a stronger notion of where clause where
      -- inequality is applied not only to each agent view, but also globally
      fIneq i n msg = case msg of
                        (Atom a) -> if isVariable a && (a /= "SID")
                            then Atom (a ++ show i ++ show n)
                            else Atom a
                        (Comp o as) -> Comp o (map (fIneq i n) as)
                        _ -> error $ patternMsgError msg "instantiate - fIneq"  
      instineq0s i1 i2 n1 n2 (s, t) = (fIneq i1 n1 s, fIneq i2 n2 t)
      instineq = let
                    l1 = [1 .. n]                   -- sessions
                    l2 = [ i | (_, i) <- nstates]   -- agents
                    l3 = if ifstrictwhere then 
                            -- considers all combinations of sessins and agents
                            [ (i1,i2,k1,k2) | k1 <- l1, k2 <- l1, i1 <- l2, i2 <- l2 ]
                            else 
                            -- considers only agents views of agents' names    
                            [ (i1,i1,k1,k1) | k1 <- l1, i1 <- l2 ]   
                 in nubOrd [instineq0s i2 i1 k1 k2 e | (i1,i2,k1,k2) <-l3, e <- ineq]
      -- </paolo-eq>
      aglili =
        [ nubOrd [name ++ show i ++ show k | k <- [1 .. n]]
          | (State r msgs, i) <- nstates,
            name <-
              ( filter ((/=) "SID")
                  . filter isVariable
                  . concatMap idents
                  . concatMap getMsgs
              )
                [State r msgs],
            isVariable name
        ]
      honestNames =
        nubOrd
          [ name ++ show i ++ show k
            | (State _ ((_, Atom name) : _), i) <- nstates,
              k <- [1 .. n],
              isVariable name
          ]
      allNames =
        ( nubOrd
            . filter ((/=) "SID")
            . filter isVariable
            . concatMap idents
            . concatMap getMsgs
        )
          instfacts
   in ( instfacts,
        honestNames,
        aglili,
        allNames,
        Iknows (Atom "guessPW") : ik,
        instineq
      )


--- Stage 5: printing the rules
--------------------------------

getTypes :: Protocol -> Types
getTypes (_, t,_, _, _, _, _, _, _) = t

-- <paolo>
ruleList :: AnBOnP -> ProtocolTranslationState -> String
ruleList args pts = ruleListIF (initial pts, rules pts) (trTypes2Ids (getTypes prot) isSeqNumberType) (eqFunsIF prot) args
                    where prot = protocol pts

ruleListIF :: (String, [Rule]) -> [Ident] -> [Ident] -> AnBOnP -> String
-- ruleListIF (init,rules) _ _ _ | trace ("ruleListIF\n" ++ "init: " ++ init ++ "\n" ++ foldr (\a s -> (ppRule IF a ++"\n") ++s ) ""  rules) False = undefined
ruleListIF (init, rules) sqns eqfuns args =
  let ruleIF [] _ = ""
      ruleIF (x : xs) n =
        let -- rule hacked SQN
            nr1 = ppRuleIFHack x sqns
            -- IF2CIF
            nr2 = if if2cif args then ppRuleIF2CIF nr1 else nr1
            -- eqHack
            nr3 = if eqnoexec args then mkRuleEq eqfuns nr2 else nr2
         in "step trans" ++ show n ++ ":=\n" ++ ppRule IF nr3 ++ "\n" ++ ruleIF xs (n + 1)
   in init ++ ruleIF rules 0

ppRuleIF2CIF :: Rule -> Rule
-- ppRuleIF2CIF r | trace ("ppRuleIF2CIF\n\tr: " ++ ppRule IF r) False = undefined
ppRuleIF2CIF (l, eq, f, r) =
  let l1 = map (subfactIF2CIFik subMsgIF2CIF) l
      l2 = map (subfactIF2CIFik subMsgIF2CIFLabel) l1
      r1 = map (subfactIF2CIFik subMsgIF2CIF) r
      r2 = map (subfactIF2CIFik subMsgIF2CIFLabel) r1
   in (l2, eq, f, r2)

subMsgIF2CIF :: Msg -> Msg
-- subMsgIF2CIF m | trace ("subMsgIF2CIF\n\tm: " ++ ppMsgOFMC Pretty m) False = undefined
-- rewrite messages IF/Annotated AnB -> CryptIF
subMsgIF2CIF (Comp Cat (Atom "atag" : [Comp Cat [Atom a, msg]])) = Comp Crypt [Comp Inv [Comp Apply [Atom "sk", Atom a]], msg]
subMsgIF2CIF (Comp Cat (Atom "fatag" : [Comp Cat [Atom a, msg]])) = Comp Crypt [Comp Inv [Comp Apply [Atom "sk", Atom a]], msg]
subMsgIF2CIF (Comp Cat (Atom "ctag" : [Comp Crypt [Comp Apply [Atom "blind", Atom b], msg]])) = Comp Crypt [Comp Apply [Atom "pk", Atom b], msg]
subMsgIF2CIF (Comp Cat (Atom "stag" : [Comp Crypt [Comp Apply [Atom "blind", Atom b], Comp Cat [Atom a, msg]]])) = Comp Crypt [Comp Apply [Atom "pk", Atom b], Comp Crypt [Comp Inv [Comp Apply [Atom "sk", Atom a]], msg]]
subMsgIF2CIF (Comp Cat (Atom "fstag" : [Comp Crypt [Comp Apply [Atom "blind", Atom b], Comp Cat [Atom a, msg]]])) = Comp Crypt [Comp Apply [Atom "pk", Atom b], Comp Crypt [Comp Inv [Comp Apply [Atom "sk", Atom a]], msg]]
subMsgIF2CIF (Comp Cat (Atom "plain" : [Atom msg])) = Atom msg
subMsgIF2CIF (Comp Cat (Atom "ctag" : [Atom msg])) = Atom msg
subMsgIF2CIF (Comp Cat (Atom "stag" : [Atom msg])) = Atom msg
subMsgIF2CIF (Comp Cat (Atom "fstag" : [Atom msg])) = Atom msg
subMsgIF2CIF (Comp Cat [Atom "plain", x]) = x
subMsgIF2CIF (Comp Cat [Atom "ctag", x]) = x
subMsgIF2CIF (Comp Cat [Atom "stag", x]) = x
subMsgIF2CIF (Comp Cat [Atom "fstag", x]) = x
subMsgIF2CIF (Comp Cat (Atom "plain" : xs)) = Comp Cat xs
subMsgIF2CIF (Comp Cat (Atom "ctag" : xs)) = Comp Cat xs
subMsgIF2CIF (Comp Cat (Atom "stag" : xs)) = Comp Cat xs
subMsgIF2CIF (Comp Cat (Atom "fstag" : xs)) = Comp Cat xs
-- subMsgIF2CIF (Comp Crypt [Comp Apply [Atom "blind",_],_]) = Atom "blind"   -- blind cleanup  iknows(pair(stag,crypt(apply(blind,A),pair(B,pair(A,Msg))))) => stateR(... crypt(apply(blind,A),pair(B,pair(A,Msg))),pair(stag,crypt(apply(blind,A),pair(B,pair(A,Msg))))
-- subMsgIF2CIF (Comp op xs) = Comp op (map (\x -> (subMsgIF2CIF x)) xs)
subMsgIF2CIF m = m

{-
replace old new l = join new . split old $ l
join sep [] = []
join sep lists = foldr1 (\ x y -> x++sep++y) lists
split sep list =
  let split0 accword acclist sep [] = reverse ((reverse accword):acclist)
      split0 accword acclist sep list = if isPrefixOf sep list
                                        then split0 "" ((reverse accword):acclist) sep (drop (length sep) list)
                                        else split0 ((head list):accword) acclist sep (tail list)
  in split0 [] [] sep list
-}

subMsgIF2CIFLabel :: Msg -> Msg
-- subMsgIF2CIFLabel (Atom a) | trace ("subMsgIF2CIFLabel\n\tAtom a: " ++ show a) False = undefined
subMsgIF2CIFLabel (Atom a) = Atom (replace "XCryptblind" "XCryptpk" a) -- blind cleanup
subMsgIF2CIFLabel (Comp op xs) = Comp op (map subMsgIF2CIFLabel xs)
subMsgIF2CIFLabel msg = error $ patternMsgError msg "subMsgIF2CIFLabel" 

filterLMsg :: [LMsg] -> [LMsg]
-- filterLMsg msgs | trace ("filterLMsg\n\tmsgs: " ++ show msgs) False = undefined
filterLMsg [] = []
filterLMsg [x] = [x]
filterLMsg (x@(Atom "blind", Atom "blind") : xs) = x : filterLMsg xs
filterLMsg ((Atom "blind", _) : xs) = filterLMsg xs -- blind cleanup
filterLMsg (x : xs) = if elem (snd x) (map snd xs) then xs else x : filterLMsg xs

-- subfactIF2CIF :: Substitution -> Fact -> Fact
---- subfactIF2CIF _ (State r msgs)| trace ("subfactIF2CIF\n\tr: " ++ show r ++ "\n\tmsgs: " ++ show msgs) False = undefined
-- subfactIF2CIF sub (FPState r msgs) = FPState r (Ord(map sub msgs))
-- subfactIF2CIF sub (State r msgs) = let
--                                        msgs1 = filterLMsg (map (\ (x,y)-> (sub x, sub y)) msgs)
--                                   in State r msgs1
-- subfactIF2CIF sub (Iknows msg) = Iknows (sub msg)
-- subfactIF2CIF sub (Fact ident msgs) = Fact ident (nubOrd(map sub msgs))
---- subfactIF2CIF _ f = f

subfactIF2CIFik :: Substitution -> Fact -> Fact
-- subfactIF2CIFIK _ (State r msgs)| trace ("subfactIF2CIFIK\n\tr: " ++ show r ++ "\n\tmsgs: " ++ show msgs) False = undefined
subfactIF2CIFik sub (Iknows msg) = Iknows (sub msg)
subfactIF2CIFik _ f = f

-------------------------------------
endstr :: Bool -> String
endstr noowngoal =
  "section attack_states:\n"
    ++ "  attack_state secrecy :=\n"
    ++ "    secret(AnB_M,AnB_A).\n"
    ++ "    iknows(AnB_M)\n"
    ++ "    & AnB_A/=i\n\n"
    ++ "  attack_state weak_auth :=\n"
    ++ "    request(AnB_A,AnB_B,AnB_PURP,AnB_MSG,SID)\n"
    ++ "    & not(witness(AnB_B,AnB_A,AnB_PURP,AnB_MSG))\n"
    ++ "    & AnB_B/=i\n"
    ++ (if noowngoal then "    & AnB_A/=AnB_B\n\n" else "\n")
    ++ "  attack_state weak_auth :=\n"
    ++ "    wrequest(AnB_A,AnB_B,AnB_PURP,AnB_MSG)\n"
    ++ "    & not(witness(AnB_B,AnB_A,AnB_PURP,AnB_MSG))\n"
    ++ "    & AnB_B/=i\n"
    ++ (if noowngoal then "    & AnB_A/=AnB_B\n\n" else "\n")
    ++ "  attack_state strong_auth :=\n"
    ++ "    request(AnB_A,AnB_B,AnB_PURP,AnB_MSG,SID).\n"
    ++ "    request(AnB_A,AnB_B,AnB_PURP,AnB_MSG,SID2)\n"
    ++ "    & SID/=SID2\n"
    ++ "    & AnB_B/=i\n"
    ++ (if noowngoal then "    & AnB_A/=AnB_B\n\n" else "\n")
    ++ "  attack_state secrets :=\n"
    ++ "    secrets(AnB_M,AnB_SET).\n"
    ++ "    iknows(AnB_M)\n"
    ++ "    & not(contains(AnB_SET,i))\n"
    ++ "  attack_state guesswhat :=\n"
    ++ "    guessChal(AnB_M,AnB_SET).\n"
    ++ "    iknows(AnB_M)\n"
    ++ "    & not(contains(AnB_SET,i))\n"

-- </paolo>

isntIknowsFunction :: Fact -> Bool
isntIknowsFunction (Iknows msg) = isntFunction msg
isntIknowsFunction _ = True

isIknows :: Fact -> Bool
isIknows (Iknows _) = True
isIknows _ = False

reorder :: [Msg] -> [Msg]
reorder l =
  let name = head l
      step = head . tail $ l
      session = last l
      rest = init $ drop 2 l
   in name : session : step : rest

ppFact :: OutputType -> Fact -> String
ppFact Isa (State _ _) = error "State-Fact in ISA mode"
ppFact Isa (FPState role msgs) = "State (r" ++ ppId role ++ ",[" ++ ppMsgListOFMC Isa (filter isntFunction msgs) ++ "])"
ppFact outf (State role msgs) = "state_r" ++ ppId role ++ "(" ++ ppMsgListOFMC outf (reorder (map snd msgs)) ++ ")"
ppFact _ (FPState _ _) = error "ppFact: should not have FPState" --- "state_r" ++ (ppId role) ++ "(" ++ (ppMsgListOFMC outf msgs) ++ ")"
ppFact outf (Iknows msg) = "iknows(" ++ ppMsgOFMC outf msg ++ ")"
ppFact outf (Fact i m) = ppId i ++ "(" ++ ppMsgListOFMC outf m ++ ")"

ppFactList :: OutputType -> [Fact] -> String
ppFactList outf = ppXList (ppFact outf) ".\n" . filter isntIknowsFunction

ppEq :: OutputType -> (Msg, Msg) -> [Char]
ppEq outf (x, y) = ppMsgOFMC outf x ++ "/=" ++ ppMsgOFMC outf y

ppRule :: OutputType -> Rule -> [Char]
ppRule Isa (l, eq, f, r) =
  ppXList (ppFact Isa) ";\n" (filter isntIknowsFunction l)
    ++ "\n"
    ++ (if null eq then "" else " | " ++ ppXList (ppEq Isa) ";\n" eq)
    ++ "\n"
    ++ (if null f then "=>" else error "fresh variable remaining")
    ++ "\n"
    ++ ppXList (ppFact Isa) ";\n" (filter isntIknowsFunction r)
    ++ "\n"
ppRule outf (l, [], f, r) = ppFactList outf l
    ++ "\n"
    ++ (if null f then "=>" else "=[exists " ++ ppIdList f ++ "]=>")
    ++ "\n"
    ++ ppFactList outf r
    ++ "\n"
ppRule outf r = error ("ppRule undefined for OuttypeType " ++ show outf ++ ": " ++ show r)

ppRuleList :: OutputType -> [Rule] -> [Char]
ppRuleList Isa list =
  let
        ppRL Isa (x : xs) c = "step rule_" ++ show c ++ ":\n" ++ ppRule Isa x ++ "\n" ++ ppRL Isa xs (c + 1)
        ppRL Isa [] _ = ""
        ppRL _ _ _ = "" -- ??
   in ppRL Isa list 0
ppRuleList outf list = ppXList (ppRule outf) "\n" list

ppInit :: String -> OutputType -> [Fact] -> String
ppInit str ot list =
  let ppFP0 ot (x : xs) c = str ++ "_" ++ show c ++ ": " ++ ppFact ot x ++ ";\n" ++ ppFP0 ot xs (c + 1)
      ppFP0 _ [] _ = ""
   in ppFP0 ot (filter isntIknowsFunction list) 0

ppFP :: String -> OutputType -> [Fact] -> String
ppFP str ot list =
  let ppFP0 ot (x : xs) c = str ++ "_" ++ show c ++ ": " ++ ppFact ot x ++ ";\n" ++ ppFP0 ot xs (c + 1)
      ppFP0 _ [] _ = ""
   in ppFP0 ot list 0

subfact :: Substitution -> Fact -> Fact
subfact sub (FPState r msgs) = FPState r (map sub msgs)
subfact sub (State r msgs) = State r (map (Data.Bifunctor.bimap sub sub) msgs)
subfact sub (Iknows msg) = Iknows (sub msg)
subfact sub (Fact ident msgs) = Fact ident (map sub msgs)

subrule :: Substitution -> ([Fact], [(Msg, Msg)], c, [Fact]) -> ([Fact], [(Msg, Msg)], c, [Fact])
subrule sub (l, eq, f, r) =
  ( map (subfact sub) l,
    map (Data.Bifunctor.bimap sub sub) eq,
    f,
    map (subfact sub) r
  )

-- <Paolo> --
-- hack to handle sequence numbers

-- sample
--  A *->B : sn(N,B),Msg
--  L => R
--  where sn(X,Y) occuring in L.
--  L . not(contains(X,seen(B)))  => R.contains(X,seen(B)))

-- example
-- step trans1:=
-- state_rB(B,0,inv(apply(sk,B)),inv(apply(pk,B)),sk,pk,A,SID).
-- iknows(crypt(inv(apply(sk,A)),pair(B,pair(SQN,Msg)))).not(contains(SQN,seen(B)))
-- =>
-- request(B,A,purposeMsg,Msg,SID).
-- state_rB(B,1,inv(apply(sk,B)),inv(apply(pk,B)),sk,pk,A,Msg,SQN,crypt(inv(apply(sk,A)),pair(B,pair(SQN,Msg))),SID).contains(SQN,seen(B))

ppRuleIFHack :: Rule -> [Ident] -> Rule
-- apply sqn hack [Ident]=list of SQNs
ppRuleIFHack ([], [], f, r) _ = ([], [], f, r)
ppRuleIFHack (l, [], f, r) sqns =
  let a = getRule2Agent l
      sqnList = nubOrd (getFacts2SQN l sqns)
      nl = l ++ map (\x -> notcsterm x a) sqnList
      nr = r ++ map (\x -> csterm x a) sqnList
   in (nl, [], f, nr)
ppRuleIFHack _ _ = error "Sequence Number translation error"

getRule2Agent :: [Fact] -> Ident
getRule2Agent xs = getFact2Agent (head xs)

getFact2Agent :: Fact -> Ident
getFact2Agent f = case f of
  State id _ -> id
  _ -> ""

-- retuns a list of SQNs
getFacts2SQN :: [Fact] -> [Ident] -> [Ident]
getFacts2SQN [] _ = []
getFacts2SQN (x : xs) sqns = getFact2SQN x sqns ++ getFacts2SQN xs sqns

getFact2SQN :: Fact -> [Ident] -> [Ident]
getFact2SQN f sqns = case f of
  State _ _ -> []
  FPState _ _ -> []
  Fact _ _ -> []
  Iknows m -> getMsg2SQN m sqns

getMsg2SQN :: Msg -> [Ident] -> [Ident]
getMsg2SQN (Atom id) sqns = [id | elem id sqns]
getMsg2SQN (Comp _ []) _ = []
getMsg2SQN (Comp _ (m : ms)) sqns = getMsg2SQN m sqns ++ getMsgs2SQN ms sqns
getMsg2SQN msg _ = error $ patternMsgError msg "getMsg2SQN" 

getMsgs2SQN :: [Msg] -> [Ident] -> [Ident]
getMsgs2SQN [] _ = []
getMsgs2SQN (m : ms) sqns = getMsg2SQN m sqns ++ getMsgs2SQN ms sqns

-- SQN, AgentName .contains(SQN,seen(B))
csterm :: Ident -> Ident -> Fact
csterm sqn agent = Fact "contains" [Atom sqn, Comp (Userdef "seen") [Atom agent]]

-- SQN, AgentName .not(contains(SQN,seen(B)))
notcsterm :: Ident -> Ident -> Fact
notcsterm sqn agent = Fact "not" [Comp (Userdef "contains") [Atom sqn, Comp (Userdef "seen") [Atom agent]]]

-- adjust the Types to translate the SQNs in Numbers
trAdjTypes :: Types -> (Type -> Bool) -> Type -> Types
trAdjTypes t is_from_t to_t =
  let idents = trTypes2Ids t is_from_t
      t1 = trTypesMoveIds t is_from_t idents to_t
   in t1

-- extract the list of ids from Type
-- used in preprocessing of Protocol

trTypes2Ids :: Types -> (Type -> Bool) -> [Ident]
trTypes2Ids [] _ = []
trTypes2Ids types t = concatMap snd (filter (\(x, _) -> t x) types)

trTypesMoveIds :: Types -> (Type -> Bool) -> [Ident] -> Type -> Types
trTypesMoveIds [] _ _ _ = []
trTypesMoveIds t _ [] _ = t
trTypesMoveIds (x : xs) is_from_t idents to_t = trTypeMoveIds x is_from_t idents to_t : trTypesMoveIds xs is_from_t idents to_t

trTypeMoveIds :: (Type, [Ident]) -> (Type -> Bool) -> [Ident] -> Type -> (Type, [Ident])
trTypeMoveIds (t, idents) is_from_t idents1 to_t | t == to_t = (t, nubOrd (idents ++ idents1))
                                              | is_from_t t = (t, [])
                                              | otherwise = (t, idents)

-- </paolo> --