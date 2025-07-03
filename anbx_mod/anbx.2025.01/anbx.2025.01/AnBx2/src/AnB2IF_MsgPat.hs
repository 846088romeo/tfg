{-

 AnBx Compiler and Code Generator

 Copyright 2023-2025 Paolo Modesti
 Copyright 2023-2024 SCM/SCDT/SCEDT, Teesside University

Code adapted from the MsgPat.hs file of the
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

-- slightly modified OFMC code, adding OFMC suffix to function names that may clash with existing functions

-------- Msg Patterns ------------------------------------

module AnB2IF_MsgPat(ProtocolState,mkname,initialState,receiveMsg,sendMsg,receiveLMsg,lversion,synthesisPattern,replacePat) where
import AnB2IF_LMsg ( LMsg, zipl, lanalysis, mkname )
import AnB2IF_Msg
import Data.List ( (\\) )
import Data.Maybe
import AnB2IF_Common
import AnBxMsg ( AnBxMsg (Comp,Atom), patternMsgError)
import Debug.Trace (trace)


-- | The type @ProtocolState@ characterizes the local state of an
-- honest agent in a protocol execution by a set of labeled messages,
-- i.e. the form the messages are supposed to have according to the
-- AnB specification and the actual view on that form that the agent
-- in question has.
type ProtocolState = [LMsg]

-- | Pretty printing labeled messages
ppLMsg :: OutputType -> (Msg, Msg) -> [Char]
ppLMsg _ (Atom x,Atom y) = ppId x ++ "%" ++ ppId y
ppLMsg ot (m, Atom y) = ppMsgOFMC ot m ++ "%" ++ ppId y
ppLMsg ot (Comp f xs, Comp _ ys) =
  let zs = zipl xs ys in
  case f of
  Cat -> ppLMsgList ot zs
  Apply -> ppLMsg ot (head zs) ++ "(" ++ ppLMsgList ot (tail zs) ++ ")"
  Crypt -> "{" ++ ( ppLMsg ot . head . tail) zs ++"}" ++ ppLMsg ot (head zs)
  Scrypt ->  "{|" ++ ( ppLMsg ot . head . tail) zs ++ "|}" ++ ppLMsg ot (head zs)
  _ -> show f ++ "(" ++ ppLMsgList ot zs ++ ")"
ppLMsg _ (_, _) = error ""

-- | Print a list of labeled messages
ppLMsgList :: OutputType -> [LMsg] -> String
ppLMsgList Pretty = ppXList (ppLMsg Pretty) "\n"
ppLMsgList ot = ppXList (ppLMsg ot) ","

-- | switch for an experimental version
lversion :: Bool
lversion = False

--- internal function -- | This function is initially used to get a labeling for messages
mklabel :: Msg -> LMsg
mklabel x = (x,mkname x)

-- | generate the initial state of a local agent from its knowledge specification
initialState :: [Msg] -> ProtocolState
initialState ik0 =
 if lversion then ((\(x,y) -> x ++ y) . lanalysis . map mklabel) ik0 else
                                                                        let ik = analysis ik0 in
                                                                        map (\ x -> (x,reshape ik x)) ik

-- | compute the new protocol state of an agent that corresponds to
-- the reception of a new message. This is typically used for the LHS
-- state-fact of an honest agent in a transition rule: given the state
-- after the last transition rule (a list of labeled messages) and the
-- newly received message (without label), compute the labeled
-- messages for the state-fact of the LHS.
receiveMsg :: Msg -> ProtocolState -> ProtocolState
receiveMsg msg state =
  if lversion then
   let (m':ik0,new) = lanalysis ((msg,reshape (map fst state) msg):state)
   in ik0 ++ new ++ [m']
 else
  let ik0 = map fst state
      ik  = analysis (msg:ik0)
      nik = ik \\ (msg:ik0)
  in
  map (\(m,p) -> (m,reshapePat ("In receiveMsg\n" ++ show msg ++ "\n" ++ show state) ik (m,p))) state
  ++ map (\ msg -> (msg, reshape ik msg)) nik
  ++ [(msg,reshape ik msg)]

--- possible improvement: only the incoming message is stored, not
--- all the other messages from NIK. Note that some functions rely
--- on an analyzed intruder knowledge.
reshape :: [Msg] -> Msg -> Msg
reshape _ (Atom a) = Atom a
reshape ik msg@(Comp f xs) =
 if f==Exp || f==Xor then
  case
   [(f',xs') |
   (Comp f' xs') <- eqMod  eqModBound stdTheo [msg], f==f',
   all (indy ik) xs']
  of
  [] -> mkname msg
  ((f',xs'):_) -> Comp f' (map (reshape ik) xs')
 else
  case opening msg of
  Nothing ->  error "Invariant violation (Nothing in reshape)"
  Just list -> if all (indy ik) list
               then Comp f (map (reshape ik) xs)
               else mkname msg
reshape _ msg = error $ patternMsgError msg "reshape"  
   
showik :: [Msg] -> String
showik = ppXList (ppMsgOFMC IF) "\n"

reshapePat :: String -> [Msg] -> LMsg -> Msg

reshapePat str ik m =
 case m of
 (Comp Apply _,Comp Cat _) -> error ("Incompatible reshape pattern: " ++str)
 _ ->
  case reshapePat0 ik m of
  Nothing -> error ("Pattern Problem:\n" ++ showik ik ++"\n->\n" ++ ppLMsg Pretty m ++" ")
  Just p -> p

reshapePat0 :: [Msg] -> LMsg -> Maybe Msg
reshapePat0 _ (Atom a,Atom b)=
  if a==b then Just (Atom a) else Nothing
reshapePat0 _ (Atom a,Comp f xs) =
  error ("Pattern " ++ show (Comp f xs) ++ " more concrete than actual msg " ++ a)
reshapePat0 ik (msg@(Comp f xs),Atom a) =
 if f==Xor then if all (indy ik) xs then Just (Comp Xor (map (reshape ik) xs)) else Just (Atom a) else
  case opening msg of
  Nothing -> error "Invariant violated: Nothing in reshape"
  Just list -> if all (indy ik) list
               then Just (Comp f (map (reshape ik) xs))
               --- here we need to go into classical reshape as
               --- further pattern is not yet available
               else Just (Atom a)
               --- get the old pattern
reshapePat0 ik (msg@(Comp Apply _),pat@(Comp Cat _)) = error ("Incompatible patterns:\n" ++ show ik ++ "\n" ++ show msg ++"\n" ++ show pat)
reshapePat0 ik (msg@(Comp f xs),pat@(Comp g ys))
 |f==Apply && g==Cat = error "Super duper strange."
 |otherwise =
  if msg==pat then Just pat else
  if f==Exp || f==Xor then
    listToMaybe
     [ Comp g xs'' | (Comp f' xs') <- eqMod eqModBound stdTheo [msg], f==f', xs'' -- ::[ Msg]
                                   <- [mapMaybe (reshapePat0 ik) (zipl xs' ys)], length xs'' == length xs]
  else
   if f==g then
    let test = zipl xs ys in
    if not (any (\ x -> case x of
                            (Comp Apply _, Comp Cat _) -> True
                            _ -> False) test) then
      deJust f (mapM (reshapePat0 ik) (zipl xs ys))
    else error ("Show :\n" ++ show msg ++"\n" ++ show msg)
   else if f==Apply && g==Cat then error "It is apply and Cat"
   else error ("Patterns do not completely agree:\n\n" ++ show msg ++ "\n\nvs.\n\n" ++ show pat)
reshapePat0 _ (msg1,msg2) = error $ patternMsgError msg1 "reshapePat0" ++ "\n" ++ patternMsgError msg2 "reshapePat0"  
   
deJust :: Operator -> Maybe [Msg] -> Maybe Msg
deJust f (Just ms) = Just (Comp f ms)
deJust _ Nothing = Nothing

opening :: Msg -> Maybe [Msg]
opening msg =
  case msg of
  Comp Crypt [Comp Inv [k],_] -> Just [k]
  Comp Crypt [k,_] -> Just [Comp Inv [k]]
  Comp Scrypt [k,_]-> Just [k]
  Comp Cat _ -> Just []
  Comp Inv [_] -> Just []
  Comp Apply ms -> Just ms
  Comp Exp ms -> Just ms
  Comp Xor _ -> error "Opening: didn't cach XOR"
  _ -> error ("Opening: Not yet supported: " ++ show msg)

--- Note: when using probabilistic encryption, we actually  cannot check that
--- {M}K has form {.}. even if we know M and K, but not inv(K).
--- We leave it, though, as probabilistic encryption must be modeled
--- by explicit nonces (introduced by AnBParser).

-----------------------

-- | Counterpart to receiveMsg: given a message to be sent (according
-- to the protocol specification) and the current execution state as a
-- list of labeled messages, check that, and how, this sendendum can
-- be generated and add it with appropriate label to the protocol state.
sendMsg :: Msg -> ProtocolState -> ProtocolState
sendMsg msg state =
  case synthesisPattern state msg of
  Nothing -> error ("Protocol not executable:\n\n" ++
                    "At the following state of the knowledge:\n" ++
                    ppLMsgList Pretty state++"\n\n" ++
                    "...one cannot compose the following message:\n" ++
                    ppMsgOFMC Pretty msg++"\n" ++
                    getProblem state msg ""
                   )
  Just p -> state++[(msg,p)]

getProblem :: ProtocolState -> Msg -> String -> String
getProblem _ (Atom _) _ = ""
getProblem ik (Comp _ xs) ind = concat [ ind ++ ppMsgOFMC Pretty x ++"\n" ++ getProblem ik x (ind ++ "|") | x <- xs, isNothing (synthesisPattern ik x) ]
getProblem _ msg _ = error $ patternMsgError msg "getProblem"   

-- | Given a protocol state and an unlabled message (on AnB level) to
-- compose, check if that is possible, and if so, give a label for that. 
synthesisPattern :: ProtocolState -> Msg -> Maybe Msg
-- synthesisPattern pts | trace ("synthesisPattern\n\tProtocol State: " ++ show pts) False = undefined
synthesisPattern ik =
  listToMaybe .
  mapMaybe (synthesisPattern0 ik) . eqMod 3 stdTheo .
  return

synthesisPattern0 :: ProtocolState -> Msg -> Maybe Msg
-- synthesisPattern0 pts msg | trace ("synthesisPattern0\n\tmsg: " ++ show msg ++ "\n\tpts: " ++ show pts) False = undefined
synthesisPattern0 ik m =
  case getElem m ik of
  Just p -> Just p
  Nothing ->
   case m of
    Atom _             -> Nothing
    Comp Inv _         -> Nothing
    Comp (Userdef _) _ -> error ("Not yet supported: " ++ show m)
    Comp Xor list      ->
     let ik0=map fst ik in
     if synthesizable ik0 m then
      if all (synthesizable ik0) list then
        Just (Comp Xor (map (fromJust . synthesisPattern0 ik) list))
      else
        -- <paolo-eq>
        let 
            lsxor = [ Just (normalizeXor (mkxor d1 d2)) | 
                        (Comp Xor l1,d1) <- ik,
                        (Comp Xor l2,d2) <- ik,
                        l1/=l2,
                        m==normalizeXor (Comp Xor (l1++l2))]
        in if null lsxor then Nothing else head lsxor
        -- <paolo-eq>
     else Nothing
    Comp f ms ->
        let mps = map (synthesisPattern0 ik) ms
        in if Nothing `elem` mps then Nothing
            else Just (Comp f (map fromJust mps))
    _-> error $ patternMsgError m "synthesisPattern0"

replacePat :: ProtocolState -> Msg -> [Msg]
replacePat _ m = [m]

mkxor :: Msg -> Msg -> Msg
mkxor (Comp Xor l1) (Comp Xor l2) = Comp Xor (l1++l2)
mkxor (Comp Xor l1) b = Comp Xor (b:l1)
mkxor a (Comp Xor l2) = Comp Xor (a:l2)
mkxor a b = Comp Xor [a,b]

getElem :: Eq t => t -> [(t, a)] -> Maybe a
getElem _ [] = Nothing
getElem x ((m,p):mps) = if x==m then Just p else getElem x mps

-------------------

enlabel :: (Msg, Msg) -> (Msg, Msg)
enlabel (Atom a,Atom b) = (Atom a,Atom b)
enlabel (Comp f xs, Comp g ys) =
                            if f/=g || length xs /= length ys then error "error in function enlabel" else
                            let (xs',ys') = unzip (map enlabel (zipl xs ys))
                            in (Comp f xs', Comp g ys')
enlabel (Comp f xs,Atom b) = (Comp f xs,mkname (Atom b))
enlabel x = error ("error in function enlabel: " ++ show x)

-- | Variant of receiveMsg when pattern for the received message is
-- given (for modeling zero-knowledge proofs).
receiveLMsg :: LMsg -> ProtocolState -> ProtocolState
-- receiveLMsg  msg state | trace ("receiveLMsg\n" ++ "LMsg: " ++ show msg ++ "\n" ++ "State: " ++  show state) False = undefined
receiveLMsg (msg,msgp) state =
 if lversion then
   let (m':ik0,new) = lanalysis (enlabel (msg,msgp):state)
   in (ik0++new++[m'])
 else
  let ik0  = map fst state
      ik   = analysis (msg:ik0)
      nik  = ik \\ ik0
  in
  map (\ (m,p) -> (m,reshapePat "" ik (m,p))) state
  ++ reshapePatAna (msg,msgp) (nik\\[msg])
  ++ [(msg,reshapePat "" ik (msg,msgp))]

reshapePatAna :: LMsg -> [Msg] -> [LMsg]
reshapePatAna (msg,msgp) ik =
  let mmap = allposL (msg,msgp)
      lookup m = let mp = [ p | (m',p) <- mmap, m==m'] in
                 if null mp then error ("did not find " ++ ppMsgOFMC Pretty m ++ "\n" ++ "mmap: " ++ show mmap) else head mp
  in map (\m -> (m,lookup m)) ik

allposL :: LMsg -> [LMsg]
allposL mp@(Comp f xs, Comp g ys) =
 if f==g then mp:concatMap allposL (zipl xs ys)
 else error ("Pattern problem:\n" ++ show f ++ "\nvs\n" ++ show g)
allposL mp = [mp]
