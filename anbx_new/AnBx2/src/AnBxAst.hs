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

--{-# LANGUAGE OverlappingInstances #-}
{-# LANGUAGE InstanceSigs #-}

module AnBxAst where
import AnBxMsg
import AnBxMsgCommon
import Data.Char
import Data.Containers.ListUtils (nubOrd)

----------- Protocol Description --------------

type ProtName = (Ident,ProtType)

type AnBxKnowledge = (AnBxKnowledgeAgents,AnBxKnowledgeWhere)
type AnBxProtocol = (ProtName,AnBxTypes,AnBxDefinitions,AnBxEquations,AnBxKnowledge,AnBxShares,AnBxAbstraction,AnBxActions,AnBxGoals)

data AnBxType =   Agent Bool Bool TypeOpts Certified -- ^ flags: static, honest; both currently unused, flag certified used only by AnBx files
                | Number TypeOpts             -- ^ aka nonce
                | SeqNumber TypeOpts          -- ^ aka sequence number
                | PublicKey TypeOpts
                | SymmetricKey TypeOpts
                | Function TypeOpts           -- ^ for free user-defined function symbols (with type specification)
                | Purpose TypeOpts            -- ^ special type for the purpose-argument of witness and request facts
                | Custom String TypeOpts      -- ^ Now allowing users to introduce their custom types
                | Untyped TypeOpts            -- ^ default for constants/variables that do not have a type declaration 
                deriving (Ord)
                --- <AnBx Mod> ---
        --          | Certified                   -- Certified Agents (used in AnBx to set the flag in Agent declaration)
                                                  -- no longer needed, handled by the parser  
                --- <AnBx Mod> ---

instance Eq AnBxType where
        (==) :: AnBxType -> AnBxType -> Bool
        t1 == t2 = eqTypes t1 t2

instance Show AnBxType where
        show :: AnBxType -> String
        show = showSpecType PTAnBx

-- extended types for typechecking
data AnBType =
               BaseType AnBxType
               | TCat [AnBType]
               | TPrivateKey
               | THash
               | THMac
               | TCrypt AnBType
               | TScrypt AnBType
               deriving (Eq,Ord)

instance Show AnBType where
        show :: AnBType -> String
        show = showSpecAnBType

showSpecAnBType :: AnBType  -> String
showSpecAnBType (BaseType t) = show t
showSpecAnBType (TCat xs) = "TCat[" ++ ppXList show "," xs ++ "]"
showSpecAnBType TPrivateKey = "TPrivateKey"
showSpecAnBType THash = "THash"
showSpecAnBType THMac = "THMac"
showSpecAnBType (TCrypt t) = "TCrypt" ++ "[" ++ showSpecAnBType t ++ "]"
showSpecAnBType (TScrypt t) = "TScrypt" ++ "[" ++ showSpecAnBType t ++ "]"

type TypeOpts = [TO]
data TO =  Option (Ident,AnBxMsg)   -- currently unhandled
         | FunSign ([AnBxType],AnBxType,PrivateFunction)
    deriving (Eq,Ord)

instance Show TO
            where 
                show :: TO -> String
                show (Option (ident,msg)) = ident ++ "=" ++ show msg
                show (FunSign (ts,t2,priv)) = ppIdList (map show ts) ++ " " ++ show priv ++ " " ++ show t2

isAgentCertified :: AnBxType -> Bool
isAgentCertified (Agent _ _ _ Cert) = True
isAgentCertified _ = False

isNumberType :: AnBxType -> Bool
isNumberType (Number {}) = True
isNumberType _ = False

agentDefaultType :: AnBxType
agentDefaultType = Agent False False [] NoCert

isAgentType :: AnBxType -> Bool
isAgentType (Agent{}) = True
isAgentType _ = False

isFunctionType :: AnBxType -> Bool
isFunctionType (Function {}) = True
isFunctionType _ = False

isPublicKeyType :: AnBxType -> Bool
isPublicKeyType (PublicKey {}) = True
isPublicKeyType _ = False

isSeqNumberType :: AnBxType -> Bool
isSeqNumberType (SeqNumber {}) = True
isSeqNumberType _ = False

showSpecType :: ProtType -> AnBxType -> String
showSpecType _ (Agent False False [] _) = "Agent"
showSpecType _ (Agent _ _ [] _) = "Agent"
showSpecType _ (Agent _ _ op _) = "Agent " ++ showTypeOpts op
showSpecType PTAnB (SymmetricKey _) = "Symmetric_key"
showSpecType _ (SymmetricKey []) = "SymmetricKey"
showSpecType _ (SymmetricKey op) = show (SymmetricKey []) ++ " " ++ showTypeOpts op
showSpecType _ (PublicKey []) = "PublicKey"
showSpecType _ (PublicKey op) = show (PublicKey []) ++ " " ++ showTypeOpts op
showSpecType PTAnB (Function _) = "Function"
showSpecType _ (Function []) = "Function"
showSpecType _ (Function op) = show (Function []) ++ " " ++ showTypeOpts op
showSpecType _ (Number []) = "Number"
showSpecType _ (Number op) = show (Number []) ++ " " ++ showTypeOpts op
showSpecType _ (SeqNumber []) = "SeqNumber"
showSpecType _ (SeqNumber op) = show (SeqNumber []) ++ " " ++ showTypeOpts op
showSpecType _ (Untyped []) = "Untyped"
showSpecType _ (Untyped op) = show (Untyped []) ++ " " ++ showTypeOpts op
showSpecType _ (Purpose []) = "Purpose"
showSpecType _ (Purpose op) = show (Purpose []) ++ " " ++ showTypeOpts op
showSpecType _ (Custom t []) = t
showSpecType _ (Custom t op) = show (Custom t []) ++ " " ++ showTypeOpts op

eqTypes :: AnBxType -> AnBxType -> Bool
eqTypes Agent {} Agent {} = True
eqTypes Number {} Number {} = True
eqTypes SeqNumber {} SeqNumber {} = True
eqTypes PublicKey {} PublicKey {} = True
eqTypes SymmetricKey {} SymmetricKey {} = True
eqTypes Function {} Function {} = True
eqTypes Purpose {} Purpose {} = True
eqTypes Untyped {} Untyped {} = True
-- eqTypes Certified Certified = True
eqTypes (Custom t1 _) (Custom t2 _) = t1==t2
eqTypes _ _ = False

eqTypesStrict :: AnBxType -> AnBxType -> Bool
eqTypesStrict (Agent p1 p2 o1 c1) (Agent p3 p4 o2 c2) = (p1==p3) && (p2==p4) && (o1==o2) && (c1==c2)
eqTypesStrict (Number o1) (Number o2) = o1==o2
eqTypesStrict (SeqNumber o1) (SeqNumber o2) = o1==o2
eqTypesStrict (PublicKey o1) (PublicKey o2) = o1==o2
eqTypesStrict (SymmetricKey o1) (SymmetricKey o2) = o1==o2
eqTypesStrict (Function o1) (Function o2) = o1==o2
eqTypesStrict (Purpose o1) (Purpose o2) = o1==o2
eqTypesStrict (Untyped o1) (Untyped o2) = o1==o2
eqTypesStrict (Custom t1 o1) (Custom t2 o2) = t1==t2 && o1==o2
eqTypesStrict _ _ = False

elemTypes :: AnBxType -> [AnBxType] -> Bool
elemTypes _ [] = False
elemTypes x (y:ys)
                | eqTypesStrict x y  = True
                | otherwise = elemTypes x ys

showTypeOpts :: TypeOpts -> String
showTypeOpts [] = ""
showTypeOpts [x] = "[" ++ show x ++ "]"
showTypeOpts (x:xs) = "[" ++ show x ++ "," ++ showTypeOpts xs ++ "]"

getIds :: [(a, [Ident])] -> (a -> Bool) -> [Ident]
getIds xs f = [ident | (t1, idents) <- xs, f t1, ident <- idents]

--- <AnBx Mod> ---
data AnBxDefinition = Def AnBxMsg AnBxMsg
          deriving (Eq,Show)

type AnBxDefinitions = [AnBxDefinition]

data AnBxEquation = Eqt AnBxMsg AnBxMsg
          deriving (Eq,Show,Ord)

type AnBxEquations = [AnBxEquation]
type AnBxEqTheory = (AnBxTypes,AnBxEquations)

-- built in equational theories 
-- these are just examples, as EXP (DH) and XOR are already hardcoded and supported
-- for potential future expansion

expTheory :: AnBxEqTheory
expTheory = ([(Number [],["g","X","Y"]),(Function [FunSign ([Number [],Number []],Number [],PubFun)],[show AnBxKap]),(Function [FunSign ([Number [],Number []],SymmetricKey [],PubFun)],[show AnBxKas])],
             [Eqt (Comp Apply [Atom (show AnBxKas),Comp Cat [Comp Apply [Atom (show AnBxKap),Comp Cat [Atom "g",Atom "X"]],Atom "Y"]]) (Comp Apply [Atom (show AnBxKas),Comp Cat [Comp Apply [Atom (show AnBxKap),Comp Cat [Atom "g",Atom "Y"]],Atom "X"]])])

expTheoryExp :: AnBxEqTheory
expTheoryExp = ([(Number [],["g","X","Y"]),(Function [FunSign ([Number [],Number []],Number [],PubFun)],[show AnBxExp])],
             [Eqt (Comp Apply [Atom (show AnBxExp),Comp Cat [Comp Apply [Atom (show AnBxExp),Comp Cat [Atom "g",Atom "X"]],Atom "Y"]]) (Comp Apply [Atom (show AnBxExp),Comp Cat [Comp Apply [Atom (show AnBxExp),Comp Cat [Atom "g",Atom "Y"]],Atom "X"]])])

xorTheory :: AnBxEqTheory
xorTheory = ([(Number [],["X","Y"]),(Function [FunSign ([Number [],Number []],Number [],PubFun)],["xor"])],[]) -- no equations defined yet

buildInEqTheories :: [AnBxEqTheory]
buildInEqTheories = []

type AnBxTypes = [(AnBxType,[Ident])]
type AnBxKnowledgeAgents = [AnBxKnowledgeAgent]
type AnBxKnowledgeWhere = [(AnBxMsg,AnBxMsg)]
type AnBxKnowledgeAgent = (Ident,[AnBxMsg])

data BMMode = Std | Fresh | Forward | ForwardFresh
          deriving (Eq,Show,Ord)

-- | The different supported channel types (descriptions from OFMC code, for standard channels)
data AnBxChannelType =    Insecure             -- ^ @ -> @ standard channel
                        | Authentic            -- ^ @ *-> @ sender and intended recipient secured
                        | Confidential         -- ^ @ ->* @ recipient secured
                        | Secure               -- ^ @ *->* @ both authentic and confidential
                        | FreshAuthentic       -- ^ @ *->> @ like authentic, but protected against replay
                        | FreshSecure          -- ^ @ *->>* @ like secure, but protected against replay
                        --- <AnBx Mod> ---
                        | Sharing ShareType    -- ^ channel for sharing information prior protocol run         
                        | ActionComment ComType String     -- ^ not really a channel, just carrying comments over the compilation chain 
                        | BMChannelTypePair BMMode AnBxPeer AnBxPeer             -- ^ AnBx channel notation pair (obsolete)
                        | BMChannelTypeTriple BMMode AnBxPeer [Ident] AnBxPeer   -- ^ AnBx channel notation triple
                        --- </AnBx Mod> ---
                        deriving (Eq,Show,Ord)

type AnBxChannel = (AnBxPeer,AnBxChannelType,AnBxPeer)

realAnBxChannelType :: AnBxChannelType -> Bool
realAnBxChannelType (ActionComment _ _) = False
realAnBxChannelType _= True

nonSharingAnBxChannelType :: AnBxChannelType -> Bool
nonSharingAnBxChannelType (Sharing _) = False
nonSharingAnBxChannelType _= True

-- | The pre-defined set of goals (descriptions from OFMC code)
data AnBxGoal = ChGoal AnBxChannel AnBxMsg AnBxGoalComment                  -- ^ Goals that are expressed in channel notation
                | Secret AnBxMsg [AnBxPeer] Bool AnBxGoalComment            -- ^ Standard secrecy goal
                | Authentication AnBxPeer AnBxPeer AnBxMsg AnBxGoalComment  -- ^ Standard authentication goal (including replay 
                                                                            -- protection; corresponds to Lowe's injective agreement)
                | WAuthentication AnBxPeer AnBxPeer AnBxMsg AnBxGoalComment -- ^ Weaker form of authentication: no protection against
                                                                            -- replay. Corresponds to Lowe's non-injective agreement.
                deriving (Show,Ord)

type AnBxGoals = [AnBxGoal]
type AnBxGoalComment = String

instance Eq AnBxGoal where
        (==) :: AnBxGoal -> AnBxGoal -> Bool
        g1 == g2 = eqGoal g1 g2

eqGoal :: AnBxGoal -> AnBxGoal -> Bool
eqGoal (ChGoal ch1 msg1 _) (ChGoal ch2 msg2 _) = (ch1==ch2) && (msg1==msg2)
eqGoal (Secret msg1 peers1 wk1 _) (Secret msg2 peers2 wk2 _) = (peers1==peers2) && (msg1==msg2) && (wk1==wk2)
eqGoal (Authentication p1 p2 msg1 _) (Authentication p3 p4 msg2 _) = (p1==p3) && (p2==p4) && (msg1==msg2)
eqGoal (WAuthentication p1 p2 msg1 _) (WAuthentication p3 p4 msg2 _) = (p1==p3) && (p2==p4) && (msg1==msg2)
eqGoal _ _ = False

showSpecGoal :: AnBxGoal  -> String
showSpecGoal (ChGoal (_,ct,_) _ _) = show ct
showSpecGoal Secret {} = "Secret"
showSpecGoal Authentication {} = "Authentication"
showSpecGoal WAuthentication {} = "WAuthentication"

-- drop comment actions when they are not required
dropActionComments :: AnBxActions -> AnBxActions
dropActionComments actions = [ a | a@((_,ct,_),_,_,_) <- actions, realAnBxChannelType ct]

-- drop share actions when they are not required
dropActionShares :: AnBxActions -> AnBxActions
dropActionShares actions = [ a | a@((_,ct,_),_,_,_) <- actions, nonSharingAnBxChannelType ct]

data AnBxMsgWrapper
        = PlainMsg AnBxMsg
        | ReplayMsg AnBxMsg

type AnBxAction =  (AnBxChannel,AnBxMsgWrapper,Maybe AnBxMsg,Maybe AnBxMsg)
type AnBxActions = [AnBxAction]

type AnBxShare = (ShareType,[Ident],[AnBxMsg])
type AnBxShares = [AnBxShare]

type AnBxPeer = (Ident,Bool,Maybe AnBxMsg)

peerIsPseudo :: AnBxPeer -> Bool
peerIsPseudo (_,True,_) = True
peerIsPseudo _ = False

type AnBxAbstraction = [(Ident,AnBxMsg)]

data AnBxNotation = Pair | Triple

type PrevFresh = Bool

data AnBxChImpl = Plain AnBxPeer AnBxPeer
                    | FromA AnBxPeer [Ident] AnBxPeer
                    | SecretForC AnBxPeer AnBxPeer AnBxPeer
                    | FromASecretForC AnBxPeer [Ident] AnBxPeer AnBxPeer
                    | FreshFromA AnBxPeer [Ident] AnBxPeer
                    | FreshFromASecretForB AnBxPeer [Ident] AnBxPeer
                    | FreshFromAWithDH AnBxPeer [Ident] AnBxPeer
                    | ForwardSighted  AnBxPeer [Ident] AnBxPeer AnBxPeer PrevFresh
                    | ForwardSightedSecret AnBxPeer [Ident] AnBxPeer AnBxPeer PrevFresh
                    | ForwardBlind AnBxPeer [Ident] AnBxPeer AnBxPeer
                    -- AnBx 2.0
                    | ForwardFreshSightedWithDH AnBxPeer [Ident] AnBxPeer AnBxPeer
                    | ForwardFreshSighted AnBxPeer [Ident] AnBxPeer AnBxPeer
                    | ForwardFreshSightedSecret  AnBxPeer [Ident] AnBxPeer AnBxPeer
                deriving (Show,Eq)

data ForwardMode = Blind | Sighted | SightedSecret
                          -- AnBx 2.0
                          | FreshSighted | FreshSightedSecret

data ConcatPos = CPLeft | CPRight
                deriving(Eq,Show,Ord)

-- determines the position where concatenation of messages occours 
-- given an integer computes the concatenation order
step2Pos :: Int -> ConcatPos
step2Pos step | even step = CPLeft
              | otherwise = CPRight

nullPeer :: AnBxPeer
nullPeer = (nullPeerName,False,Nothing)

ident2AnBxPeer :: Ident -> AnBxPeer
ident2AnBxPeer id | id == "" = error "empty peer name"
ident2AnBxPeer id | id == nullPeerName = nullPeer
ident2AnBxPeer id  = (id,False,Nothing)

isNullPeer :: AnBxPeer -> Bool
isNullPeer (id,False,_) | id == nullPeerName = True
isNullPeer (_,_,_) = False

getAgents :: AnBxTypes -> [Ident]
getAgents types = getIds types isAgentType

getCertifiedAgents :: AnBxTypes -> [Ident]
getCertifiedAgents types = getIds types isAgentCertified

getActiveAgents :: AnBxActions -> [Ident]
getActiveAgents [] = []
getActiveAgents (((_,ActionComment _ _,_),_,_,_):as) = getActiveAgents as
getActiveAgents (((_,Sharing _,_),_,_,_):as) = getActiveAgents as
getActiveAgents ((ch,_,_,_):as) = nubOrd ([getSender ch,getReceiver ch] ++ getActiveAgents as)

getSender :: AnBxChannel -> Ident
getSender (a,_,_) = peer2Ident a

getReceiver :: AnBxChannel -> Ident
getReceiver ( _,_,b) = peer2Ident b

setSender :: AnBxChannel -> Ident -> AnBxChannel
setSender ((_,isps,pseudo),chtype,recv) subst = ((subst,isps,pseudo),chtype,recv)

setReceiver :: AnBxChannel -> Ident -> AnBxChannel
setReceiver (sender,chtype,(_,isps,pseudo)) subst = (sender,chtype,(subst,isps,pseudo))

peer2Ident :: AnBxPeer -> String
peer2Ident (a,_,_) = a

peer2Agent :: AnBxPeer -> AnBxMsg
peer2Agent p = Atom (peer2Ident p)

-- given the name, create a corresponding (AnB) peer
ident2Peer :: Ident -> AnBxPeer
ident2Peer id  = (id,False,Nothing)

ids2Msgs :: [Ident] -> [AnBxMsg]
ids2Msgs ids = [Atom x | x <- ids, not (all isSpace x)]

-- list of identifiers in a message (excludes functions)
msgs2IdsNoFun :: AnBxMsg -> AnBxTypes -> [Ident]
msgs2IdsNoFun msg types = [ x | x <- idents, inMsg msg x ]
                                    where
                                        idents = concat [ ids | (t,ids) <- types, not (isFunctionType t) ]

inMsg :: AnBxMsg -> Ident -> Bool
inMsg (Atom id1) id = id == id1
inMsg (Comp _ msgs) id = any (\x -> inMsg x id) msgs
inMsg (DigestHash msg) id = inMsg msg id
inMsg (DigestHmac msg id1) id = inMsg msg id || id1 == id

initKnowledges :: [Ident] -> (Ident -> [AnBxMsg]) -> AnBxKnowledgeAgents -> AnBxKnowledgeAgents
initKnowledges  _ _ []= []
initKnowledges  [] _ k= k
initKnowledges  idents f (x:xs) = initKnowledge x idents f : initKnowledges  idents f xs

initKnowledge :: (Ident,[AnBxMsg]) -> [Ident] -> (Ident ->[AnBxMsg]) -> (Ident,[AnBxMsg])
initKnowledge (ident,msgs) idents f  | elem ident idents = (ident, nubOrd (msgs ++ f ident))
                                                 | otherwise = (ident,nubOrd msgs)

isPeerMemberOf :: AnBxPeer -> [Ident] -> Bool
isPeerMemberOf (p,_,_) peerList = elem p peerList

