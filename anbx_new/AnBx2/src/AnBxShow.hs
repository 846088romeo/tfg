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

module AnBxShow where
import AnBxMsg
import AnBxAst
import AnBxMsgCommon
---------------------------------- show functions ----------------

showAnBx :: AnBxProtocol -> String
showAnBx ((protname,prottype),types,definitions,equations,(ak,wk),shares,abstraction,actions,goals) =
        showSection "Protocol" (protname ++ " " ++ show prottype) False ++
        showSection "Types" (showTypes prottype CTAnBx types equations) False ++
        showSection "Definitions" (showDefinitions definitions) False ++
        showSection "Equations" (showEquations CTAnBx equations) False ++
        showSection "Knowledge" (showKnowledgeAgents ak) False ++
        showSection "Shares" (showShares shares) False ++
        showSection "Where" (showKnowledgeWhere wk) False ++
        showSection "Abstraction" (showAbstractions abstraction) False ++
        showSection "Actions" (showActions actions) False ++
        showSection "Goals" (showGoals goals) True

showIdents :: [Ident] -> String
showIdents [] = ""
showIdents [x] = x
showIdents (x:xs) = x  ++ "," ++ showIdents xs

showIdentsMsg :: [Ident] -> [AnBxMsg]
showIdentsMsg = map Atom

showChannelType :: AnBxChannelType -> String
showChannelType ct = showAnBChannelType ct CTSGoals PTAnBx

showChannel :: AnBxChannel -> String
showChannel ch@(_,ActionComment _ _,_) = error ("comment is not a channel: " ++ show ch)
showChannel ch@(_,Sharing SHShare,_) = error (show ch ++ " in not really an action, it should not be used explicitly")
showChannel (peerFrom,channeltype,peerTo) | isAnBxChannelMode channeltype = showPeer peerFrom ++ " " ++ showChannelType Insecure ++ " " ++ showPeer peerTo ++ ", " ++ ct ++ ": "
                                          | otherwise = showPeer peerFrom ++ " " ++ ct ++ " " ++ showPeer peerTo ++ ": "
                                                where
                                                    ct = showChannelType channeltype

showPeer :: (Ident,Bool,Maybe AnBxMsg) -> String
showPeer (ident,False,Nothing) = ident
showPeer (ident,True,Nothing) = "[" ++ ident ++ "]"
showPeer (ident,True,Just msg) = "[" ++ ident ++ ":" ++ show msg ++"]"
showPeer (_,False,Just _) = ""

showPeers :: [AnBxPeer] -> String
showPeers peers = showAstList peers showPeer ","

showChannelMode :: BMMode -> AnBxPeer -> [Ident] -> AnBxPeer -> String
showChannelMode Std a v b = "(" ++  showPeer a ++ "|" ++ showChannelModeIdents v ++ "|" ++ showPeer b ++ ")"
showChannelMode Fresh a v b = "@(" ++  showPeer a ++ "|" ++ showChannelModeIdents v ++ "|" ++ showPeer b ++ ")"
showChannelMode Forward a v b = "^(" ++  showPeer a ++ "|" ++ showChannelModeIdents v ++ "|" ++ showPeer b ++ ")"
-- AnBx 2.0
showChannelMode ForwardFresh a v b = "^@(" ++  showPeer a ++ "|" ++ showChannelModeIdents v ++ "|" ++ showPeer b ++ ")"

showChannelModeIdents :: [Ident] -> String
showChannelModeIdents [] = nullPeerName
showChannelModeIdents v = showIdents v

showAnBxChImpl :: AnBxChImpl -> String
showAnBxChImpl ch =
        case ch of
                Plain _ _ -> showChannelMode Std nullPeer nullVers nullPeer
                FromA a vers _ -> showChannelMode Std a vers nullPeer
                FromASecretForC a vers _ c -> showChannelMode Std a vers c
                SecretForC _ _ c -> showChannelMode Std nullPeer nullVers c

                FreshFromA a vers _ -> showChannelMode Fresh a vers nullPeer
                FreshFromASecretForB a vers b -> showChannelMode Fresh a vers b
                FreshFromAWithDH a vers _ -> showChannelMode Fresh a vers nullPeer

                ForwardSighted a vers _ c _ -> showChannelMode Forward a vers c
                ForwardSightedSecret a vers _ c _ ->  showChannelMode Forward a vers c
                ForwardBlind a vers _ c -> showChannelMode Forward a vers c

                -- AnBx 2.0                 
                ForwardFreshSighted a vers _ c -> showChannelMode Forward a vers c
                ForwardFreshSightedWithDH a vers _ c -> showChannelMode Forward a vers c
                ForwardFreshSightedSecret a vers _ c -> showChannelMode Forward a vers c

isAnBxChannelMode :: AnBxChannelType -> Bool
isAnBxChannelMode BMChannelTypePair {} = True
isAnBxChannelMode BMChannelTypeTriple {} = True
isAnBxChannelMode _ = False

isAnBChannelMode :: AnBxChannelType -> Bool
isAnBChannelMode = not . isAnBxChannelMode

-- in AnB/OFMC Authentic Channels and Goals have different notation
data ChannelTypeSection = CTSActions | CTSGoals

showAnBChannelType :: AnBxChannelType -> ChannelTypeSection -> ProtType -> String
showAnBChannelType (BMChannelTypePair mode peerA peerB) _ PTAnBx = showChannelMode mode peerA nullVers peerB
showAnBChannelType (BMChannelTypeTriple mode peerA vers peerB) _ PTAnBx = showChannelMode mode peerA vers peerB
showAnBChannelType Insecure _ _ = "->"
showAnBChannelType Authentic _ _ = "*->"
showAnBChannelType Confidential _ _   = "->*"
showAnBChannelType Secure _ _ = "*->*"
showAnBChannelType (Sharing SHAgree) cts pt = showAnBChannelType Secure cts pt
showAnBChannelType (Sharing SHAgreeInsecurely) cts pt = showAnBChannelType Insecure cts pt
showAnBChannelType FreshAuthentic CTSActions PTAnB = "*->>"
showAnBChannelType FreshAuthentic _ _ = "*->"
showAnBChannelType FreshSecure CTSActions PTAnB = "*->>*"
showAnBChannelType FreshSecure _ _ = "*->*"
showAnBChannelType (ActionComment _ _) _  _ = "#"
showAnBChannelType (Sharing SHShare) _ _ = "share"     -- not a real channel
showAnBChannelType ch _ pt = error ("unexpected channeltype: " ++ show ch ++ " - protocol type:" ++ show pt)

showAction :: AnBxAction -> String
showAction ((_,ActionComment CTAnBx "",_),_,_,_) = ""
showAction ((_,ActionComment CTAnBx str,_),_,_,_) = "\n\t" ++ "# " ++ str
showAction ((_,ActionComment CTAnB _,_),_,_,_) = ""
showAction (ch@(_,channeltype,_),msgw,_,_) = "\t" ++
                                                            case channeltype of
                                                                Sharing SHShare -> "#" ++ "\t"
                                                                _ -> ""  
                                                            --
                                                            ++ showChannel ch ++
                                                            show msgw ++
                                                            case channeltype of
                                                                Sharing SHAgree -> "\t" ++ "# agree"
                                                                Sharing SHAgreeInsecurely -> "\t" ++ "# insecurely agree"
                                                                _ -> ""

showActions :: [AnBxAction] -> String
showActions [] = ""
showActions [x] = showAction x
showActions (x:xs) = showAction x ++ "\n" ++ showActions xs

showGoals :: AnBxGoals -> String
showGoals goals = showAstList goals showGoal "\n"

showGoalComment :: String -> String
showGoalComment comment = if null comment then "" else "\t" ++ "# " ++ comment ++ "\n"

showSimpleGoals :: AnBxGoals -> String
showSimpleGoals goals = showAstList goals showSimpleGoal "; "

showGoal :: AnBxGoal -> String
showGoal g@(ChGoal _ _ comment) = showGoalComment comment ++ "\t" ++ showSimpleGoal g
showGoal g@(Secret _ _ _ comment) = showGoalComment comment ++ "\t" ++ showSimpleGoal g
showGoal g@(Authentication _ _ _ comment) = showGoalComment comment ++ "\t" ++ showSimpleGoal g
showGoal g@(WAuthentication _ _ _ comment) = showGoalComment comment ++ "\t" ++ showSimpleGoal g

showSimpleGoal :: AnBxGoal -> String
-- showSimpleGoal (ChGoal channel msg _) = showAnBChannel channel CTSGoals ++ show msg
showSimpleGoal (ChGoal channel msg _) = showChannel channel ++ show msg
showSimpleGoal (Secret msg peers False _) = show msg ++  " " ++ "secret between" ++ " " ++ showPeers peers
showSimpleGoal (Secret msg peers True _) = show msg ++  " " ++ "guessable secret between" ++ " " ++ showPeers peers
showSimpleGoal (Authentication peerFrom peerTo msg _) = showPeer peerFrom ++ " " ++ "authenticates" ++ " " ++ showPeer peerTo ++ " on " ++ show msg
showSimpleGoal (WAuthentication peerFrom peerTo msg _) = showPeer peerFrom ++ " " ++ "weakly authenticates" ++ " " ++ showPeer peerTo ++ " on " ++ show msg

showTypes :: ProtType -> ComType -> AnBxTypes -> AnBxEquations -> String
showTypes _ _ [] _ = ""
showTypes _ _ [(_,[])] _ = ""
showTypes pt ct types equations = showAstList types (\x -> showType pt ct x equations) "\n"


showType :: ProtType -> ComType -> (AnBxType,[Ident]) -> AnBxEquations -> String
showType _ _ (_,[]) _ = ""
showType PTAnBx CTAnBx (t@(Agent _ _ _ Cert),ids) _ = "\t" ++ show t ++ " " ++ showAstList ids id "," ++ ";" ++ "\n\t" ++ show AnBxCertified ++ " " ++ showAstList ids id "," ++ ";"
showType _ _ (t@(Agent _ _ _ Cert),ids) _ = "\t" ++ show t ++ " " ++ showAstList ids id "," ++ ";" ++ "\t\t" ++ "# " ++ show AnBxCertified
showType pt CTAnB (t@(Function (to@(FunSign _):_)),ids) _ = let
                                                                    notEqFun = ids   -- may potentially check equations ids (not needed at the moment)
                                                                  in case notEqFun of
                                                                        [] -> ""
                                                                        _ -> "\t" ++ showSpecType pt t ++ " " ++ showAstList notEqFun id "," ++ ";" ++
                                                                            "\t\t" ++ "# " ++ show to
showType _ CTAnBx (t@(Function _),ids) _ =  "\t" ++ show t ++ " " ++ showAstList ids id "," ++ ";"
showType pt _ (t,ids) _ = "\t" ++ showSpecType pt t ++ " " ++ showAstList ids id "," ++ ";"

showKnowledges :: AnBxKnowledge -> String
showKnowledges (ak,[]) = showKnowledgeAgents ak
showKnowledges (ak,wk) = showKnowledgeAgents ak ++ "\n" ++ showKnowledgeWhere wk -- ++ "\n"

showKnowledgeAgents :: AnBxKnowledgeAgents -> String
showKnowledgeAgents ak = showAstList ak showKnowledgeAgent ";\n"

showKnowledgeWhere :: AnBxKnowledgeWhere -> String
showKnowledgeWhere [] = ""
showKnowledgeWhere wk = "\t" ++ "where" ++ " " ++ showAstList wk showKnowledgeWhereIneq ", "

showKnowledgeAgent :: (String, [AnBxMsg]) -> [Char]
showKnowledgeAgent (_,[]) = []
showKnowledgeAgent (ident,msgs) = "\t" ++ ident ++ ": " ++ showMsgs msgs

showKnowledgeWhereIneq :: (AnBxMsg, AnBxMsg) -> String
showKnowledgeWhereIneq (msg1@(Atom ag1), msg2) = if isVariable ag1 then out
                                                else error ("in the where clause " ++ out ++ " the identifier on the left must be a variable")
                                                where out = show msg1 ++ "!=" ++ show msg2
showKnowledgeWhereIneq (msg1,msg2) = show msg1 ++ "!=" ++ show msg2

showMsgs :: [AnBxMsg] -> String
showMsgs msgs = showAstList msgs show ","

showAbstractions :: AnBxAbstraction -> String
showAbstractions abstractions = showAstList abstractions showAbstraction "\n"

showAbstraction :: (Ident,AnBxMsg) -> String
showAbstraction (ident,msg) = "\t" ++ ident ++ ": " ++ show msg

showShares :: AnBxShares -> String
showShares shares = showAstList shares showShare ";\n"

showShare :: AnBxShare -> String
showShare (share,ids,msgs) = "\t" ++ showIdents ids ++ " " ++ show share ++ " " ++ showMsgs msgs

showDefinitions :: AnBxDefinitions -> String
showDefinitions definitions = showAstList definitions showDefinition ";\n"

showDefinition :: AnBxDefinition -> String
showDefinition (Def msg1 msg2) = "\t" ++ show msg1 ++ ": " ++ show msg2

showEquations :: ComType -> AnBxEquations -> String
showEquations CTAnBx equations = showAstList equations showEquation ";\n"
showEquations CTAnB equations = showAstList equations (\x-> "#\t" ++ showEquation x) "\n"

showEquation :: AnBxEquation -> String
showEquation (Eqt msg1 msg2) = "\t" ++ show msg1 ++ " = " ++ show msg2
