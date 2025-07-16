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

module Vdm (showVDM) where
import Data.List ( (\\), intercalate )
import Data.Containers.ListUtils (nubOrd)
import AnBAst
import AnBxMsgCommon
import AnBxMsg ( AnBxMsg (Comp,Atom),isAtype, patternMsgError)
import qualified AnBxShow as AnB
import AnBxAst (AnBxChannelType(..), AnBxType (..), TO (..), AnBxGoal (..), agentDefaultType, isAgentType, isFunctionType, peerIsPseudo, showSpecGoal, unwrapMsg)
import AnBxShow (showType, showSimpleGoal)

----------------------- AnB Show ---------------------------

-- various output modes for different part of the VDM specifications
data OutType = AnB | VDM | VDMDec | VDMAct     

-- default indentation based on message output mode (with or without indentation)
defIndent :: VdmMsgOutputMode -> Int
defIndent VDMIndent = 2
defIndent _ = 0

invOp :: String
invOp = "INV"

intruder :: String
intruder = "intruder"

makePrefix :: String
makePrefix ="make_"

msgActPrefix :: String
msgActPrefix ="Act_Msg_"

msgGoalPrefix :: String
msgGoalPrefix ="Goal_Msg_"

mkApply :: String
mkApply = makePrefix ++ "ApplyExpr"

mkCat :: String
mkCat = makePrefix ++ "CatExpr"

mkCrypt :: String
mkCrypt = makePrefix ++ "crypt"

mkSCrypt :: String
mkSCrypt = mkCrypt

mkDigSig :: String
mkDigSig = mkCrypt

mkGoalItem :: String
mkGoalItem = makePrefix ++ "GoalItem"

mkSecretAgreement :: String
mkSecretAgreement = makePrefix ++ "SecretAgreement"

mkId :: String
mkId = makePrefix ++ "Id"

mkAction :: String
mkAction = makePrefix ++ "Action"

mkProtocol :: String
mkProtocol = makePrefix ++ "Protocol"

mkPublicKey :: String
mkPublicKey = makePrefix ++ "agent_public_key"

mkPrivateKeyApplyExpr :: String
mkPrivateKeyApplyExpr = makePrefix ++ "private_key_ApplyExpr"

mkPrivatekey :: String
mkPrivatekey = makePrefix ++ "private_key"

mkFunctionType :: String
mkFunctionType = makePrefix ++ "FunctionType"

mkCatType :: String
mkCatType = makePrefix ++ "CatType"

strProtocolKnowledge :: String
strProtocolKnowledge = "str_ProtocolKnowledge"

defaultTypeMap :: String
defaultTypeMap = "default_typemap"

tpm :: String
tpm = "tpm"

renameFun :: String -> String
renameFun s = "\t" ++ s ++ " renamed " ++ s ++ ";\n"

predefinedFunctions :: [String]
predefinedFunctions = [show AnBxPK,show AnBxSK,show AnBxHK, show AnBxHash, show AnBxHmac, show AnBxExp]

renamedTypesAnBSigma :: [String]
renamedTypesAnBSigma = ["Expr","TypeMap"]

renamedValuesAnBSigma :: [String]
renamedValuesAnBSigma = [show AnBxPK,show AnBxSK,show AnBxHK,show AnBxHash, show AnBxHmac, show Exp, show Xor, showTypeSigma (Agent True False [] NoCert),showTypeSigma (Agent False False [] NoCert),showTypeSigma (Number []),showTypeSigma (SeqNumber []),showTypeSigma (SymmetricKey []),showTypeSigma (PublicKey []), showTypeSigma (Untyped [])]
                        ++ (if enableExp2KasKap then [show AnBxKap,show AnBxKas] else [])

renamedFunctionsAnBSigma :: [String]
renamedFunctionsAnBSigma = [mkId,mkPrivatekey,mkPrivateKeyApplyExpr,mkPublicKey,mkCrypt,mkCat,mkApply,defaultTypeMap,strProtocolKnowledge,mkFunctionType,mkCatType]

renamedTypesAnB :: [String]
renamedTypesAnB = ["Protocol"]

renamedFunctionsAnB :: [String]
renamedFunctionsAnB = [mkAction,mkGoalItem,mkProtocol,mkSecretAgreement,"wf_Protocol","protocol_knowledge","satisfy_goals"]

renamedSection :: String -> [String] -> String
renamedSection _ [] = ""
renamedSection s xs = s ++ "\n" ++ concatMap renameFun xs

headerAnBSigma :: String
headerAnBSigma = renamedSection "types" renamedTypesAnBSigma ++ "\n" ++
                 renamedSection "values" renamedValuesAnBSigma ++ "\n" ++
                 renamedSection "functions" renamedFunctionsAnBSigma

headerAnB :: String
headerAnB = renamedSection "types" renamedTypesAnB ++ "\n" ++
            renamedSection "functions" renamedFunctionsAnB

-- default environment
defEnvList :: [(Type, String)]
defEnvList = [(agentDefaultType,intruder),(Function [],invOp), (Function [],show Exp), (Function [],show Xor),(Function [],show AnBxHmac),(Function [],show AnBxHash)] ++ map (\pk -> (Function [],show pk)) pkiFunList

defEnvIds :: [String]
defEnvIds = [x | (_,x) <- defEnvList]

-- list of reserved identifiers to be remapped 
reservedNames :: [(String, String)]
reservedNames = [("pre","pre1")]

-- returns the mapped identifiers if they exists 
isVDMReserved :: String -> [(String,String)] -> Maybe String
isVDMReserved _ [] = Nothing
isVDMReserved name ((m,m1):xs) = if m==name then Just m1 else isVDMReserved name xs

-- print the identifier checking if it needs to me mapped
ppVDMres :: String -> String
ppVDMres x = case isVDMReserved x reservedNames of
                            Just m -> ppId m
                            Nothing -> ppId x

showVDM :: Protocol -> VdmMsgOutputMode -> String
showVDM prot@((protocolname,_),types,_,equations,knowledge,shares,abstraction,actions,goals) mode =  -- equations and shares are not shown
        let
            pseudos = listPeerPred prot peerIsPseudo
            ids = nubOrd ([ x | (_,ids) <- types, x <- ids] \\ defEnvIds) -- ++ defEnvIds)
        in if not (null pseudos) then 
            error ("Pseudonyms like " ++ AnB.showPeers pseudos ++ " are not supported yet in the AnB2VDM translation")
        else
            "------------------------- Automatic generation begins here -------------------------" ++ "\n" ++
            "module " ++ protocolname ++ "\n" ++
            "imports" ++  "\n" ++
            "-- imports for term producing" ++ "\n" ++
            "from AnBSigma" ++  "\n" ++
            headerAnBSigma ++
            "," ++ "\n" ++
            "-- imports for protocol producing expressions" ++ "\n" ++
            "from AnB" ++  "\n" ++
            headerAnB ++ "\n" ++
            "exports" ++ "\n" ++
            "functions" ++ "\n" ++
            "\t" ++ makePrefix ++  protocolname ++ ": () -> Protocol;" ++ "\n" ++
            "definitions" ++ "\n\n" ++
            "functions" ++ "\n" ++
            "\t" ++ makePrefix ++ protocolname ++ ": () -> Protocol" ++ "\n" ++
            "\t" ++ makePrefix ++ protocolname ++ "() ==" ++ "\n" ++
            "let" ++ "\n" ++
            mkTokenList ids ++
            "\t" ++ tpm ++ ": TypeMap = " ++ defaultTypeMap ++ "("++ Vdm.showTypes types equations ++ ")," ++ "\n" ++
            Vdm.showActions mode actions VDMDec ++ ",\n\n" ++
            Vdm.showGoals mode goals VDMDec ++ "\n" ++
            "in"  ++ "\n" ++
            mkProtocol ++ "(" ++ "\n" ++
            "-- Name ---------------------" ++ "\n" ++
            "\t" ++ mkId ++ "(\"" ++ protocolname ++ "\")," ++ "\n" ++
            "-- Types --------------------" ++ "\n" ++
            "\t" ++ "tpm," ++ "\n" ++
            "-- Knowledge ----------------" ++ "\n" ++
             "{\n" ++
            Vdm.showKnowledges knowledge ++
             "\n},\n" ++
             (if null equations then "" else
             "-- Equations --------------" ++ "\n" ++
            "-- {\n" ++
             Vdm.showEquations equations ++
             "\n-- },\n") ++
            (if null shares then "" else
            "-- Shares --------------" ++ "\n" ++
            "-- {\n" ++
             Vdm.showShares shares ++
             "\n-- },\n") ++
             (if null abstraction then "" else
             "-- Abstractions -----------" ++ "\n" ++
             "-- {\n" ++
             Vdm.showAbstractions abstraction ++
             "\n-- },\n") ++
             "-- Actions ----------------" ++ "\n" ++
             "[\n" ++
             Vdm.showActions mode actions VDMAct ++
             "\n],\n" ++
             "-- Goals ------------------" ++ "\n" ++
             "[\n" ++
             Vdm.showGoals mode goals VDMAct ++
             "\n]\n" ++
             ");" ++ "\n\n" ++
             "\n" ++ "end" ++ " " ++ protocolname ++ "\n"
             ++ "------------------------- Automatic generation ends here -------------------------" ++ "\n"
             ++ "------------------------------------ Commands ------------------------------------" ++ "\n"
             ++ "-- " ++ "default " ++ protocolname  ++ "\n"
             ++ "-- print " ++ "wf_Protocol(" ++  makePrefix ++ protocolname ++ "())" ++ "\n"
             ++ "-- print " ++ "protocol_knowledge(" ++  makePrefix ++ protocolname ++ "(),bool)" ++ "\n"
             ++ "-- print " ++ "satisfy_goals(" ++  makePrefix ++ protocolname ++ "(),bool)" ++ "\n"
             ++ "------------------------------------ Commands ------------------------------------"  ++ "\n"

showActions :: VdmMsgOutputMode -> Actions -> OutType -> String
showActions mode actions VDM = showAstList actions (\x-> Vdm.showAction mode x (defIndent mode) AnB) "\n" ++ "\n\n" ++
                          showAstList actions (\x-> Vdm.showAction mode x (defIndent mode) VDM) ",\n"
showActions _ _ AnB = error "showActions (AnB) should not occur here"
showActions mode actions ot = showAstList actions (\x -> Vdm.showAction mode x (defIndent mode) AnB) "\n" ++ "\n\n" ++
                         showAstList (zip actions [1..length actions]) (\(x,y)-> Vdm.showAction mode x y ot) ",\n"

showAction :: VdmMsgOutputMode -> Action -> Int -> OutType -> String
-- showAction a n AnB | trace ("showAction (" ++ show n ++ "): " ++ AnB.showAction a ++ " / " ++ show a) False = undefined
showAction _ a@((_,ActionComment CTAnBx _,_),_,_,_) _ AnB = "\t-- " ++ replace "\n" "\n\t--" (AnB.showAction a)
showAction _ ((_,ActionComment _ _,_),_,_,_) _ _ = ""
showAction _ a _ AnB = "\t-- " ++ AnB.showAction a
showAction mode ((peerFrom,channeltype,peerTo),msg,x1,x2) _ VDM = case channeltype of
                                                            Sharing SHShare -> ""
                                                            Sharing SHAgree -> Vdm.showAction mode ((peerFrom,FreshSecure,peerTo),msg,x1,x2) (defIndent mode) VDM
                                                            Sharing SHAgreeInsecurely -> Vdm.showAction mode ((peerFrom,Insecure,peerTo),msg,x1,x2) (defIndent mode) VDM
                                                            _ -> let (msg',_) = unwrapMsg msg 
                                                                in "\t" ++ mkAction ++ "(" ++ Vdm.showPeer peerFrom ++ ",<" ++ show channeltype ++ ">," ++ Vdm.showPeer peerTo ++ "," ++ showMsg mode (defIndent mode) msg' ++ ")"
showAction mode ((peerFrom,channeltype,peerTo),msg,x1,x2) n VDMDec = case channeltype of
                                                            Sharing SHShare -> ""
                                                            Sharing SHAgree -> Vdm.showAction mode ((peerFrom,FreshSecure,peerTo),msg,x1,x2) n VDMDec
                                                            Sharing SHAgreeInsecurely -> Vdm.showAction mode ((peerFrom,Insecure,peerTo),msg,x1,x2) n VDMDec
                                                            _ -> let (msg',_) = unwrapMsg msg
                                                                 in "\t" ++ msgActPrefix ++ show n ++ ": Expr = " ++ showMsg mode (defIndent mode) msg' 
showAction mode ((peerFrom,channeltype,peerTo),msg,x1,x2) n VDMAct = case channeltype of
                                                            Sharing SHShare -> ""
                                                            Sharing SHAgree -> Vdm.showAction mode ((peerFrom,FreshSecure,peerTo),msg,x1,x2) n VDMAct
                                                            Sharing SHAgreeInsecurely -> Vdm.showAction mode ((peerFrom,Insecure,peerTo),msg,x1,x2) n VDMAct
                                                            _ -> "\t" ++ mkAction ++ "(" ++ Vdm.showPeer peerFrom ++ ",<" ++ show channeltype ++ ">," ++ Vdm.showPeer peerTo ++ "," ++ msgActPrefix ++ show n ++ ")"

showPeers :: [Peer] -> String
showPeers peers = showAstList peers Vdm.showPeer ","

showPeer :: (Ident,Bool,Maybe Msg) -> String
showPeer (ident,False,Nothing) = ppVDMres ident
showPeer (ident,True,_) = error ("Pseudonyms like " ++ ppVDMres ident ++ " are unsupported in AnB2VDM translation")
-- showPeer (ident,True,Nothing) = "["++ ppVDMres ident ++"]"
-- showPeer (ident,True,Just msg) = "["++ ppVDMres ident++":"++showMsg VDMLine msg++"]"
showPeer (_,False,Just _) = ""

showAbstractions :: Abstraction -> String
showAbstractions abstractions = showAstList abstractions Vdm.showAbstraction "\n"

showAbstraction :: (Ident,Msg) -> String
showAbstraction (ident,msg) = let mode = VDMLine in "\t-- " ++ show (ppVDMres ident) ++ ": " ++ showMsg VDMLine (defIndent mode) msg

showEquations :: AnBEquations -> String
showEquations equations = showAstList equations Vdm.showEquation "\n"

showEquation :: AnBEquation -> String
showEquation equation = "\t-- " ++ AnB.showEquation equation

showShares :: AnBShares -> String
showShares shares = showAstList shares Vdm.showShare "\n"

showShare :: AnBShare -> String
showShare share = "\t-- " ++ AnB.showShare share

showTypes :: Types -> AnBEquations -> String
showTypes [] _ = ""
showTypes [(_,[])] _ = ""
showTypes types equations = let
                     varagents = [ (Agent False b to c,id) | (t@(Agent _ b to c),ids) <- types, id <- ids, not (isHonest id), isAgentType t]
                     honagents = [ (Agent True b to c,id) | (t@(Agent _ b to c),ids) <- types, id <- ids, isHonest id, isAgentType t]
                     tids = [(t, id) |
                               (t, ids) <- types,
                               not (isFunctionType t),
                               not (isAgentType t),
                               id <- ids]
                     functions = [(t, id) |
                                    (t, ids) <- types,
                                    isFunctionType t,
                                    id <- ids,
                                    notElem id predefinedFunctions]
                     types1 = varagents ++ honagents ++ tids ++ functions
                  in "{\n" ++ intercalate ",\n" (map (\x -> Vdm.showType x equations) types1) ++ "\n}\n"

showType :: (Type,Ident) -> AnBEquations -> String
showType (_,"") _ = ""
showType (t,id) equations = "\t" ++ ppVDMres id ++ " |-> " ++ showTypeSigma t ++ "\t /* " ++ AnBxShow.showType PTAnB CTAnBx (t,[id]) equations ++ "\t*/"

showTypeSigma :: Type -> String
showTypeSigma (Agent True _ _ _) = "FIXED_HONEST_AGENT_TYPE"
showTypeSigma (Agent False _ _ _) = "SYMBOLIC_HONEST_AGENT_TYPE"
showTypeSigma Number {} = "NUMBER_TYPE"
showTypeSigma SeqNumber {} = "SEQ_NUMBER_TYPE"
showTypeSigma PublicKey {} = "PUBLIC_KEY_TYPE"
showTypeSigma SymmetricKey {} = "SYMMETRIC_KEY_TYPE"
showTypeSigma (Function to) = case to of
                                    (FunSign (t1,t2,_):_) -> mkFunctionType ++ "(" ++ mkCatType ++ "([" ++ intercalate "," (map showTypeSigma t1) ++ "])," ++ showTypeSigma t2 ++ ")"
                                    _ -> mkFunctionType ++ "(" ++ mkCatType ++ "([" ++ showTypeSigma (Number [])  ++ "])," ++ showTypeSigma (Number []) ++ ")"

showTypeSigma (Untyped _) = "ANY_TYPE"
showTypeSigma t = show t

showKnowledges :: Knowledge -> String
showKnowledges (knowledges,[]) =    showAstList knowledges (\x -> "\t-- " ++ AnB.showKnowledgeAgent x) "\n" ++ "\n\n" ++
                                    showAstList knowledges showKnowledge ",\n"

showKnowledges (knowledges,whereknowledge) = showAstList knowledges showKnowledge ",\n" ++ "\n\t-- where statement not supported yet\n\t-- where " ++ showAstList whereknowledge Vdm.showKnowledgeWhereIneq ", " ++ "\n"

showKnowledge :: ([Char], [Msg]) -> String
showKnowledge (_,[]) = []
showKnowledge (ident,msgs) = "\t" ++ ident ++ " |-> [" ++ Vdm.showMsgs VDMLine msgs ++ "]"

showKnowledgeWhereIneq :: (Msg, Msg) -> String
showKnowledgeWhereIneq (msg1,msg2) = let mode = VDMLine in showMsg VDMLine (defIndent mode) msg1 ++ "!=" ++ showMsg VDMLine (defIndent mode) msg2 

showMsg :: VdmMsgOutputMode -> Int -> Msg -> String
showMsg = Vdm.ppMsg

formatIndent :: VdmMsgOutputMode -> Int -> String
formatIndent VDMLine _ = ""
formatIndent VDMIndent indent = "\n" ++ replicate indent '\t'

mkEncPar :: VdmMsgOutputMode -> Int -> String -> [Msg] -> String
mkEncPar mode indent encfun xs = encfun ++ "(" ++ (showMsg mode indent . head . tail) xs ++ "," ++ formatIndent mode (indent + 1) ++ showMsg mode (indent + 1) (head xs) ++ "," ++ tpm ++ ")"

mkEnc :: VdmMsgOutputMode -> Int -> String -> Msg -> [Msg] -> String
mkEnc mode indent pk key xs = let
                                pkfun = getKeyFun pk
                                encfun
                                    | elem pkfun pkiEncFunList = mkCrypt
                                    | elem pkfun pkiSigFunList = mkDigSig
                                    | otherwise = error ("VDM - unsupported key: " ++ show key)
                              in mkEncPar mode (indent + 1) encfun xs

ppMsg :: VdmMsgOutputMode -> Int -> Msg -> String
ppMsg _ _ (Atom x) = ppVDMres x
ppMsg mode indent m@(Comp f xs) = case f of
                                Cat -> formatIndent mode indent ++ mkCat ++ "([" ++ Vdm.ppMsgList mode (indent + 1) xs ++ "])"
                                Apply -> if isAtype (head xs) && hideTypes then Vdm.ppMsgList mode (indent + 1) (tail xs)
                                                else if head xs == Atom (show AnBxPK) || head xs == Atom (show AnBxSK) || head xs == Atom (show AnBxHK) then
                                                        mkPublicKey ++ "(" ++ show (head xs) ++ "," ++ Vdm.ppMsgList mode (indent + 1) (tail xs) ++ ",tpm)"
                                                        else formatIndent mode indent ++ mkApply ++ "(" ++ Vdm.ppMsg mode indent (head xs) ++ "," ++ Vdm.ppMsgList mode (indent + 1) (tail xs) ++ "," ++ tpm ++ ")"
                                Crypt -> let
                                            key = head xs
                                         in case key of
                                            -- distinguish between encryption and signature keys
                                            Comp Apply [Atom pk,Atom _] -> formatIndent mode indent ++ mkEnc mode indent pk key xs
                                            Comp Inv [Comp Apply [Atom sk,Atom _]] -> mkEnc mode indent sk key xs
                                            Atom _ -> mkEncPar mode indent mkCrypt xs -- single key   
                                            Comp Inv [Atom _] -> mkEncPar mode  indent mkCrypt xs -- single key 
                                            _ -> error ("VDM - unsupported key: " ++ Vdm.ppMsg mode indent key ++ "\nin message: " ++ show m)
                                Scrypt -> formatIndent mode indent ++ mkEncPar mode indent  mkSCrypt xs
                                Inv -> case xs of
                                        [Atom _] -> mkPrivatekey ++ "("++ Vdm.ppMsgList mode (indent + 1) xs ++ "," ++ tpm ++ ")"
                                        _ -> mkPrivateKeyApplyExpr ++ "("++ Vdm.ppMsgList mode (indent + 1) xs ++ "," ++ tpm ++ ")"
                                -- rewriting Exp terms to NEKas/NEKap
                                Exp -> if enableExp2KasKap then let m1 = trMsgExp2KasKap m in Vdm.ppMsg mode indent m1
                                            -- no Exp term rewriting
                                            else formatIndent mode indent ++ mkApply ++ "(" ++ show Exp ++ "," ++ mkCat ++ "([" ++ Vdm.ppMsgList mode (indent + 1) xs ++"])," ++ tpm ++ ")"
                                Xor -> formatIndent mode indent ++ mkApply ++ "(" ++ show Xor ++ "," ++ mkCat ++ "([" ++ Vdm.ppMsgList mode (indent + 1) xs ++"])," ++ tpm ++ ")"
                                _ -> show f ++ "("++ Vdm.ppMsgList mode (indent + 1) xs ++")"
ppMsg _ _ msg = error $ patternMsgError msg "ppMsg"   
    
enableExp2KasKap :: Bool
enableExp2KasKap = True

-- rewrite Exp expression to support NEKas/NEKap functions
trMsgExp2KasKap :: Msg -> Msg
trMsgExp2KasKap (Comp Exp [Comp Exp [m1,m2],m3]) = Comp Apply [Atom (show AnBxKas), Comp Cat [Comp Apply [Atom (show AnBxKap),Comp Cat [m1,m2]],m3]]     -- kas(kap(g,XxX),YxY) 
trMsgExp2KasKap (Comp Exp [m1,m2]) = Comp Apply [Atom (show AnBxKap), Comp Cat [m1,m2]]                                                                  -- kap(g,XxX)
trMsgExp2KasKap msg = msg

--	Number g;
--	Number XxX,YxY;
--	Function [Number, Number -> PublicKey] kap;                 /* to be added to AnBSigma built-in funcions */
--	Function [PublicKey, Number -> SymmetricKey] kas            /* to be added to AnBSigma built-in funcions */

-- alternatively, more precise typing, based on concrete implementation

--	DHGPar g;
--	DHSecret XxX,YxY;
--	Function [DHGPar, DHSecret -> PublicKey] kap;
--	Function [PublicKey, DHSecret -> SymmetricKey] kas

-- what about pseudonyms?

ppMsgList :: VdmMsgOutputMode -> Int -> [Msg] -> String
ppMsgList mode indent = ppXList (showMsg mode indent) ","

showMsgs :: VdmMsgOutputMode -> [Msg] -> String
showMsgs mode msgs = showAstList msgs (showMsg mode 0) ","

showGoals :: VdmMsgOutputMode -> Goals -> OutType -> String
showGoals mode goals VDM = showAstList goals (\x-> Vdm.showGoal mode x (defIndent mode) AnB) "\n" ++ "\n\n" ++
                           showAstList goals (\x-> Vdm.showGoal mode x (defIndent mode) VDM) ",\n"
showGoals _ _ AnB = error "showGoals goals AnB should not occur here"
showGoals mode goals ot = showAstList goals (\x -> Vdm.showGoal mode x (defIndent mode) AnB) "\n" ++ "\n\n" ++
                          showAstList (zip goals [1..length goals]) (\(x,y)-> Vdm.showGoal mode x y ot) ",\n"

showGoal :: VdmMsgOutputMode -> Goal -> Int -> OutType -> String
showGoal _ (ChGoal (_,ActionComment _ _,_) _ _) _ _ = error "comment is not a channel"
showGoal _ g _ AnB = "\t-- " ++ showSimpleGoal g
showGoal _ (ChGoal (_,ch@(Sharing SHShare),_) _ _) _ _ = error (show ch ++ " in not really an action, it should not be used explicitly")
showGoal mode (ChGoal (peerFrom,channeltype,peerTo) msg _) n ot = "\t" ++ case ot of
                                                                         AnB -> "-- " ++ showSimpleGoal (ChGoal (peerFrom,channeltype,peerTo) msg undefined)
                                                                         VDM -> mkAction ++"(" ++ Vdm.showPeer peerFrom ++ ",<" ++ show channeltype ++ ">," ++ Vdm.showPeer peerTo ++ "," ++ showMsg mode (defIndent mode) msg ++ ")"
                                                                         VDMDec -> msgGoalPrefix ++ show n ++ ": Expr = " ++ showMsg mode (defIndent mode) msg
                                                                         VDMAct -> mkAction ++"(" ++ Vdm.showPeer peerFrom ++ ",<" ++ show channeltype ++ ">," ++ Vdm.showPeer peerTo ++ "," ++ msgGoalPrefix ++ show n ++ ")"
showGoal mode (Secret msg peers False _) n ot = "\t" ++ case ot of
                                         AnB -> "-- " ++ showSimpleGoal (Secret msg peers False undefined)
                                         VDM -> mkSecretAgreement ++ "({" ++ Vdm.showPeers peers ++ "}," ++ showMsg mode (defIndent mode) msg ++ ")"
                                         VDMDec -> msgGoalPrefix ++ show n ++ ": Expr = " ++ showMsg mode (defIndent mode) msg
                                         VDMAct -> mkSecretAgreement ++ "({" ++ Vdm.showPeers peers ++ "}," ++ msgGoalPrefix ++ show n ++ ")"
showGoal _ g@(Secret _ _ True _) _ _ = error ("goal not implemented yet: " ++ show g)
showGoal mode g@(Authentication peerFrom peerTo msg _) n ot = "\t" ++ case ot of
                                         AnB -> "-- " ++ showSimpleGoal g
                                         VDM -> mkGoalItem ++"(" ++ Vdm.showPeer peerFrom ++ ",<" ++ showSpecGoal g ++ ">," ++ Vdm.showPeer peerTo ++ "," ++ showMsg mode (defIndent mode) msg ++ ")"
                                         VDMDec -> msgGoalPrefix ++ show n ++ ": Expr = " ++ showMsg mode (defIndent mode) msg
                                         VDMAct -> mkGoalItem ++"(" ++ Vdm.showPeer peerFrom ++ ",<" ++ showSpecGoal g ++ ">," ++ Vdm.showPeer peerTo ++ "," ++ msgGoalPrefix ++ show n ++ ")"
showGoal mode g@(WAuthentication peerFrom peerTo msg _) n ot = "\t" ++ case ot of
                                         AnB -> "-- " ++ showSimpleGoal g
                                         VDM -> mkGoalItem ++"(" ++ Vdm.showPeer peerFrom ++ ",<" ++ showSpecGoal g ++ ">," ++ Vdm.showPeer peerTo ++ "," ++ showMsg mode (defIndent mode) msg ++ ")"
                                         VDMDec -> msgGoalPrefix ++ show n ++ ": Expr = " ++ showMsg mode (defIndent mode) msg
                                         VDMAct -> mkGoalItem ++"(" ++ Vdm.showPeer peerFrom ++ ",<" ++ showSpecGoal g ++ ">," ++ Vdm.showPeer peerTo ++ "," ++ msgGoalPrefix ++ show n ++ ")"

mkToken :: Ident -> String
mkToken id = "\t" ++ ppVDMres id ++ ": Expr = " ++ mkId ++ "(\"" ++ ppVDMres id ++ "\"),\n"

mkTokenList :: [Ident] -> String
mkTokenList = concatMap mkToken
