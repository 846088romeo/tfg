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

module AnBxDefinitions where

import AnBxAst
import AnBxMsg
import AnBxShow
import AnBxMsgCommon
import AnBxOnP
import AnBxImplementation (ckDefs,types2idents)
import Data.List ( foldl', intersect )
import Debug.Trace
import Data.Containers.ListUtils (nubOrd)

-- predefined AnBx functions
baseFun :: [(AnBxType, [Ident])]
baseFun =  [(Function [FunSign ([Agent False False [] NoCert ],PublicKey [],PubFun)], map show pkiFunList)] ++ 
        [(Function [FunSign ([Untyped []],Number [],PubFun)], [show AnBxHash])] ++
        [(Function [FunSign ([Untyped [],SymmetricKey []],Number [],PubFun)], [show AnBxHmac])]

blindFun :: [(AnBxType, [Ident])]
blindFun = [(Function [FunSign ([Agent False False [] NoCert ],PublicKey [],PubFun)], [show AnBxBlind])]   

agreeFun :: [(AnBxType, [Ident])]
agreeFun = [(Function [FunSign ([Agent False False [] NoCert,Agent False False [] NoCert],SymmetricKey [],PrivFun)], [show AnBxShAgree])]   

-- predefined AnBx identifiers 
initFunctions :: ImplType -> Bool -> [Ident]
initFunctions impltype useTagsif2cif  = nubOrd $ concatMap snd (initFunctionsTyped impltype useTagsif2cif)

-- predefined AnBx functions (typed)
initFunctionsTyped :: ImplType -> Bool -> [(AnBxType, [Ident])]
initFunctionsTyped AANB _ = baseFun ++ blindFun
initFunctionsTyped CIF True = baseFun ++ blindFun
initFunctionsTyped _ _ = baseFun

-------------- definitions substitution ------------------------
mkPrepros :: AnBxProtocol -> AnBxOnP -> AnBxProtocol
mkPrepros (name,types,definitions,equations,knowledge,shares,abstractions,actions, goals) options = let
                                                                                  -- this check is less strict then the standard compilation because initFunctions is used (only for debug) 
                                                                                  definitions1 = reverse (fst (ckDefs (mkDef definitions definitions,initFunctions (anbximpltype options) (anbxif2cif options) ++ types2idents types)))
                                                                                  -- in error ("Defs:\n" ++ showDefinitions definitions) 
                                                                                  in (name,types,reverse definitions1,equations,mkDef definitions1 knowledge,mkDef definitions1 shares,abstractions, mkDef definitions1 actions, mkDef definitions1 goals)

dbgDefs  :: AnBxProtocol -> AnBxOnP -> String
dbgDefs prot@(_,_,definitions,_,_,_,_,actions,goals) options =
        let
             (_,_,definitions1,_,_,_,_,actions1,goals1) = mkPrepros prot options
             str = "\n\n--- Definitions ---\n\n"
                    ++ showDefinitions definitions
                    ++ "\n\n--- Definitions Changed ---\n\n"
                    ++ showDefinitions definitions1
                    ++ "\n\n--- Actions ---\n\n"
                    ++ showActions actions ++ "\n"
                    ++ "\n--- Actions Changed ---\n\n"
                    ++ showActions actions1 ++ "\n"
                    ++ "\n--- Goals ---\n\n"
                    ++ showGoals goals ++ "\n"
                    ++ "\n--- Goals Changed ---\n\n"
                    ++ showGoals goals1 ++ "\n"
         in str

class Defs a where
        mkDef :: AnBxDefinitions -> a -> a

instance Defs [AnBxEquation] where
        mkDef defs xs = map (mkDef defs) xs

instance Defs [AnBxAction] where
        mkDef defs xs = map (mkDef defs) xs

instance Defs AnBxKnowledge where
        mkDef defs (ka,kw) = (map (mkDef defs) ka,map (mkDef defs) kw)

instance Defs AnBxKnowledgeAgents where
        mkDef defs xs = map (mkDef defs) xs

instance Defs AnBxKnowledgeWhere where
        mkDef defs xs = map (mkDef defs) xs

instance Defs AnBxKnowledgeAgent where
        mkDef defs (idents,msgs) = (idents,mkDef defs msgs)

instance Defs AnBxShares where
        mkDef defs xs = map (mkDef defs) xs

instance Defs AnBxShare where
        mkDef defs (shtype,idents,msgs) = (shtype,idents,mkDef defs msgs)

instance Defs AnBxAction where
        mkDef defs (ch,msgWrap,msg2,msg3) = 
                (ch, mapMsgWrapper (mkDef defs) msgWrap, msg2, msg3)

instance Defs [AnBxGoal] where
        mkDef defs xs = map (mkDef defs) xs

instance Defs AnBxGoal where
        mkDef defs goal =
                case goal of
                        ChGoal ch msg comment-> ChGoal ch (mkDef defs msg) comment
                        Secret msg peers bool comment -> Secret (mkDef defs msg) peers bool comment
                        Authentication p1 p2 msg comment -> Authentication p1 p2 (mkDef defs msg) comment
                        WAuthentication p1 p2 msg comment -> WAuthentication p1 p2 (mkDef defs msg) comment

instance Defs [AnBxDefinition] where
--         mkDef defs xs | trace ("mkDef AnBxDefinitions\n\tdefs: " ++ showDefinitions defs ++ "\n\txs1:" ++ showDefinitions xs) False = undefined
        mkDef [] xs = xs
        mkDef [def] xs = map (mkDef [def]) xs
        mkDef (def:defs) xs = mkDef defs (mkDef [def] xs)

instance Defs AnBxDefinition where
--        mkDef defs def | trace ("mkDef AnBxDefinition\n\tdef: " ++ showDefinition def ++ "\n\tdefs:\n" ++ showDefinitions defs) False = undefined
        mkDef [] def = def
        mkDef ((Def msg1 msg2):defs) (Def msg3 msg4) = if msg1==msg3 then Def msg3 (mkDef defs msg2) else Def msg3 (mkDef defs msg4)

instance Defs [AnBxMsg] where
        mkDef defs xs = map (mkDef defs) xs

instance Defs (AnBxMsg,AnBxMsg) where
        mkDef defs (x,y) = (mkDef defs x,mkDef defs y)

instance Defs AnBxEquation where
        mkDef defs (Eqt x y) = Eqt (mkDef defs x) (mkDef defs y)

instance Defs AnBxMsg where
--        mkDef defs msg | trace ("mkDef AnBxMsg\n\tmsg: " ++ show msg ++ "\n\tdefs:\n" ++ showDefinitions defs) False = undefined
        mkDef [] msg@(Atom _) = msg
        mkDef [Def (Atom id1) msg1] msg@(Atom id2) = if id1==id2 then msg1 else msg
        mkDef ((Def (Atom id1) msg1):defs) msg@(Atom id2) = if id1==id2 then mkDef defs msg1 else mkDef defs msg
        mkDef (_:defs) msg@(Atom _) = mkDef defs msg
        mkDef defs@[Def (Comp Apply [Atom id1,msg1]) msg2] (Comp Apply [Atom id3,msg3]) = if id1==id3 then applyFun id1 msg1 msg2 msg3 else Comp Apply [Atom id3,mkDef defs msg3]
        mkDef (def@(Def (Comp Apply [Atom id1,msg1]) msg2):defs) (Comp Apply [Atom id3,msg3]) = if id1==id3 then mkDef defs (applyFun id1 msg1 msg2 msg3) else mkDef defs (Comp Apply [Atom id3,mkDef (def:defs) msg3])
        mkDef defs (Comp operator xs) = Comp operator (mkDef defs xs)
        mkDef defs (DigestHash msg) = DigestHash (mkDef defs msg)
        mkDef defs (DigestHmac msg id) = DigestHmac (mkDef defs msg) id

applyFun :: Ident -> AnBxMsg -> AnBxMsg -> AnBxMsg -> AnBxMsg
-- applyFun f msgparams msgimpl msg | trace ("applyFun\n\tf: " ++ f ++ "\n\tmsgparams: " ++ show msgparams  ++ "\n\tmsgimpl: " ++ show msgimpl ++ "\n\tmsg: " ++ show msg) False = undefined
applyFun f msgparams@(Atom id) msgimpl msg@(Atom id1) = if id/=id1 then substVars msgimpl [(id,id1)] else error (errorApplyFunMsg f msgparams msg)
applyFun f msgparams@(Comp Cat xs) msgimpl msg@(Comp Cat xs1) = if applyFunCheckPars xs xs1 then substVars msgimpl (zip (concatMap AnBxMsg.idents xs) (concatMap AnBxMsg.idents xs1)) else error (errorApplyFunMsg f msgparams msg)
applyFun f msgparams _ msg = error (errorApplyFunMsg f msgparams msg)

errorApplyFunMsg :: String -> AnBxMsg -> AnBxMsg -> String
errorApplyFunMsg f msgparams msg = "\nerror in applying\n\tfunction: " ++ f ++ "(" ++ show msgparams ++ ") \n\tto message: " ++ f ++ "(" ++ show msg ++")" ++
                                       "\n\tcheck definition, arity or variable clash" ++ "\n\tdisable the option -pvtagfuntt if in use"

applyFunCheckPars :: [AnBxMsg] -> [AnBxMsg] -> Bool
applyFunCheckPars xs xs1 = let
                             ids = concatMap AnBxMsg.idents xs
                             ids1 = concatMap AnBxMsg.idents xs1
                           in length ids == length ids1 && null (intersect ids ids1)

substVars :: AnBxMsg -> [(Ident,Ident)] -> AnBxMsg
substVars msg ids = foldl' substVar msg ids

substVar :: AnBxMsg -> (Ident,Ident) -> AnBxMsg
substVar (Atom id) (id1,id2) = if id==id1 then Atom id2 else Atom id
substVar (Comp op xs) (id1,id2) = Comp op (map (\x -> substVar x (id1,id2)) xs)
substVar (DigestHash msg) sbst = DigestHash (substVar msg sbst)
substVar (DigestHmac msg id) (id1,id2) = if id==id1 then DigestHmac (substVar msg (id1,id2)) id2 else DigestHmac (substVar msg (id1,id2)) id
