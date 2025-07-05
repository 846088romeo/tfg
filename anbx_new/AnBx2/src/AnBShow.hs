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

module AnBShow where
import AnBAst
import AnBxMsgCommon
    ( showSection,
      Ident,
      PrivateFunction(PrivFun), ComType (CTAnB))
import Data.List ( (\\), intercalate )
import AnBxMain (getExt)
import AnBxShow (showKnowledges, showAbstractions, showEquation, showGoals, showActions, showTypes, showEquations)
import Data.Char (toUpper)
import AnBxOnP (OutType(..), productNameWithOptions, AnBxOnP)
import AnBxAst (AnBxType(..), TO (..), AnBxEquation (..), isFunctionType)
import Data.Containers.ListUtils (nubOrd)

----------------------- AnB Show ---------------------------

showAnB :: Protocol -> String
showAnB ((protocolname,prottype),types,_,equations,knowledge,_,abstraction,actions,goals) =    -- equations and shares are not shown
        showSection "Protocol" protocolname False ++
        showSection "Types" (showTypes prottype CTAnB types equations) False ++
        (if null equations then "" else showSection "# Equations" (showEquations CTAnB equations) False ++
                                        showEquationInstructions protocolname types equations) ++
        showSection "Knowledge" (showKnowledges knowledge) False ++
        showSection "Abstraction" (showAbstractions abstraction) False ++
        showSection "Actions" (showActions actions) False ++
        showSection "Goals" (showGoals goals) True

showEquationInstructions :: String -> Types -> AnBEquations -> String
showEquationInstructions protocolname _ _ = let
                                                -- signatures = eqSignatures types equations
                                                theoryFile = protocolname ++ "." ++ getExt AnBEqTheory
                                                anbxFile = protocolname ++ "." ++ getExt AnBxIntr
                                                ifFile =  protocolname ++ "." ++ getExt AnBIF
                                            in "\n" ++ "#" ++ "\n" ++
                                            "#" ++ " " ++ "To verify this AnB protocol with equational theories with OFMC" ++ "\n" ++
                                            "#" ++ " " ++ "1) Generate the theory file (" ++ theoryFile ++ ") from the AnBx file" ++ "\n" ++
                                            "#" ++ " " ++ "   anbxc -out:AnBEqTheory" ++ " " ++ anbxFile  ++  " -cfg <your-config-file>" ++ "\n" ++
                                            "#" ++ " " ++ "   Double check Analysis and TopDec rules and adjust them to the expected behaviour of your equations" ++  "\n" ++
                                            "#" ++ " " ++ "2) Generate the IF file from the AnBx file" ++ "\n" ++
                                            "#" ++ " " ++ "   anbxc -out:AnBIF" ++ " " ++ anbxFile  ++  " -ifsessions 2 -cfg <your-config-file>" ++ "\n" ++
                                            "#" ++ " " ++ "   If there is any \"CheckHERE\" annotations in the IF code, double check the positions of goals and fix" ++  "\n" ++
                                            "#" ++ " " ++ "3) Run OFMC to verify the IF file with the theory file" ++ "\n" ++
                                            "#" ++ " " ++ "   ofmc --numSess 2 --noowngoal --theory " ++ theoryFile ++ " " ++ ifFile ++ "\n" ++
                                            "#" ++ " " ++ "Note that functions used in equations are not declared in AnB"                                        

{-

:: generates theory file from AnBx
%anbxc% %protocol%.AnBx -out:AnBEqTheory -cfg %anbxc-cfg% -nocfgmsg	

:: generates IF file from AnBx
%anbxc% %protocol%.AnBx -out:AnBIF -cfg %anbxc-cfg% -nocfgmsg -ifsessions %sessions%	

:: verification of IF with OFMC
%ofmc% --numSess %sessions% --noowngoal --theory %protocol%.thy %protocol%.if

-}

-- generation of theory file .thy

type Signature = (Type,Ident)
type Decana = (Msg,[Ident],[Ident])

type TopDec =  Ident -> [(Msg,[TTCase])]
data TTCase = Unconditional [[Msg]]
             | Conditional TTCondition [TTCase]
type TTCondition = (Ident,Msg)

data AnBHeaderType = AnBHTEquations | AnBHTIF | AnBHTAnB

showAnBOutputHeader :: String -> AnBHeaderType -> AnBxOnP -> String
showAnBOutputHeader protName ht opt = comment ++ " " ++ firstline ++ " - Protocol: " ++ protName ++ "\n" ++ 
                         comment ++ " " ++ "Automatically generated by the" ++ "\n" ++
                         comment ++ " " ++ productNameWithOptions opt ++ "\n" 
                            where 
                                comment = case ht of 
                                        AnBHTEquations -> "%%"
                                        AnBHTIF -> "%" 
                                        AnBHTAnB -> "#"
                                firstline = case ht of 
                                        AnBHTEquations -> "Algebraic Theories"
                                        AnBHTIF -> "IF specification" 
                                        AnBHTAnB -> "AnB specification"

showEqTheory :: Protocol -> AnBxOnP -> String
showEqTheory ((protocolName,_),types,_,equations,_,_,_,_,_) opt | null equations = error (noEqMsg protocolName)
                                                          | otherwise = showAnBOutputHeader protocolName AnBHTEquations opt ++ "\n" ++
                                                                    "Theory "++ eqTheoryName protocolName ++ ":" ++ "\n" ++
                                                                    "  " ++ "Signature:" ++ "\n" ++
                                                                    "    " ++ showEqSignatures signatures ++ "\n" ++
                                                                    "  " ++ "Cancellation:" ++ "\n" ++
                                                                    concatMap (\x -> "    " ++ showEquation x ++ "\n") equations ++
                                                                    "  " ++ "% Topdec:" ++ "\n" ++
                                                                    "    " ++ "% write your own rules here, if they are required" ++ "\n" ++
                                                                    "  " ++ "Analysis:" ++ "\n" ++
                                                                    "    " ++ "% double check and modify (if necessary)" ++ "\n" ++
                                                                    showDecanas decanas
                                                                    where
                                                                            decanas = decanaEquations types equations
                                                                            signatures = eqSignatures types equations

noEqMsg :: String -> String
noEqMsg protocolName = "No custom equational theory is available for protocol " ++ protocolName ++ "\n"

isEqFunction :: Ident -> Types -> AnBEquations -> Bool
isEqFunction ident types equations = let
                                             signatures = eqSignatures types equations
                                             ids = map snd signatures
                                       in elem ident ids

eqTheoryName :: String -> String
eqTheoryName name = toUpper (head name) : tail name

showEqSignatures :: [Signature] -> String
showEqSignatures signatures = intercalate ",\n    " (map showFunArity signatures)

showEqFunNames :: [Signature] -> String
showEqFunNames signatures = intercalate ", " (map snd signatures)

eqSignature :: Types -> AnBEquation -> [(Type,Ident)]
eqSignature types (Eqt msg1 msg2) = let
                                           f1 = spMsg2IdentsType msg1 types isFunctionType
                                           f2 = spMsg2IdentsType msg2 types isFunctionType
                                    in map (\x -> (id2Type x types,x)) (nubOrd (f1 ++ f2))

eqSignatures :: Types -> AnBEquations -> [(Type,Ident)]
eqSignatures types equations = nubOrd (concatMap (eqSignature types) equations)

parEquation :: Types -> AnBEquation -> ([Ident],[Ident])
parEquation types (Eqt msg1 msg2) = let
                                           ids1 = spMsg2IdentsNoFun msg1 types
                                           ids2 = spMsg2IdentsNoFun msg2 types
                                    in (ids1\\ids2,ids2)

decanaEquation :: Types -> AnBEquation -> Decana
decanaEquation types equation@(Eqt msg1 _) = (msg1,ids1,ids2)
                                        where
                                            (ids1,ids2) = parEquation types equation

decanaEquations :: Types -> AnBEquations -> [Decana]
decanaEquations types = map (decanaEquation types)

showFunArity :: (Type,Ident) -> String
showFunArity (Function (to@(FunSign (t1,_,priv)):_),id) | arity > 2 = error ("Function " ++ id ++ " (arity " ++ show arity ++ ") cannot be used in a theory file. Max allowed arity is 2.") 
                                                    | otherwise =  "% " ++  id ++ ": " ++ show to ++ "  " ++
                                                                   (if priv==PrivFun && tail id /= "_" then "# This private function should be renamed to " ++ id ++ "_" ++ " in the AnB protocol"  else "") ++ "\n    " ++
                                                                   id ++ "/" ++ show arity
                                                                   where arity = length t1
showFunArity t = error "arity not defined for " ++ show t

showDecana :: Decana -> String
showDecana (msg,ids1,ids2) = "    " ++ "decana(" ++ show msg ++")=[" ++ intercalate "," ids1 ++ "]->[" ++ intercalate "," ids2 ++ "]"

showDecanas :: [Decana] -> String
showDecanas decanas = intercalate "\n" (map showDecana decanas)


{-
Theory Concatenation:
  % Concatenation/Pairing
  % This operator is associative which can be changed 
  % by simply commenting-out the entire topdec-section.
  Signature: 
    fst/1, snd/1, pair/2
  Cancellation:
    fst(pair(X1,X2)) = X1
    snd(pair(X1,X2)) = X2
  Topdec:
  % pair(pair(Z1,Z2),T2)=pair(Z1,pair(Z2,T2))
    topdec(pair,pair(T1,T2))=
      [T1,T2]
      if T1==pair(Z1,Z2){
        [Z1,pair(Z2,T2)]}
  Analysis:
    decana(pair(X1,X2))=[]->[X1,X2]


-- from OFMC Decomposiotion.hs --
-- type Var = Int
-- type BinOp = Int64
-- type TopdecTheo   = BinOp -> [(TT_decomp,[TT_case])]
-- data TT_case      = Unconditional [[Msg]]
--                   | Conditional TT_Condition [TT_case]
--                   deriving (Eq,Show)
-- type TT_Condition = (Var,TT_decomp)
-- type TT_decomp    = (BinOp,[Var])

-- 
-- topdec (Ident,Msg) = [[Ident]]
-- if ident = Msg {[(Msg,Msg)]}

--  Topdec:
--   % kep(kap(G,Z1),T2) = kep(kap(G,T2),Z1)
--     topdec(kap,kap(T1,T2))=
--       [T1,T2]
--     topdec(kep,kep(T1,T2))=
--       [T1,T2]
--       if T1==kap(G,Z1){
--       [kap(G,T2),Z1]}

-}