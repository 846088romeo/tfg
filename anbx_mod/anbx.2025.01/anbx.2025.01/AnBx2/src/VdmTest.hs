{-

 AnBx Compiler and Code Generator

 Copyright 2011-2025 Paolo Modesti
 Copyright 2018-2025 SCM/SCDT/SCEDT, Teesside University
 Copyright 2016-2018 School of Computer Science, University of Sunderland
 Copyright 2013-2015 School of Computing Science, Newcastle University
 Copyright 2011-2012 DAIS, Universita' Ca' Foscari Venezia

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

module VdmTest (showVDMTest) where 
import  AnBxOnP (VDMTestType (VDMTestSG,VDMTestWF))
import Data.List ( intercalate )

anbSigma :: String
anbSigma = "AnBSigma"

traceName :: VDMTestType ->String
traceName VDMTestSG = "trace_satisfy_goals"
traceName VDMTestWF = "trace_wf"

renFunctions :: VDMTestType -> [String]
renFunctions VDMTestSG = ["protocol_knowledge","trace_protocol_knowledge","trace_derived_knowledge","satisfy_goals","satisfy_goals_Protocols","trace_satisfy_goals", "trace_satisfy_goals_Protocols"]
renFunctions VDMTestWF = ["protocol_knowledge","trace_protocol_knowledge","trace_derived_knowledge","wf_Protocols"]

showVDMTest :: VDMTestType -> String -> [String] -> String
showVDMTest _ _ [] = error "No vdmsl protocol found"
-- showVDMTest _ _ list = error (show list) 
-- showVDMTest VDMTestWF _ _ = error "Not implemented yet"
showVDMTest vdmtt vdmModuleName list = mkFile vdmtt vdmModuleName list

mkFile :: VDMTestType -> String -> [String] -> String
mkFile vdmtt name xs = mkPrelude vdmtt name ++ "\n" ++
                        mkFromRenames xs ++ "\n\n" ++
                        mkExports ++ "\n\n" ++
                        mkDefinitions  ++ "\n\n" ++
                        mkFunctions xs  ++ "\n\n" ++
                        mkTraces vdmtt xs ++ "\n\n" ++
                        "end " ++ name ++ "\n"
            
mkFunctions :: [String] -> String
mkFunctions xs = "functions" ++ "\n" ++
            "\t" ++ "make_PROTOCOLS: () -> Protocols" ++ "\n" ++
            "\t" ++ "make_PROTOCOLS() ==" ++ "\n" ++
            "\t\t" ++ "[" ++  "\n" ++ 
            mkFunctionsList xs ++  "\n" ++
            "\t\t" ++ "];"

mkFunctionsList :: [String] -> String
mkFunctionsList xs = intercalate ",\n" (map (\x -> mkFunction x "\t\t") xs)

mkFunction :: String -> String -> String
mkFunction prot prefix = prefix ++ "make_" ++ prot ++"()"

mkTraces :: VDMTestType -> [String] -> String
mkTraces vdmtt xs = "traces" ++ "\n" ++ intercalate "\n" (map (mkTrace vdmtt) xs)        

mkTrace :: VDMTestType -> String -> String
mkTrace vdmtt prot = "\t" ++ traceName vdmtt ++ "_" ++ prot ++ " : " ++ traceName vdmtt ++ "(" ++ mkFunction prot "" ++ ");"
            
mkExports :: String
mkExports = "exports" ++ "\n" ++
            "\t" ++ "functions" ++ "\n" ++
            "\t\t" ++ "make_PROTOCOLS: () -> Protocols;"         
            
mkDefinitions :: String
mkDefinitions = "definitions"
    
mkRename :: String -> String 
mkRename fun = "\t" ++ fun ++ " renamed " ++ fun ++ ";"

mkFromRenames :: [String] -> String
mkFromRenames xs = intercalate ",\n" (map mkFromRename xs)

mkFromRename :: String -> String
mkFromRename prot = "from " ++ prot ++ "\t" ++ "functions make_" ++ prot ++ "\t" ++  "renamed make_" ++ prot

mkPrelude :: VDMTestType -> String -> String
mkPrelude vdmtt name = "module" ++ " " ++ name ++ "\n\n" ++
                        "imports" ++ "\n\n" ++
                        "from " ++ anbSigma ++ "\n" ++
                        "functions" ++ "\n" ++
                        mkRename "derived_knowledge" ++ "\n" ++
                        ","  ++ "\n" ++
                        "from AnB"  ++ "\n" ++ 
                        "types" ++ "\n" ++ 
                        mkRename "Protocols" ++ "\n" ++ 
                        "functions" ++ "\n" ++ 
                        intercalate "\n" (map mkRename (renFunctions vdmtt)) ++ "\n" ++
                        ","
