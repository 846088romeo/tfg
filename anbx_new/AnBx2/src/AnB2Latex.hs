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

module AnB2Latex where

import AnBxAst
import Data.Char (toLower)
import AnBxShow
import AnBxMsgCommon (ProtType)

-- parameter for fitting in page width
scaleFactor :: Double
scaleFactor = 0.62

-- parameter for vertical distance between steps
unitFactor :: Double
unitFactor = 0.70

-- the distance between agents in cm, depending on the number of agents
distAgents :: [String] -> Int
distAgents xs | length xs <= 2 = 10
              | length xs == 3 = 6
              | length xs == 4 = 3
              | otherwise = 2

-- the .tex file is build with: prologue ++ redefineMess ++ prologue2 ++ agents ++ actions ++ epilogue

prologue :: String
prologue =  "\\documentclass{article}" ++ "\n" ++
            "\\usepackage{tikz}" ++ "\n" ++
            "\\usetikzlibrary{positioning,arrows.meta,shapes}" ++ "\n" ++
            "\\usepackage{pgf-umlsd}" ++ "\n" ++
            "\\usepackage{comment}" ++ "\n" ++
            "\\begin{document}" ++ "\n" ++
            "\\begin{figure}[ht]" ++ "\n" ++
            "\\centering" ++ "\n" ++
            "\\tikzset{" ++ "\n" ++
            "% add this style to all tikzpicture environments" ++ "\n" ++
            "every picture/.append style={" ++ "\n" ++
            "% enable scaling of nodes" ++ "\n" ++
            "transform shape," ++ "\n" ++
            "% set scale factor" ++ "\n" ++
            "scale=" ++ show scaleFactor ++ "\n" ++
            "}" ++ "\n" ++
            "}" ++ "\n\n" ++
            "% steps can be optionally grouped by sdblocs, e.g." ++ "\n" ++
            "%\\begin{sdblock}{Step 1}{Step 1 description}" ++ "\n" ++
            "%\\end{sdblock}" ++ "\n"

-- need to redefine \mess in order to allow to use symbols like {} ()
redefineMess :: String
redefineMess = 
        "% redefine \\mess" ++ "\n" ++ 
        "\\renewcommand{\\mess}[4][0]{" ++ "\n" ++
        "\\stepcounter{seqlevel}" ++ "\n" ++
        "\\path" ++ "\n" ++
        "(#2)+(0,-\\theseqlevel*\\unitfactor-0.7*\\unitfactor) node (mess from) {};" ++ "\n" ++ 
        "\\addtocounter{seqlevel}{#1}" ++ "\n" ++
        "\\path" ++ "\n" ++
        "(#4)+(0,-\\theseqlevel*\\unitfactor-0.7*\\unitfactor) node (mess to) {};" ++ "\n" ++
        "\\draw[->,>=angle 60] (mess from) -- (mess to) node[midway, above]" ++ "\n" ++
        "{#3};" ++ "\n" ++
        "}" ++ "\n\n" 

prologue2 :: String        
prologue2 = "\\begin{sequencediagram}" ++ "\n" ++
            "% vertical distance" ++ "\n" ++
            "\\renewcommand\\unitfactor{" ++ show unitFactor ++ "}"


-- escaping some symbols to avoid errors in Latex
escapeLatex :: String -> String
escapeLatex [] = []
escapeLatex (x:xs)
    | x `elem` "\\_&%{}" = '\\' : x : escapeLatex xs
    | otherwise = x : escapeLatex xs

epilogue :: String -> String -> String
epilogue protname ext = "\\end{sequencediagram}" ++ "\n" ++
                        "\\caption{" ++ escapeLatex protname ++ "." ++ ext ++ "}" ++ "\n" ++
                        "\\label{fig:" ++ map toLower protname ++ "_seq_diagram}" ++ "\n" ++
                        "\\end{figure}" ++ "\n" ++
                        "\\end{document}"

showAgents :: [String] -> String
showAgents [] = error "no agent specified"
showAgents xs = let 
                    dist = distAgents xs 
                in "\\newinst{" ++ head xs ++ "}" ++ "{" ++ head xs ++ "}" ++  "\n" ++
                    "% [" ++ show dist ++ "] distance between nodes" ++ "\n" ++ 
                    concatMap (\x -> "\\newinst[" ++ show dist ++ "]{" ++ x ++ "}{" ++ x ++ "}" ++ "\n") (tail xs)

showLatex ::  ProtType -> AnBxProtocol ->String
showLatex pt ((protname,_),types,_,_,_,_,_,actions,_) = prologue ++ "\n" ++ redefineMess ++ "\n" ++ prologue2 ++ "\n" ++
                                                         showAgents (getAgents types) ++ "\n" ++
                                                         showLatexActions pt actions ++ "\n" ++
                                                         epilogue protname (show pt)

showChannelTypeLatex :: ProtType -> AnBxChannelType -> [Char]
showChannelTypeLatex _ AnBxAst.Insecure = ""          -- no need to print insecure channel
showChannelTypeLatex _ ch = showChannelType ch ++ ":"

showLatexActions :: ProtType -> AnBxActions -> String
showLatexActions pt = concatMap $
  \((a, ch, b), msgWrapper, _, _) ->
    case ch of
      -- skip Comment and Sharing actions
      ActionComment _ _ -> ""
      Sharing _         -> ""
      _ ->
        let (msg, _) = unwrapMsg msgWrapper
        in "\\mess{" ++ showPeer a ++ "}{$" ++ showChannelTypeLatex pt ch ++ escapeLatex (show msg) ++ "$}{" ++ showPeer b ++ "}" ++ "\n"


