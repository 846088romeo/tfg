{
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

module AnBxLexer (Token(..), 
                Ident, 
                AlexPosn(..), alexScanTokens, 
                token_posn) where
-- import Ast
-- import AnBxAst
-- import AnBxMsg
import AnBxMsgCommon

}

%wrapper "posn"

$digit   = [0-9]
$alpha   = [a-zA-Z]
$alphaL  = [a-z]
$alphaU  = [A-Z]
$identChar = [a-zA-Z0-9_]

tokens :-

  $white+        ;
  "#".*          ;
  --- <AnBx Tokens> 
  "@"      { (\ p _ -> TAT p) }
  "^"      { (\ p _ -> THAT p) }
  "-"      { (\ p _ -> THYPHEN p) }
  "<"      { (\ p _ -> TOPENAB p) } 
  ">"      { (\ p _ -> TCLOSEAB p) }
  "|"      { (\ p _ -> TVERLINE p) }
  --- </AnBx Tokens> 
  "("      { (\ p _ -> TOPENP p)  }
  ")"      { (\ p _ -> TCLOSEP p) }
  "{|"     { (\ p _ -> TOPENSCRYPT p)}
  "|}"     { (\ p _ -> TCLOSESCRYPT p)}
  "{"      { (\ p _ -> TOPENB p)  }
  "}"      { (\ p _ -> TCLOSEB p) }
  ":"      { (\ p _ -> TCOLON p)  }
  ";"      { (\ p _ -> TSEMICOLON p) }
  "*->*"   { (\ p _ -> TSECCH p)  }
  "*->"    { (\ p _ -> TAUTHCH p) }
  "->*"    { (\ p _ -> TCONFCH p) }
  "->"     { (\ p _ -> TINSECCH p)}
  "*->>"   { (\ p _ -> TFAUTHCH p) }
  "*->>*"  { (\ p _ -> TFSECCH p) }
  "%"      { (\ p _ -> TPERCENT p)}
  "!"      { (\ p _ -> TEXCLAM  p)}
  "!="     { (\ p _ -> TUNEQUAL p)}
  "="      {(\ p _ -> TEQUAL p)}
  "."      { (\ p _ -> TDOT p) }
  ","      { (\ p _ -> TCOMMA p) }
  "["      { (\ p _ -> TOPENSQB p) } 
  "]"      { (\ p _ -> TCLOSESQB p) }
  -- NEW TOKEN
  "~"      { (\ p _ -> TPREVSESSION p) }
  -- ---------------------------------------------------------------
  "Protocol"    { (\ p _ -> TPROTOCOL p) }
  "Knowledge"   { (\ p _ -> TKNOWLEDGE p)}
  "where"       { (\ p _ -> TWHERE p) }
  --- <AnBx Tokens> 
  "Definitions" { (\ p _ -> TDEFINITIONS p)}
  "Equations"   { (\p _ -> TEQUATIONS p)}
  "Shares"      { (\ p _ -> TSHARES p)}
  "share"       { (\p _ -> TSHARE p)}
  "agree"       { (\p _ -> TAGREE p)}
  "insecurely"  { (\p _ -> TAGREEINSECURELY p)}
  --- </AnBx Tokens> 
  "Types"       { (\ p _ -> TTYPES p)}
  "Actions"     { (\ p _ -> TACTIONS p)}
  "Abstraction" { (\ p _ -> TABSTRACTION p)}
  "Goals"       { (\ p _ -> TGOALS p)}
  "authenticates" { (\ p _ -> TAUTHENTICATES p)}
  "on"          { (\p _ -> TON p)}
  "weakly"      { (\p _ -> TWEAKLY p)}
  "secret"      { (\p _ -> TSECRET p)}
  "between"     { (\p _ -> TBETWEEN p)}
  "guessable"   { (\p _ -> TGUESS p)}
  --- <AnBx Tokens>
  "confidentially"  { (\p _ -> TCONFIDENTIAL p)}
  "sends"           { (\p _ -> TCONFIDENTIALSENDS p)}
  "to"              { (\p _ -> TTO p)}
  --- </AnBx Tokens>
  $alpha $identChar* { (\ p s -> TATOM p s) }
  $digit+            { (\ p s -> TATOM p s) }

{

data Token= 
 --- <AnBx Tokens>  
   TATOM AlexPosn Ident
   | THYPHEN AlexPosn
   | THAT AlexPosn
   | TAT AlexPosn   
   | TDEFINITIONS AlexPosn
   | TSHARE AlexPosn
   | TAGREE AlexPosn
   | TAGREEINSECURELY AlexPosn
   | TSHARES AlexPosn
   | TOPENAB AlexPosn
   | TCLOSEAB AlexPosn
   | TVERLINE AlexPosn
   | TEQUATIONS AlexPosn
 --- </AnBx Tokens> 
   | TOPENP AlexPosn
   | TCLOSEP AlexPosn
   | TOPENSCRYPT AlexPosn
   | TCLOSESCRYPT AlexPosn
   | TOPENB AlexPosn
   | TCLOSEB AlexPosn
   | TCOLON AlexPosn
   | TSEMICOLON AlexPosn
   | TSECCH AlexPosn
   | TAUTHCH AlexPosn
   | TCONFCH AlexPosn
   | TINSECCH AlexPosn
   | TPERCENT AlexPosn
   | TEXCLAM AlexPosn
   | TDOT AlexPosn
   | TCOMMA AlexPosn
   | TOPENSQB AlexPosn
   | TCLOSESQB AlexPosn
   | TPROTOCOL AlexPosn
   | TKNOWLEDGE AlexPosn
   | TTYPES AlexPosn
   | TACTIONS AlexPosn
   | TABSTRACTION AlexPosn
   | TGOALS AlexPosn
   | TFSECCH AlexPosn
   | TFAUTHCH AlexPosn
   | TAUTHENTICATES AlexPosn
   | TON AlexPosn
   | TWEAKLY AlexPosn
   | TSECRET AlexPosn
   | TBETWEEN AlexPosn
   | TGUESS AlexPosn
   | TCONFIDENTIAL AlexPosn
   | TCONFIDENTIALSENDS AlexPosn
   | TTO AlexPosn
   | TUNEQUAL AlexPosn
   | TEQUAL AlexPosn
   | TWHERE AlexPosn
   | TFUNSIGN AlexPosn
   | TPREVSESSION AlexPosn
   deriving (Eq,Show)

 --- <AnBx Tokens>     
token_posn (THAT p)=p
token_posn (TAT p)=p
token_posn (THYPHEN p)=p
token_posn (TATOM p _)=p
token_posn (TDEFINITIONS p)=p
token_posn (TSHARE p)=p
token_posn (TAGREE p)=p
token_posn (TAGREEINSECURELY p)=p
token_posn (TSHARES p)=p
token_posn (TOPENAB p)=p
token_posn (TCLOSEAB p)=p
token_posn (TVERLINE p)=p
token_posn (TFUNSIGN p)=p
token_posn (TEQUATIONS p)=p
 --- </AnBx Tokens>  
token_posn (TOPENP p)=p
token_posn (TCLOSEP p)=p
token_posn (TOPENSCRYPT p)=p
token_posn (TCLOSESCRYPT p)=p
token_posn (TOPENB p)=p
token_posn (TCLOSEB p)=p
token_posn (TCOLON p)=p
token_posn (TSEMICOLON p)=p
token_posn (TSECCH p)=p
token_posn (TAUTHCH p)=p
token_posn (TCONFCH p)=p
token_posn (TINSECCH p)=p
token_posn (TPERCENT p)=p
token_posn (TEXCLAM p)=p
token_posn (TDOT p)=p
token_posn (TCOMMA p)=p
token_posn (TOPENSQB p)=p
token_posn (TCLOSESQB p)=p
token_posn (TPROTOCOL p)=p
token_posn (TKNOWLEDGE p)=p
token_posn (TTYPES p)=p
token_posn (TACTIONS p)=p
token_posn (TABSTRACTION p)=p
token_posn (TGOALS p)=p
token_posn (TFSECCH p)=p
token_posn (TFAUTHCH p)=p
token_posn (TAUTHENTICATES p)=p
token_posn (TWEAKLY p)=p
token_posn (TON p)=p
token_posn (TSECRET p)=p
token_posn (TBETWEEN p)=p
token_posn (TGUESS p)=p
token_posn (TWHERE p)=p
token_posn (TUNEQUAL p)=p
token_posn (TEQUAL p)=p
token_posn (TPREVSESSION p) = p
 --- <AnBx Tokens>  
token_posn (TCONFIDENTIAL p)=p
token_posn (TCONFIDENTIALSENDS p)=p
token_posn (TTO p)=p
 --- </AnBx Tokens>  
}