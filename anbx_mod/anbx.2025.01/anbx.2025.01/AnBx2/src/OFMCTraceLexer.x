{
{-

 AnBx Compiler and Code Generator

 Copyright 2021-2024 Rémi Garcia
 Copyright 2021-2024 Paolo Modesti
 Copyright SCM/SCDT/SCEDT, Teesside University

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

module OFMCTraceLexer (Token(..), 
                Ident, 
                AlexPosn(..), alexScanTokens, 
                token_posn) where
--import AnBAst
import AnBxMsgCommon
}

%wrapper "posn"

$digit   = 0-9
$alpha   = [a-zA-Z]
$identChar   = [a-zA-Z0-9_]
$ignore = [\ \t\f\v\r]
$newline = [\n]

tokens :-

  $ignore+        ;
  "("      { (\ p _ -> TOPENP p)  }
  ")"      { (\ p _ -> TCLOSEP p) }
  "XOR"    {(\ p _ -> TXOR p)}
  "{|"     { (\ p _ -> TOPENSCRYPT p)}
  "|}_"     { (\ p _ -> TCLOSESCRYPT p)}
  "{"      { (\ p _ -> TOPENB p)  }
  "}_"      { (\ p _ -> TCLOSEB p) }
  ":"      { (\ p _ -> TCOLON p)  }
  "->"     { (\ p _ -> TINSECCH p)}
  ","      { (\ p _ -> TCOMMA p) }
  "Reached" { (\ p _ -> TREACHED p) }
  "State" { (\ p _ -> TRSTATE p) }
  "%"     { (\ p _ -> TPERCENT p) }
  $newline+    { (\ p _ -> TACTSEP p) }
  $alpha $identChar* { (\ p s -> TATOM p s) }
  $digit+            { \p s -> TINT p s }

{

data Token= 
   TATOM AlexPosn Ident
   | TINT AlexPosn Ident
   | TREACHED AlexPosn
   | TRSTATE AlexPosn
   | TPERCENT AlexPosn
   | TACTSEP AlexPosn
   | TXOR AlexPosn
   | TOPENP AlexPosn
   | TCLOSEP AlexPosn
   | TOPENSCRYPT AlexPosn
   | TCLOSESCRYPT AlexPosn
   | TOPENB AlexPosn
   | TCLOSEB AlexPosn
   | TCOLON AlexPosn
   | TINSECCH AlexPosn
   | TCOMMA AlexPosn
   deriving (Eq,Show)

token_posn (TATOM p _)=p
token_posn (TINT p _)=p
token_posn (TXOR p)=p
token_posn (TACTSEP p)=p
token_posn (TREACHED p)=p
token_posn (TRSTATE p)=p
token_posn (TPERCENT p)=p
token_posn (TOPENP p)=p
token_posn (TCLOSEP p)=p
token_posn (TOPENSCRYPT p)=p
token_posn (TCLOSESCRYPT p)=p
token_posn (TOPENB p)=p
token_posn (TCLOSEB p)=p
token_posn (TCOLON p)=p
token_posn (TINSECCH p)=p
token_posn (TCOMMA p)=p
}
