{
{-

 AnBx Compiler and Code Generator

 Copyright 2011-2022 Paolo Modesti
 Copyright 2018-2022 SCM/SCDT/SCEDT, Teesside University
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

module AnBxMsgLexer (Token(..), 
                AlexPosn(..), alexScanTokens, 
                token_posn) where
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
  "("            { (\ p s -> TOPENP p)  }
  ")"            { (\ p s -> TCLOSEP p) }
  ","            { (\ p s -> TCOMMA p) }
 "{"             { (\ p s -> TOPENB p)  }
  "}"            { (\ p s -> TCLOSEB p) }
  "{|"           { (\ p s -> TOPENSCRYPT p)}
  "|}"           { (\ p s -> TCLOSESCRYPT p)}
  ":"            { (\ p s -> TCOLON p)  }
  "["            { (\ p s -> TOPENSQB p) } 
  "]"            { (\ p s -> TCLOSESQB p) }
  $alpha $identChar* { (\ p s -> TATOM p s) }
  $digit+       { (\ p s -> TATOM p s) }

{

data Token = 
   TATOM AlexPosn AnBxMsgCommon.Ident
   | TOPENP AlexPosn
   | TCLOSEP AlexPosn
   | TCOMMA AlexPosn
   | TOPENB AlexPosn
   | TCLOSEB AlexPosn
   | TOPENSCRYPT AlexPosn
   | TCLOSESCRYPT AlexPosn
   | TCOLON AlexPosn
   | TOPENSQB AlexPosn
   | TCLOSESQB AlexPosn
   deriving (Eq,Show)

token_posn (TATOM p _) =p
token_posn (TOPENP p) =p
token_posn (TCLOSEP p) =p
token_posn (TCOMMA p) =p
token_posn (TOPENSCRYPT p) =p
token_posn (TCLOSESCRYPT p) =p
token_posn (TOPENB p) =p
token_posn (TCLOSEB p) =p
token_posn (TCOLON p) =p
token_posn (TOPENSQB p) =p
token_posn (TCLOSESQB p) =p
}