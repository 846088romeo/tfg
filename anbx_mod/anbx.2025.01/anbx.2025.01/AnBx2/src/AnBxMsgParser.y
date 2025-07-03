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

module AnBxMsgParser where
import AnBxMsgLexer
import AnBxMsg
import AnBxMsgCommon
}

%name anbxmsgparser
%tokentype {Token}

%token            
  ident        { TATOM _ $$ }
  "("          { TOPENP _  }
  ")"          { TCLOSEP _ }
  ","          { TCOMMA _ }
  "{|"         { TOPENSCRYPT _ }
  "|}"         { TCLOSESCRYPT _ }
  "{"          { TOPENB _ }
  "}"          { TCLOSEB _ }
  ":"          { TCOLON _ }
  "["          { TOPENSQB _ } 
  "]"          { TCLOSESQB _ }
%%

msglist :: {[AnBxMsg]}
  : msgNOP {[$1]}
  | msgNOP "," msglist {$1:$3}

msg :: {AnBxMsg}
  : msgNOP               {$1}
  | msgNOP "," msg       {Comp Cat [$1,$3]}

msgNOP :: {AnBxMsg}
  : ident                {Atom $1}
  | "~" msgNOP           {PrevSession $2}
  | "{" msg "}" msgNOP   {Comp Crypt [$4,$2]}
  | "{|" msg "|}" msgNOP {Comp Scrypt [$4,$2]}
  | ident "(" msglist ")"{if $1=="inv" then Comp Inv $3
                          else if $1=="exp" then Comp Exp $3
                          else if $1=="xor" then Comp Xor $3
                          else case $3 of
                                [x] -> Comp Apply ((Atom $1):[x])
                                _ -> Comp Apply ((Atom $1):[Comp Cat $3])}
  | "(" msg ")"                 {$2}
--<paolo>
  | "[" msg "]"                 {DigestHash $2}
  | "[" msg ":" ident "]"       {DigestHmac $2 $4}
--</paolo>

---------------------------------

{
happyError :: [Token] -> a
happyError tks = error ("AnBxMsg parse error at " ++ lcn ++ "\n" )
        where
        lcn = case tks of
                          [] -> "end of file"
                          tk:_ -> "line " ++ show l ++ ", column " ++ show c ++ " - Token: " ++ show tk
                                where
                                        AlexPn _ l c = token_posn tk
}
