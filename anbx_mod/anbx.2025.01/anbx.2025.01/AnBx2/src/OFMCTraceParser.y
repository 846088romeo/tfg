{
{-

 AnBx Compiler and Code Generator

 Copyright 2021-2024 Rémi Garcia
 Copyright 2021-2024 Paolo Modesti
 Copyright 2021-2024 SCM/SCDT/SCEDT, Teesside University

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

module OFMCTraceParser where
import AnBAst
import AnBxMsgCommon
import AnBxMsg ( AnBxMsg (Comp,Atom))
import AnBxAst ( AnBxChannelType(Insecure))
import qualified OFMCTraceLexer as L
}
%name ofmctraceparser
%tokentype { L.Token }
%error { happyError }

%token 
      ident           { L.TATOM _ $$ }
      ":"             { L.TCOLON _  }
      ","             { L.TCOMMA _ }
      "("             { L.TOPENP _ }
      ")"             { L.TCLOSEP _ }
      "->"            { L.TINSECCH _ }
      "XOR"           { L.TXOR _ }
      "{"             { L.TOPENB _ }
      "}_"            { L.TCLOSEB _ }
      "{|"            { L.TOPENSCRYPT _ }
      "|}_"           { L.TCLOSESCRYPT _ }
      "Reached"       { L.TREACHED _ }
      "State"         { L.TRSTATE _ }
      "%"             { L.TPERCENT _ }
      newline         { L.TACTSEP _ }
      int             { L.TINT _ $$ }

%%

ofmctrace :: {(Actions, [Msg])}
  : actionslist "%" "Reached" "State" ":" newline reachedstate {($1,$7)}

actionslist :: {Actions}
  : action {[$1]}
  | action actionslist {($1:$2)}

action :: {Action}
  : channel ":" msg newline {($1,$3,Nothing,Nothing)}

channel :: {Channel} 
  : peer "->" peer {($1,Insecure,$3)}

msglist :: {[Msg]}
  : msgNOP {[$1]}
  | msgNOP "," msglist {$1:$3}

msg :: {Msg}
 : msgNOP                {$1}
 | msgNOP "," msg           {Comp Cat [$1,$3]}

msgNOP :: {Msg}
  : ident                 {Atom $1}
  | int 		  {Atom $1}
  | ident "(" int ")"     {Atom $1}
  | "{" msg "}_" msgNOP   {Comp Crypt [$4,$2]}
  | "{|" msg "|}_" msgNOP {Comp Scrypt [$4,$2]}
  | ident "(" msglist ")"{if $1=="inv" then Comp Inv $3
                          else if $1=="exp" then Comp Exp $3
                        --  else if $1=="xor" then Comp Xor $3
                          else case $3 of
                                [x] -> Comp Apply ((Atom $1):[x])
                                _ -> Comp Apply ((Atom $1):[Comp Cat $3])}
  | msgNOP "XOR" msgNOP {Comp Xor [$1,$3]}
  | "(" msg ")"                 {$2}


peer :: {Peer}
  : ident {($1,False,Nothing)}
    | "(" ident "," int ")" {($2,False,Nothing)}


reachedstate :: {[Msg]}
  : "%" newline reachedstate {$3}
  | "%" msgNOP newline {[$2]}
  | "%" msgNOP newline reachedstate {$2:$4}
{

happyError :: [L.Token] -> a
happyError tks = error ("OFMC trace parse error at " ++ lcn ++ "\n" )
        where
        lcn = case tks of
                          [] -> "end of file"
                          tk:_ -> "line " ++ show l ++ ", column " ++ show c ++ " - Token: " ++ show tk
                                where
                                        L.AlexPn _ l c = L.token_posn tk
}
