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

module AnBxParser where
import AnBxLexer
import AnBxAst
import AnBxMsg
import AnBxMsgCommon
import Data.Char
import AnBxMain (setCertifiedAgents)
}

%name anbxparser
%tokentype { Token }
%error { happyError }

%token            
  ident                 { TATOM _ $$}
   --- <AnBx Tokens>  
  "-"                   { THYPHEN _ }
  "^"                   { THAT _ }
   "@"                  { TAT _ }
  "Definitions"         { TDEFINITIONS _}
  "Shares"              { TSHARES _}
  "share"               { TSHARE _}
  "agree"               { TAGREE _}
  "insecurely"          { TAGREEINSECURELY _}
  "<"                   { TOPENAB _  }
  ">"                   { TCLOSEAB _ }
  "|"                   { TVERLINE _ }
  "Equations"           { TEQUATIONS _ }
   --- </AnBx Tokens>  
  "("                   { TOPENP _  }
  ")"                   { TCLOSEP _ }
  "{"                   { TOPENB _  }
  "}"                   { TCLOSEB _ }
  "{|"                  { TOPENSCRYPT _}
  "|}"                  { TCLOSESCRYPT _}
  ":"                   { TCOLON _  }
  ";"                   { TSEMICOLON _ }
  "*->*"                { TSECCH _  }
  "*->"                 { TAUTHCH _ }
  "->*"                 { TCONFCH _ }
  "->"                  { TINSECCH _}
  "*->>"                { TFAUTHCH _}
  "*->>*"               { TFSECCH _}
  "%"                   { TPERCENT _}
  "!"                   { TEXCLAM  _}
  "!="                  { TUNEQUAL _}
  "."                   { TDOT _ }
  ","                   { TCOMMA _ }
  "["                   { TOPENSQB _ }
  "]"                   { TCLOSESQB _ }
  -- New token
  "~"                   { TPREVSESSION _}
  -- -----------
  "Protocol"            { TPROTOCOL _ }
  "Knowledge"           { TKNOWLEDGE _}
  "where"               { TWHERE _}
  "Types"               { TTYPES _}
  "Actions"             { TACTIONS _}
  "Abstraction"         { TABSTRACTION _}
  "Goals"               { TGOALS _}
  "authenticates"       { TAUTHENTICATES _}
  "weakly"              { TWEAKLY _}
  "on"                  { TON _}
  "secret"              { TSECRET _}
  "between"             { TBETWEEN _}
  "confidentially"      { TCONFIDENTIAL _}
  "sends"               { TCONFIDENTIALSENDS _}
  "to"                  { TTO _}
  "guessable"           { TGUESS _}
  "="                   { TEQUAL _}
  "funsign"             { TFUNSIGN _}

%%

protocol :: {AnBxProtocol}
  : "Protocol" ":" protname
    "Types" ":" typedec
    defdec
    equations
    "Knowledge" ":" knowledge optwheredec
    "Actions" ":" actionsdec
    "Goals" ":" goalsdec
    absdec 
    {($3, setCertifiedAgents $6 (snd $3), $7, $8, (fst $11, $12), snd $11, $19, $15, $18)}
    
--    {($3, $6, $7, $8, (fst ($11), $12), snd ($11), $19, $15, $18)}

protname :: {ProtName}
    : ident {($1,PTAnBx)}
    | ident ident {case map toLower $2 of
                        "anbx" -> ($1,PTAnBx)
                        "anb"  -> ($1,PTAnB)
                        _ -> error ("Unknown Protocol Type: " ++ $2)}
    
optSemicolon :: {()}
: ";"  {()}
|      {()}

absdec :: {AnBxAbstraction}
  : {[]}
  | "Abstraction" ":" abslist {$3}

abslist :: {AnBxAbstraction}
  : ident "->" msgNOP optSemicolon {[($1,$3)]} 
  | ident "->" msgNOP ";" abslist {(($1,$3):$5)}

--- <AnBx Mod>
defdec :: {AnBxDefinitions}
  : {[]}
  | "Definitions" ":" deflist {$3}

deflist :: {AnBxDefinitions}
  : def optSemicolon {[$1]} 
  | def ";" deflist {($1:$3)} 
    
defidentlist :: {[AnBxMsg]}
  : ident {[Atom $1]}
  | ident "," defidentlist {((Atom $1):$3)}
    
def :: {AnBxDefinition}
  : ident ":" msg {Def (Atom $1) $3}
  | ident "(" ident ")" ":" msg {Def (Comp Apply [Atom $1,Atom $3]) $6}
  | ident "(" defidentlist ")" ":" msg {Def (Comp Apply ((Atom $1):[Comp Cat $3])) $6}

equations :: {AnBxEquations}
  : {[]}
  | "Equations" ":" eqlist {$3}

eqlist :: {AnBxEquations}
  : eq optSemicolon {[$1]} 
  | eq ";" eqlist {($1:$3)} 

eq :: {AnBxEquation}
  : msg "=" msg {Eqt $1 $3}
  
--- </AnBx Mod>

funsign :: {([AnBxType],AnBxType,PrivateFunction)}
          : typelist "->" type {($1,$3,PubFun)}         -- public functions
          | typelist "->*" type {($1,$3,PrivFun)}       -- private functions       

typeOption :: {TypeOpts}
    : ident "=" ident {[Option ($1,Atom $3)]}
    | ident "=" ident "," typeOption {(Option ($1,Atom $3)):$5}
    | funsign {[FunSign $1]}
    | funsign "," typeOption {(FunSign $1):$3}

typeOptions :: {TypeOpts}
    : {[]} 
    | "[" typeOption "]" {$2}    

typelist :: {[AnBxType]} 
        : type {[$1]}
        | type "," typelist {$1:$3}

typedec :: {AnBxTypes} 
  : type identlist optSemicolon {[($1,$2)]}
  | type identlist ";" typedec {($1,$2):$4}

type :: {AnBxType}
  : ident typeOptions {case $1 of
               "Agent" -> Agent False False $2 NoCert   -- no certified by default
               "Certified" -> Agent False False $2 Cert  -- certified agent
               "Number" -> Number $2
               "SeqNumber" -> SeqNumber $2
               "PublicKey" -> PublicKey $2
               "SymmetricKey" -> SymmetricKey $2
               "Symmetric_key" -> SymmetricKey $2  -- sic!! (OFMC)
               "Function" -> Function $2           
               "Untyped" -> Untyped $2
               _ -> Custom $1 $2
               }

identlist :: {[Ident]}
  : ident {[$1]}
  | ident "," identlist {$1:$3}

knowledge :: {([AnBxKnowledgeAgent], [AnBxShare])}
    : ident ":" msglist optSemicolon { ([($1,$3)], []) }
    | ident ":" msglist ";" knowledge { let (agents, shares) = $5 in (($1,$3) : agents, shares) }
    | ident "," identlist "share" msglist optSemicolon { ([], [(SHShare, ($1 : $3), $5)]) }
    | ident "," identlist "share" msglist ";" knowledge { let (agents, shares) = $7 in (agents, (SHShare, ($1 : $3), $5) : shares) } 
    | ident "," identlist "agree" msglist optSemicolon { ([], [(SHAgree, ($1 : $3), $5)]) }
    | ident "," identlist "agree" msglist ";" knowledge { let (agents, shares) = $7 in (agents, (SHAgree, ($1 : $3), $5) : shares) }
    | ident "," identlist "insecurely" "agree" msglist optSemicolon { ([], [(SHAgreeInsecurely, ($1 : $3), $6)]) }
    | ident "," identlist "insecurely" "agree" msglist ";" knowledge { let (agents, shares) = $8 in (agents, (SHAgreeInsecurely, ($1 : $3), $6) : shares) }

optwheredec :: {AnBxKnowledgeWhere}
  : "where" wheredec {$2}
  | {[]}  

wheredec :: {[(AnBxMsg,AnBxMsg)]}
: ident "!=" ident {[(Atom $1,Atom $3)]}
| ident "!=" ident "," wheredec {((Atom $1,Atom $3):$5)}

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

actionsdec :: {AnBxActions}
  : action {[$1]}
  | action actionsdec {($1:$2)}

action :: {AnBxAction}
  : channel ":" msg "%" msg "!" msg 
     {($1,$3,Just $5,Just $7)}
  | channel ":" msg "%" msg 
     {($1,$3,Just $5,Nothing)}
  | channel ":" msg 
     {($1,$3,Nothing,Nothing)}

channeltype :: {AnBxChannelType}
  : "*->*"      {Secure}
  | "*->"       {Authentic}
  | "->*"       {Confidential}
  | "->"        {Insecure}

channeltypeG :: {AnBxChannelType}
  : "*->*"      {FreshSecure}
  | "*->"       {FreshAuthentic}
  | "->*"       {Confidential}
  | "->"        {Insecure}
  
--- <AnBx channels> 

bmchannelmode :: {AnBxChannelType} 
-- pair notation
  : "^" "(" "@" peerC "," peer")"                          { BMChannelTypePair ForwardFresh $4 $6 }
  | "^" "("  peerC "," peer")"                             { BMChannelTypePair Forward $3 $5 }
  | "(" "@" peerC "," peer")"                              { BMChannelTypePair Fresh $3 $5 }
  | "(" peerC "," peerC ")"                                { BMChannelTypePair Std $2 $4 } 
-- triple notation
  | "^" "(" "@" peerC "," verlist "," peerC ")"            { BMChannelTypeTriple ForwardFresh $4 $6 $8 }
  | "^" "("  peerC "," verlist "," peerC ")"               { BMChannelTypeTriple Forward $3 $5 $7 }
  | "(" "@" peerC "," verlist "," peerC ")"                { BMChannelTypeTriple Fresh $3 $5 $7 }
  | "(" peerC "," verlist "," peerC  ")"                   { BMChannelTypeTriple Std $2 $4 $6} 
-- new triple notation (with @ outside parenthesis)
  | "^" "@" "(" peerC "|" verlist3 "|" peerC ")"           { BMChannelTypeTriple ForwardFresh $4 $6 $8 }
  | "^" "("  peerC "|" verlist3 "|" peerC ")"              { BMChannelTypeTriple Forward $3 $5 $7 }
  | "@" "(" peerC "|" verlist3 "|" peerC ")"               { BMChannelTypeTriple Fresh $3 $5 $7 }
  | "(" peerC "|" verlist3 "|" peerC ")"                   { BMChannelTypeTriple Std $2 $4 $6} 
  
  --- </AnBx channels> 
  
verlist3 :: {[Ident]}
  -- : "-"           {["-"]}
  : "-"           {[]}         -- null Verifiers
  | identlist     {$1}  
  
channel :: {AnBxChannel} 
--- <AnBx channels> 
  : peer channeltype peer "," bmchannelmode {($1,$5,$3)}
--- </AnBx channels> 
  | channelG {$1}

channelG :: {AnBxChannel} 
  : peer channeltype peer {($1,$2,$3)} 
 
channelGoal :: {AnBxChannel} 
  : peer channeltypeG peer {($1,$2,$3)} 

--- peer used in channel notation 
peerC :: {AnBxPeer}
    : peer          {$1}     
    | nullpeer      {$1}

peer :: {AnBxPeer}
  : ident {($1,False,Nothing)}
  | pseudonym {$1}
  
nullpeer ::  {AnBxPeer}
  : "-"  {("-",False,Nothing)}
  
pseudonym :: {AnBxPeer}
  : "[" ident "]" {($2,True,Nothing)}
  | "[" ident ":" msg "]" {($2,True, Just $4)}

goalsdec :: {AnBxGoals}
  : goal {[$1]}
  | goal goalsdec {$1:$2}

goal :: {AnBxGoal}
  : channelGoal ":" msg                                             {(ChGoal $1 $3 "")}
  | peer "authenticates" peer "on" msg                              {(Authentication $1 $3 $5 "")}
  | peer "weakly" "authenticates" peer "on" msg                     {(WAuthentication $1 $4 $6 "")}
  | peer "confidentially" "sends" msg "to" peer                     {(ChGoal ($1,Confidential,$6) $4 "")} -- {(ConfidentiallySends $1 $6 $4 "")} 
  | msg "secret" "between" peers                                    {(Secret $1 $4 False "")}
  | msg "guessable" "secret" "between" peers                        {(Secret $1 $5 True "")}

peers :: {[AnBxPeer]}
  : peer {[$1]}
  | peer "," peers {($1:$3)}

 verlist :: {[Ident]}
  : ident {[$1]}
  | "[" ident "]" {[$2]}
  | "[" identlist "]" {$2}

---------------------------------
{

happyError :: [Token] -> a
happyError tks = error ("AnBx parse error at " ++ lcn ++ "\n" )
        where
        lcn = case tks of
                          [] -> "end of file"
                          tk:_ -> "line " ++ show l ++ ", column " ++ show c ++ " - Token: " ++ show tk
                                where
                                        AlexPn _ l c = token_posn tk
}