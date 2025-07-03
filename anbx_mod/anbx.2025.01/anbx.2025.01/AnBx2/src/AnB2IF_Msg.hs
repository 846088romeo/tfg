{-

 AnBx Compiler and Code Generator

 Copyright 2023-2025 Paolo Modesti
 Copyright 2023-2024 SCM/SCDT/SCEDT, Teesside University

Code adapted from the Msg.hs file of the
Open Source Fixedpoint Model-Checker version 2022

(C) Copyright Sebastian Moedersheim 2003,2022
(C) Copyright Jakub Janaszkiewicz 2022
(C) Copyright Paolo Modesti 2012
(C) Copyright Nicklas Bo Jensen 2012
(C) Copyright IBM Corp. 2009
(C) Copyright ETH Zurich (Swiss Federal Institute of Technology) 2003,2007

All Rights Reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

- Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

- Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

- Neither the name of the ETH Zuerich, IBM, nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

-}

-- slightly modified OFMC code, adding OFMC suffix to function names that may clash with existing functions

-- | This module defines the @Msg@ data type for the AnB translators and several functions for it. 
module AnB2IF_Msg(Ident,Operator(..),Msg,Theory,
           isConstant,isVariable,
           addSub,Substitution,
           eqMod,eqModBound,(===),catty,deCat,stdTheo,
           synthesizable,analysis,indy,
           normalizeXor,
           ppId,ppIdList,ppMsgOFMC,ppMsgListOFMC,ppXList,match0,isAtype)  where
import AnBAst (  Msg )
import AnBxMsg ( AnBxMsg (Comp,Atom), isAtype, patternMsgError, isCat, foldMsg )
import AnBxMsgCommon
    ( Operator(..),
      Ident,
      isConstant,
      isVariable,
      hideTypes,
      ppXList,
      ppId,
      ppIdList )
import AnB2IF_Common ( OutputType(Isa, Pretty, IF) )
import Data.List ( (\\), nubBy, intercalate )
import Control.Monad.State ( State, MonadState(get, put), evalState )
import Data.Containers.ListUtils (nubOrd)

-- | this is an internal constant to control the number of algebraic reasoning steps that the translator will use.
eqModBound :: Int
eqModBound = 3

-- | Type to identify the position of a subterm with in a term, e.g. the @y@ in @f(g(x,y),z)@ has position @[0,1]@. 
type Position = [Int]

-- | Substitutions when already extended to a homomorphism on @Msg@ 
type Substitution = Msg -> Msg

-- | Equational theory as a set of pairs of messages that are supposed to be equal
type Theory = [(Msg,Msg)]

-- | The message type belongs to class @Eq@: so @==@ is defined on
-- @Msg@, namely as equivalence modulo via at most @eqModBound@ applications of an equivalence in 
-- @stdTheo@.
-- instance Eq Msg where
-- a==b = a===b || elemBy (===) a (eqMod eqModBound stdTheo [b])

--- internal function -- | @elemBy eq a list@ is true if @a@ is an element of @list@ modulo relation @eq@
-- elemBy eq a = any (eq a)

-- | syntactic equivalence on @Msg@
(===) :: Msg -> Msg -> Bool
(Atom ident)===(Atom ident') = ident==ident'
(Comp f xs)===(Comp g ys) = (f==g) && all (uncurry (===)) (zip xs ys)
_===_ = False

--- Algebraic equations ----

thA :: Msg
thA = Atom "TheoA"
thB :: Msg
thB = Atom "TheoB"
thC :: Msg
thC = Atom "TheoC"
thX :: Msg
thX = Atom "TheoX"
thY :: Msg
thY = Atom "TheoY"

stdAlgOps :: [Operator]
stdAlgOps = [Exp,Xor]

stdEqs :: [(Msg, Msg)]
stdEqs = [--- (A^X)^Y = (A^Y)^X
          (aexp (aexp thA thX) thY,
           aexp (aexp thA thY) thX),
          --- A xor B = B xor A
          (axor thA thB,
           axor thB thA),
          --- A xor (B xor C) = (A xor B) xor C
          (axor thA (axor thB thC),
           axor (axor thA thB) thC)]

aexp :: Msg -> Msg -> Msg
aexp a b = Comp Exp [a,b]
axor :: Msg -> Msg -> Msg
axor a b = Comp Xor [a,b]

-- | standard equational theory for @exp@ and @xor@
stdTheo :: [(Msg, Msg)]
stdTheo = stdEqs++[(r,l) | (l,r) <- stdEqs]

--- internal function -- | equivalence modulo one application of a rule of a theory
eqModOne :: Theory -> [Msg] -> [Msg]
eqModOne theo msgs =
  Data.List.nubBy (===)
      (msgs++
       maxLength 10
       [ replaceOFMC msg pos (sigma r)
       | (l,r) <- theo, msg <- msgs, (sigma,pos) <- matchAllPos l msg])

maxLength :: (Eq t, Num t, Show a) => t -> [a] -> [a]
maxLength 0 l = error ("Length exceeded: " ++ show (take 10 l))
maxLength _ [] = []
maxLength n (x:xs) = x:maxLength n xs

-- | equivalence modulo a given number of applications of rules of a theory
eqMod :: Int -> Theory -> [Msg] -> [Msg]
eqMod 0 _ msgs = msgs
eqMod n theo msgs = eqMod (n-1) theo (eqModOne theo msgs)


--- internal function -- | @replaceOFMC m p m'@  replaces in message @m@ the subterm at position @p@ with @m'@. 
replaceOFMC :: Msg -> Position -> Msg -> Msg
replaceOFMC _ [] msg' = msg'
replaceOFMC (Comp f xs) (i:pos) msg' =
  let (pre,x:post) = splitAt i xs in
  Comp f (pre++[replaceOFMC x pos msg']++post)
replaceOFMC (Atom a) _ _ = error ("replace OFMC unhandled " ++ show a )
replaceOFMC msg _ _ = error $ patternMsgError msg "replaceOFMC"

{-
--- internal function -- | all valid position in a @Msg@
positions :: Msg -> [Position]
positions = foldMsg (\x -> [[]])
		    (\_ xs-> []:[i:p| (i,x) <- zip [0..] xs, p<-x])
-}

--- internal function -- | positions where algebraic properties can be applied 
positionsAlg :: Msg -> [Position]
positionsAlg (Atom _) = []
positionsAlg (Comp f xs) = ([[] | f `elem` stdAlgOps]) ++ [i:p | (i,x) <- zip [0..] xs, p <- positionsAlg x]
positionsAlg msg = error $ patternMsgError msg "positionsAlg"

--- internal function -- | returns the subterm of a message at a given position
atPos :: Position -> Msg -> Msg
atPos [] msg = msg
atPos (i:p) (Comp _ xs) = atPos p (xs !! i)
atPos _ (Atom a) = error ("atPos: unhandled " ++ show a)
atPos _ msg = error $ patternMsgError msg "atPos"

--- internal function -- | @matchAllPos p m@ find all (algebraic) positions in @m@ that
-- match @p@
matchAllPos :: Msg -> Msg -> [(Substitution,Position)]
matchAllPos pattern msg =
  [ (sigma,pos)
  | pos <- positionsAlg msg,
    sigma <- match pattern (atPos pos msg) ]

--- internal function -- | normal matching between terms
match :: Msg -> Msg -> [Substitution]
match m1 m2 = match0 [(m1,m2)] id
--- warning: this is matching in free algebra!

-- | Matching function: takes a list of pairs @(p,m)@ of messages and
-- an initial substitution @sigma0@. (Typically, this is called with
-- the identity as an initial substitution.) We require that @sigma0@
-- does not substitute variables that occur in any pair @(p,m)@. The
-- procedure computes all substitutions @sigma@ that extend the
-- initial substitution @sigma0@ such that @p sigma=m@. Warning:
-- variables in @m@ may not be handled correctly, 
match0 :: [(Msg,Msg)] -> Substitution -> [Substitution]
match0 [] sigma = [sigma]
match0 ((Atom x,Atom y):rest) sigma
  | x==y = match0 rest sigma
  | isVariable x = let tau = addSub sigma x (Atom y)
                   in match0 (map (\(m1,m2) -> (tau m1,tau m2)) rest) tau
  | otherwise = []
match0 ((Comp f xs,Comp g ys):rest) sigma =
  if f==g && length xs==length ys then
    match0 (zip xs ys++rest) sigma
  else []
match0 ((Atom x,m):rest) sigma =
  if isVariable x then
    let tau = addSub sigma x m
    in match0 (map (\(m1,m2) -> (tau m1,tau m2)) rest) tau
  else []
match0 _ _ = []


-- | @addSub sigma x t@ yields the substition @[x|->t] . sigma@ where
-- we assume that x and the variables of t are disjoint from the
-- domain of sigma and x does not occur in the range of sigma.
addSub :: Substitution -> Ident -> Msg -> Substitution
addSub sigma x t =
  foldMsg (\ y -> if x==y then t else sigma (Atom y))
          (\ f xs -> Comp f xs)

--------------------------------------------------
--------------------- Ground Dolev-Yao -----------

-- | Ground Dolev-Yao: @synthesizable ik m@ holds (for ground @ik@ and
-- @m@) if @m@ can be composed from messages in @ik@ (i.e. without
-- analysis steps). This does take the standard equational theory into
-- account.
synthesizable :: [Msg] -> Msg -> Bool
synthesizable ik m =
 any (synthesizable0 ik) (eqMod eqModBound stdTheo [m])


--- internal function
synthesizable0 :: [Msg] -> Msg -> Bool
synthesizable0 ik m =
  (m `elem` ik) || (case m of
   Atom _             -> False
   Comp Inv _         -> False
   Comp (Userdef _) _ -> error ("Not yet supported: " ++ show m)
   Comp Xor list      ->
     all (synthesizable ik) list ||
     any (\(Comp Xor list')-> list'==list)
          [normalizeXor (Comp Xor (l1++l2))
          |Comp Xor l1<-ik,
           Comp Xor l2<-ik, l1/=l2]
   Comp _ ms          -> all (synthesizable ik) ms
   msg -> error $ patternMsgError msg "synthesizable0")

data AnalysisState = AnaSt { new  :: [Msg],
                             test :: [Msg],
                             done :: [Msg] }

initAna :: [Msg] -> AnalysisState
initAna ik = AnaSt { new=ik,test=[],done=[] }

-- type AnaM a = State AnalysisState a

top :: State AnalysisState Msg
top     = do st <- get
             (return . head . new) st

getik :: State AnalysisState [Msg]
getik   = do st <- get
             return (nubOrd (new st ++ done st ++ test st))

pop :: State AnalysisState ()
pop     = do st <- get
             put (st {new  = tail (new st), done = head (new st):done st})
delay :: State AnalysisState ()
delay   = do st <- get
             put (st {new  = tail (new st), test = head (new st):test st})

push :: [Msg] -> State AnalysisState ()
push ms = do pop
             st <- get
             put (st {new = ms++ new st ++ test st ,test = []})

pushMore :: [Msg] -> State AnalysisState ()
pushMore ms
        = do st <- get
             put (st {new = nubOrd (ms++new st++test st),test = []})

isEmpty :: State AnalysisState Bool
isEmpty = do null . new <$> get

analysis0 :: State AnalysisState [Msg]
analysis0 =
  do b <- isEmpty
     if b then getik else
      do x <- top
         ik <- getik
         (case x of
          Atom _ -> pop
          Comp Crypt [Comp Inv [k],p] ->
            if synthesizable (ik\\[x]) p then pop else
            if synthesizable (ik\\[x]) k then push [p] else delay
          Comp Crypt [k,p] ->
            if synthesizable (ik\\[x]) p then pop else
            if synthesizable (ik\\[x]) (Comp Inv [k]) then push [p] else delay
          Comp Scrypt [k,p] ->
            if synthesizable (ik\\[x]) p then pop else
            if synthesizable (ik\\[x]) k then push [p] else delay
          Comp Cat ms  -> push ms
          Comp Inv   _ -> pop
          Comp Apply _ -> pop
          Comp Exp   _ -> pop
          Comp Xor ms ->
           if length ik > 200 then
            error ("Exceeding length...: " ++ (show ms ++ "\n" ++ show (getallXors ms (ik\\[x])) ++ "\n" ++ show ik))
           else
            let new = getallXors ms (ik\\[x]) \\ ik in
            if null new then do delay else do pushMore new
          _ -> error ("Analysis: Not yet supported: " ++ show x))
         analysis0

--- compute which of the components can be generated and 
--- also which other XORs have a common component
getallXors ::  [Msg] -> [Msg] -> [Msg]
getallXors terms ik =
  let terms' = filter (not . synthesizable ik) terms in
    ([normalizeXor (Comp Xor terms') | length terms'/=length terms])

-- | Normalize a ground term modulo the cancelation theory for XOR
-- (i.e. @t XOR t -> e@ and @t XOR e -> t@).
normalizeXor :: Msg -> Msg
normalizeXor (Comp f xs) =
  let xs'= map normalizeXor xs
  in case f of
     Xor -> case getFirstDupRemoved xs [] of
            Nothing -> let xs''= filter ((/=) (Atom "e")) xs'
                       in case xs'' of
                          [] -> Atom "e"
                          [x] -> x
                          _ -> Comp Xor xs''
            Just xs'' -> normalizeXor (Comp Xor xs'')
     _ -> Comp f xs'
normalizeXor m = m

getFirstDupRemoved :: Eq a => [a] -> [a] -> Maybe [a]
getFirstDupRemoved [] _ = Nothing
getFirstDupRemoved (x:xs) done =
  if x `elem` done then Just ((reverse done\\[x])++xs)
  else getFirstDupRemoved xs (x:done)

-- | Analysis according to Dolev-Yao: given ground set of messages,
-- compute the closure under analysis steps (pairs are filtered out). 
analysis :: [Msg] -> [Msg]
analysis = filter (not . isCat) . evalState analysis0 . initAna

-- | @indy ik m@ holds for ground @ik@ and @m@ if @ik |- m@ (Dolev-Yao
-- deduction modulo the standard equational theory).
indy :: [Msg] -> Msg -> Bool
indy = synthesizable . analysis

------------ Pretty Printing -----------------------

--- local
ppagentisa :: Msg -> String
ppagentisa (Atom "i") = "dishonest i"
ppagentisa (Atom "a") = "honest a"
ppagentisa (Atom "b") = "honest b"
ppagentisa (Atom a) = if isVariable a then a else error ("Illegal agent name: " ++ show a)
ppagentisa m = error ("Illegal agent name: " ++ show m)

-- | print a message
ppMsgOFMC :: OutputType -> Msg -> String
ppMsgOFMC ot (Atom x) =
  case ot of
  Isa -> if x=="a" then error "UNTYPED agent a" else
         if x=="b" then error "UNTYPED agent b" else
         if x=="i" then error "UNTYPED agent i" else
         if x=="SID" then "(SID sid)" else
         if length x ==1 && (head x `elem` ['0'..'9'])
              then "Step "++x else ppId x
  _ -> ppId x
ppMsgOFMC ot (Comp f xs) =
  case f of
  Cat -> case ot of
         Pretty -> ppMsgListOFMC ot xs
         IF -> catty IF xs
         Isa -> catty Isa xs
  Apply -> case ot of
         Pretty -> if isAtype  (head xs) && hideTypes  then ppMsgListOFMC ot (tail xs)
                   else ppMsgOFMC ot (head xs) ++ "(" ++ ppMsgListOFMC ot (tail xs) ++ ")"
         IF -> if isAtype  (head xs)
               then ppMsgListOFMC ot (tail xs)
               else "apply(" ++ ppMsgListOFMC ot xs ++ ")"
         Isa ->
               if isAtype (head xs)
               then case head xs of
                     (Atom "typeAgent") -> "Agent (" ++ ppagentisa (head (tail xs)) ++ ")"
                     (Atom "typeNumber") -> "Nonce (" ++ ppMsgListOFMC ot (tail xs) ++ ")"
                     (Atom "typeFun") -> ppMsgListOFMC ot (tail xs)
                     (Atom "typeSK") -> "SymKey (" ++ ppMsgListOFMC ot (tail xs) ++ ")"
                     (Atom "typePK") -> "PubKey (" ++ ppMsgListOFMC ot (tail xs) ++ ")"
                     (Atom "typePurpose") -> "Purpose (" ++ ppMsgListOFMC ot (tail xs) ++ ")"
                     (Atom any) -> error ("Unknown Isa type: " ++ any)
                     _ -> error ("ppMsgOFMC - unhandled type: " ++ show ot)
               else ppMsgOFMC ot (head xs) ++ "(" ++ ppMsgListOFMC ot (tail xs) ++ ")"
  Crypt -> case ot of
         Pretty ->  "{" ++ (ppMsgOFMC ot . head . tail) xs ++ "}" ++ ppMsgOFMC ot (head xs)
         IF -> "crypt(" ++ ppMsgListOFMC ot xs ++ ")"
         Isa -> "crypt(" ++ ppMsgListOFMC ot xs ++ ")"
  Scrypt -> case ot of
         Pretty ->  "{|" ++ (ppMsgOFMC ot . head . tail) xs ++ "|}" ++ ppMsgOFMC ot (head xs)
         IF -> "scrypt(" ++ ppMsgListOFMC ot xs ++ ")"
         Isa -> "scrypt(" ++ ppMsgListOFMC ot xs ++ ")"
  Inv -> "inv(" ++ (ppMsgOFMC ot .head) xs ++ ")"
  Exp -> "exp(" ++ ppMsgListOFMC ot xs ++ ")"
  Xor -> "xor(" ++ ppMsgListOFMC ot xs ++ ")"
  -- <paolo> SQN hack
  Userdef id -> id ++ "(" ++ ppMsgListOFMC ot xs ++ ")" 
  -- </paolo> SQN hack
ppMsgOFMC _ msg = error $ patternMsgError msg "ppMsgOFMC"  
  -- _ -> (show f ++ "(" ++ ppMsgList ot xs ++ ")"

-- | remove the Cat-operator from a message (return the list of concatenated messages).
deCat :: Msg -> [Msg]
deCat (Comp Cat ms) = ms
deCat m = error ("decat function used in the wrong context: " ++ show m)

-- | print non-empty list of messages @[m1,...,mk]@ in the form
-- @pair(m1,pair(m2,...,mk))@ using @ppMsg@ for printing messages with
-- the given output format.
catty :: OutputType -> [Msg] -> [Char]
catty _ [] = error "Empty Concatenation"
catty display [x] = ppMsgOFMC  display x
catty display [x,y] = "pair(" ++ ppMsgOFMC  display x ++ "," ++ ppMsgOFMC  display y ++ ")"
catty display (x:y:z) = "pair(" ++ ppMsgOFMC  display x ++ "," ++ catty display (y:z) ++ ")"

-- | print list of messages (comma-separated)
ppMsgListOFMC :: OutputType -> [Msg] -> String
ppMsgListOFMC ot list =
  case ot of
  Isa -> ppXListOFMC (ppMsgOFMC ot) "," (filter firstorder list)
  _ -> ppXListOFMC (ppMsgOFMC ot) "," list

firstorder :: Msg -> Bool
firstorder (Comp Apply [Atom "typeFun",_]) = False
firstorder _ = True

-- | generic printing functional: given a printer for type @alpha@, a
-- seperator, and a list of @alpha@-type elements, compute the
-- printout of this list using the @alpha@-printer and interspered by
-- the seperator.
ppXListOFMC :: (a -> String) -> String -> [a] -> String
ppXListOFMC ppX sep = intercalate sep . map ppX
