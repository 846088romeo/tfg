{-

 AnBx Compiler and Code Generator

 Copyright 2023-2025 Paolo Modesti
 Copyright 2023-2024 SCM/SCDT/SCEDT, Teesside University

Code adapted from the LMsg.hs file of the
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

---------- Messages -----------------------

module AnB2IF_LMsg(LMsg,lanalysis,mkname,zipl) where
import AnB2IF_Msg
import AnBxMsg ( AnBxMsg (Comp,Atom), foldMsg)
import Data.List ( (\\) )
import Control.Monad.State
import qualified Data.Bifunctor
import Data.Containers.ListUtils (nubOrd)

-- | Labeled message: the message itself as it was specified in AnB,
-- and another message labeling it, representing the view that a
-- particular agent has on it. Example: @(h(N),HN)@ if we have what is
-- supposed to be a hash of a nonce, and we model an agent who cannot
-- check this (because he does not know the nonce and cannot invert
-- it).
type LMsg = (Msg,Msg)


--------------------------------------------------
--------------------- Ground Dolev-Yao -----------

llsynthesizable :: [LMsg] -> Msg -> [Msg]
llsynthesizable ik m =
  [ m | synthesizable (map fst ik) m]

data AnalysisState = AnaSt { new  :: [LMsg],
                             test :: [LMsg],
                             done :: [LMsg],
                             ik0  :: [LMsg],
                             sub  :: Substitution }


linitAna :: [LMsg] -> AnalysisState
linitAna lik = AnaSt
 { new = lik, test = [], done = [], sub = id, ik0 = lik }

-- type AnaM a = State AnalysisState a

top :: State AnalysisState LMsg
top     = do st <- get
             (return . head . new) st

getik :: State AnalysisState [LMsg]
getik   = do st <- get
             return (nubOrd (new st ++ done st ++ test st))

getikOut :: State AnalysisState ([LMsg], [LMsg])
getikOut= do st <- get
             return (ik0 st,nubOrd ((new st ++ done st ++ test st)\\ik0 st))

pop :: State AnalysisState ()
pop     = do st <- get

             put (st {new  = tail (new st), done = head (new st):done st})
delay :: State AnalysisState ()
delay   = do st <- get
             put (st {new  = tail (new st), test = head (new st):test st})

push :: [LMsg] -> State AnalysisState ()
push ms = do pop
             st <- get
             put (st {new = ms ++ new st ++ test st ,test = []})

isEmpty :: State AnalysisState Bool
isEmpty = do gets (null . new)

substitute :: Ident -> Msg -> State AnalysisState ()
substitute x t = do st <- get
                    let sub' = addSub (sub st) x t
                    put (st {new=sublml sub' (new st),
                                test=sublml sub' (test st),
                                done=sublml sub' (done st),
                                ik0=sublml sub' (ik0 st),
                                sub=sub'})

obtainName :: Msg -> State AnalysisState Msg
obtainName x = do st <- get
                  return (sub st (mkname x))

sublml :: Substitution -> [LMsg] -> [LMsg]
sublml sub = map (Data.Bifunctor.bimap sub sub)

lanalysis0 :: State AnalysisState ([LMsg], [LMsg])
lanalysis0 =
  do b <- isEmpty
     (if b then getikOut else
      do x <- top
         ik <- getik
         (case fst x of
          Atom _ -> pop
          Comp Crypt [Comp Inv [k],p] ->
            --- another way to derive p! 
            --- so we do not do this check: 
            --- if synthesizable ((map fst ik)\\[fst x]) p then pop else
            case llsynthesizable (ik\\[x]) k of
            [] -> delay
            _ ->
              case snd x of
              Comp Crypt [_,p'] ->
                push [(p,p')]
              Atom x ->
                do p'<-obtainName p
                   k'<-obtainName (Comp Inv [k])
                   substitute x (Comp Crypt [k',p'])
                   push [(p,p')]
              _ -> error ("Decomposition: " ++ show x)
          Comp Crypt [k,p] ->
            case llsynthesizable (ik\\[x]) (Comp Inv [k]) of
            [] -> delay
            _ ->
              case snd x of
              Comp Crypt [_,p'] ->
                push [(p,p')]
              Atom x ->
                do p'<-obtainName p
                   k'<-obtainName k
                   substitute x (Comp Crypt [k',p'])
                   push [(p,p')]
              _ -> error ("Decomposition: " ++ show x)
          Comp Scrypt [k,p] ->
            case llsynthesizable (ik\\[x]) k of
            [] -> delay
            _ ->
              case snd x of
              Comp Scrypt [_,p'] ->
               push [(p,p')]
              Atom x ->
               do p' <- obtainName p
                  k' <- obtainName k
                  substitute x (Comp Scrypt [k',p'])
                  push [(p,p')]
              _ -> error ("Decompositon: " ++ show x)
          Comp Cat ms  ->
            case snd x of
            Comp Cat ms' -> push (zipl ms ms')
            Atom x -> do ms' <- mapM obtainName ms
                         substitute x (Comp Cat ms')
                         push (zipl ms ms')
            _ -> error ("Decompositon: " ++ show x)
          Comp Inv   _ -> pop
          Comp Apply ms ->
           case snd x of
                Comp Apply _ -> pop
                Atom a ->
                    let ms' = map (llsynthesizable (ik\\[x])) ms in
                    if [] `elem` ms' then do delay
                    else do substitute a (Comp Apply (map head ms'))
                            pop
                x -> error ("Lanalysis not yet supported: " ++ show x )
          Comp Exp   _ -> pop
          Comp Xor [a,b] ->
           case (llsynthesizable (ik\\[x]) a,llsynthesizable (ik\\[x]) b) of
           ([],[]) -> delay
           _ -> case snd x of
                Atom t -> do a' <- obtainName a
                             b' <- obtainName b
                             substitute t (Comp Xor [a',b'])
                             push [(a,a'),(b,b')]
                Comp Xor [a',b'] -> push [(a,a'),(b,b')]
                _ -> error ("Lanalysis not yet supported: " ++ show x )
          _ -> error ("Lanalysis not yet supported: " ++ show x ))
         lanalysis0)

-- | Like zip with an additional check that the lengths of the zipped lists are identical
zipl :: [a] -> [b] -> [(a,b)]
zipl l1 l2 = if length l1==length l2 then zip l1 l2 else error "ZIP with different length!"

-- | Main analysis function: given a set of labeled messages, compute
-- the closure under analysis rules. This is typically used in the
-- translation step after an agent has learned a new message. The
-- existing labels of the messages may be updated by this, because
-- analysis reveals new checks that can be performed. Also, the result
-- distinguishes the 'old' and 'new' messages (i.e. messages that were
-- part of the given knowledge but may have new labels are
-- distinguished from messages obtained by analysis steps).
lanalysis :: [LMsg] -> ([LMsg],[LMsg])
lanalysis =
  evalState lanalysis0 . linitAna

-- | This function generates a 'unique' variable name of the form @Xsomething@ from a given message; 
mkname :: Msg -> Msg
mkname x = Atom ("X" ++ mkname0 x )
 where mkname0 = foldMsg id
                 (\f xs-> (if printable f then show f else "") ++ concat xs)
       printable f =  f `elem` [Crypt,Scrypt,Exp,Inv,Xor]
