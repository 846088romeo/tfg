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

module AnBxImplementationCIF where

import           AnBxAst
import           AnBxMsg
import           AnBxMsgCommon
import           Debug.Trace   ()


---- remove forward symbol ---

mkAnBxCIF :: AnBxProtocol -> AnBxProtocol
mkAnBxCIF (name,types,definitions,equations,knowledge,shares,abstraction,actions,goals) = (name,types,definitions,equations,knowledge,shares,abstraction,mkActionsCIF actions,goals)

mkActionsCIF :: AnBxActions -> AnBxActions
mkActionsCIF = map mkActionCIF

mkActionCIF :: AnBxAction -> AnBxAction
mkActionCIF (ch,msg,msg1,msg2) = (mkAnBxChannelCIF ch,msg,msg1,msg2)

mkAnBxChannelCIF :: AnBxChannel -> AnBxChannel
mkAnBxChannelCIF (p1,BMChannelTypeTriple Forward auth vers conf,p2) = (p1,BMChannelTypeTriple Std auth vers conf,p2)
mkAnBxChannelCIF (p1,BMChannelTypeTriple ForwardFresh auth vers conf,p2) = (p1,BMChannelTypeTriple Fresh auth vers conf,p2)
mkAnBxChannelCIF ch = ch

--- NonceStore ---
                  -- agent,verifiers,msg,Nonce,step
type NonceEntry = (Ident,[Ident],AnBxMsg,Ident,ConcatPos)
type NonceStore = [NonceEntry]

getNonceFromStore :: (Ident,[Ident],AnBxMsg) -> NonceStore -> Maybe (Ident,ConcatPos)
getNonceFromStore _ [] = Nothing
getNonceFromStore (agent,vers,msg) ((a,v,m,n,cPos):xs) = if (agent==a) && (vers==v) && (msg==m) then Just (n,cPos) else getNonceFromStore (agent,vers,msg) xs

-- the most recent nonce is taken
addNonceToStore :: NonceEntry -> NonceStore -> NonceStore
addNonceToStore x xs = x : xs



