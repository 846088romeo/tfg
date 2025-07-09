{-# OPTIONS_GHC -w #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE NoStrictData #-}
{-# LANGUAGE UnboxedTuples #-}
{-# LANGUAGE PartialTypeSignatures #-}
#if __GLASGOW_HASKELL__ >= 710
{-# LANGUAGE PartialTypeSignatures #-}
#endif
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
import qualified Data.Function as Happy_Prelude
import qualified Data.Bool as Happy_Prelude
import qualified Data.Function as Happy_Prelude
import qualified Data.Maybe as Happy_Prelude
import qualified Data.Int as Happy_Prelude
import qualified Data.String as Happy_Prelude
import qualified Data.Tuple as Happy_Prelude
import qualified Data.List as Happy_Prelude
import qualified Control.Monad as Happy_Prelude
import qualified Text.Show as Happy_Prelude
import qualified GHC.Num as Happy_Prelude
import qualified GHC.Err as Happy_Prelude
import qualified Data.Array as Happy_Data_Array
import qualified Data.Bits as Bits
import qualified GHC.Exts as Happy_GHC_Exts
import Control.Applicative(Applicative(..))
import Control.Monad (ap)

-- parser produced by Happy Version 2.1.5

newtype HappyAbsSyn  = HappyAbsSyn HappyAny
#if __GLASGOW_HASKELL__ >= 607
type HappyAny = Happy_GHC_Exts.Any
#else
type HappyAny = forall a . a
#endif
newtype HappyWrap5 = HappyWrap5 (AnBxProtocol)
happyIn5 :: (AnBxProtocol) -> (HappyAbsSyn )
happyIn5 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap5 x)
{-# INLINE happyIn5 #-}
happyOut5 :: (HappyAbsSyn ) -> HappyWrap5
happyOut5 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut5 #-}
newtype HappyWrap6 = HappyWrap6 (ProtName)
happyIn6 :: (ProtName) -> (HappyAbsSyn )
happyIn6 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap6 x)
{-# INLINE happyIn6 #-}
happyOut6 :: (HappyAbsSyn ) -> HappyWrap6
happyOut6 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut6 #-}
newtype HappyWrap7 = HappyWrap7 (())
happyIn7 :: (()) -> (HappyAbsSyn )
happyIn7 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap7 x)
{-# INLINE happyIn7 #-}
happyOut7 :: (HappyAbsSyn ) -> HappyWrap7
happyOut7 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut7 #-}
newtype HappyWrap8 = HappyWrap8 (AnBxAbstraction)
happyIn8 :: (AnBxAbstraction) -> (HappyAbsSyn )
happyIn8 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap8 x)
{-# INLINE happyIn8 #-}
happyOut8 :: (HappyAbsSyn ) -> HappyWrap8
happyOut8 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut8 #-}
newtype HappyWrap9 = HappyWrap9 (AnBxAbstraction)
happyIn9 :: (AnBxAbstraction) -> (HappyAbsSyn )
happyIn9 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap9 x)
{-# INLINE happyIn9 #-}
happyOut9 :: (HappyAbsSyn ) -> HappyWrap9
happyOut9 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut9 #-}
newtype HappyWrap10 = HappyWrap10 (AnBxDefinitions)
happyIn10 :: (AnBxDefinitions) -> (HappyAbsSyn )
happyIn10 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap10 x)
{-# INLINE happyIn10 #-}
happyOut10 :: (HappyAbsSyn ) -> HappyWrap10
happyOut10 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut10 #-}
newtype HappyWrap11 = HappyWrap11 (AnBxDefinitions)
happyIn11 :: (AnBxDefinitions) -> (HappyAbsSyn )
happyIn11 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap11 x)
{-# INLINE happyIn11 #-}
happyOut11 :: (HappyAbsSyn ) -> HappyWrap11
happyOut11 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut11 #-}
newtype HappyWrap12 = HappyWrap12 ([AnBxMsg])
happyIn12 :: ([AnBxMsg]) -> (HappyAbsSyn )
happyIn12 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap12 x)
{-# INLINE happyIn12 #-}
happyOut12 :: (HappyAbsSyn ) -> HappyWrap12
happyOut12 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut12 #-}
newtype HappyWrap13 = HappyWrap13 (AnBxDefinition)
happyIn13 :: (AnBxDefinition) -> (HappyAbsSyn )
happyIn13 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap13 x)
{-# INLINE happyIn13 #-}
happyOut13 :: (HappyAbsSyn ) -> HappyWrap13
happyOut13 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut13 #-}
newtype HappyWrap14 = HappyWrap14 (AnBxEquations)
happyIn14 :: (AnBxEquations) -> (HappyAbsSyn )
happyIn14 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap14 x)
{-# INLINE happyIn14 #-}
happyOut14 :: (HappyAbsSyn ) -> HappyWrap14
happyOut14 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut14 #-}
newtype HappyWrap15 = HappyWrap15 (AnBxEquations)
happyIn15 :: (AnBxEquations) -> (HappyAbsSyn )
happyIn15 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap15 x)
{-# INLINE happyIn15 #-}
happyOut15 :: (HappyAbsSyn ) -> HappyWrap15
happyOut15 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut15 #-}
newtype HappyWrap16 = HappyWrap16 (AnBxEquation)
happyIn16 :: (AnBxEquation) -> (HappyAbsSyn )
happyIn16 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap16 x)
{-# INLINE happyIn16 #-}
happyOut16 :: (HappyAbsSyn ) -> HappyWrap16
happyOut16 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut16 #-}
newtype HappyWrap17 = HappyWrap17 (([AnBxType],AnBxType,PrivateFunction))
happyIn17 :: (([AnBxType],AnBxType,PrivateFunction)) -> (HappyAbsSyn )
happyIn17 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap17 x)
{-# INLINE happyIn17 #-}
happyOut17 :: (HappyAbsSyn ) -> HappyWrap17
happyOut17 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut17 #-}
newtype HappyWrap18 = HappyWrap18 (TypeOpts)
happyIn18 :: (TypeOpts) -> (HappyAbsSyn )
happyIn18 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap18 x)
{-# INLINE happyIn18 #-}
happyOut18 :: (HappyAbsSyn ) -> HappyWrap18
happyOut18 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut18 #-}
newtype HappyWrap19 = HappyWrap19 (TypeOpts)
happyIn19 :: (TypeOpts) -> (HappyAbsSyn )
happyIn19 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap19 x)
{-# INLINE happyIn19 #-}
happyOut19 :: (HappyAbsSyn ) -> HappyWrap19
happyOut19 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut19 #-}
newtype HappyWrap20 = HappyWrap20 ([AnBxType])
happyIn20 :: ([AnBxType]) -> (HappyAbsSyn )
happyIn20 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap20 x)
{-# INLINE happyIn20 #-}
happyOut20 :: (HappyAbsSyn ) -> HappyWrap20
happyOut20 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut20 #-}
newtype HappyWrap21 = HappyWrap21 (AnBxTypes)
happyIn21 :: (AnBxTypes) -> (HappyAbsSyn )
happyIn21 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap21 x)
{-# INLINE happyIn21 #-}
happyOut21 :: (HappyAbsSyn ) -> HappyWrap21
happyOut21 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut21 #-}
newtype HappyWrap22 = HappyWrap22 (AnBxType)
happyIn22 :: (AnBxType) -> (HappyAbsSyn )
happyIn22 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap22 x)
{-# INLINE happyIn22 #-}
happyOut22 :: (HappyAbsSyn ) -> HappyWrap22
happyOut22 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut22 #-}
newtype HappyWrap23 = HappyWrap23 ([Ident])
happyIn23 :: ([Ident]) -> (HappyAbsSyn )
happyIn23 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap23 x)
{-# INLINE happyIn23 #-}
happyOut23 :: (HappyAbsSyn ) -> HappyWrap23
happyOut23 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut23 #-}
newtype HappyWrap24 = HappyWrap24 (([AnBxKnowledgeAgent], [AnBxShare]))
happyIn24 :: (([AnBxKnowledgeAgent], [AnBxShare])) -> (HappyAbsSyn )
happyIn24 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap24 x)
{-# INLINE happyIn24 #-}
happyOut24 :: (HappyAbsSyn ) -> HappyWrap24
happyOut24 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut24 #-}
newtype HappyWrap25 = HappyWrap25 (AnBxKnowledgeWhere)
happyIn25 :: (AnBxKnowledgeWhere) -> (HappyAbsSyn )
happyIn25 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap25 x)
{-# INLINE happyIn25 #-}
happyOut25 :: (HappyAbsSyn ) -> HappyWrap25
happyOut25 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut25 #-}
newtype HappyWrap26 = HappyWrap26 ([(AnBxMsg,AnBxMsg)])
happyIn26 :: ([(AnBxMsg,AnBxMsg)]) -> (HappyAbsSyn )
happyIn26 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap26 x)
{-# INLINE happyIn26 #-}
happyOut26 :: (HappyAbsSyn ) -> HappyWrap26
happyOut26 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut26 #-}
newtype HappyWrap27 = HappyWrap27 ([AnBxMsg])
happyIn27 :: ([AnBxMsg]) -> (HappyAbsSyn )
happyIn27 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap27 x)
{-# INLINE happyIn27 #-}
happyOut27 :: (HappyAbsSyn ) -> HappyWrap27
happyOut27 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut27 #-}
newtype HappyWrap28 = HappyWrap28 (AnBxMsg)
happyIn28 :: (AnBxMsg) -> (HappyAbsSyn )
happyIn28 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap28 x)
{-# INLINE happyIn28 #-}
happyOut28 :: (HappyAbsSyn ) -> HappyWrap28
happyOut28 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut28 #-}
newtype HappyWrap29 = HappyWrap29 (AnBxMsg)
happyIn29 :: (AnBxMsg) -> (HappyAbsSyn )
happyIn29 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap29 x)
{-# INLINE happyIn29 #-}
happyOut29 :: (HappyAbsSyn ) -> HappyWrap29
happyOut29 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut29 #-}
newtype HappyWrap30 = HappyWrap30 (AnBxActions)
happyIn30 :: (AnBxActions) -> (HappyAbsSyn )
happyIn30 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap30 x)
{-# INLINE happyIn30 #-}
happyOut30 :: (HappyAbsSyn ) -> HappyWrap30
happyOut30 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut30 #-}
newtype HappyWrap31 = HappyWrap31 (AnBxAction)
happyIn31 :: (AnBxAction) -> (HappyAbsSyn )
happyIn31 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap31 x)
{-# INLINE happyIn31 #-}
happyOut31 :: (HappyAbsSyn ) -> HappyWrap31
happyOut31 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut31 #-}
newtype HappyWrap32 = HappyWrap32 (AnBxChannelType)
happyIn32 :: (AnBxChannelType) -> (HappyAbsSyn )
happyIn32 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap32 x)
{-# INLINE happyIn32 #-}
happyOut32 :: (HappyAbsSyn ) -> HappyWrap32
happyOut32 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut32 #-}
newtype HappyWrap33 = HappyWrap33 (AnBxChannelType)
happyIn33 :: (AnBxChannelType) -> (HappyAbsSyn )
happyIn33 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap33 x)
{-# INLINE happyIn33 #-}
happyOut33 :: (HappyAbsSyn ) -> HappyWrap33
happyOut33 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut33 #-}
newtype HappyWrap34 = HappyWrap34 (AnBxChannelType)
happyIn34 :: (AnBxChannelType) -> (HappyAbsSyn )
happyIn34 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap34 x)
{-# INLINE happyIn34 #-}
happyOut34 :: (HappyAbsSyn ) -> HappyWrap34
happyOut34 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut34 #-}
newtype HappyWrap35 = HappyWrap35 ([Ident])
happyIn35 :: ([Ident]) -> (HappyAbsSyn )
happyIn35 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap35 x)
{-# INLINE happyIn35 #-}
happyOut35 :: (HappyAbsSyn ) -> HappyWrap35
happyOut35 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut35 #-}
newtype HappyWrap36 = HappyWrap36 (AnBxChannel)
happyIn36 :: (AnBxChannel) -> (HappyAbsSyn )
happyIn36 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap36 x)
{-# INLINE happyIn36 #-}
happyOut36 :: (HappyAbsSyn ) -> HappyWrap36
happyOut36 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut36 #-}
newtype HappyWrap37 = HappyWrap37 (AnBxChannel)
happyIn37 :: (AnBxChannel) -> (HappyAbsSyn )
happyIn37 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap37 x)
{-# INLINE happyIn37 #-}
happyOut37 :: (HappyAbsSyn ) -> HappyWrap37
happyOut37 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut37 #-}
newtype HappyWrap38 = HappyWrap38 (AnBxChannel)
happyIn38 :: (AnBxChannel) -> (HappyAbsSyn )
happyIn38 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap38 x)
{-# INLINE happyIn38 #-}
happyOut38 :: (HappyAbsSyn ) -> HappyWrap38
happyOut38 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut38 #-}
newtype HappyWrap39 = HappyWrap39 (AnBxPeer)
happyIn39 :: (AnBxPeer) -> (HappyAbsSyn )
happyIn39 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap39 x)
{-# INLINE happyIn39 #-}
happyOut39 :: (HappyAbsSyn ) -> HappyWrap39
happyOut39 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut39 #-}
newtype HappyWrap40 = HappyWrap40 (AnBxPeer)
happyIn40 :: (AnBxPeer) -> (HappyAbsSyn )
happyIn40 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap40 x)
{-# INLINE happyIn40 #-}
happyOut40 :: (HappyAbsSyn ) -> HappyWrap40
happyOut40 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut40 #-}
newtype HappyWrap41 = HappyWrap41 (AnBxPeer)
happyIn41 :: (AnBxPeer) -> (HappyAbsSyn )
happyIn41 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap41 x)
{-# INLINE happyIn41 #-}
happyOut41 :: (HappyAbsSyn ) -> HappyWrap41
happyOut41 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut41 #-}
newtype HappyWrap42 = HappyWrap42 (AnBxPeer)
happyIn42 :: (AnBxPeer) -> (HappyAbsSyn )
happyIn42 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap42 x)
{-# INLINE happyIn42 #-}
happyOut42 :: (HappyAbsSyn ) -> HappyWrap42
happyOut42 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut42 #-}
newtype HappyWrap43 = HappyWrap43 (AnBxGoals)
happyIn43 :: (AnBxGoals) -> (HappyAbsSyn )
happyIn43 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap43 x)
{-# INLINE happyIn43 #-}
happyOut43 :: (HappyAbsSyn ) -> HappyWrap43
happyOut43 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut43 #-}
newtype HappyWrap44 = HappyWrap44 (AnBxGoal)
happyIn44 :: (AnBxGoal) -> (HappyAbsSyn )
happyIn44 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap44 x)
{-# INLINE happyIn44 #-}
happyOut44 :: (HappyAbsSyn ) -> HappyWrap44
happyOut44 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut44 #-}
newtype HappyWrap45 = HappyWrap45 ([AnBxPeer])
happyIn45 :: ([AnBxPeer]) -> (HappyAbsSyn )
happyIn45 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap45 x)
{-# INLINE happyIn45 #-}
happyOut45 :: (HappyAbsSyn ) -> HappyWrap45
happyOut45 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut45 #-}
newtype HappyWrap46 = HappyWrap46 ([Ident])
happyIn46 :: ([Ident]) -> (HappyAbsSyn )
happyIn46 x = Happy_GHC_Exts.unsafeCoerce# (HappyWrap46 x)
{-# INLINE happyIn46 #-}
happyOut46 :: (HappyAbsSyn ) -> HappyWrap46
happyOut46 x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOut46 #-}
happyInTok :: (Token) -> (HappyAbsSyn )
happyInTok x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyInTok #-}
happyOutTok :: (HappyAbsSyn ) -> (Token)
happyOutTok x = Happy_GHC_Exts.unsafeCoerce# x
{-# INLINE happyOutTok #-}


{-# NOINLINE happyTokenStrings #-}
happyTokenStrings = ["ident","\"-\"","\"^\"","\"@\"","\"Definitions\"","\"Shares\"","\"share\"","\"agree\"","\"insecurely\"","\"<\"","\">\"","\"|\"","\"Equations\"","\"~\"","\"(\"","\")\"","\"{\"","\"}\"","\"{|\"","\"|}\"","\":\"","\";\"","\"*->*\"","\"*->\"","\"->*\"","\"->\"","\"*->>\"","\"*->>*\"","\"%\"","\"!\"","\"!=\"","\".\"","\",\"","\"[\"","\"]\"","\"Protocol\"","\"Knowledge\"","\"where\"","\"Types\"","\"Actions\"","\"Abstraction\"","\"Goals\"","\"authenticates\"","\"weakly\"","\"on\"","\"secret\"","\"between\"","\"confidentially\"","\"sends\"","\"to\"","\"guessable\"","\"=\"","\"funsign\"","%eof"]

happyActOffsets :: HappyAddr
happyActOffsets = HappyA# "\xea\xff\xff\xff\xea\xff\xff\xff\x46\x00\x00\x00\xdb\xff\xff\xff\x1a\x00\x00\x00\x4c\x00\x00\x00\x4b\x00\x00\x00\x00\x00\x00\x00\x56\x00\x00\x00\x7b\x00\x00\x00\x80\x00\x00\x00\x94\x00\x00\x00\x5e\x00\x00\x00\x00\x00\x00\x00\xa4\x00\x00\x00\x92\x00\x00\x00\x93\x00\x00\x00\xa0\x00\x00\x00\x04\x01\x00\x00\xbe\x00\x00\x00\xf1\x00\x00\x00\x06\x01\x00\x00\x53\x01\x00\x00\x00\x00\x00\x00\x54\x01\x00\x00\x35\x01\x00\x00\x37\x01\x00\x00\xaa\x00\x00\x00\x3b\x01\x00\x00\xee\xff\xff\xff\x56\x01\x00\x00\x57\x01\x00\x00\x57\x01\x00\x00\x57\x01\x00\x00\x00\x00\x00\x00\x58\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x08\x01\x00\x00\x00\x00\x00\x00\x09\x01\x00\x00\x6f\x00\x00\x00\x5a\x01\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x5c\x01\x00\x00\x5d\x01\x00\x00\x00\x00\x00\x00\x49\x01\x00\x00\x2d\x01\x00\x00\x3f\x01\x00\x00\x55\x01\x00\x00\x06\x00\x00\x00\x06\x00\x00\x00\x06\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x41\x01\x00\x00\x62\x01\x00\x00\xec\xff\xff\xff\x51\x01\x00\x00\x59\x01\x00\x00\x5e\x01\x00\x00\x06\x00\x00\x00\x06\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x40\x01\x00\x00\x60\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x5f\x01\x00\x00\x2a\x00\x00\x00\x52\x01\x00\x00\x67\x01\x00\x00\x5b\x01\x00\x00\x06\x00\x00\x00\x68\x01\x00\x00\x42\x01\x00\x00\x6b\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x61\x01\x00\x00\x4c\x01\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x06\x00\x00\x00\x71\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x50\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x60\x01\x00\x00\x63\x01\x00\x00\xfb\x00\x00\x00\x64\x01\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x65\x01\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x73\x01\x00\x00\x06\x00\x00\x00\x06\x00\x00\x00\x6d\x01\x00\x00\x03\x00\x00\x00\x75\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x66\x01\x00\x00\x4d\x01\x00\x00\x03\x00\x00\x00\x69\x01\x00\x00\x00\x00\x00\x00\xaf\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x78\x01\x00\x00\x06\x00\x00\x00\x6a\x01\x00\x00\x6c\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7a\x01\x00\x00\x00\x00\x00\x00\x7a\x01\x00\x00\x6e\x01\x00\x00\x58\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x70\x01\x00\x00\x7b\x01\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x6f\x01\x00\x00\x1f\x00\x00\x00\x72\x01\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7c\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x74\x01\x00\x00\x8f\x00\x00\x00\x77\x01\x00\x00\x1f\x00\x00\x00\x29\x00\x00\x00\x76\x01\x00\x00\x37\x00\x00\x00\x79\x01\x00\x00\x20\x00\x00\x00\xf1\xff\xff\xff\x25\x00\x00\x00\x31\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7d\x01\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x7e\x01\x00\x00\x7f\x01\x00\x00\x28\x00\x00\x00\x80\x01\x00\x00\x83\x01\x00\x00\x81\x01\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x44\x00\x00\x00\x82\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xfc\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3b\x00\x00\x00\x3b\x00\x00\x00\x86\x01\x00\x00\x09\x00\x00\x00\x85\x01\x00\x00\x28\x00\x00\x00\x84\x01\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x28\x00\x00\x00\x03\x00\x00\x00\x87\x01\x00\x00\x00\x00\x00\x00\x88\x01\x00\x00\x00\x00\x00\x00\x8a\x01\x00\x00\x28\x00\x00\x00\x89\x01\x00\x00\x4f\x01\x00\x00\x8b\x01\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x28\x00\x00\x00\x39\x00\x00\x00\x3b\x00\x00\x00\x3b\x00\x00\x00\x8c\x01\x00\x00\x8d\x01\x00\x00\x23\x01\x00\x00\x3d\x00\x00\x00\x8e\x01\x00\x00\x91\x01\x00\x00\x94\x01\x00\x00\x8f\x01\x00\x00\x00\x00\x00\x00\x90\x01\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x23\x01\x00\x00\x95\x01\x00\x00\x96\x01\x00\x00\x23\x01\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2b\x00\x00\x00\x2b\x00\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x28\x00\x00\x00\x92\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x97\x01\x00\x00\x98\x01\x00\x00\x99\x01\x00\x00\x34\x00\x00\x00\x23\x01\x00\x00\x9a\x01\x00\x00\x9b\x01\x00\x00\x9c\x01\x00\x00\x42\x00\x00\x00\x9d\x01\x00\x00\x5c\x00\x00\x00\x42\x00\x00\x00\x00\x00\x00\x00\xa8\x01\x00\x00\x9e\x01\x00\x00\x00\x00\x00\x00\xaa\x01\x00\x00\x42\x00\x00\x00\x00\x00\x00\x00\x42\x00\x00\x00\xa1\x01\x00\x00\xab\x01\x00\x00\xa0\x01\x00\x00\x42\x00\x00\x00\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x9f\x01\x00\x00\x00\x00\x00\x00\xac\x01\x00\x00\xae\x01\x00\x00\x42\x00\x00\x00\x00\x00\x00\x00\x42\x00\x00\x00\xb2\x01\x00\x00\xb3\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb4\x01\x00\x00\xb5\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"#

happyGotoOffsets :: HappyAddr
happyGotoOffsets = HappyA# "\xc7\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17\x01\x00\x00\xa6\x01\x00\x00\xb6\x01\x00\x00\xbc\x01\x00\x00\x00\x00\x00\x00\x8c\x00\x00\x00\xc9\x01\x00\x00\x00\x00\x00\x00\x93\x01\x00\x00\x00\x00\x00\x00\x98\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xba\x01\x00\x00\x00\x00\x00\x00\x19\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbf\x01\x00\x00\x00\x00\x00\x00\xf7\x00\x00\x00\xbd\x01\x00\x00\xbe\x01\x00\x00\x00\x00\x00\x00\xa5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xce\x01\x00\x00\x00\x00\x00\x00\xca\x01\x00\x00\x14\x01\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\xc0\x01\x00\x00\x00\x00\x00\x00\xd0\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x16\x01\x00\x00\x18\x01\x00\x00\x1a\x01\x00\x00\x1c\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf4\x00\x00\x00\x1e\x01\x00\x00\x20\x01\x00\x00\x00\x00\x00\x00\x70\x00\x00\x00\xc1\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xcd\x01\x00\x00\x00\x00\x00\x00\xf5\x00\x00\x00\xc4\x01\x00\x00\x00\x00\x00\x00\xc2\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc3\x01\x00\x00\xc5\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd6\x01\x00\x00\x22\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc6\x01\x00\x00\xf9\x00\x00\x00\xfc\x00\x00\x00\x00\x00\x00\x00\x6a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x72\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xcb\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfd\x00\x00\x00\xd8\x01\x00\x00\xda\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xcc\x01\x00\x00\x00\x00\x00\x00\xcf\x01\x00\x00\xdc\x01\x00\x00\x00\x00\x00\x00\xf3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x26\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd2\x01\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x00\x00\x00\x00\x28\x01\x00\x00\x00\x00\x00\x00\x2a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd1\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd3\x01\x00\x00\x00\x00\x00\x00\x2c\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd5\x01\x00\x00\xdd\x01\x00\x00\x52\x00\x00\x00\x00\x00\x00\x00\x2e\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf6\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x32\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xad\x00\x00\x00\xb1\x00\x00\x00\x00\x00\x00\x00\xb5\x00\x00\x00\x00\x00\x00\x00\x34\x01\x00\x00\x00\x00\x00\x00\x96\x00\x00\x00\x00\x00\x00\x00\x36\x01\x00\x00\xfe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xdf\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x38\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x9a\x00\x00\x00\x00\x00\x00\x00\x3a\x01\x00\x00\x00\x00\x00\x00\xb9\x00\x00\x00\xbd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x38\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd7\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x82\x00\x00\x00\x41\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7c\x00\x00\x00\x87\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x9e\x00\x00\x00\xff\x00\x00\x00\x3c\x01\x00\x00\x00\x00\x00\x00\xd4\x01\x00\x00\xe3\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x8a\x00\x00\x00\x7e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc9\x00\x00\x00\x00\x00\x00\x00\xcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd1\x00\x00\x00\xd5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe4\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd9\x00\x00\x00\x00\x00\x00\x00\xdd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"#

happyDefActions :: HappyAddr
happyDefActions = HappyA# "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfd\xff\xff\xff\xfc\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xf5\xff\xff\xff\x00\x00\x00\x00\xe1\xff\xff\xff\xdb\xff\xff\xff\x00\x00\x00\x00\xfa\xff\xff\xff\xda\xff\xff\xff\xec\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xdd\xff\xff\xff\xfb\xff\xff\xff\xe3\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xdf\xff\xff\xff\xe1\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe0\xff\xff\xff\x00\x00\x00\x00\xdc\xff\xff\xff\xd9\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xf4\xff\xff\xff\xfa\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf3\xff\xff\xff\xfb\xff\xff\xff\x00\x00\x00\x00\xeb\xff\xff\xff\xfa\xff\xff\xff\x00\x00\x00\x00\xca\xff\xff\xff\xc8\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe2\xff\xff\xff\xe7\xff\xff\xff\xe6\xff\xff\xff\xde\xff\xff\xff\xe5\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xea\xff\xff\xff\xfb\xff\xff\xff\xcf\xff\xff\xff\x00\x00\x00\x00\xf2\xff\xff\xff\xef\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe9\xff\xff\xff\xe8\xff\xff\xff\xc9\xff\xff\xff\x00\x00\x00\x00\xcc\xff\xff\xff\xc4\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc3\xff\xff\xff\xe4\xff\xff\xff\x00\x00\x00\x00\xc6\xff\xff\xff\xc7\xff\xff\xff\x00\x00\x00\x00\xc5\xff\xff\xff\xd0\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfa\xff\xff\xff\x00\x00\x00\x00\xf0\xff\xff\xff\xf1\xff\xff\xff\x00\x00\x00\x00\xee\xff\xff\xff\xed\xff\xff\xff\xd8\xff\xff\xff\xfb\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xcb\xff\xff\xff\xc2\xff\xff\xff\xce\xff\xff\xff\x00\x00\x00\x00\xc1\xff\xff\xff\x00\x00\x00\x00\xa2\xff\xff\xff\x00\x00\x00\x00\x9c\xff\xff\xff\x9d\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xfa\xff\xff\xff\xfa\xff\xff\xff\xd7\xff\xff\xff\xd6\xff\xff\xff\xfb\xff\xff\xff\xd4\xff\xff\xff\xfb\xff\xff\xff\xfa\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xb9\xff\xff\xff\xb8\xff\xff\xff\xb7\xff\xff\xff\xb6\xff\xff\xff\x00\x00\x00\x00\xc0\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xcd\xff\xff\xff\x00\x00\x00\x00\xbd\xff\xff\xff\x00\x00\x00\x00\xa1\xff\xff\xff\x00\x00\x00\x00\x9a\xff\xff\xff\xd2\xff\xff\xff\xfb\xff\xff\xff\xd3\xff\xff\xff\xd5\xff\xff\xff\xd1\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xba\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf9\xff\xff\xff\x98\xff\xff\xff\x9d\xff\xff\xff\x00\x00\x00\x00\xc8\xff\xff\xff\x97\xff\xff\xff\xfe\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xb5\xff\xff\xff\xb4\xff\xff\xff\xb3\xff\xff\xff\xb2\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbe\xff\xff\xff\x00\x00\x00\x00\xa3\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x99\xff\xff\xff\x00\x00\x00\x00\x9f\xff\xff\xff\x9e\xff\xff\xff\x9b\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbb\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x96\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0\xff\xff\xff\x00\x00\x00\x00\xf8\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x90\xff\xff\xff\x92\xff\xff\xff\x00\x00\x00\x00\xbf\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x9d\xff\xff\xff\x00\x00\x00\x00\xa4\xff\xff\xff\x00\x00\x00\x00\xa5\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbc\xff\xff\xff\x91\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x95\xff\xff\xff\x00\x00\x00\x00\xfa\xff\xff\xff\x94\xff\xff\xff\x93\xff\xff\xff\x8f\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xae\xff\xff\xff\x00\x00\x00\x00\x9a\xff\xff\xff\x8c\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xaf\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0\xff\xff\xff\xf7\xff\xff\xff\xfb\xff\xff\xff\xf6\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb1\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa6\xff\xff\xff\xaa\xff\xff\xff\xab\xff\xff\xff\xa7\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xa8\xff\xff\xff\xac\xff\xff\xff\xad\xff\xff\xff\xa9\xff\xff\xff"#

happyCheck :: HappyAddr
happyCheck = HappyA# "\xff\xff\xff\xff\x10\x00\x00\x00\x16\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x05\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x0d\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x05\x00\x00\x00\x25\x00\x00\x00\x24\x00\x00\x00\x23\x00\x00\x00\x37\x00\x00\x00\x22\x00\x00\x00\x0f\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x12\x00\x00\x00\x12\x00\x00\x00\x14\x00\x00\x00\x14\x00\x00\x00\x10\x00\x00\x00\x02\x00\x00\x00\x12\x00\x00\x00\x22\x00\x00\x00\x14\x00\x00\x00\x2f\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x35\x00\x00\x00\x23\x00\x00\x00\x34\x00\x00\x00\x23\x00\x00\x00\x02\x00\x00\x00\x23\x00\x00\x00\x23\x00\x00\x00\x02\x00\x00\x00\x23\x00\x00\x00\x23\x00\x00\x00\x02\x00\x00\x00\x23\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x12\x00\x00\x00\x12\x00\x00\x00\x14\x00\x00\x00\x14\x00\x00\x00\x10\x00\x00\x00\x02\x00\x00\x00\x12\x00\x00\x00\x10\x00\x00\x00\x14\x00\x00\x00\x12\x00\x00\x00\x11\x00\x00\x00\x14\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x10\x00\x00\x00\x23\x00\x00\x00\x23\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x0d\x00\x00\x00\x16\x00\x00\x00\x23\x00\x00\x00\x05\x00\x00\x00\x12\x00\x00\x00\x23\x00\x00\x00\x22\x00\x00\x00\x02\x00\x00\x00\x23\x00\x00\x00\x18\x00\x00\x00\x19\x00\x00\x00\x1a\x00\x00\x00\x1b\x00\x00\x00\x12\x00\x00\x00\x10\x00\x00\x00\x24\x00\x00\x00\x1e\x00\x00\x00\x23\x00\x00\x00\x2f\x00\x00\x00\x0a\x00\x00\x00\x0b\x00\x00\x00\x22\x00\x00\x00\x16\x00\x00\x00\x34\x00\x00\x00\x23\x00\x00\x00\x1e\x00\x00\x00\x23\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x2c\x00\x00\x00\x2d\x00\x00\x00\x23\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x31\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x21\x00\x00\x00\x16\x00\x00\x00\x23\x00\x00\x00\x16\x00\x00\x00\x25\x00\x00\x00\x26\x00\x00\x00\x27\x00\x00\x00\x16\x00\x00\x00\x21\x00\x00\x00\x28\x00\x00\x00\x23\x00\x00\x00\x16\x00\x00\x00\x25\x00\x00\x00\x26\x00\x00\x00\x27\x00\x00\x00\x0a\x00\x00\x00\x0b\x00\x00\x00\x24\x00\x00\x00\x02\x00\x00\x00\x22\x00\x00\x00\x10\x00\x00\x00\x24\x00\x00\x00\x23\x00\x00\x00\x22\x00\x00\x00\x19\x00\x00\x00\x1a\x00\x00\x00\x16\x00\x00\x00\x06\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x1f\x00\x00\x00\x20\x00\x00\x00\x19\x00\x00\x00\x1a\x00\x00\x00\x23\x00\x00\x00\x12\x00\x00\x00\x25\x00\x00\x00\x12\x00\x00\x00\x1f\x00\x00\x00\x20\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x23\x00\x00\x00\x02\x00\x00\x00\x25\x00\x00\x00\x0c\x00\x00\x00\x0d\x00\x00\x00\x1e\x00\x00\x00\x0f\x00\x00\x00\x1e\x00\x00\x00\x11\x00\x00\x00\x06\x00\x00\x00\x10\x00\x00\x00\x08\x00\x00\x00\x22\x00\x00\x00\x23\x00\x00\x00\x24\x00\x00\x00\x25\x00\x00\x00\x23\x00\x00\x00\x02\x00\x00\x00\x25\x00\x00\x00\x29\x00\x00\x00\x17\x00\x00\x00\x23\x00\x00\x00\x29\x00\x00\x00\x25\x00\x00\x00\x23\x00\x00\x00\x0e\x00\x00\x00\x25\x00\x00\x00\x29\x00\x00\x00\x0c\x00\x00\x00\x0d\x00\x00\x00\x29\x00\x00\x00\x0f\x00\x00\x00\x22\x00\x00\x00\x11\x00\x00\x00\x0c\x00\x00\x00\x0d\x00\x00\x00\x23\x00\x00\x00\x0f\x00\x00\x00\x25\x00\x00\x00\x11\x00\x00\x00\x23\x00\x00\x00\x28\x00\x00\x00\x25\x00\x00\x00\x02\x00\x00\x00\x23\x00\x00\x00\x28\x00\x00\x00\x25\x00\x00\x00\x1a\x00\x00\x00\x1b\x00\x00\x00\x28\x00\x00\x00\x18\x00\x00\x00\x19\x00\x00\x00\x1a\x00\x00\x00\x1b\x00\x00\x00\x22\x00\x00\x00\x23\x00\x00\x00\x24\x00\x00\x00\x25\x00\x00\x00\x22\x00\x00\x00\x23\x00\x00\x00\x24\x00\x00\x00\x25\x00\x00\x00\x22\x00\x00\x00\x23\x00\x00\x00\x24\x00\x00\x00\x25\x00\x00\x00\x22\x00\x00\x00\x23\x00\x00\x00\x24\x00\x00\x00\x25\x00\x00\x00\x22\x00\x00\x00\x23\x00\x00\x00\x24\x00\x00\x00\x25\x00\x00\x00\x22\x00\x00\x00\x23\x00\x00\x00\x24\x00\x00\x00\x25\x00\x00\x00\x22\x00\x00\x00\x23\x00\x00\x00\x24\x00\x00\x00\x25\x00\x00\x00\x22\x00\x00\x00\x23\x00\x00\x00\x24\x00\x00\x00\x25\x00\x00\x00\x22\x00\x00\x00\x23\x00\x00\x00\x24\x00\x00\x00\x25\x00\x00\x00\x22\x00\x00\x00\x23\x00\x00\x00\x24\x00\x00\x00\x25\x00\x00\x00\x22\x00\x00\x00\x23\x00\x00\x00\x24\x00\x00\x00\x25\x00\x00\x00\x22\x00\x00\x00\x23\x00\x00\x00\x24\x00\x00\x00\x25\x00\x00\x00\x22\x00\x00\x00\x23\x00\x00\x00\x24\x00\x00\x00\x25\x00\x00\x00\x22\x00\x00\x00\x23\x00\x00\x00\x24\x00\x00\x00\x25\x00\x00\x00\x08\x00\x00\x00\x09\x00\x00\x00\x0a\x00\x00\x00\x0f\x00\x00\x00\x06\x00\x00\x00\x11\x00\x00\x00\x08\x00\x00\x00\x16\x00\x00\x00\x16\x00\x00\x00\x18\x00\x00\x00\x18\x00\x00\x00\x16\x00\x00\x00\x16\x00\x00\x00\x18\x00\x00\x00\x18\x00\x00\x00\x16\x00\x00\x00\x16\x00\x00\x00\x18\x00\x00\x00\x18\x00\x00\x00\x23\x00\x00\x00\x26\x00\x00\x00\x25\x00\x00\x00\x23\x00\x00\x00\x16\x00\x00\x00\x25\x00\x00\x00\x16\x00\x00\x00\x23\x00\x00\x00\x16\x00\x00\x00\x25\x00\x00\x00\x17\x00\x00\x00\x23\x00\x00\x00\x23\x00\x00\x00\x25\x00\x00\x00\x25\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x10\x00\x00\x00\x11\x00\x00\x00\x10\x00\x00\x00\x11\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x22\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x24\x00\x00\x00\x02\x00\x00\x00\x22\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x17\x00\x00\x00\x22\x00\x00\x00\x35\x00\x00\x00\x22\x00\x00\x00\x02\x00\x00\x00\x10\x00\x00\x00\x15\x00\x00\x00\x27\x00\x00\x00\x16\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x29\x00\x00\x00\x13\x00\x00\x00\x02\x00\x00\x00\x22\x00\x00\x00\x11\x00\x00\x00\x11\x00\x00\x00\x16\x00\x00\x00\x11\x00\x00\x00\x02\x00\x00\x00\x24\x00\x00\x00\x02\x00\x00\x00\x09\x00\x00\x00\x02\x00\x00\x00\x2b\x00\x00\x00\x16\x00\x00\x00\x02\x00\x00\x00\x17\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x16\x00\x00\x00\x20\x00\x00\x00\x17\x00\x00\x00\x33\x00\x00\x00\x17\x00\x00\x00\xff\xff\xff\xff\x17\x00\x00\x00\x16\x00\x00\x00\x22\x00\x00\x00\x22\x00\x00\x00\xff\xff\xff\xff\x02\x00\x00\x00\xff\xff\xff\xff\x16\x00\x00\x00\x1e\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x10\x00\x00\x00\x16\x00\x00\x00\x22\x00\x00\x00\x1e\x00\x00\x00\x10\x00\x00\x00\xff\xff\xff\xff\x24\x00\x00\x00\x0d\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x09\x00\x00\x00\x0d\x00\x00\x00\xff\xff\xff\xff\x11\x00\x00\x00\x1f\x00\x00\x00\x02\x00\x00\x00\x0d\x00\x00\x00\x2a\x00\x00\x00\x1f\x00\x00\x00\x1b\x00\x00\x00\x0d\x00\x00\x00\x0d\x00\x00\x00\x11\x00\x00\x00\x17\x00\x00\x00\x2c\x00\x00\x00\x05\x00\x00\x00\x11\x00\x00\x00\x22\x00\x00\x00\x0d\x00\x00\x00\x22\x00\x00\x00\x30\x00\x00\x00\x32\x00\x00\x00\x2f\x00\x00\x00\x22\x00\x00\x00\x30\x00\x00\x00\x2e\x00\x00\x00\x22\x00\x00\x00\x2e\x00\x00\x00\x22\x00\x00\x00\x11\x00\x00\x00\x22\x00\x00\x00\x11\x00\x00\x00\x11\x00\x00\x00\x11\x00\x00\x00\x22\x00\x00\x00\x11\x00\x00\x00\x22\x00\x00\x00\x24\x00\x00\x00\x22\x00\x00\x00\x11\x00\x00\x00\x11\x00\x00\x00\x11\x00\x00\x00\x11\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00\x01\x00\x00\x00\x0e\x00\x00\x00\x02\x00\x00\x00\x12\x00\x00\x00\x0e\x00\x00\x00\x11\x00\x00\x00\x11\x00\x00\x00\x02\x00\x00\x00\x07\x00\x00\x00\x02\x00\x00\x00\x13\x00\x00\x00\x07\x00\x00\x00\x14\x00\x00\x00\x12\x00\x00\x00\x15\x00\x00\x00\x02\x00\x00\x00\x13\x00\x00\x00\x02\x00\x00\x00\x18\x00\x00\x00\x02\x00\x00\x00\x18\x00\x00\x00\x02\x00\x00\x00\x13\x00\x00\x00\x03\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x04\x00\x00\x00\x13\x00\x00\x00\x02\x00\x00\x00\x1b\x00\x00\x00\x15\x00\x00\x00\x04\x00\x00\x00\x12\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x18\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x1d\x00\x00\x00\x1c\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"#

happyTable :: HappyAddr
happyTable = HappyA# "\x00\x00\x00\x00\x44\x00\x00\x00\x5e\x00\x00\x00\x81\x00\x00\x00\xc6\x00\x00\x00\x81\x00\x00\x00\xc7\x00\x00\x00\x35\x00\x00\x00\x35\x00\x00\x00\xe4\x00\x00\x00\xe8\x00\x00\x00\x81\x00\x00\x00\xc6\x00\x00\x00\xab\x00\x00\x00\xe0\x00\x00\x00\x03\x00\x00\x00\x5f\x00\x00\x00\x0f\x00\x00\x00\xff\xff\xff\xff\xc8\xff\xff\xff\x99\x00\x00\x00\x36\x00\x00\x00\x36\x00\x00\x00\x37\x00\x00\x00\x37\x00\x00\x00\x38\x00\x00\x00\x38\x00\x00\x00\x36\x00\x00\x00\x07\x00\x00\x00\x37\x00\x00\x00\xe5\x00\x00\x00\x38\x00\x00\x00\xc8\xff\xff\xff\x35\x00\x00\x00\xab\x00\x00\x00\x1f\x00\x00\x00\x82\x00\x00\x00\xc8\xff\xff\xff\x82\x00\x00\x00\xad\x00\x00\x00\x39\x00\x00\x00\x39\x00\x00\x00\x35\x00\x00\x00\xe9\x00\x00\x00\x82\x00\x00\x00\x81\x00\x00\x00\xac\x00\x00\x00\x36\x00\x00\x00\x36\x00\x00\x00\x37\x00\x00\x00\x37\x00\x00\x00\x38\x00\x00\x00\x38\x00\x00\x00\x36\x00\x00\x00\xe8\x00\x00\x00\x37\x00\x00\x00\x36\x00\x00\x00\x38\x00\x00\x00\x37\x00\x00\x00\x4f\x00\x00\x00\x38\x00\x00\x00\x81\x00\x00\x00\xc6\x00\x00\x00\xe8\x00\x00\x00\xc6\x00\x00\x00\x44\x00\x00\x00\x39\x00\x00\x00\xac\x00\x00\x00\x81\x00\x00\x00\xc6\x00\x00\x00\xf1\x00\x00\x00\x9b\x00\x00\x00\x39\x00\x00\x00\xc9\x00\x00\x00\xe9\x00\x00\x00\x39\x00\x00\x00\x50\x00\x00\x00\x08\x00\x00\x00\x82\x00\x00\x00\xb2\x00\x00\x00\xb3\x00\x00\x00\xb4\x00\x00\x00\xb5\x00\x00\x00\xe9\x00\x00\x00\xca\x00\x00\x00\x9c\x00\x00\x00\xea\x00\x00\x00\xe9\x00\x00\x00\xba\x00\x00\x00\x30\x00\x00\x00\x31\x00\x00\x00\xf2\x00\x00\x00\x05\x00\x00\x00\xbb\x00\x00\x00\x82\x00\x00\x00\x02\x01\x00\x00\xe9\x00\x00\x00\xa5\x00\x00\x00\x33\x00\x00\x00\xb6\x00\x00\x00\xb7\x00\x00\x00\x82\x00\x00\x00\x32\x00\x00\x00\x33\x00\x00\x00\xb8\x00\x00\x00\xa5\x00\x00\x00\x33\x00\x00\x00\xa6\x00\x00\x00\x0a\x00\x00\x00\xa7\x00\x00\x00\x9b\x00\x00\x00\x7f\x00\x00\x00\xa8\x00\x00\x00\xa9\x00\x00\x00\x9b\x00\x00\x00\xa6\x00\x00\x00\x09\x00\x00\x00\xa7\x00\x00\x00\x52\x00\x00\x00\x7f\x00\x00\x00\xad\x00\x00\x00\xa9\x00\x00\x00\x55\x00\x00\x00\x31\x00\x00\x00\x9c\x00\x00\x00\x0d\x00\x00\x00\x17\x00\x00\x00\x2c\x00\x00\x00\x0c\x01\x00\x00\x0f\x00\x00\x00\x53\x00\x00\x00\x7a\x00\x00\x00\x7b\x00\x00\x00\x2d\x00\x00\x00\x13\x00\x00\x00\x32\x00\x00\x00\x33\x00\x00\x00\x7c\x00\x00\x00\x7d\x00\x00\x00\x92\x00\x00\x00\x7b\x00\x00\x00\x7e\x00\x00\x00\xe9\x00\x00\x00\x7f\x00\x00\x00\xe9\x00\x00\x00\x7c\x00\x00\x00\x7d\x00\x00\x00\xbf\x00\x00\x00\xc0\x00\x00\x00\x7e\x00\x00\x00\x11\x00\x00\x00\x7f\x00\x00\x00\x19\x00\x00\x00\x1a\x00\x00\x00\xff\x00\x00\x00\x1b\x00\x00\x00\x11\x01\x00\x00\x1c\x00\x00\x00\x28\x00\x00\x00\xc1\x00\x00\x00\x29\x00\x00\x00\xe5\x00\x00\x00\xc3\x00\x00\x00\xc4\x00\x00\x00\x7f\x00\x00\x00\x03\x01\x00\x00\x1e\x00\x00\x00\x7f\x00\x00\x00\xe6\x00\x00\x00\x19\x00\x00\x00\xfd\x00\x00\x00\x04\x01\x00\x00\x7f\x00\x00\x00\x12\x01\x00\x00\x16\x00\x00\x00\x7f\x00\x00\x00\xfe\x00\x00\x00\x19\x00\x00\x00\x39\x00\x00\x00\x13\x01\x00\x00\x1b\x00\x00\x00\x17\x00\x00\x00\x1c\x00\x00\x00\x19\x00\x00\x00\x5f\x00\x00\x00\xd9\x00\x00\x00\x1b\x00\x00\x00\x7f\x00\x00\x00\x1c\x00\x00\x00\xd9\x00\x00\x00\xda\x00\x00\x00\x7f\x00\x00\x00\x2b\x00\x00\x00\xd9\x00\x00\x00\xf3\x00\x00\x00\x7f\x00\x00\x00\x21\x00\x00\x00\x22\x00\x00\x00\xfc\x00\x00\x00\x8e\x00\x00\x00\x8f\x00\x00\x00\x90\x00\x00\x00\x91\x00\x00\x00\xc2\x00\x00\x00\xc3\x00\x00\x00\xc4\x00\x00\x00\x7f\x00\x00\x00\xe2\x00\x00\x00\xc3\x00\x00\x00\xc4\x00\x00\x00\x7f\x00\x00\x00\xe1\x00\x00\x00\xc3\x00\x00\x00\xc4\x00\x00\x00\x7f\x00\x00\x00\xde\x00\x00\x00\xc3\x00\x00\x00\xc4\x00\x00\x00\x7f\x00\x00\x00\xef\x00\x00\x00\xc3\x00\x00\x00\xc4\x00\x00\x00\x7f\x00\x00\x00\xee\x00\x00\x00\xc3\x00\x00\x00\xc4\x00\x00\x00\x7f\x00\x00\x00\x0d\x01\x00\x00\xc3\x00\x00\x00\xc4\x00\x00\x00\x7f\x00\x00\x00\x0a\x01\x00\x00\xc3\x00\x00\x00\xc4\x00\x00\x00\x7f\x00\x00\x00\x20\x01\x00\x00\xc3\x00\x00\x00\xc4\x00\x00\x00\x7f\x00\x00\x00\x1f\x01\x00\x00\xc3\x00\x00\x00\xc4\x00\x00\x00\x7f\x00\x00\x00\x1b\x01\x00\x00\xc3\x00\x00\x00\xc4\x00\x00\x00\x7f\x00\x00\x00\x1a\x01\x00\x00\xc3\x00\x00\x00\xc4\x00\x00\x00\x7f\x00\x00\x00\x26\x01\x00\x00\xc3\x00\x00\x00\xc4\x00\x00\x00\x7f\x00\x00\x00\x25\x01\x00\x00\xc3\x00\x00\x00\xc4\x00\x00\x00\x7f\x00\x00\x00\x73\x00\x00\x00\x74\x00\x00\x00\x75\x00\x00\x00\x3c\x00\x00\x00\x4a\x00\x00\x00\x1c\x00\x00\x00\x29\x00\x00\x00\x58\x00\x00\x00\x69\x00\x00\x00\x59\x00\x00\x00\x59\x00\x00\x00\x77\x00\x00\x00\x84\x00\x00\x00\x59\x00\x00\x00\x59\x00\x00\x00\x83\x00\x00\x00\x8a\x00\x00\x00\x59\x00\x00\x00\x59\x00\x00\x00\x99\x00\x00\x00\x28\x00\x00\x00\x7f\x00\x00\x00\xd2\x00\x00\x00\x14\x00\x00\x00\x7f\x00\x00\x00\x27\x00\x00\x00\xd1\x00\x00\x00\x30\x00\x00\x00\x7f\x00\x00\x00\x2f\x00\x00\x00\xd7\x00\x00\x00\xfb\x00\x00\x00\x7f\x00\x00\x00\x7f\x00\x00\x00\x11\x00\x00\x00\xec\x00\x00\x00\x0a\x00\x00\x00\x0b\x00\x00\x00\x24\x00\x00\x00\x0b\x00\x00\x00\x4b\x00\x00\x00\x33\x00\x00\x00\x42\x00\x00\x00\x33\x00\x00\x00\x41\x00\x00\x00\x33\x00\x00\x00\x40\x00\x00\x00\x33\x00\x00\x00\x3f\x00\x00\x00\x33\x00\x00\x00\x57\x00\x00\x00\x33\x00\x00\x00\x56\x00\x00\x00\x33\x00\x00\x00\x6f\x00\x00\x00\x33\x00\x00\x00\x6e\x00\x00\x00\x33\x00\x00\x00\x97\x00\x00\x00\x33\x00\x00\x00\xa3\x00\x00\x00\x33\x00\x00\x00\xa1\x00\x00\x00\x33\x00\x00\x00\xbb\x00\x00\x00\x33\x00\x00\x00\x3f\x00\x00\x00\x33\x00\x00\x00\xce\x00\x00\x00\x33\x00\x00\x00\xca\x00\x00\x00\x33\x00\x00\x00\xdc\x00\x00\x00\x33\x00\x00\x00\xd8\x00\x00\x00\x33\x00\x00\x00\xf7\x00\x00\x00\x33\x00\x00\x00\xf2\x00\x00\x00\x33\x00\x00\x00\xfa\x00\x00\x00\x33\x00\x00\x00\x11\x00\x00\x00\x0d\x00\x00\x00\x24\x00\x00\x00\x3e\x00\x00\x00\x0d\x00\x00\x00\x1e\x00\x00\x00\x23\x00\x00\x00\x4e\x00\x00\x00\x20\x00\x00\x00\x2b\x00\x00\x00\x4a\x00\x00\x00\x48\x00\x00\x00\x45\x00\x00\x00\x46\x00\x00\x00\x3f\x00\x00\x00\x1e\x00\x00\x00\x44\x00\x00\x00\x5d\x00\x00\x00\x55\x00\x00\x00\x6e\x00\x00\x00\x6d\x00\x00\x00\x11\x00\x00\x00\x68\x00\x00\x00\x5c\x00\x00\x00\x67\x00\x00\x00\x64\x00\x00\x00\x5b\x00\x00\x00\x51\x00\x00\x00\x6b\x00\x00\x00\x65\x00\x00\x00\x61\x00\x00\x00\x79\x00\x00\x00\x4a\x00\x00\x00\x83\x00\x00\x00\x7a\x00\x00\x00\x94\x00\x00\x00\x76\x00\x00\x00\x8c\x00\x00\x00\x72\x00\x00\x00\x4a\x00\x00\x00\x67\x00\x00\x00\x4a\x00\x00\x00\x92\x00\x00\x00\x77\x00\x00\x00\x8a\x00\x00\x00\xf6\x00\x00\x00\x88\x00\x00\x00\x00\x00\x00\x00\x9e\x00\x00\x00\x97\x00\x00\x00\x50\x00\x00\x00\x95\x00\x00\x00\x00\x00\x00\x00\xd6\x00\x00\x00\x00\x00\x00\x00\xb9\x00\x00\x00\xa5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x01\x00\x00\xc8\x00\x00\x00\xd4\x00\x00\x00\xa3\x00\x00\x00\xbd\x00\x00\x00\xe1\x00\x00\x00\x00\x00\x00\x00\xc2\x00\x00\x00\xee\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x06\x01\x00\x00\x00\x00\x00\x00\x0a\x01\x00\x00\xcc\x00\x00\x00\xd6\x00\x00\x00\x02\x01\x00\x00\xb0\x00\x00\x00\xde\x00\x00\x00\xf9\x00\x00\x00\x15\x01\x00\x00\x11\x01\x00\x00\x17\x01\x00\x00\x19\x01\x00\x00\xd1\x00\x00\x00\x11\x00\x00\x00\x10\x01\x00\x00\xf5\x00\x00\x00\x1f\x01\x00\x00\xed\x00\x00\x00\xce\x00\x00\x00\xd0\x00\x00\x00\xcd\x00\x00\x00\x09\x01\x00\x00\xdc\x00\x00\x00\xd7\x00\x00\x00\x8e\xff\xff\xff\xf7\x00\x00\x00\x01\x01\x00\x00\x23\x01\x00\x00\x16\x01\x00\x00\x22\x01\x00\x00\x1e\x01\x00\x00\x29\x01\x00\x00\x0f\x01\x00\x00\x28\x01\x00\x00\x8d\xff\xff\xff\x0d\x01\x00\x00\x1d\x01\x00\x00\x25\x01\x00\x00\x24\x01\x00\x00\x2b\x01\x00\x00\x2a\x01\x00\x00\x03\x00\x00\x00\x0f\x00\x00\x00\x05\x00\x00\x00\x0d\x00\x00\x00\x17\x00\x00\x00\x25\x00\x00\x00\x0d\x00\x00\x00\x3b\x00\x00\x00\x3a\x00\x00\x00\x2d\x00\x00\x00\x4c\x00\x00\x00\x46\x00\x00\x00\x48\x00\x00\x00\x6b\x00\x00\x00\x53\x00\x00\x00\x68\x00\x00\x00\x65\x00\x00\x00\x70\x00\x00\x00\x85\x00\x00\x00\x88\x00\x00\x00\x62\x00\x00\x00\x86\x00\x00\x00\x61\x00\x00\x00\x9c\x00\x00\x00\x9f\x00\x00\x00\xae\x00\x00\x00\x00\x00\x00\x00\x9e\x00\x00\x00\xd4\x00\x00\x00\xa0\x00\x00\x00\x17\x01\x00\x00\x8c\x00\x00\x00\x95\x00\x00\x00\x19\x01\x00\x00\x06\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbd\x00\x00\x00\xb0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"#

happyReduceArr = Happy_Data_Array.array (1, 115) [
        (1 , happyReduce_1),
        (2 , happyReduce_2),
        (3 , happyReduce_3),
        (4 , happyReduce_4),
        (5 , happyReduce_5),
        (6 , happyReduce_6),
        (7 , happyReduce_7),
        (8 , happyReduce_8),
        (9 , happyReduce_9),
        (10 , happyReduce_10),
        (11 , happyReduce_11),
        (12 , happyReduce_12),
        (13 , happyReduce_13),
        (14 , happyReduce_14),
        (15 , happyReduce_15),
        (16 , happyReduce_16),
        (17 , happyReduce_17),
        (18 , happyReduce_18),
        (19 , happyReduce_19),
        (20 , happyReduce_20),
        (21 , happyReduce_21),
        (22 , happyReduce_22),
        (23 , happyReduce_23),
        (24 , happyReduce_24),
        (25 , happyReduce_25),
        (26 , happyReduce_26),
        (27 , happyReduce_27),
        (28 , happyReduce_28),
        (29 , happyReduce_29),
        (30 , happyReduce_30),
        (31 , happyReduce_31),
        (32 , happyReduce_32),
        (33 , happyReduce_33),
        (34 , happyReduce_34),
        (35 , happyReduce_35),
        (36 , happyReduce_36),
        (37 , happyReduce_37),
        (38 , happyReduce_38),
        (39 , happyReduce_39),
        (40 , happyReduce_40),
        (41 , happyReduce_41),
        (42 , happyReduce_42),
        (43 , happyReduce_43),
        (44 , happyReduce_44),
        (45 , happyReduce_45),
        (46 , happyReduce_46),
        (47 , happyReduce_47),
        (48 , happyReduce_48),
        (49 , happyReduce_49),
        (50 , happyReduce_50),
        (51 , happyReduce_51),
        (52 , happyReduce_52),
        (53 , happyReduce_53),
        (54 , happyReduce_54),
        (55 , happyReduce_55),
        (56 , happyReduce_56),
        (57 , happyReduce_57),
        (58 , happyReduce_58),
        (59 , happyReduce_59),
        (60 , happyReduce_60),
        (61 , happyReduce_61),
        (62 , happyReduce_62),
        (63 , happyReduce_63),
        (64 , happyReduce_64),
        (65 , happyReduce_65),
        (66 , happyReduce_66),
        (67 , happyReduce_67),
        (68 , happyReduce_68),
        (69 , happyReduce_69),
        (70 , happyReduce_70),
        (71 , happyReduce_71),
        (72 , happyReduce_72),
        (73 , happyReduce_73),
        (74 , happyReduce_74),
        (75 , happyReduce_75),
        (76 , happyReduce_76),
        (77 , happyReduce_77),
        (78 , happyReduce_78),
        (79 , happyReduce_79),
        (80 , happyReduce_80),
        (81 , happyReduce_81),
        (82 , happyReduce_82),
        (83 , happyReduce_83),
        (84 , happyReduce_84),
        (85 , happyReduce_85),
        (86 , happyReduce_86),
        (87 , happyReduce_87),
        (88 , happyReduce_88),
        (89 , happyReduce_89),
        (90 , happyReduce_90),
        (91 , happyReduce_91),
        (92 , happyReduce_92),
        (93 , happyReduce_93),
        (94 , happyReduce_94),
        (95 , happyReduce_95),
        (96 , happyReduce_96),
        (97 , happyReduce_97),
        (98 , happyReduce_98),
        (99 , happyReduce_99),
        (100 , happyReduce_100),
        (101 , happyReduce_101),
        (102 , happyReduce_102),
        (103 , happyReduce_103),
        (104 , happyReduce_104),
        (105 , happyReduce_105),
        (106 , happyReduce_106),
        (107 , happyReduce_107),
        (108 , happyReduce_108),
        (109 , happyReduce_109),
        (110 , happyReduce_110),
        (111 , happyReduce_111),
        (112 , happyReduce_112),
        (113 , happyReduce_113),
        (114 , happyReduce_114),
        (115 , happyReduce_115)
        ]

happyRuleArr :: HappyAddr
happyRuleArr = HappyA# "\x00\x00\x00\x00\x13\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x03\x00\x00\x00\x06\x00\x00\x00\x02\x00\x00\x00\x06\x00\x00\x00\x03\x00\x00\x00\x07\x00\x00\x00\x01\x00\x00\x00\x07\x00\x00\x00\x03\x00\x00\x00\x08\x00\x00\x00\x03\x00\x00\x00\x08\x00\x00\x00\x06\x00\x00\x00\x08\x00\x00\x00\x06\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x03\x00\x00\x00\x0a\x00\x00\x00\x02\x00\x00\x00\x0a\x00\x00\x00\x03\x00\x00\x00\x0b\x00\x00\x00\x03\x00\x00\x00\x0c\x00\x00\x00\x03\x00\x00\x00\x0c\x00\x00\x00\x03\x00\x00\x00\x0d\x00\x00\x00\x03\x00\x00\x00\x0d\x00\x00\x00\x05\x00\x00\x00\x0d\x00\x00\x00\x01\x00\x00\x00\x0d\x00\x00\x00\x03\x00\x00\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x0e\x00\x00\x00\x03\x00\x00\x00\x0f\x00\x00\x00\x01\x00\x00\x00\x0f\x00\x00\x00\x03\x00\x00\x00\x10\x00\x00\x00\x03\x00\x00\x00\x10\x00\x00\x00\x04\x00\x00\x00\x11\x00\x00\x00\x02\x00\x00\x00\x12\x00\x00\x00\x01\x00\x00\x00\x12\x00\x00\x00\x03\x00\x00\x00\x13\x00\x00\x00\x04\x00\x00\x00\x13\x00\x00\x00\x05\x00\x00\x00\x13\x00\x00\x00\x06\x00\x00\x00\x13\x00\x00\x00\x07\x00\x00\x00\x13\x00\x00\x00\x06\x00\x00\x00\x13\x00\x00\x00\x07\x00\x00\x00\x13\x00\x00\x00\x07\x00\x00\x00\x13\x00\x00\x00\x08\x00\x00\x00\x14\x00\x00\x00\x02\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x00\x03\x00\x00\x00\x15\x00\x00\x00\x05\x00\x00\x00\x16\x00\x00\x00\x01\x00\x00\x00\x16\x00\x00\x00\x03\x00\x00\x00\x17\x00\x00\x00\x01\x00\x00\x00\x17\x00\x00\x00\x03\x00\x00\x00\x18\x00\x00\x00\x01\x00\x00\x00\x18\x00\x00\x00\x04\x00\x00\x00\x18\x00\x00\x00\x04\x00\x00\x00\x18\x00\x00\x00\x04\x00\x00\x00\x18\x00\x00\x00\x03\x00\x00\x00\x18\x00\x00\x00\x03\x00\x00\x00\x18\x00\x00\x00\x05\x00\x00\x00\x19\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x02\x00\x00\x00\x1a\x00\x00\x00\x07\x00\x00\x00\x1a\x00\x00\x00\x05\x00\x00\x00\x1a\x00\x00\x00\x03\x00\x00\x00\x1a\x00\x00\x00\x08\x00\x00\x00\x1a\x00\x00\x00\x06\x00\x00\x00\x1a\x00\x00\x00\x04\x00\x00\x00\x1b\x00\x00\x00\x01\x00\x00\x00\x1b\x00\x00\x00\x01\x00\x00\x00\x1b\x00\x00\x00\x01\x00\x00\x00\x1b\x00\x00\x00\x01\x00\x00\x00\x1c\x00\x00\x00\x01\x00\x00\x00\x1c\x00\x00\x00\x01\x00\x00\x00\x1c\x00\x00\x00\x01\x00\x00\x00\x1c\x00\x00\x00\x01\x00\x00\x00\x1d\x00\x00\x00\x07\x00\x00\x00\x1d\x00\x00\x00\x06\x00\x00\x00\x1d\x00\x00\x00\x06\x00\x00\x00\x1d\x00\x00\x00\x05\x00\x00\x00\x1d\x00\x00\x00\x09\x00\x00\x00\x1d\x00\x00\x00\x08\x00\x00\x00\x1d\x00\x00\x00\x08\x00\x00\x00\x1d\x00\x00\x00\x07\x00\x00\x00\x1d\x00\x00\x00\x09\x00\x00\x00\x1d\x00\x00\x00\x08\x00\x00\x00\x1d\x00\x00\x00\x08\x00\x00\x00\x1d\x00\x00\x00\x07\x00\x00\x00\x1e\x00\x00\x00\x01\x00\x00\x00\x1e\x00\x00\x00\x01\x00\x00\x00\x1f\x00\x00\x00\x05\x00\x00\x00\x1f\x00\x00\x00\x01\x00\x00\x00\x20\x00\x00\x00\x03\x00\x00\x00\x21\x00\x00\x00\x03\x00\x00\x00\x22\x00\x00\x00\x01\x00\x00\x00\x22\x00\x00\x00\x01\x00\x00\x00\x23\x00\x00\x00\x01\x00\x00\x00\x23\x00\x00\x00\x01\x00\x00\x00\x24\x00\x00\x00\x01\x00\x00\x00\x25\x00\x00\x00\x03\x00\x00\x00\x25\x00\x00\x00\x05\x00\x00\x00\x26\x00\x00\x00\x01\x00\x00\x00\x26\x00\x00\x00\x02\x00\x00\x00\x27\x00\x00\x00\x03\x00\x00\x00\x27\x00\x00\x00\x05\x00\x00\x00\x27\x00\x00\x00\x06\x00\x00\x00\x27\x00\x00\x00\x06\x00\x00\x00\x27\x00\x00\x00\x04\x00\x00\x00\x27\x00\x00\x00\x05\x00\x00\x00\x28\x00\x00\x00\x01\x00\x00\x00\x28\x00\x00\x00\x03\x00\x00\x00\x29\x00\x00\x00\x01\x00\x00\x00\x29\x00\x00\x00\x03\x00\x00\x00\x29\x00\x00\x00\x03\x00\x00\x00"#

happyCatchStates :: [Happy_Prelude.Int]
happyCatchStates = []

happy_n_terms = 56 :: Happy_Prelude.Int
happy_n_nonterms = 42 :: Happy_Prelude.Int

happy_n_starts = 1 :: Happy_Prelude.Int

happyReduce_1 = happyReduce 19# 0# happyReduction_1
happyReduction_1 (happy_x_19 `HappyStk`
        happy_x_18 `HappyStk`
        happy_x_17 `HappyStk`
        happy_x_16 `HappyStk`
        happy_x_15 `HappyStk`
        happy_x_14 `HappyStk`
        happy_x_13 `HappyStk`
        happy_x_12 `HappyStk`
        happy_x_11 `HappyStk`
        happy_x_10 `HappyStk`
        happy_x_9 `HappyStk`
        happy_x_8 `HappyStk`
        happy_x_7 `HappyStk`
        happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut6 happy_x_3 of { (HappyWrap6 happy_var_3) -> 
        case happyOut21 happy_x_6 of { (HappyWrap21 happy_var_6) -> 
        case happyOut10 happy_x_7 of { (HappyWrap10 happy_var_7) -> 
        case happyOut14 happy_x_8 of { (HappyWrap14 happy_var_8) -> 
        case happyOut24 happy_x_11 of { (HappyWrap24 happy_var_11) -> 
        case happyOut25 happy_x_12 of { (HappyWrap25 happy_var_12) -> 
        case happyOut30 happy_x_15 of { (HappyWrap30 happy_var_15) -> 
        case happyOut43 happy_x_18 of { (HappyWrap43 happy_var_18) -> 
        case happyOut8 happy_x_19 of { (HappyWrap8 happy_var_19) -> 
        happyIn5
                 ((happy_var_3, setCertifiedAgents happy_var_6 (snd happy_var_3), happy_var_7, happy_var_8, (fst happy_var_11, happy_var_12), snd happy_var_11, happy_var_19, happy_var_15, happy_var_18)
        ) `HappyStk` happyRest}}}}}}}}}

happyReduce_2 = happySpecReduce_1  1# happyReduction_2
happyReduction_2 happy_x_1
         =  case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        happyIn6
                 ((happy_var_1,PTAnBx)
        )}

happyReduce_3 = happySpecReduce_2  1# happyReduction_3
happyReduction_3 happy_x_2
        happy_x_1
         =  case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOutTok happy_x_2 of { (TATOM _ happy_var_2) -> 
        happyIn6
                 (case map toLower happy_var_2 of
                        "anbx" -> (happy_var_1,PTAnBx)
                        "anb"  -> (happy_var_1,PTAnB)
                        _ -> error ("Unknown Protocol Type: " ++ happy_var_2)
        )}}

happyReduce_4 = happySpecReduce_1  2# happyReduction_4
happyReduction_4 happy_x_1
         =  happyIn7
                 (()
        )

happyReduce_5 = happySpecReduce_0  2# happyReduction_5
happyReduction_5  =  happyIn7
                 (()
        )

happyReduce_6 = happySpecReduce_0  3# happyReduction_6
happyReduction_6  =  happyIn8
                 ([]
        )

happyReduce_7 = happySpecReduce_3  3# happyReduction_7
happyReduction_7 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut9 happy_x_3 of { (HappyWrap9 happy_var_3) -> 
        happyIn8
                 (happy_var_3
        )}

happyReduce_8 = happyReduce 4# 4# happyReduction_8
happyReduction_8 (happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOut29 happy_x_3 of { (HappyWrap29 happy_var_3) -> 
        happyIn9
                 ([(happy_var_1,happy_var_3)]
        ) `HappyStk` happyRest}}

happyReduce_9 = happyReduce 5# 4# happyReduction_9
happyReduction_9 (happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOut29 happy_x_3 of { (HappyWrap29 happy_var_3) -> 
        case happyOut9 happy_x_5 of { (HappyWrap9 happy_var_5) -> 
        happyIn9
                 (((happy_var_1,happy_var_3):happy_var_5)
        ) `HappyStk` happyRest}}}

happyReduce_10 = happySpecReduce_0  5# happyReduction_10
happyReduction_10  =  happyIn10
                 ([]
        )

happyReduce_11 = happySpecReduce_3  5# happyReduction_11
happyReduction_11 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut11 happy_x_3 of { (HappyWrap11 happy_var_3) -> 
        happyIn10
                 (happy_var_3
        )}

happyReduce_12 = happySpecReduce_2  6# happyReduction_12
happyReduction_12 happy_x_2
        happy_x_1
         =  case happyOut13 happy_x_1 of { (HappyWrap13 happy_var_1) -> 
        happyIn11
                 ([happy_var_1]
        )}

happyReduce_13 = happySpecReduce_3  6# happyReduction_13
happyReduction_13 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut13 happy_x_1 of { (HappyWrap13 happy_var_1) -> 
        case happyOut11 happy_x_3 of { (HappyWrap11 happy_var_3) -> 
        happyIn11
                 ((happy_var_1:happy_var_3)
        )}}

happyReduce_14 = happySpecReduce_1  7# happyReduction_14
happyReduction_14 happy_x_1
         =  case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        happyIn12
                 ([Atom happy_var_1]
        )}

happyReduce_15 = happySpecReduce_3  7# happyReduction_15
happyReduction_15 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOut12 happy_x_3 of { (HappyWrap12 happy_var_3) -> 
        happyIn12
                 (((Atom happy_var_1):happy_var_3)
        )}}

happyReduce_16 = happySpecReduce_3  8# happyReduction_16
happyReduction_16 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOut28 happy_x_3 of { (HappyWrap28 happy_var_3) -> 
        happyIn13
                 (Def (Atom happy_var_1) happy_var_3
        )}}

happyReduce_17 = happyReduce 6# 8# happyReduction_17
happyReduction_17 (happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOutTok happy_x_3 of { (TATOM _ happy_var_3) -> 
        case happyOut28 happy_x_6 of { (HappyWrap28 happy_var_6) -> 
        happyIn13
                 (Def (Comp Apply [Atom happy_var_1,Atom happy_var_3]) happy_var_6
        ) `HappyStk` happyRest}}}

happyReduce_18 = happyReduce 6# 8# happyReduction_18
happyReduction_18 (happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOut12 happy_x_3 of { (HappyWrap12 happy_var_3) -> 
        case happyOut28 happy_x_6 of { (HappyWrap28 happy_var_6) -> 
        happyIn13
                 (Def (Comp Apply ((Atom happy_var_1):[Comp Cat happy_var_3])) happy_var_6
        ) `HappyStk` happyRest}}}

happyReduce_19 = happySpecReduce_0  9# happyReduction_19
happyReduction_19  =  happyIn14
                 ([]
        )

happyReduce_20 = happySpecReduce_3  9# happyReduction_20
happyReduction_20 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut15 happy_x_3 of { (HappyWrap15 happy_var_3) -> 
        happyIn14
                 (happy_var_3
        )}

happyReduce_21 = happySpecReduce_2  10# happyReduction_21
happyReduction_21 happy_x_2
        happy_x_1
         =  case happyOut16 happy_x_1 of { (HappyWrap16 happy_var_1) -> 
        happyIn15
                 ([happy_var_1]
        )}

happyReduce_22 = happySpecReduce_3  10# happyReduction_22
happyReduction_22 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut16 happy_x_1 of { (HappyWrap16 happy_var_1) -> 
        case happyOut15 happy_x_3 of { (HappyWrap15 happy_var_3) -> 
        happyIn15
                 ((happy_var_1:happy_var_3)
        )}}

happyReduce_23 = happySpecReduce_3  11# happyReduction_23
happyReduction_23 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut28 happy_x_1 of { (HappyWrap28 happy_var_1) -> 
        case happyOut28 happy_x_3 of { (HappyWrap28 happy_var_3) -> 
        happyIn16
                 (Eqt happy_var_1 happy_var_3
        )}}

happyReduce_24 = happySpecReduce_3  12# happyReduction_24
happyReduction_24 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut20 happy_x_1 of { (HappyWrap20 happy_var_1) -> 
        case happyOut22 happy_x_3 of { (HappyWrap22 happy_var_3) -> 
        happyIn17
                 ((happy_var_1,happy_var_3,PubFun)
        )}}

happyReduce_25 = happySpecReduce_3  12# happyReduction_25
happyReduction_25 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut20 happy_x_1 of { (HappyWrap20 happy_var_1) -> 
        case happyOut22 happy_x_3 of { (HappyWrap22 happy_var_3) -> 
        happyIn17
                 ((happy_var_1,happy_var_3,PrivFun)
        )}}

happyReduce_26 = happySpecReduce_3  13# happyReduction_26
happyReduction_26 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOutTok happy_x_3 of { (TATOM _ happy_var_3) -> 
        happyIn18
                 ([Option (happy_var_1,Atom happy_var_3)]
        )}}

happyReduce_27 = happyReduce 5# 13# happyReduction_27
happyReduction_27 (happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOutTok happy_x_3 of { (TATOM _ happy_var_3) -> 
        case happyOut18 happy_x_5 of { (HappyWrap18 happy_var_5) -> 
        happyIn18
                 ((Option (happy_var_1,Atom happy_var_3)):happy_var_5
        ) `HappyStk` happyRest}}}

happyReduce_28 = happySpecReduce_1  13# happyReduction_28
happyReduction_28 happy_x_1
         =  case happyOut17 happy_x_1 of { (HappyWrap17 happy_var_1) -> 
        happyIn18
                 ([FunSign happy_var_1]
        )}

happyReduce_29 = happySpecReduce_3  13# happyReduction_29
happyReduction_29 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut17 happy_x_1 of { (HappyWrap17 happy_var_1) -> 
        case happyOut18 happy_x_3 of { (HappyWrap18 happy_var_3) -> 
        happyIn18
                 ((FunSign happy_var_1):happy_var_3
        )}}

happyReduce_30 = happySpecReduce_0  14# happyReduction_30
happyReduction_30  =  happyIn19
                 ([]
        )

happyReduce_31 = happySpecReduce_3  14# happyReduction_31
happyReduction_31 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut18 happy_x_2 of { (HappyWrap18 happy_var_2) -> 
        happyIn19
                 (happy_var_2
        )}

happyReduce_32 = happySpecReduce_1  15# happyReduction_32
happyReduction_32 happy_x_1
         =  case happyOut22 happy_x_1 of { (HappyWrap22 happy_var_1) -> 
        happyIn20
                 ([happy_var_1]
        )}

happyReduce_33 = happySpecReduce_3  15# happyReduction_33
happyReduction_33 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut22 happy_x_1 of { (HappyWrap22 happy_var_1) -> 
        case happyOut20 happy_x_3 of { (HappyWrap20 happy_var_3) -> 
        happyIn20
                 (happy_var_1:happy_var_3
        )}}

happyReduce_34 = happySpecReduce_3  16# happyReduction_34
happyReduction_34 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut22 happy_x_1 of { (HappyWrap22 happy_var_1) -> 
        case happyOut23 happy_x_2 of { (HappyWrap23 happy_var_2) -> 
        happyIn21
                 ([(happy_var_1,happy_var_2)]
        )}}

happyReduce_35 = happyReduce 4# 16# happyReduction_35
happyReduction_35 (happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut22 happy_x_1 of { (HappyWrap22 happy_var_1) -> 
        case happyOut23 happy_x_2 of { (HappyWrap23 happy_var_2) -> 
        case happyOut21 happy_x_4 of { (HappyWrap21 happy_var_4) -> 
        happyIn21
                 ((happy_var_1,happy_var_2):happy_var_4
        ) `HappyStk` happyRest}}}

happyReduce_36 = happySpecReduce_2  17# happyReduction_36
happyReduction_36 happy_x_2
        happy_x_1
         =  case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOut19 happy_x_2 of { (HappyWrap19 happy_var_2) -> 
        happyIn22
                 (case happy_var_1 of
               "Agent" -> Agent False False happy_var_2 NoCert   -- no certified by default
               "Certified" -> Agent False False happy_var_2 Cert  -- certified agent
               "Number" -> Number happy_var_2
               "SeqNumber" -> SeqNumber happy_var_2
               "PublicKey" -> PublicKey happy_var_2
               "SymmetricKey" -> SymmetricKey happy_var_2
               "Symmetric_key" -> SymmetricKey happy_var_2  -- sic!! (OFMC)
               "Function" -> Function happy_var_2           
               "Untyped" -> Untyped happy_var_2
               _ -> Custom happy_var_1 happy_var_2
        )}}

happyReduce_37 = happySpecReduce_1  18# happyReduction_37
happyReduction_37 happy_x_1
         =  case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        happyIn23
                 ([happy_var_1]
        )}

happyReduce_38 = happySpecReduce_3  18# happyReduction_38
happyReduction_38 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOut23 happy_x_3 of { (HappyWrap23 happy_var_3) -> 
        happyIn23
                 (happy_var_1:happy_var_3
        )}}

happyReduce_39 = happyReduce 4# 19# happyReduction_39
happyReduction_39 (happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOut27 happy_x_3 of { (HappyWrap27 happy_var_3) -> 
        happyIn24
                 (([(happy_var_1,happy_var_3)], [])
        ) `HappyStk` happyRest}}

happyReduce_40 = happyReduce 5# 19# happyReduction_40
happyReduction_40 (happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOut27 happy_x_3 of { (HappyWrap27 happy_var_3) -> 
        case happyOut24 happy_x_5 of { (HappyWrap24 happy_var_5) -> 
        happyIn24
                 (let (agents, shares) = happy_var_5 in ((happy_var_1,happy_var_3) : agents, shares)
        ) `HappyStk` happyRest}}}

happyReduce_41 = happyReduce 6# 19# happyReduction_41
happyReduction_41 (happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOut23 happy_x_3 of { (HappyWrap23 happy_var_3) -> 
        case happyOut27 happy_x_5 of { (HappyWrap27 happy_var_5) -> 
        happyIn24
                 (([], [(SHShare, (happy_var_1 : happy_var_3), happy_var_5)])
        ) `HappyStk` happyRest}}}

happyReduce_42 = happyReduce 7# 19# happyReduction_42
happyReduction_42 (happy_x_7 `HappyStk`
        happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOut23 happy_x_3 of { (HappyWrap23 happy_var_3) -> 
        case happyOut27 happy_x_5 of { (HappyWrap27 happy_var_5) -> 
        case happyOut24 happy_x_7 of { (HappyWrap24 happy_var_7) -> 
        happyIn24
                 (let (agents, shares) = happy_var_7 in (agents, (SHShare, (happy_var_1 : happy_var_3), happy_var_5) : shares)
        ) `HappyStk` happyRest}}}}

happyReduce_43 = happyReduce 6# 19# happyReduction_43
happyReduction_43 (happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOut23 happy_x_3 of { (HappyWrap23 happy_var_3) -> 
        case happyOut27 happy_x_5 of { (HappyWrap27 happy_var_5) -> 
        happyIn24
                 (([], [(SHAgree, (happy_var_1 : happy_var_3), happy_var_5)])
        ) `HappyStk` happyRest}}}

happyReduce_44 = happyReduce 7# 19# happyReduction_44
happyReduction_44 (happy_x_7 `HappyStk`
        happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOut23 happy_x_3 of { (HappyWrap23 happy_var_3) -> 
        case happyOut27 happy_x_5 of { (HappyWrap27 happy_var_5) -> 
        case happyOut24 happy_x_7 of { (HappyWrap24 happy_var_7) -> 
        happyIn24
                 (let (agents, shares) = happy_var_7 in (agents, (SHAgree, (happy_var_1 : happy_var_3), happy_var_5) : shares)
        ) `HappyStk` happyRest}}}}

happyReduce_45 = happyReduce 7# 19# happyReduction_45
happyReduction_45 (happy_x_7 `HappyStk`
        happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOut23 happy_x_3 of { (HappyWrap23 happy_var_3) -> 
        case happyOut27 happy_x_6 of { (HappyWrap27 happy_var_6) -> 
        happyIn24
                 (([], [(SHAgreeInsecurely, (happy_var_1 : happy_var_3), happy_var_6)])
        ) `HappyStk` happyRest}}}

happyReduce_46 = happyReduce 8# 19# happyReduction_46
happyReduction_46 (happy_x_8 `HappyStk`
        happy_x_7 `HappyStk`
        happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOut23 happy_x_3 of { (HappyWrap23 happy_var_3) -> 
        case happyOut27 happy_x_6 of { (HappyWrap27 happy_var_6) -> 
        case happyOut24 happy_x_8 of { (HappyWrap24 happy_var_8) -> 
        happyIn24
                 (let (agents, shares) = happy_var_8 in (agents, (SHAgreeInsecurely, (happy_var_1 : happy_var_3), happy_var_6) : shares)
        ) `HappyStk` happyRest}}}}

happyReduce_47 = happySpecReduce_2  20# happyReduction_47
happyReduction_47 happy_x_2
        happy_x_1
         =  case happyOut26 happy_x_2 of { (HappyWrap26 happy_var_2) -> 
        happyIn25
                 (happy_var_2
        )}

happyReduce_48 = happySpecReduce_0  20# happyReduction_48
happyReduction_48  =  happyIn25
                 ([]
        )

happyReduce_49 = happySpecReduce_3  21# happyReduction_49
happyReduction_49 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOutTok happy_x_3 of { (TATOM _ happy_var_3) -> 
        happyIn26
                 ([(Atom happy_var_1,Atom happy_var_3)]
        )}}

happyReduce_50 = happyReduce 5# 21# happyReduction_50
happyReduction_50 (happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOutTok happy_x_3 of { (TATOM _ happy_var_3) -> 
        case happyOut26 happy_x_5 of { (HappyWrap26 happy_var_5) -> 
        happyIn26
                 (((Atom happy_var_1,Atom happy_var_3):happy_var_5)
        ) `HappyStk` happyRest}}}

happyReduce_51 = happySpecReduce_1  22# happyReduction_51
happyReduction_51 happy_x_1
         =  case happyOut29 happy_x_1 of { (HappyWrap29 happy_var_1) -> 
        happyIn27
                 ([happy_var_1]
        )}

happyReduce_52 = happySpecReduce_3  22# happyReduction_52
happyReduction_52 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut29 happy_x_1 of { (HappyWrap29 happy_var_1) -> 
        case happyOut27 happy_x_3 of { (HappyWrap27 happy_var_3) -> 
        happyIn27
                 (happy_var_1:happy_var_3
        )}}

happyReduce_53 = happySpecReduce_1  23# happyReduction_53
happyReduction_53 happy_x_1
         =  case happyOut29 happy_x_1 of { (HappyWrap29 happy_var_1) -> 
        happyIn28
                 (happy_var_1
        )}

happyReduce_54 = happySpecReduce_3  23# happyReduction_54
happyReduction_54 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut29 happy_x_1 of { (HappyWrap29 happy_var_1) -> 
        case happyOut28 happy_x_3 of { (HappyWrap28 happy_var_3) -> 
        happyIn28
                 (Comp Cat [happy_var_1,happy_var_3]
        )}}

happyReduce_55 = happySpecReduce_1  24# happyReduction_55
happyReduction_55 happy_x_1
         =  case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        happyIn29
                 (Atom happy_var_1
        )}

happyReduce_56 = happyReduce 4# 24# happyReduction_56
happyReduction_56 (happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut28 happy_x_2 of { (HappyWrap28 happy_var_2) -> 
        case happyOut29 happy_x_4 of { (HappyWrap29 happy_var_4) -> 
        happyIn29
                 (Comp Crypt [happy_var_4,happy_var_2]
        ) `HappyStk` happyRest}}

happyReduce_57 = happyReduce 4# 24# happyReduction_57
happyReduction_57 (happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut28 happy_x_2 of { (HappyWrap28 happy_var_2) -> 
        case happyOut29 happy_x_4 of { (HappyWrap29 happy_var_4) -> 
        happyIn29
                 (Comp Scrypt [happy_var_4,happy_var_2]
        ) `HappyStk` happyRest}}

happyReduce_58 = happyReduce 4# 24# happyReduction_58
happyReduction_58 (happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        case happyOut27 happy_x_3 of { (HappyWrap27 happy_var_3) -> 
        happyIn29
                 (if happy_var_1=="inv" then Comp Inv happy_var_3
                          else if happy_var_1=="exp" then Comp Exp happy_var_3
                          else if happy_var_1=="xor" then Comp Xor happy_var_3
                          else case happy_var_3 of
                                [x] -> Comp Apply ((Atom happy_var_1):[x])
                                _ -> Comp Apply ((Atom happy_var_1):[Comp Cat happy_var_3])
        ) `HappyStk` happyRest}}

happyReduce_59 = happySpecReduce_3  24# happyReduction_59
happyReduction_59 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut28 happy_x_2 of { (HappyWrap28 happy_var_2) -> 
        happyIn29
                 (happy_var_2
        )}

happyReduce_60 = happySpecReduce_3  24# happyReduction_60
happyReduction_60 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut28 happy_x_2 of { (HappyWrap28 happy_var_2) -> 
        happyIn29
                 (DigestHash happy_var_2
        )}

happyReduce_61 = happyReduce 5# 24# happyReduction_61
happyReduction_61 (happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut28 happy_x_2 of { (HappyWrap28 happy_var_2) -> 
        case happyOutTok happy_x_4 of { (TATOM _ happy_var_4) -> 
        happyIn29
                 (DigestHmac happy_var_2 happy_var_4
        ) `HappyStk` happyRest}}

happyReduce_62 = happySpecReduce_1  25# happyReduction_62
happyReduction_62 happy_x_1
         =  case happyOut31 happy_x_1 of { (HappyWrap31 happy_var_1) -> 
        happyIn30
                 ([happy_var_1]
        )}

happyReduce_63 = happySpecReduce_2  25# happyReduction_63
happyReduction_63 happy_x_2
        happy_x_1
         =  case happyOut31 happy_x_1 of { (HappyWrap31 happy_var_1) -> 
        case happyOut30 happy_x_2 of { (HappyWrap30 happy_var_2) -> 
        happyIn30
                 ((happy_var_1:happy_var_2)
        )}}

happyReduce_64 = happyReduce 7# 26# happyReduction_64
happyReduction_64 (happy_x_7 `HappyStk`
        happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut36 happy_x_1 of { (HappyWrap36 happy_var_1) -> 
        case happyOut28 happy_x_3 of { (HappyWrap28 happy_var_3) -> 
        case happyOut28 happy_x_5 of { (HappyWrap28 happy_var_5) -> 
        case happyOut28 happy_x_7 of { (HappyWrap28 happy_var_7) -> 
        happyIn31
                 ((happy_var_1,PlainMsg happy_var_3,Just happy_var_5,Just happy_var_7)
        ) `HappyStk` happyRest}}}}

happyReduce_65 = happyReduce 5# 26# happyReduction_65
happyReduction_65 (happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut36 happy_x_1 of { (HappyWrap36 happy_var_1) -> 
        case happyOut28 happy_x_3 of { (HappyWrap28 happy_var_3) -> 
        case happyOut28 happy_x_5 of { (HappyWrap28 happy_var_5) -> 
        happyIn31
                 ((happy_var_1,PlainMsg happy_var_3,Just happy_var_5,Nothing)
        ) `HappyStk` happyRest}}}

happyReduce_66 = happySpecReduce_3  26# happyReduction_66
happyReduction_66 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut36 happy_x_1 of { (HappyWrap36 happy_var_1) -> 
        case happyOut28 happy_x_3 of { (HappyWrap28 happy_var_3) -> 
        happyIn31
                 ((happy_var_1,PlainMsg happy_var_3,Nothing,Nothing)
        )}}

happyReduce_67 = happyReduce 8# 26# happyReduction_67
happyReduction_67 (happy_x_8 `HappyStk`
        happy_x_7 `HappyStk`
        happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut36 happy_x_1 of { (HappyWrap36 happy_var_1) -> 
        case happyOut28 happy_x_4 of { (HappyWrap28 happy_var_4) -> 
        case happyOut28 happy_x_6 of { (HappyWrap28 happy_var_6) -> 
        case happyOut28 happy_x_8 of { (HappyWrap28 happy_var_8) -> 
        happyIn31
                 ((happy_var_1,ReplayMsg happy_var_4,Just happy_var_6,Just happy_var_8)
        ) `HappyStk` happyRest}}}}

happyReduce_68 = happyReduce 6# 26# happyReduction_68
happyReduction_68 (happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut36 happy_x_1 of { (HappyWrap36 happy_var_1) -> 
        case happyOut28 happy_x_4 of { (HappyWrap28 happy_var_4) -> 
        case happyOut28 happy_x_6 of { (HappyWrap28 happy_var_6) -> 
        happyIn31
                 ((happy_var_1,ReplayMsg happy_var_4,Just happy_var_6,Nothing)
        ) `HappyStk` happyRest}}}

happyReduce_69 = happyReduce 4# 26# happyReduction_69
happyReduction_69 (happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut36 happy_x_1 of { (HappyWrap36 happy_var_1) -> 
        case happyOut28 happy_x_4 of { (HappyWrap28 happy_var_4) -> 
        happyIn31
                 ((happy_var_1,ReplayMsg happy_var_4,Nothing,Nothing)
        ) `HappyStk` happyRest}}

happyReduce_70 = happySpecReduce_1  27# happyReduction_70
happyReduction_70 happy_x_1
         =  happyIn32
                 (Secure
        )

happyReduce_71 = happySpecReduce_1  27# happyReduction_71
happyReduction_71 happy_x_1
         =  happyIn32
                 (Authentic
        )

happyReduce_72 = happySpecReduce_1  27# happyReduction_72
happyReduction_72 happy_x_1
         =  happyIn32
                 (Confidential
        )

happyReduce_73 = happySpecReduce_1  27# happyReduction_73
happyReduction_73 happy_x_1
         =  happyIn32
                 (Insecure
        )

happyReduce_74 = happySpecReduce_1  28# happyReduction_74
happyReduction_74 happy_x_1
         =  happyIn33
                 (FreshSecure
        )

happyReduce_75 = happySpecReduce_1  28# happyReduction_75
happyReduction_75 happy_x_1
         =  happyIn33
                 (FreshAuthentic
        )

happyReduce_76 = happySpecReduce_1  28# happyReduction_76
happyReduction_76 happy_x_1
         =  happyIn33
                 (Confidential
        )

happyReduce_77 = happySpecReduce_1  28# happyReduction_77
happyReduction_77 happy_x_1
         =  happyIn33
                 (Insecure
        )

happyReduce_78 = happyReduce 7# 29# happyReduction_78
happyReduction_78 (happy_x_7 `HappyStk`
        happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut39 happy_x_4 of { (HappyWrap39 happy_var_4) -> 
        case happyOut40 happy_x_6 of { (HappyWrap40 happy_var_6) -> 
        happyIn34
                 (BMChannelTypePair ForwardFresh happy_var_4 happy_var_6
        ) `HappyStk` happyRest}}

happyReduce_79 = happyReduce 6# 29# happyReduction_79
happyReduction_79 (happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut39 happy_x_3 of { (HappyWrap39 happy_var_3) -> 
        case happyOut40 happy_x_5 of { (HappyWrap40 happy_var_5) -> 
        happyIn34
                 (BMChannelTypePair Forward happy_var_3 happy_var_5
        ) `HappyStk` happyRest}}

happyReduce_80 = happyReduce 6# 29# happyReduction_80
happyReduction_80 (happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut39 happy_x_3 of { (HappyWrap39 happy_var_3) -> 
        case happyOut40 happy_x_5 of { (HappyWrap40 happy_var_5) -> 
        happyIn34
                 (BMChannelTypePair Fresh happy_var_3 happy_var_5
        ) `HappyStk` happyRest}}

happyReduce_81 = happyReduce 5# 29# happyReduction_81
happyReduction_81 (happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut39 happy_x_2 of { (HappyWrap39 happy_var_2) -> 
        case happyOut39 happy_x_4 of { (HappyWrap39 happy_var_4) -> 
        happyIn34
                 (BMChannelTypePair Std happy_var_2 happy_var_4
        ) `HappyStk` happyRest}}

happyReduce_82 = happyReduce 9# 29# happyReduction_82
happyReduction_82 (happy_x_9 `HappyStk`
        happy_x_8 `HappyStk`
        happy_x_7 `HappyStk`
        happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut39 happy_x_4 of { (HappyWrap39 happy_var_4) -> 
        case happyOut46 happy_x_6 of { (HappyWrap46 happy_var_6) -> 
        case happyOut39 happy_x_8 of { (HappyWrap39 happy_var_8) -> 
        happyIn34
                 (BMChannelTypeTriple ForwardFresh happy_var_4 happy_var_6 happy_var_8
        ) `HappyStk` happyRest}}}

happyReduce_83 = happyReduce 8# 29# happyReduction_83
happyReduction_83 (happy_x_8 `HappyStk`
        happy_x_7 `HappyStk`
        happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut39 happy_x_3 of { (HappyWrap39 happy_var_3) -> 
        case happyOut46 happy_x_5 of { (HappyWrap46 happy_var_5) -> 
        case happyOut39 happy_x_7 of { (HappyWrap39 happy_var_7) -> 
        happyIn34
                 (BMChannelTypeTriple Forward happy_var_3 happy_var_5 happy_var_7
        ) `HappyStk` happyRest}}}

happyReduce_84 = happyReduce 8# 29# happyReduction_84
happyReduction_84 (happy_x_8 `HappyStk`
        happy_x_7 `HappyStk`
        happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut39 happy_x_3 of { (HappyWrap39 happy_var_3) -> 
        case happyOut46 happy_x_5 of { (HappyWrap46 happy_var_5) -> 
        case happyOut39 happy_x_7 of { (HappyWrap39 happy_var_7) -> 
        happyIn34
                 (BMChannelTypeTriple Fresh happy_var_3 happy_var_5 happy_var_7
        ) `HappyStk` happyRest}}}

happyReduce_85 = happyReduce 7# 29# happyReduction_85
happyReduction_85 (happy_x_7 `HappyStk`
        happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut39 happy_x_2 of { (HappyWrap39 happy_var_2) -> 
        case happyOut46 happy_x_4 of { (HappyWrap46 happy_var_4) -> 
        case happyOut39 happy_x_6 of { (HappyWrap39 happy_var_6) -> 
        happyIn34
                 (BMChannelTypeTriple Std happy_var_2 happy_var_4 happy_var_6
        ) `HappyStk` happyRest}}}

happyReduce_86 = happyReduce 9# 29# happyReduction_86
happyReduction_86 (happy_x_9 `HappyStk`
        happy_x_8 `HappyStk`
        happy_x_7 `HappyStk`
        happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut39 happy_x_4 of { (HappyWrap39 happy_var_4) -> 
        case happyOut35 happy_x_6 of { (HappyWrap35 happy_var_6) -> 
        case happyOut39 happy_x_8 of { (HappyWrap39 happy_var_8) -> 
        happyIn34
                 (BMChannelTypeTriple ForwardFresh happy_var_4 happy_var_6 happy_var_8
        ) `HappyStk` happyRest}}}

happyReduce_87 = happyReduce 8# 29# happyReduction_87
happyReduction_87 (happy_x_8 `HappyStk`
        happy_x_7 `HappyStk`
        happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut39 happy_x_3 of { (HappyWrap39 happy_var_3) -> 
        case happyOut35 happy_x_5 of { (HappyWrap35 happy_var_5) -> 
        case happyOut39 happy_x_7 of { (HappyWrap39 happy_var_7) -> 
        happyIn34
                 (BMChannelTypeTriple Forward happy_var_3 happy_var_5 happy_var_7
        ) `HappyStk` happyRest}}}

happyReduce_88 = happyReduce 8# 29# happyReduction_88
happyReduction_88 (happy_x_8 `HappyStk`
        happy_x_7 `HappyStk`
        happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut39 happy_x_3 of { (HappyWrap39 happy_var_3) -> 
        case happyOut35 happy_x_5 of { (HappyWrap35 happy_var_5) -> 
        case happyOut39 happy_x_7 of { (HappyWrap39 happy_var_7) -> 
        happyIn34
                 (BMChannelTypeTriple Fresh happy_var_3 happy_var_5 happy_var_7
        ) `HappyStk` happyRest}}}

happyReduce_89 = happyReduce 7# 29# happyReduction_89
happyReduction_89 (happy_x_7 `HappyStk`
        happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut39 happy_x_2 of { (HappyWrap39 happy_var_2) -> 
        case happyOut35 happy_x_4 of { (HappyWrap35 happy_var_4) -> 
        case happyOut39 happy_x_6 of { (HappyWrap39 happy_var_6) -> 
        happyIn34
                 (BMChannelTypeTriple Std happy_var_2 happy_var_4 happy_var_6
        ) `HappyStk` happyRest}}}

happyReduce_90 = happySpecReduce_1  30# happyReduction_90
happyReduction_90 happy_x_1
         =  happyIn35
                 ([]
        )

happyReduce_91 = happySpecReduce_1  30# happyReduction_91
happyReduction_91 happy_x_1
         =  case happyOut23 happy_x_1 of { (HappyWrap23 happy_var_1) -> 
        happyIn35
                 (happy_var_1
        )}

happyReduce_92 = happyReduce 5# 31# happyReduction_92
happyReduction_92 (happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut40 happy_x_1 of { (HappyWrap40 happy_var_1) -> 
        case happyOut40 happy_x_3 of { (HappyWrap40 happy_var_3) -> 
        case happyOut34 happy_x_5 of { (HappyWrap34 happy_var_5) -> 
        happyIn36
                 ((happy_var_1,happy_var_5,happy_var_3)
        ) `HappyStk` happyRest}}}

happyReduce_93 = happySpecReduce_1  31# happyReduction_93
happyReduction_93 happy_x_1
         =  case happyOut37 happy_x_1 of { (HappyWrap37 happy_var_1) -> 
        happyIn36
                 (happy_var_1
        )}

happyReduce_94 = happySpecReduce_3  32# happyReduction_94
happyReduction_94 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut40 happy_x_1 of { (HappyWrap40 happy_var_1) -> 
        case happyOut32 happy_x_2 of { (HappyWrap32 happy_var_2) -> 
        case happyOut40 happy_x_3 of { (HappyWrap40 happy_var_3) -> 
        happyIn37
                 ((happy_var_1,happy_var_2,happy_var_3)
        )}}}

happyReduce_95 = happySpecReduce_3  33# happyReduction_95
happyReduction_95 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut40 happy_x_1 of { (HappyWrap40 happy_var_1) -> 
        case happyOut33 happy_x_2 of { (HappyWrap33 happy_var_2) -> 
        case happyOut40 happy_x_3 of { (HappyWrap40 happy_var_3) -> 
        happyIn38
                 ((happy_var_1,happy_var_2,happy_var_3)
        )}}}

happyReduce_96 = happySpecReduce_1  34# happyReduction_96
happyReduction_96 happy_x_1
         =  case happyOut40 happy_x_1 of { (HappyWrap40 happy_var_1) -> 
        happyIn39
                 (happy_var_1
        )}

happyReduce_97 = happySpecReduce_1  34# happyReduction_97
happyReduction_97 happy_x_1
         =  case happyOut41 happy_x_1 of { (HappyWrap41 happy_var_1) -> 
        happyIn39
                 (happy_var_1
        )}

happyReduce_98 = happySpecReduce_1  35# happyReduction_98
happyReduction_98 happy_x_1
         =  case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        happyIn40
                 ((happy_var_1,False,Nothing)
        )}

happyReduce_99 = happySpecReduce_1  35# happyReduction_99
happyReduction_99 happy_x_1
         =  case happyOut42 happy_x_1 of { (HappyWrap42 happy_var_1) -> 
        happyIn40
                 (happy_var_1
        )}

happyReduce_100 = happySpecReduce_1  36# happyReduction_100
happyReduction_100 happy_x_1
         =  happyIn41
                 (("-",False,Nothing)
        )

happyReduce_101 = happySpecReduce_3  37# happyReduction_101
happyReduction_101 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOutTok happy_x_2 of { (TATOM _ happy_var_2) -> 
        happyIn42
                 ((happy_var_2,True,Nothing)
        )}

happyReduce_102 = happyReduce 5# 37# happyReduction_102
happyReduction_102 (happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOutTok happy_x_2 of { (TATOM _ happy_var_2) -> 
        case happyOut28 happy_x_4 of { (HappyWrap28 happy_var_4) -> 
        happyIn42
                 ((happy_var_2,True, Just happy_var_4)
        ) `HappyStk` happyRest}}

happyReduce_103 = happySpecReduce_1  38# happyReduction_103
happyReduction_103 happy_x_1
         =  case happyOut44 happy_x_1 of { (HappyWrap44 happy_var_1) -> 
        happyIn43
                 ([happy_var_1]
        )}

happyReduce_104 = happySpecReduce_2  38# happyReduction_104
happyReduction_104 happy_x_2
        happy_x_1
         =  case happyOut44 happy_x_1 of { (HappyWrap44 happy_var_1) -> 
        case happyOut43 happy_x_2 of { (HappyWrap43 happy_var_2) -> 
        happyIn43
                 (happy_var_1:happy_var_2
        )}}

happyReduce_105 = happySpecReduce_3  39# happyReduction_105
happyReduction_105 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut38 happy_x_1 of { (HappyWrap38 happy_var_1) -> 
        case happyOut28 happy_x_3 of { (HappyWrap28 happy_var_3) -> 
        happyIn44
                 ((ChGoal happy_var_1 happy_var_3 "")
        )}}

happyReduce_106 = happyReduce 5# 39# happyReduction_106
happyReduction_106 (happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut40 happy_x_1 of { (HappyWrap40 happy_var_1) -> 
        case happyOut40 happy_x_3 of { (HappyWrap40 happy_var_3) -> 
        case happyOut28 happy_x_5 of { (HappyWrap28 happy_var_5) -> 
        happyIn44
                 ((Authentication happy_var_1 happy_var_3 happy_var_5 "")
        ) `HappyStk` happyRest}}}

happyReduce_107 = happyReduce 6# 39# happyReduction_107
happyReduction_107 (happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut40 happy_x_1 of { (HappyWrap40 happy_var_1) -> 
        case happyOut40 happy_x_4 of { (HappyWrap40 happy_var_4) -> 
        case happyOut28 happy_x_6 of { (HappyWrap28 happy_var_6) -> 
        happyIn44
                 ((WAuthentication happy_var_1 happy_var_4 happy_var_6 "")
        ) `HappyStk` happyRest}}}

happyReduce_108 = happyReduce 6# 39# happyReduction_108
happyReduction_108 (happy_x_6 `HappyStk`
        happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut40 happy_x_1 of { (HappyWrap40 happy_var_1) -> 
        case happyOut28 happy_x_4 of { (HappyWrap28 happy_var_4) -> 
        case happyOut40 happy_x_6 of { (HappyWrap40 happy_var_6) -> 
        happyIn44
                 ((ChGoal (happy_var_1,Confidential,happy_var_6) happy_var_4 "")
        ) `HappyStk` happyRest}}}

happyReduce_109 = happyReduce 4# 39# happyReduction_109
happyReduction_109 (happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut28 happy_x_1 of { (HappyWrap28 happy_var_1) -> 
        case happyOut45 happy_x_4 of { (HappyWrap45 happy_var_4) -> 
        happyIn44
                 ((Secret happy_var_1 happy_var_4 False "")
        ) `HappyStk` happyRest}}

happyReduce_110 = happyReduce 5# 39# happyReduction_110
happyReduction_110 (happy_x_5 `HappyStk`
        happy_x_4 `HappyStk`
        happy_x_3 `HappyStk`
        happy_x_2 `HappyStk`
        happy_x_1 `HappyStk`
        happyRest)
         = case happyOut28 happy_x_1 of { (HappyWrap28 happy_var_1) -> 
        case happyOut45 happy_x_5 of { (HappyWrap45 happy_var_5) -> 
        happyIn44
                 ((Secret happy_var_1 happy_var_5 True "")
        ) `HappyStk` happyRest}}

happyReduce_111 = happySpecReduce_1  40# happyReduction_111
happyReduction_111 happy_x_1
         =  case happyOut40 happy_x_1 of { (HappyWrap40 happy_var_1) -> 
        happyIn45
                 ([happy_var_1]
        )}

happyReduce_112 = happySpecReduce_3  40# happyReduction_112
happyReduction_112 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut40 happy_x_1 of { (HappyWrap40 happy_var_1) -> 
        case happyOut45 happy_x_3 of { (HappyWrap45 happy_var_3) -> 
        happyIn45
                 ((happy_var_1:happy_var_3)
        )}}

happyReduce_113 = happySpecReduce_1  41# happyReduction_113
happyReduction_113 happy_x_1
         =  case happyOutTok happy_x_1 of { (TATOM _ happy_var_1) -> 
        happyIn46
                 ([happy_var_1]
        )}

happyReduce_114 = happySpecReduce_3  41# happyReduction_114
happyReduction_114 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOutTok happy_x_2 of { (TATOM _ happy_var_2) -> 
        happyIn46
                 ([happy_var_2]
        )}

happyReduce_115 = happySpecReduce_3  41# happyReduction_115
happyReduction_115 happy_x_3
        happy_x_2
        happy_x_1
         =  case happyOut23 happy_x_2 of { (HappyWrap23 happy_var_2) -> 
        happyIn46
                 (happy_var_2
        )}

happyTerminalToTok term = case term of {
        TATOM _ happy_dollar_dollar -> 2#;
        THYPHEN _ -> 3#;
        THAT _ -> 4#;
        TAT _ -> 5#;
        TDEFINITIONS _ -> 6#;
        TSHARES _ -> 7#;
        TSHARE _ -> 8#;
        TAGREE _ -> 9#;
        TAGREEINSECURELY _ -> 10#;
        TOPENAB _ -> 11#;
        TCLOSEAB _ -> 12#;
        TVERLINE _ -> 13#;
        TEQUATIONS _ -> 14#;
        TPREVSESS _ -> 15#;
        TOPENP _ -> 16#;
        TCLOSEP _ -> 17#;
        TOPENB _ -> 18#;
        TCLOSEB _ -> 19#;
        TOPENSCRYPT _ -> 20#;
        TCLOSESCRYPT _ -> 21#;
        TCOLON _ -> 22#;
        TSEMICOLON _ -> 23#;
        TSECCH _ -> 24#;
        TAUTHCH _ -> 25#;
        TCONFCH _ -> 26#;
        TINSECCH _ -> 27#;
        TFAUTHCH _ -> 28#;
        TFSECCH _ -> 29#;
        TPERCENT _ -> 30#;
        TEXCLAM  _ -> 31#;
        TUNEQUAL _ -> 32#;
        TDOT _ -> 33#;
        TCOMMA _ -> 34#;
        TOPENSQB _ -> 35#;
        TCLOSESQB _ -> 36#;
        TPROTOCOL _ -> 37#;
        TKNOWLEDGE _ -> 38#;
        TWHERE _ -> 39#;
        TTYPES _ -> 40#;
        TACTIONS _ -> 41#;
        TABSTRACTION _ -> 42#;
        TGOALS _ -> 43#;
        TAUTHENTICATES _ -> 44#;
        TWEAKLY _ -> 45#;
        TON _ -> 46#;
        TSECRET _ -> 47#;
        TBETWEEN _ -> 48#;
        TCONFIDENTIAL _ -> 49#;
        TCONFIDENTIALSENDS _ -> 50#;
        TTO _ -> 51#;
        TGUESS _ -> 52#;
        TEQUAL _ -> 53#;
        TFUNSIGN _ -> 54#;
        _ -> -1#;
        }
{-# NOINLINE happyTerminalToTok #-}

happyLex kend  _kmore []       = kend notHappyAtAll []
happyLex _kend kmore  (tk:tks) = kmore (happyTerminalToTok tk) tk tks
{-# INLINE happyLex #-}

happyNewToken action sts stk = happyLex (\tk -> happyDoAction 55# notHappyAtAll action sts stk) (\i tk -> happyDoAction i tk action sts stk)

happyReport 55# tk explist resume tks = happyReport' tks explist resume
happyReport _ tk explist resume tks = happyReport' (tk:tks) explist (\tks -> resume (Happy_Prelude.tail tks))


newtype HappyIdentity a = HappyIdentity a
happyIdentity = HappyIdentity
happyRunIdentity (HappyIdentity a) = a

instance Happy_Prelude.Functor HappyIdentity where
    fmap f (HappyIdentity a) = HappyIdentity (f a)

instance Applicative HappyIdentity where
    pure  = HappyIdentity
    (<*>) = ap
instance Happy_Prelude.Monad HappyIdentity where
    return = pure
    (HappyIdentity p) >>= q = q p

happyThen :: () => (HappyIdentity a) -> (a -> (HappyIdentity b)) -> (HappyIdentity b)
happyThen = (Happy_Prelude.>>=)
happyReturn :: () => a -> (HappyIdentity a)
happyReturn = (Happy_Prelude.return)
happyThen1 m k tks = (Happy_Prelude.>>=) m (\a -> k a tks)
happyFmap1 f m tks = happyThen (m tks) (\a -> happyReturn (f a))
happyReturn1 :: () => a -> b -> (HappyIdentity a)
happyReturn1 = \a tks -> (Happy_Prelude.return) a
happyReport' :: () => [(Token)] -> [Happy_Prelude.String] -> ([(Token)] -> (HappyIdentity a)) -> (HappyIdentity a)
happyReport' = (\tokens expected resume -> HappyIdentity Happy_Prelude.$ (happyError) tokens)

happyAbort :: () => [(Token)] -> (HappyIdentity a)
happyAbort = Happy_Prelude.error "Called abort handler in non-resumptive parser"

anbxparser tks = happyRunIdentity happySomeParser where
 happySomeParser = happyThen (happyParse 0# tks) (\x -> happyReturn (let {(HappyWrap5 x') = happyOut5 x} in x'))

happySeq = happyDontSeq


happyError :: [Token] -> a
happyError tks = error ("AnBx parse error at " ++ lcn ++ "\n" )
        where
        lcn = case tks of
                          [] -> "end of file"
                          tk:_ -> "line " ++ show l ++ ", column " ++ show c ++ " - Token: " ++ show tk
                                where
                                        AlexPn _ l c = token_posn tk
#define HAPPY_COERCE 1
-- $Id: GenericTemplate.hs,v 1.26 2005/01/14 14:47:22 simonmar Exp $

#if !defined(__GLASGOW_HASKELL__)
#  error This code isn't being built with GHC.
#endif

-- Get WORDS_BIGENDIAN (if defined)
#include "MachDeps.h"

-- Do not remove this comment. Required to fix CPP parsing when using GCC and a clang-compiled alex.
#define LT(n,m) ((Happy_GHC_Exts.tagToEnum# (n Happy_GHC_Exts.<# m)) :: Happy_Prelude.Bool)
#define GTE(n,m) ((Happy_GHC_Exts.tagToEnum# (n Happy_GHC_Exts.>=# m)) :: Happy_Prelude.Bool)
#define EQ(n,m) ((Happy_GHC_Exts.tagToEnum# (n Happy_GHC_Exts.==# m)) :: Happy_Prelude.Bool)
#define PLUS(n,m) (n Happy_GHC_Exts.+# m)
#define MINUS(n,m) (n Happy_GHC_Exts.-# m)
#define TIMES(n,m) (n Happy_GHC_Exts.*# m)
#define NEGATE(n) (Happy_GHC_Exts.negateInt# (n))

type Happy_Int = Happy_GHC_Exts.Int#
data Happy_IntList = HappyCons Happy_Int Happy_IntList

#define INVALID_TOK -1#
#define ERROR_TOK 0#
#define CATCH_TOK 1#

#if defined(HAPPY_COERCE)
#  define GET_ERROR_TOKEN(x)  (case Happy_GHC_Exts.unsafeCoerce# x of { (Happy_GHC_Exts.I# i) -> i })
#  define MK_ERROR_TOKEN(i)   (Happy_GHC_Exts.unsafeCoerce# (Happy_GHC_Exts.I# i))
#  define MK_TOKEN(x)         (happyInTok (x))
#else
#  define GET_ERROR_TOKEN(x)  (case x of { HappyErrorToken (Happy_GHC_Exts.I# i) -> i })
#  define MK_ERROR_TOKEN(i)   (HappyErrorToken (Happy_GHC_Exts.I# i))
#  define MK_TOKEN(x)         (HappyTerminal (x))
#endif

#if defined(HAPPY_DEBUG)
#  define DEBUG_TRACE(s)    (happyTrace (s)) Happy_Prelude.$
happyTrace string expr = Happy_System_IO_Unsafe.unsafePerformIO Happy_Prelude.$ do
    Happy_System_IO.hPutStr Happy_System_IO.stderr string
    Happy_Prelude.return expr
#else
#  define DEBUG_TRACE(s)    {- nothing -}
#endif

infixr 9 `HappyStk`
data HappyStk a = HappyStk a (HappyStk a)

-----------------------------------------------------------------------------
-- starting the parse

happyParse start_state = happyNewToken start_state notHappyAtAll notHappyAtAll

-----------------------------------------------------------------------------
-- Accepting the parse

-- If the current token is ERROR_TOK, it means we've just accepted a partial
-- parse (a %partial parser).  We must ignore the saved token on the top of
-- the stack in this case.
happyAccept ERROR_TOK tk st sts (_ `HappyStk` ans `HappyStk` _) =
        happyReturn1 ans
happyAccept j tk st sts (HappyStk ans _) =
        (happyTcHack j (happyTcHack st)) (happyReturn1 ans)

-----------------------------------------------------------------------------
-- Arrays only: do the next action

happyDoAction i tk st =
  DEBUG_TRACE("state: " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# st) Happy_Prelude.++
              ",\ttoken: " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# i) Happy_Prelude.++
              ",\taction: ")
  case happyDecodeAction (happyNextAction i st) of
    HappyFail             -> DEBUG_TRACE("failing.\n")
                             happyFail i tk st
    HappyAccept           -> DEBUG_TRACE("accept.\n")
                             happyAccept i tk st
    HappyReduce rule      -> DEBUG_TRACE("reduce (rule " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# rule) Happy_Prelude.++ ")")
                             (happyReduceArr Happy_Data_Array.! (Happy_GHC_Exts.I# rule)) i tk st
    HappyShift  new_state -> DEBUG_TRACE("shift, enter state " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# new_state) Happy_Prelude.++ "\n")
                             happyShift new_state i tk st

{-# INLINE happyNextAction #-}
happyNextAction i st = case happyIndexActionTable i st of
  Happy_Prelude.Just (Happy_GHC_Exts.I# act) -> act
  Happy_Prelude.Nothing                      -> happyIndexOffAddr happyDefActions st

{-# INLINE happyIndexActionTable #-}
happyIndexActionTable i st
  | GTE(i, 0#), GTE(off, 0#), EQ(happyIndexOffAddr happyCheck off, i)
  -- i >= 0:   Guard against INVALID_TOK (do the default action, which ultimately errors)
  -- off >= 0: Otherwise it's a default action
  -- equality check: Ensure that the entry in the compressed array is owned by st
  = Happy_Prelude.Just (Happy_GHC_Exts.I# (happyIndexOffAddr happyTable off))
  | Happy_Prelude.otherwise
  = Happy_Prelude.Nothing
  where
    off = PLUS(happyIndexOffAddr happyActOffsets st, i)

data HappyAction
  = HappyFail
  | HappyAccept
  | HappyReduce Happy_Int -- rule number
  | HappyShift Happy_Int  -- new state
  deriving Happy_Prelude.Show

{-# INLINE happyDecodeAction #-}
happyDecodeAction :: Happy_Int -> HappyAction
happyDecodeAction  0#                        = HappyFail
happyDecodeAction -1#                        = HappyAccept
happyDecodeAction action | LT(action, 0#)    = HappyReduce NEGATE(PLUS(action, 1#))
                         | Happy_Prelude.otherwise = HappyShift MINUS(action, 1#)

{-# INLINE happyIndexGotoTable #-}
happyIndexGotoTable nt st = happyIndexOffAddr happyTable off
  where
    off = PLUS(happyIndexOffAddr happyGotoOffsets st, nt)

{-# INLINE happyIndexOffAddr #-}
happyIndexOffAddr :: HappyAddr -> Happy_Int -> Happy_Int
happyIndexOffAddr (HappyA# arr) off =
#if __GLASGOW_HASKELL__ >= 901
  Happy_GHC_Exts.int32ToInt# -- qualified import because it doesn't exist on older GHC's
#endif
#ifdef WORDS_BIGENDIAN
  -- The CI of `alex` tests this code path
  (Happy_GHC_Exts.word32ToInt32# (Happy_GHC_Exts.wordToWord32# (Happy_GHC_Exts.byteSwap32# (Happy_GHC_Exts.word32ToWord# (Happy_GHC_Exts.int32ToWord32#
#endif
  (Happy_GHC_Exts.indexInt32OffAddr# arr off)
#ifdef WORDS_BIGENDIAN
  )))))
#endif

happyIndexRuleArr :: Happy_Int -> (# Happy_Int, Happy_Int #)
happyIndexRuleArr r = (# nt, len #)
  where
    !(Happy_GHC_Exts.I# n_starts) = happy_n_starts
    offs = TIMES(MINUS(r,n_starts),2#)
    nt = happyIndexOffAddr happyRuleArr offs
    len = happyIndexOffAddr happyRuleArr PLUS(offs,1#)

data HappyAddr = HappyA# Happy_GHC_Exts.Addr#

-----------------------------------------------------------------------------
-- Shifting a token

happyShift new_state ERROR_TOK tk st sts stk@(x `HappyStk` _) =
     -- See "Error Fixup" below
     let i = GET_ERROR_TOKEN(x) in
     DEBUG_TRACE("shifting the error token")
     happyDoAction i tk new_state (HappyCons st sts) stk

happyShift new_state i tk st sts stk =
     happyNewToken new_state (HappyCons st sts) (MK_TOKEN(tk) `HappyStk` stk)

-- happyReduce is specialised for the common cases.

happySpecReduce_0 nt fn j tk st sts stk
     = happySeq fn (happyGoto nt j tk st (HappyCons st sts) (fn `HappyStk` stk))

happySpecReduce_1 nt fn j tk old_st sts@(HappyCons st _) (v1 `HappyStk` stk')
     = let r = fn v1 in
       happyTcHack old_st (happySeq r (happyGoto nt j tk st sts (r `HappyStk` stk')))

happySpecReduce_2 nt fn j tk old_st
  (HappyCons _ sts@(HappyCons st _))
  (v1 `HappyStk` v2 `HappyStk` stk')
     = let r = fn v1 v2 in
       happyTcHack old_st (happySeq r (happyGoto nt j tk st sts (r `HappyStk` stk')))

happySpecReduce_3 nt fn j tk old_st
  (HappyCons _ (HappyCons _ sts@(HappyCons st _)))
  (v1 `HappyStk` v2 `HappyStk` v3 `HappyStk` stk')
     = let r = fn v1 v2 v3 in
       happyTcHack old_st (happySeq r (happyGoto nt j tk st sts (r `HappyStk` stk')))

happyReduce k nt fn j tk st sts stk
     = case happyDrop MINUS(k,(1# :: Happy_Int)) sts of
         sts1@(HappyCons st1 _) ->
                let r = fn stk in -- it doesn't hurt to always seq here...
                st `happyTcHack` happyDoSeq r (happyGoto nt j tk st1 sts1 r)

happyMonadReduce k nt fn j tk st sts stk =
      case happyDrop k (HappyCons st sts) of
        sts1@(HappyCons st1 _) ->
          let drop_stk = happyDropStk k stk in
          j `happyTcHack` happyThen1 (fn stk tk)
                                     (\r -> happyGoto nt j tk st1 sts1 (r `HappyStk` drop_stk))

happyMonad2Reduce k nt fn j tk st sts stk =
      case happyDrop k (HappyCons st sts) of
        sts1@(HappyCons st1 _) ->
          let drop_stk = happyDropStk k stk
              off = happyIndexOffAddr happyGotoOffsets st1
              off_i = PLUS(off, nt)
              new_state = happyIndexOffAddr happyTable off_i
          in
            j `happyTcHack` happyThen1 (fn stk tk)
                                       (\r -> happyNewToken new_state sts1 (r `HappyStk` drop_stk))

happyDrop 0# l               = l
happyDrop n  (HappyCons _ t) = happyDrop MINUS(n,(1# :: Happy_Int)) t

happyDropStk 0# l                 = l
happyDropStk n  (x `HappyStk` xs) = happyDropStk MINUS(n,(1#::Happy_Int)) xs

-----------------------------------------------------------------------------
-- Moving to a new state after a reduction

happyGoto nt j tk st =
   DEBUG_TRACE(", goto state " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# new_state) Happy_Prelude.++ "\n")
   happyDoAction j tk new_state
  where new_state = happyIndexGotoTable nt st

{- Note [Error recovery]
~~~~~~~~~~~~~~~~~~~~~~~~
When there is no applicable action for the current lookahead token `tk`,
happy enters error recovery mode. Depending on whether the grammar file
declares the two action form `%error { abort } { report }` for
    Resumptive Error Handling,
it works in one (not resumptive) or two phases (resumptive):

 1. Fixup mode:
    Try to see if there is an action for the error token ERROR_TOK. If there
    is, do *not* emit an error and pretend instead that an `error` token was
    inserted.
    When there is no ERROR_TOK action, report an error.

    In non-resumptive error handling, calling the single error handler
    (e.g. `happyError`) will throw an exception and abort the parser.
    However, in resumptive error handling we enter *error resumption mode*.

 2. Error resumption mode:
    After reporting the error (with `report`), happy will attempt to find
    a good state stack to resume parsing in.
    For each candidate stack, it discards input until one of the candidates
    resumes (i.e. shifts the current input).
    If no candidate resumes before the end of input, resumption failed and
    calls the `abort` function, to much the same effect as in non-resumptive
    error handling.

    Candidate stacks are declared by the grammar author using the special
    `catch` terminal and called "catch frames".
    This mechanism is described in detail in Note [happyResume].

The `catch` resumption mechanism (2) is what usually is associated with
`error` in `bison` or `menhir`. Since `error` is used for the Fixup mechanism
(1) above, we call the corresponding token `catch`.
Furthermore, in constrast to `bison`, our implementation of `catch`
non-deterministically considers multiple catch frames on the stack for
resumption (See Note [Multiple catch frames]).

Note [happyResume]
~~~~~~~~~~~~~~~~~~
`happyResume` implements the resumption mechanism from Note [Error recovery].
It is best understood by example. Consider

Exp :: { String }
Exp : '1'                { "1" }
    | catch              { "catch" }
    | Exp '+' Exp %shift { $1 Happy_Prelude.++ " + " Happy_Prelude.++ $3 } -- %shift: associate 1 + 1 + 1 to the right
    | '(' Exp ')'        { "(" Happy_Prelude.++ $2 Happy_Prelude.++ ")" }

The idea of the use of `catch` here is that upon encountering a parse error
during expression parsing, we can gracefully degrade using the `catch` rule,
still producing a partial syntax tree and keep on parsing to find further
syntax errors.

Let's trace the parser state for input 11+1, which will error out after shifting 1.
After shifting, we have the following item stack (growing downwards and omitting
transitive closure items):

  State 0: %start_parseExp -> . Exp
  State 5: Exp -> '1' .

(Stack as a list of state numbers: [5,0].)
As Note [Error recovery] describes, we will first try Fixup mode.
That fails because no production can shift the `error` token.
Next we try Error resumption mode. This works as follows:

  1. Pop off the item stack until we find an item that can shift the `catch`
     token. (Implemented in `pop_items`.)
       * State 5 cannot shift catch. Pop.
       * State 0 can shift catch, which would transition into
          State 4: Exp -> catch .
     So record the *stack* `[4,0]` after doing the shift transition.
     We call this a *catch frame*, where the top is a *catch state*,
     corresponding to an item in which we just shifted a `catch` token.
     There can be multiple such catch stacks, see Note [Multiple catch frames].

  2. Discard tokens from the input until the lookahead can be shifted in one
     of the catch stacks. (Implemented in `discard_input_until_exp` and
     `some_catch_state_shifts`.)
       * We cannot shift the current lookahead '1' in state 4, so we discard
       * We *can* shift the next lookahead '+' in state 4, but only after
         reducing, which pops State 4 and goes to State 3:
           State 3: %start_parseExp -> Exp .
                    Exp -> Exp . '+' Exp
         Here we can shift '+'.
     As you can see, to implement this machinery we need to simulate
     the operation of the LALR automaton, especially reduction
     (`happySimulateReduce`).

Note [Multiple catch frames]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
For fewer spurious error messages, it can be beneficial to trace multiple catch
items. Consider

Exp : '1'
    | catch
    | Exp '+' Exp %shift
    | '(' Exp ')'

Let's trace the parser state for input (;+1, which will error out after shifting (.
After shifting, we have the following item stack (growing downwards):

  State 0: %start_parseExp -> . Exp
  State 6: Exp -> '(' . Exp ')'

Upon error, we want to find items in the stack which can shift a catch token.
Note that both State 0 and State 6 can shift a catch token, transitioning into
  State 4: Exp -> catch .
Hence we record the catch frames `[4,6,0]` and `[4,0]` for possible resumption.

Which catch frame do we pick for resumption?
Note that resuming catch frame `[4,0]` will parse as "catch+1", whereas
resuming the innermost frame `[4,6,0]` corresponds to parsing "(catch+1".
The latter would keep discarding input until the closing ')' is found.
So we will discard + and 1, leading to a spurious syntax error at the end of
input, aborting the parse and never producing a partial syntax tree. Bad!

It is far preferable to resume with catch frame `[4,0]`, where we can resume
successfully on input +, so that is what we do.

In general, we pick the catch frame for resumption that discards the least
amount of input for a successful shift, preferring the topmost such catch frame.
-}

-- happyFail :: Happy_Int -> Token -> Happy_Int -> _
-- This function triggers Note [Error recovery].
-- If the current token is ERROR_TOK, phase (1) has failed and we might try
-- phase (2).
happyFail ERROR_TOK = happyFixupFailed
happyFail i         = happyTryFixup i

-- Enter Error Fixup (see Note [Error recovery]):
-- generate an error token, save the old token and carry on.
-- When a `happyShift` accepts the error token, we will pop off the error token
-- to resume parsing with the current lookahead `i`.
happyTryFixup i tk action sts stk =
  DEBUG_TRACE("entering `error` fixup.\n")
  happyDoAction ERROR_TOK tk action sts (MK_ERROR_TOKEN(i) `HappyStk` stk)
  -- NB: `happyShift` will simply pop the error token and carry on with
  --     `tk`. Hence we don't change `tk` in the call here

-- See Note [Error recovery], phase (2).
-- Enter resumption mode after reporting the error by calling `happyResume`.
happyFixupFailed tk st sts (x `HappyStk` stk) =
  let i = GET_ERROR_TOKEN(x) in
  DEBUG_TRACE("`error` fixup failed.\n")
  let resume   = happyResume i tk st sts stk
      expected = happyExpectedTokens st sts in
  happyReport i tk expected resume

-- happyResume :: Happy_Int -> Token -> Happy_Int -> _
-- See Note [happyResume]
happyResume i tk st sts stk = pop_items [] st sts stk
  where
    !(Happy_GHC_Exts.I# n_starts) = happy_n_starts   -- this is to test whether we have a start token
    !(Happy_GHC_Exts.I# eof_i) = happy_n_terms Happy_Prelude.- 1   -- this is the token number of the EOF token
    happy_list_to_list :: Happy_IntList -> [Happy_Prelude.Int]
    happy_list_to_list (HappyCons st sts)
      | LT(st, n_starts)
      = [(Happy_GHC_Exts.I# st)]
      | Happy_Prelude.otherwise
      = (Happy_GHC_Exts.I# st) : happy_list_to_list sts

    -- See (1) of Note [happyResume]
    pop_items catch_frames st sts stk
      | LT(st, n_starts)
      = DEBUG_TRACE("reached start state " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# st) Happy_Prelude.++ ", ")
        if Happy_Prelude.null catch_frames_new
          then DEBUG_TRACE("no resumption.\n")
               happyAbort
          else DEBUG_TRACE("now discard input, trying to anchor in states " Happy_Prelude.++ Happy_Prelude.show (Happy_Prelude.map (happy_list_to_list . Happy_Prelude.fst) (Happy_Prelude.reverse catch_frames_new)) Happy_Prelude.++ ".\n")
               discard_input_until_exp i tk (Happy_Prelude.reverse catch_frames_new)
      | (HappyCons st1 sts1) <- sts, _ `HappyStk` stk1 <- stk
      = pop_items catch_frames_new st1 sts1 stk1
      where
        !catch_frames_new
          | HappyShift new_state <- happyDecodeAction (happyNextAction CATCH_TOK st)
          , DEBUG_TRACE("can shift catch token in state " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# st) Happy_Prelude.++ ", into state " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# new_state) Happy_Prelude.++ "\n")
            Happy_Prelude.null (Happy_Prelude.filter (\(HappyCons _ (HappyCons h _),_) -> EQ(st,h)) catch_frames)
          = (HappyCons new_state (HappyCons st sts), MK_ERROR_TOKEN(i) `HappyStk` stk):catch_frames -- MK_ERROR_TOKEN(i) is just some dummy that should not be accessed by user code
          | Happy_Prelude.otherwise
          = DEBUG_TRACE("already shifted or can't shift catch in " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# st) Happy_Prelude.++ "\n")
            catch_frames

    -- See (2) of Note [happyResume]
    discard_input_until_exp i tk catch_frames
      | Happy_Prelude.Just (HappyCons st (HappyCons catch_st sts), catch_frame) <- some_catch_state_shifts i catch_frames
      = DEBUG_TRACE("found expected token in state " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# st) Happy_Prelude.++ " after shifting from " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# catch_st) Happy_Prelude.++ ": " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# i) Happy_Prelude.++ "\n")
        happyDoAction i tk st (HappyCons catch_st sts) catch_frame
      | EQ(i,eof_i) -- is i EOF?
      = DEBUG_TRACE("reached EOF, cannot resume. abort parse :(\n")
        happyAbort
      | Happy_Prelude.otherwise
      = DEBUG_TRACE("discard token " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# i) Happy_Prelude.++ "\n")
        happyLex (\eof_tk -> discard_input_until_exp eof_i eof_tk catch_frames) -- eof
                 (\i tk   -> discard_input_until_exp i tk catch_frames)         -- not eof

    some_catch_state_shifts _ [] = DEBUG_TRACE("no catch state could shift.\n") Happy_Prelude.Nothing
    some_catch_state_shifts i catch_frames@(((HappyCons st sts),_):_) = try_head i st sts catch_frames
      where
        try_head i st sts catch_frames = -- PRECONDITION: head catch_frames = (HappyCons st sts)
          DEBUG_TRACE("trying token " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# i) Happy_Prelude.++ " in state " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# st) Happy_Prelude.++ ": ")
          case happyDecodeAction (happyNextAction i st) of
            HappyFail     -> DEBUG_TRACE("fail.\n")   some_catch_state_shifts i (Happy_Prelude.tail catch_frames)
            HappyAccept   -> DEBUG_TRACE("accept.\n") Happy_Prelude.Just (Happy_Prelude.head catch_frames)
            HappyShift _  -> DEBUG_TRACE("shift.\n")  Happy_Prelude.Just (Happy_Prelude.head catch_frames)
            HappyReduce r -> case happySimulateReduce r st sts of
              (HappyCons st1 sts1) -> try_head i st1 sts1 catch_frames

happySimulateReduce r st sts =
  DEBUG_TRACE("simulate reduction of rule " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# r) Happy_Prelude.++ ", ")
  let (# nt, len #) = happyIndexRuleArr r in
  DEBUG_TRACE("nt " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# nt) Happy_Prelude.++ ", len: " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# len) Happy_Prelude.++ ", new_st ")
  let !(sts1@(HappyCons st1 _)) = happyDrop len (HappyCons st sts)
      new_st = happyIndexGotoTable nt st1 in
  DEBUG_TRACE(Happy_Prelude.show (Happy_GHC_Exts.I# new_st) Happy_Prelude.++ ".\n")
  (HappyCons new_st sts1)

happyTokenToString :: Happy_Prelude.Int -> Happy_Prelude.String
happyTokenToString i = happyTokenStrings Happy_Prelude.!! (i Happy_Prelude.- 2) -- 2: errorTok, catchTok

happyExpectedTokens :: Happy_Int -> Happy_IntList -> [Happy_Prelude.String]
-- Upon a parse error, we want to suggest tokens that are expected in that
-- situation. This function computes such tokens.
-- It works by examining the top of the state stack.
-- For every token number that does a shift transition, record that token number.
-- For every token number that does a reduce transition, simulate that reduction
-- on the state state stack and repeat.
-- The recorded token numbers are then formatted with 'happyTokenToString' and
-- returned.
happyExpectedTokens st sts =
  DEBUG_TRACE("constructing expected tokens.\n")
  Happy_Prelude.map happyTokenToString (search_shifts st sts [])
  where
    search_shifts st sts shifts = Happy_Prelude.foldr (add_action st sts) shifts (distinct_actions st)
    add_action st sts (Happy_GHC_Exts.I# i, Happy_GHC_Exts.I# act) shifts =
      DEBUG_TRACE("found action in state " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# st) Happy_Prelude.++ ", input " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# i) Happy_Prelude.++ ", " Happy_Prelude.++ Happy_Prelude.show (happyDecodeAction act) Happy_Prelude.++ "\n")
      case happyDecodeAction act of
        HappyFail     -> shifts
        HappyAccept   -> shifts -- This would always be %eof or error... Not helpful
        HappyShift _  -> Happy_Prelude.insert (Happy_GHC_Exts.I# i) shifts
        HappyReduce r -> case happySimulateReduce r st sts of
          (HappyCons st1 sts1) -> search_shifts st1 sts1 shifts
    distinct_actions st
      -- The (token number, action) pairs of all actions in the given state
      = ((-1), (Happy_GHC_Exts.I# (happyIndexOffAddr happyDefActions st)))
      : [ (i, act) | i <- [begin_i..happy_n_terms], act <- get_act row_off i ]
      where
        row_off = happyIndexOffAddr happyActOffsets st
        begin_i = 2 -- +2: errorTok,catchTok
    get_act off (Happy_GHC_Exts.I# i) -- happyIndexActionTable with cached row offset
      | let off_i = PLUS(off,i)
      , GTE(off_i,0#)
      , EQ(happyIndexOffAddr happyCheck off_i,i)
      = [(Happy_GHC_Exts.I# (happyIndexOffAddr happyTable off_i))]
      | Happy_Prelude.otherwise
      = []

-- Internal happy errors:

notHappyAtAll :: a
notHappyAtAll = Happy_Prelude.error "Internal Happy parser panic. This is not supposed to happen! Please open a bug report at https://github.com/haskell/happy/issues.\n"

-----------------------------------------------------------------------------
-- Hack to get the typechecker to accept our action functions

happyTcHack :: Happy_Int -> a -> a
happyTcHack x y = y
{-# INLINE happyTcHack #-}

-----------------------------------------------------------------------------
-- Seq-ing.  If the --strict flag is given, then Happy emits
--      happySeq = happyDoSeq
-- otherwise it emits
--      happySeq = happyDontSeq

happyDoSeq, happyDontSeq :: a -> b -> b
happyDoSeq   a b = a `Happy_GHC_Exts.seq` b
happyDontSeq a b = b

-----------------------------------------------------------------------------
-- Don't inline any functions from the template.  GHC has a nasty habit
-- of deciding to inline happyGoto everywhere, which increases the size of
-- the generated parser quite a bit.

{-# NOINLINE happyDoAction #-}
{-# NOINLINE happyTable #-}
{-# NOINLINE happyCheck #-}
{-# NOINLINE happyActOffsets #-}
{-# NOINLINE happyGotoOffsets #-}
{-# NOINLINE happyDefActions #-}

{-# NOINLINE happyShift #-}
{-# NOINLINE happySpecReduce_0 #-}
{-# NOINLINE happySpecReduce_1 #-}
{-# NOINLINE happySpecReduce_2 #-}
{-# NOINLINE happySpecReduce_3 #-}
{-# NOINLINE happyReduce #-}
{-# NOINLINE happyMonadReduce #-}
{-# NOINLINE happyGoto #-}
{-# NOINLINE happyFail #-}

-- end of Happy Template.
