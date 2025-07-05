module AnB2IF_Common where
{-

 AnBx Compiler and Code Generator

 Copyright 2023-2025 Paolo Modesti
 Copyright 2023-2024 SCM/SCDT/SCEDT, Teesside University

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

-- some data types, similar to OFMC but simplified    

-- | The output type of the AnB translators
data OutputType = 
                Pretty  -- ^ standard AnB output
                | IF    -- ^ standard translation to AVISPA Intermediate Format
                | Isa   -- ^ output for Isabelle (not used)
                deriving (Eq,Show)

-- | The set of options and parameters that are passed to the AnB translators
data AnBOnP = 
                AnBOnP { anbfilename  :: String,        -- ^ AnB file to translate 
                            theory    :: Maybe String,  -- ^ Algebraic theory file (not supported now)
                            anboutput :: Maybe String,  -- ^ Output filename
                            numSess   :: Maybe Int,     -- ^ Number of sessions (for translation to IF)
                            outt      :: OutputType,    -- ^ Output type
                            typed     :: Bool,          -- ^ flag for typed protocol model
                            noowngoal :: Bool,          -- ^ whether authentication on oneself is checked
                            if2cif    :: Bool,          -- ^ rewriting step from IF/Annotated AnB to cryptIF
                            -- <paolo-eq>
                            eqnoexec  :: Bool           -- ^ disable executable checks on AnB -> IF, if executable checks have been already performed in previous steps 
                            -- <paolo-eq>     
                       }

defaultAnBOpts :: AnBOnP
defaultAnBOpts = AnBOnP {   anbfilename = "",
                            theory = Nothing,
                            anboutput = Nothing,
                            numSess = Just 2,
                            outt = IF,
                            typed = True,
                            noowngoal = True,
                            if2cif = False,
                            -- <paolo-eq>
                            eqnoexec = True 
                            -- <paolo-eq>     
                       }