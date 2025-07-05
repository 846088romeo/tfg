{-

 AnBx Compiler and Code Generator

 Copyright 2011-2025 Paolo Modesti
 Copyright 2021 Rémi Garcia
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

module JavaType where
import AnBAst
import AnBxMsgCommon
import Java_TypeSystem_JType
import Java_TypeSystem_Context
import Java_TypeSystem_Evaluator
import JavaCodeGenConfig

import Data.Char
import Debug.Trace()

---------------------

castofTypeExpr :: NExpression -> String
castofTypeExpr = castofType . typeof

javaTypeofExpression :: NExpression -> String
javaTypeofExpression = showJavaType . typeof

castofType :: JType -> String
castofType t = parOpen ++ showJavaType t ++ parClose ++ " "

typeof :: NExpression -> JType
typeof e = typeofTS e newContext

jDefaultType :: JType
jDefaultType = JString

-- all the idents defined in Types
identsOfProtocol :: Types -> [Ident]
identsOfProtocol types = concat [ ids | (_,ids) <- types]

-- find the id as defined in Types
properIdent :: String -> [Ident] -> Ident
properIdent s [] = s
properIdent s (id:ids) = if map toLower s == map toLower id then id else properIdent s ids


