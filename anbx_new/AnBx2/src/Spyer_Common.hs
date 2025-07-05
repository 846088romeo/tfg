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

module Spyer_Common where
import qualified Data.Set as Set
import Data.List (transpose)

-- build a list of terms that can be built from a list of lists 
zipLists :: [[a]] -> [[a]]
zipLists list = takeWhile (\x -> length x == length list) $ transpose list                               

foldset :: (a -> b -> b) -> b -> Set.Set a -> b
foldset = Set.foldr

setChoose :: Set.Set a -> a
setChoose = Set.findMin

setExist :: (a -> Bool) -> Set.Set a -> Bool
setExist p s = not (Set.null (Set.filter p s))
