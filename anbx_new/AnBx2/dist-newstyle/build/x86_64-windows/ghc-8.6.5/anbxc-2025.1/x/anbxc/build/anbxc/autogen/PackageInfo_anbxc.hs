{-# LANGUAGE NoRebindableSyntax #-}
{-# OPTIONS_GHC -fno-warn-missing-import-lists #-}
{-# OPTIONS_GHC -w #-}
module PackageInfo_anbxc (
    name,
    version,
    synopsis,
    copyright,
    homepage,
  ) where

import Data.Version (Version(..))
import Prelude

name :: String
name = "anbxc"
version :: Version
version = Version [2025,1] []

synopsis :: String
synopsis = "AnBx Compiler and Code Generator"
copyright :: String
copyright = ""
homepage :: String
homepage = "https://www.dais.unive.it/~modesti/anbx/"
