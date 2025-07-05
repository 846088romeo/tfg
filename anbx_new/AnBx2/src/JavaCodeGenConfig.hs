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
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "Use camelCase" #-}

module JavaCodeGenConfig where
--import Debug.Trace
import Java_TypeSystem_JType
import AnBAst
import AnBxOnP (OutType (..))
import AnBxAst (AnBxChannelType(..), AnBxType (..), showSpecType, agentDefaultType)
import AnBxMsgCommon (ProtType (PTAnBx))
import Data.Containers.ListUtils (nubOrd)

data APIOp = APISend | APIReceive | APIEncrypt | APIEncryptS | APIDecrypt | APIDecryptS | APISign | APIVerify
                     | APIHash | APIHmac | APISQN | APINonce | APISymKey | APISymKeyPBE | APIHmacKey
                     | APIDHSecret | APIDHSecKey | APIDHPubKey | APIEqCheck | APIInvCheck | APIWffCheck | APINotEqCheck | APIWriteObject | APIReadObject
                     | APIKeyPair | APIKeyPairPublicKey | APIPublicKey | APIXor | APItoString | APIgetBytes | APIhashCode | APISeen
                  deriving (Eq,Show)

data ChannelMode = SSL_PLAIN | SSL_AUTH | SSL_SECRET | SSL_SECURE
                  deriving (Eq,Show)

data CryptoMode = CM_Std | CM_Block -- not implemented yet
cryptomode :: CryptoMode
cryptomode = CM_Std
               
-- must match the Java API
getAPIOp :: APIOp -> String
getAPIOp APISend = "Send"
getAPIOp APIReceive = "Receive"
getAPIOp APIEncrypt = "encrypt"
getAPIOp APIEncryptS = "encrypt"
getAPIOp APIDecrypt = "decrypt"
getAPIOp APIDecryptS = "decrypt"
getAPIOp APISign = "sign"
getAPIOp APIVerify = "verify"
getAPIOp APIHash = "makeDigest"
getAPIOp APIHmac = "makeHmac"
getAPIOp APISQN = "getSeqNumber"
getAPIOp APINonce = "getNonce"
getAPIOp APISymKey = "getSymmetricKey"
getAPIOp APISymKeyPBE = "getSymmetricKeyPBE"
getAPIOp APIHmacKey = "getHmacKey"
getAPIOp APIDHPubKey = "getKeyEx_PublicKey"
getAPIOp APIDHSecret = "getKeyEx_KeyPair"
getAPIOp APIDHSecKey = "getKeyEx_SecretKey"
getAPIOp APINotEqCheck = "noteqCheck"
getAPIOp APIEqCheck = "eqCheck"
getAPIOp APIInvCheck = "invCheck"
getAPIOp APIWffCheck = "wffCheck"
-- getAPIOp APINotEqCheck = if showCheckLabel then "noteqCheckL" else "noteqCheck"
-- getAPIOp APIEqCheck = if showCheckLabel then "eqCheckL" else "eqCheck"
-- getAPIOp APIInvCheck = if showCheckLabel then "invCheckL" else "invCheck"
-- getAPIOp APIWffCheck = if showCheckLabel then "wffCheckL" else "wffCheck"
getAPIOp APIWriteObject = "writeObject"
getAPIOp APIReadObject = "readObject"
getAPIOp APIKeyPair = "getKeyPair"
getAPIOp APIKeyPairPublicKey = "getKeyPair_PublicKey"
getAPIOp APIPublicKey = "getPublicKey"
getAPIOp APIXor = "xor"
getAPIOp APIgetBytes = "getBytes"
getAPIOp APItoString = "toString"
getAPIOp APIhashCode = "hashCode"
getAPIOp APISeen = "seen"
-- must match the concrete types in the target language (Java)

-- type names
type_Crypto_ByteArray :: String
type_Crypto_ByteArray = "Crypto_ByteArray"
type_Crypto_SealedPair :: String
type_Crypto_SealedPair = "Crypto_SealedPair"
type_SealedObject :: String
type_SealedObject = "SealedObject"
type_SignedObject :: String
type_SignedObject = "SignedObject"
type_Crypto_KeyPair :: String
type_Crypto_KeyPair = "Crypto_KeyPair"
type_KeyPair :: String
type_KeyPair = "KeyPair"
type_SecretKey :: String
type_SecretKey = "SecretKey"
type_PublicKey :: String
type_PublicKey = "PublicKey"
type_PrivateKey :: String
type_PrivateKey = "PrivateKey"
type_String :: String
type_String = "String"
type_Object :: String
type_Object = "Object"
type_DHParameterSpec :: String
type_DHParameterSpec = "DHParameterSpec"
type_AnBx_Params :: String
type_AnBx_Params = "AnBx_Params"
type_AnB_Session :: String
type_AnB_Session = "AnB_Session"

-- ProVerif
bitstring :: String
bitstring = "bitstring"
boolean :: String
boolean = "bool"
typeSealedPair :: String
typeSealedPair = "SealedPair"
typeDHSecret :: String
typeDHSecret = "DHSecret"

showJavaType :: JType -> String
showJavaType t = case t of
                        SealedPair _ -> case cryptomode of
                                        CM_Block -> type_Crypto_ByteArray
                                        _ -> type_Crypto_SealedPair
                        SealedObject _ -> case cryptomode of
                                        CM_Block -> type_Crypto_ByteArray
                                        _ -> type_SealedObject
                        SignedObject _ -> type_SignedObject
                        JHmac -> type_Crypto_ByteArray
                        JHash -> type_Crypto_ByteArray
                        AnBxParams _ -> type_AnBx_Params
                        JString -> type_String
                        JObject -> type_Object
                        JHmacKey -> type_SecretKey
                        JSymmetricKey -> type_SecretKey
                        JNonce -> type_Crypto_ByteArray
                        JSeqNumber -> type_Crypto_ByteArray
                        JDHBase -> type_DHParameterSpec
                        JDHPubKey -> type_PublicKey
                        JDHSecret -> type_KeyPair             -- In Java the DH secrets are randomly generated key pairs
                        JDHSecKey -> type_SecretKey
                        JPublicKey Nothing -> type_PublicKey 
                        JPublicKey _ -> type_PublicKey
                        JPrivateKey {} -> type_PrivateKey
                        JKeyPair -> type_Crypto_KeyPair
                        NEVarArgs -> type_Object ++ " ..."
                        JInt -> intType
                        JBool -> "boolean"
                        JAgent -> showJavaType JString
                        JConstant t -> showJavaType t
                        -- JConstant _ -> showJavaType JString
                        JVoid -> "void"
                        JAnBSession -> type_AnB_Session
                        JUserDef t -> t
                        JUntyped -> showJavaType NEVarArgs 
                        _ -> error ("cannot handle type " ++ show t ++ " in Java")
                        -- _ -> showJavaType JString                   -- default type, must be a serializable type

showType :: JType -> OutType -> String
-- this function defines types different ProVerif output versions 
-- build in types in ProVerif
showType JObject _ = bitstring                    -- base type bitstring
showType JBool _ = boolean
-- untyped output
showType _ PV = bitstring
-- specific catch-all output mapping
showType JAgent _ = showSpecType PTAnBx agentDefaultType
showType (AnBxParams _) pv = showType JObject pv
showType NEVarArgs pv = showType JObject pv
showType JUntyped pv = showType JObject pv
-- Java mode 
showType t PVTJava = showJavaType t
-- generic output mapping
showType (JUserDef t) _ = t
showType t@JKeyPair _ = showTypeError t
showType t@JFunction {} _ = showTypeError t
showType t@JPurpose _ = showTypeError t
showType t@(JPublicKey _) _ = showJavaType t
showType t@(JPrivateKey _) _ = showJavaType t
showType t@JSymmetricKey _ = showJavaType t
showType t@JInt _ = showJavaType t
showType t@JVoid _ = showJavaType t
showType t@JAnBSession _ =  showJavaType t
showType (JConstant t) pv = showType t pv
showType t pv | isTypeNonceAnB t =
                            case pv of
                                 PVTAnB -> showType JNonce pv
                                 PVTCBAB -> showTypesCBAB t pv
                                 _  -> case t of
                                        SealedPair _ -> typeSealedPair
                                        _ -> showJavaType t
              | t == JDHSecKey || t == JHmacKey = case pv of
                                 PVTAnB -> showJavaType JSymmetricKey
                                 _ -> showJavaType t   -- (PV_Typed)
              | t == JNonce = case pv of
                                 PVTAnB -> showSpecType PTAnBx (Number [])
                                 PVTCBAB -> showTypesCBAB t pv
                                 _ -> showJavaType t   -- (PV_Typed) 
              | t == JDHBase = case pv of
                                 PVTAnB -> showType JNonce pv
                                 PVTCBAB -> showTypesCBAB t pv
                                 _ -> showJavaType t   -- (PV_Typed) 
              | t == JDHPubKey = showJavaType t
              | t == JDHSecret = typeDHSecret
              | otherwise = error ("unable to display type " ++ show t ++ " in mode " ++ show pv)


eqTypePV :: OutType -> JType -> JType ->  Bool
-- eqTypePV pv t1 t2 | trace ("eqTypePV - " ++ show pv ++ "\n\tt1: " ++ show t1 ++ "/" ++ showType t1 pv ++ "\n\tt2: " ++ show t2 ++ "/" ++ showType t2 pv ++ "\n") False = undefined 
eqTypePV pv t1 t2 = showType t1 pv == showType t2 pv

eqTypePVFunType :: OutType -> (NEIdent,Int) -> (NEIdent,Int) ->  Bool
eqTypePVFunType pv ((JFunction _ (t1,t2),id1),i1) ((JFunction _ (t3,t4),id2),i2) = i1 == i2 && id1==id2 && eqTypePV pv t1 t3 && eqTypePV pv t2 t4
eqTypePVFunType _ _ _ = False

typesCBAB :: [String]
typesCBAB = nubOrd (map showJavaType [SealedPair JVoid, SealedObject JVoid, SignedObject JVoid, JString, JNonce, JSeqNumber] ++ [type_Crypto_ByteArray])

-- maps Crypto_ByteArray to bitstring
showTypesCBAB :: JType -> OutType -> String
showTypesCBAB t pv = if elem (showJavaType t) typesCBAB then showType JObject pv else showType t PVT

sepDot :: String
sepDot = "."
sepComma :: String
sepComma = ","
concatOp :: String
concatOp = "+"
newLine :: String
newLine = "\n"
eoS :: String
eoS = ";"
parOpen :: String
parOpen = "("
parClose :: String
parClose = ")"
commentPrefix :: String
commentPrefix = "// "
inlinecommentPrefix :: [Char]
inlinecommentPrefix = "\t\t" ++ commentPrefix
strDelimiter :: String
strDelimiter = "\""
sessName :: String
sessName = "s"
outDockerExt :: String
outDockerExt = sepDot ++ "yml"
outXMLExt :: String
outXMLExt = sepDot ++ "xml"
serExt :: String
serExt = sepDot ++ "ser"
pathSeparator :: String
pathSeparator = "/"
rolePrefix :: String
rolePrefix = "ROLE_"
roleXPrefix :: [Char]
roleXPrefix = rolePrefix ++ "x"
cryptostoretype :: String
cryptostoretype = "Crypto_KeyStoreType"
newKeyword :: String
integerType :: String
newKeyword = "new"
integerType = "Integer"
intType :: String
intType = "int"

showCheckLabel :: Bool
showCheckLabel = True

writeActionComments :: Bool
writeActionComments = False

toRole :: String -> String
toRole r = rolePrefix ++ r

toStep :: Int -> String
toStep s = "STEP_" ++ show s

applyOp :: APIOp -> String -> String
applyOp APIEqCheck str = getAPIOp APIEqCheck ++ parOpen ++ str ++ parClose
applyOp APIInvCheck str = getAPIOp APIInvCheck ++ parOpen ++ str ++ parClose
applyOp APIWffCheck str = getAPIOp APIWffCheck ++ parOpen ++ str ++ parClose
applyOp APINotEqCheck str = getAPIOp APINotEqCheck ++ parOpen ++ str ++ parClose
applyOp APIWriteObject str = type_AnB_Session ++ sepDot ++ getAPIOp APIWriteObject ++ parOpen ++ str ++ parClose
applyOp APIReadObject str = type_AnB_Session ++ sepDot ++ getAPIOp APIReadObject ++ parOpen ++ str ++ parClose
applyOp APIPublicKey str = getAPIOp APIPublicKey ++ parOpen ++ str ++ parClose
applyOp APIgetBytes str = str ++ sepDot ++ getAPIOp APIgetBytes ++ parOpen ++ parClose
applyOp APItoString str = sepDot ++ getAPIOp APItoString ++ parOpen ++ str ++ parClose
applyOp APIhashCode str = str ++ sepDot ++ getAPIOp APIhashCode ++ parOpen ++ parClose
applyOp APISeen str = getAPIOp APISeen ++ parOpen ++ str ++ parClose
applyOp op str = sessName ++ sepDot ++ getAPIOp op ++ parOpen ++ str ++ parClose

getIndex :: Int -> String
getIndex index = sepDot ++ "getValue" ++ parOpen ++ show (index-1) ++ parClose

agent2alias :: String -> String
agent2alias agent = "aliases" ++ sepDot ++ "get" ++ parOpen ++ strDelimiter ++ toRole agent ++ strDelimiter ++ parClose

showTypeConstructor :: JType -> String -> String
-- showTypeConstructor t pars | trace ("showTypeConstructor\n\tt: " ++ show t ++ "\tpars: " ++ pars) False = undefined
showTypeConstructor t pars = case t of
                                                JSeqNumber -> applyOp APISQN ""
                                                JNonce -> applyOp APINonce ""
                                                JSymmetricKey -> applyOp APISymKey ""
                                                JHmacKey -> applyOp APIHmacKey ""
                                                JDHSecret -> applyOp APIDHSecret ""
                                                JPublicKey Nothing -> applyOp APIKeyPair ""
                                                NEVarArgs -> error ("cannot create new variable of type " ++ show t)
                                                JDHBase -> error ("cannot create new variable of type " ++ show t)
                                                JPublicKey _ -> error ("cannot create new variable of type " ++ show t ++ "\na proper API call should be used")
                                                JPrivateKey {} -> error ("cannot create new variable of type " ++ show t ++ "\na proper API call should be used")
                                                JConstant t -> showTypeConstructor t pars
                                                JString -> newObject t (strDelimiter ++ pars ++ strDelimiter)
                                                _ -> newObject t pars
                                                
showTypeConstructorStatic :: JType -> String -> String
-- showTypeConstructorStatic t pars | trace ("showTypeConstructorStatic\n\tt: " ++ show t ++ "\tpars: " ++ pars) False = undefined
showTypeConstructorStatic t pars = case t of
                                                JConstant t -> showTypeConstructorStatic t pars
                                                JSeqNumber -> newObject t (applyOp APIgetBytes (strDelimiter ++ pars ++ strDelimiter))
                                                JNonce -> newObject t (applyOp APIgetBytes (strDelimiter ++ pars ++ strDelimiter))
                                                _ -> showTypeConstructor t pars

showTypeConstructorStaticFunction :: JType -> String -> String
-- showTypeConstructorStaticFunction t pars | trace ("showTypeConstructorStaticFunction\n\tt: " ++ show t ++ "\tpars: " ++ pars) False = undefined
showTypeConstructorStaticFunction t pars = case t of
                                                JSymmetricKey -> applyOp APISymKeyPBE pars
                                                JSeqNumber -> newObject t pars
                                                JNonce -> newObject t pars    
                                                _ -> showTypeConstructorStatic t pars

newObject :: JType -> String ->  String
-- newObject JUntyped pars = newKeyword ++ " " ++ showJavaType JObject ++ parOpen ++ pars ++ parClose
newObject t@JUntyped _ = error("Creation of new objects of type " ++ showJavaType t ++ " in Java is not supported.\n" ++ 
                               "This error can be fixed by declaring a variable of custom type rather than of type" ++ showSpecType PTAnBx (Untyped []) ++ ", in the AnBx/AnB model")
newObject t pars = newKeyword ++ " " ++ showJavaType t ++ parOpen ++ pars ++ parClose

mapChanneType :: ChannelType -> ChannelMode
mapChanneType Insecure = SSL_PLAIN 
mapChanneType Authentic = SSL_AUTH
mapChanneType FreshAuthentic = SSL_AUTH
mapChanneType Confidential = SSL_SECRET
mapChanneType Secure = SSL_SECURE
mapChanneType FreshSecure = SSL_SECURE 
mapChanneType ct = error ("mapChanneType: unsupported channel type: " ++ show ct)