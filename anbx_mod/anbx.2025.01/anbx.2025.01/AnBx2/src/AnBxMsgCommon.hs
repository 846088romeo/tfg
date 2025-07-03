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

{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE StrictData #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "Use infix" #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE DerivingStrategies #-}

module AnBxMsgCommon where
import Data.List ( intercalate, stripPrefix )
import Data.Typeable
import Data.Data
import Data.Char
import Debug.Trace()
import Net.IPv4 (IPv4, ipv4)
import qualified Net.IPv4 as IPv4
import Data.Maybe (fromJust)

type Ident = String

-- | standard AnB operators - Type for operators (function symbols) in message terms.
data Operator =
       Crypt            -- ^ asymmetric encryption
       | Scrypt         -- ^ symmetric encryption 
       | Cat            -- ^ concatenation---may be soon exchanged for family of n-tuples (n in Nat)  
       | Inv            -- ^ private key of a given public key -- we plan to introduce a distinction between these mappings and other operators
       | Exp            -- ^ modular exponentation
       | Xor            -- ^ bitwise exclusive OR 
       | Apply          -- ^ function application, e.g. @Apply(f,x)@ for @f(x)@ is old AVISPA IF standard for user defined functions, aka 1.5th-order logic! 
       | Userdef Ident  -- ^ user-defined function symbols, may replace the above @Apply@ eventually. 
       deriving  (Eq,Ord,Typeable,Data)

instance Show Operator where show :: Operator -> String
                             show a = case a of
                                                Crypt -> "Crypt"
                                                Scrypt -> "Scrypt"
                                                Cat -> "Cat"
                                                Inv -> "Inv"
                                                Exp -> "Exp"
                                                Xor -> "Xor"
                                                Apply -> "Apply"
                                                Userdef id -> id

data AnBVarType = Nonce | SymKey | DHG | DHX | DHY | SQN | HmacKey
                               deriving (Eq,Show)

data ShareType = SHAgree | SHAgreeInsecurely | SHShare
          deriving (Eq,Ord)

instance Show ShareType where show :: ShareType -> String
                              show SHAgree = "agree"
                              show SHAgreeInsecurely = "insecurely" ++ " " ++ show SHAgree
                              show SHShare = "share"
-- certified agent flag
data Certified = Cert | NoCert
    deriving (Eq,Ord,Show)

-- private function flag
data PrivateFunction = PrivFun | PubFun
    deriving (Eq,Typeable,Data,Ord)

instance Show PrivateFunction
            where show :: PrivateFunction -> String
                  show PrivFun = "->*"
                  show PubFun = "->"

data VdmMsgOutputMode = VDMLine | VDMIndent
    deriving (Eq)

-- default paths for Java code generation
data AnBxCfg = AnBxCfg {
                        pathSTemplates :: FilePath,
                        pathJavaDest :: FilePath,
                        pathVdmDest :: FilePath,
                        pathOfmcStdEqTheory :: FilePath,
                        sharePathDefault :: FilePath,
                        keyPathDefault :: FilePath,
                        anbxjPathDefault :: FilePath,
                        cfgAliases :: [String],
                        functionsST :: [String],
                        cryptoConfig :: CryptoConfig,
                        interface :: String,
                        ipAddress :: IPv4,
                        startingPort :: PortRange,
                        dockerImage :: String,
                        dockerDYImage :: String,
                        dockerMemLimit :: String,
                        dockerCPUQuota :: Int,
                        dockerSharedFolder :: String,
                        dockerJavaRoot :: String,
                        dockerJavaDest :: String,
                        dockerIPBase :: IPv4,
                        dockerSessionTimeout :: Int,
                        dockerDYMinTimeout :: Int,
                        dockerDYInterval :: Int
                        }
            deriving (Eq,Show)

initAnBxCfg :: AnBxCfg
initAnBxCfg =  AnBxCfg {
                            pathSTemplates = "", -- d_pathSTemplates,
                            pathJavaDest = "", --d_pathJavaDest,
                            pathVdmDest = "", -- d_pathVdmDest,
                            pathOfmcStdEqTheory = "",
                            sharePathDefault = "", -- d_pathJavaShare, 
                            keyPathDefault = "", -- d_keyPathDefault,
                            anbxjPathDefault = "",
                            cfgAliases = [], -- defaultAliases,
                            functionsST = [],
                            cryptoConfig = cryptoConfigDefault,
                            interface = "",
                            ipAddress = defaultHostClient,
                            startingPort = defaultStartingPort,
                            dockerImage = "anbx:1.0.0",
                            dockerDYImage = "anbx:1.0.0",
                            dockerMemLimit = "256m",
                            dockerCPUQuota = 200000,
                            dockerSharedFolder = "app",
                            dockerJavaRoot = "./../../../",
                            dockerJavaDest = "genAnBx/src/",
                            dockerIPBase = ipv4 10 0 0 0,
                            dockerSessionTimeout = dockerSessionTimeoutDefault,
                            dockerDYMinTimeout = dockerDYMinTimeoutDefault,
                            dockerDYInterval = dockerDYIntervalDefault
                       }

dockerDYIntervalDefault :: Int
dockerDYIntervalDefault = 2
dockerSessionTimeoutDefault :: Int
dockerSessionTimeoutDefault = 5
dockerDYMinTimeoutDefault :: Int
dockerDYMinTimeoutDefault = 20

newtype PortRange = UnsafeMkPortRange { unPortRange :: Int }
                        deriving (Ord)

instance Eq PortRange where
                (==) :: PortRange -> PortRange -> Bool
                UnsafeMkPortRange i == UnsafeMkPortRange j = i ==j

instance Show PortRange where
                show :: PortRange -> String
                show (UnsafeMkPortRange i) = show i

mkPortRange :: Int -> Maybe PortRange
mkPortRange i
    | i `elem` [1..65535] = Just (UnsafeMkPortRange i)
    | otherwise = error (show i ++ " is not allowed port. Please check your config file") -- Nothing

nextPort :: PortRange -> PortRange
nextPort (UnsafeMkPortRange port) = UnsafeMkPortRange (port + 1)

defaultHostServer :: IPv4
defaultHostServer = IPv4.any

defaultHostClient :: IPv4
defaultHostClient = IPv4.localhost

defaultStartingPort :: PortRange
defaultStartingPort = fromJust (mkPortRange 55555)

data CryptoConfig = CryptoConfig {
                cipherScheme :: String,
                keySize :: Int,
                keyGenerationScheme :: String,
                keyGenerationSchemePBE :: String,
                keyGenerationSize :: Int,
                keyPairGenerationScheme :: String,
                keyPairGenerationSize :: Int,
                secureRandomAlgorithm  :: String,
                hMacAlgorithm  :: String,
                messageDigestAlgorithm  :: String,
                keyAgreementAlgorithm  :: String,
                keyAgreementKeyPairGenerationScheme :: String,
                dhRndExpSize :: Int,
                ecGenParameterSpec :: String,
                asymcipherSchemeBlock :: String,
                sslContext :: String,
                securityProvider :: String
                } deriving (Eq,Show)

cryptoConfigDefault :: CryptoConfig
cryptoConfigDefault = CryptoConfig {
                   cipherScheme ="AES/CBC/PKCS5Padding",            -- default symmetric cipherScheme
                   keySize = 256,                                   -- default key size for symmetric encryprion
                   keyGenerationScheme = "AES",                     -- default key generation symmetric encryption scheme
                   keyGenerationSchemePBE = "PBKDF2WithHmacSHA512", -- default key generation symmetric password based encryption (PBE) scheme
                   keyGenerationSize = 256,                         -- default key size for the generation symmetric encryption scheme
                   keyPairGenerationScheme = "RSA",                 -- default key generation asymmetric encryption scheme
                   keyPairGenerationSize = 2048,                    -- default key size for generation asymmetric encryption scheme
                   secureRandomAlgorithm = "DRBG",                  -- default secure random generator algorithm
                   hMacAlgorithm = "HmacSHA256",                    -- default hmac algorithm
                   messageDigestAlgorithm = "SHA-256",              -- default message digest algorithm
                   keyAgreementAlgorithm = "DH",                    -- default key exchange algorithm
                   keyAgreementKeyPairGenerationScheme = "DH",      -- default key exchange key pair generation algorithm
                   dhRndExpSize = 2048,                             -- default key size for key exchange algorithm
                   ecGenParameterSpec = "secp256r1",                -- default ellipctic curver used in ECDH
                   asymcipherSchemeBlock = "RSA",                   -- default asymmetric cipherScheme
                   sslContext = "TLSv1.2",
                   securityProvider = "default"
                   }


-- "# Java 8 - https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html" ++ "\n" ++

javaVersion :: String
javaVersion = "21"
urlBaseJava :: String
urlBaseJava = "https://docs.oracle.com/en/java/javase/" ++ javaVersion ++ "/docs/specs/security/standard-names.html"
urlBaseJCE :: String
urlBaseJCE = "https://docs.oracle.com/en/java/javase/" ++ javaVersion ++ "/security/java-cryptography-architecture-jca-reference-guide.html"
urlBaseBouncyCastle :: String
urlBaseBouncyCastle = "https://www.bouncycastle.org/documentation/specification_interoperability/#algorithms-and-key-types"
-- "https://www.bouncycastle.org/specifications.html"
lineSeparator :: [Char]
lineSeparator = lineSeparatorBase ++ "\n"
lineSeparatorBase :: [Char]
lineSeparatorBase  = "# -----------------------------"

attackTraceSuffix :: String
attackTraceSuffix = "_AttackTrace"


cmdCipherScheme :: String
cmdCipherScheme = "cipherScheme"
cmdKeySize :: String
cmdKeySize = "keySize"
cmdKeyGenerationScheme :: String
cmdKeyGenerationScheme = "keyGenerationScheme"
cmdKeyGenerationSchemePBE :: String
cmdKeyGenerationSchemePBE = "keyGenerationSchemePBE"
cmdKeyGenerationSize :: String
cmdKeyGenerationSize = "keyGenerationSize"
cmdKeyPairGenerationScheme :: String
cmdKeyPairGenerationScheme = "keyPairGenerationScheme"
cmdKeyPairGenerationSize :: String
cmdKeyPairGenerationSize = "keyPairGenerationSize"
cmdSecureRandomAlgorithm :: String
cmdSecureRandomAlgorithm = "secureRandomAlgorithm"
cmdHMacAlgorithm :: String
cmdHMacAlgorithm  = "hMacAlgorithm"
cmdMessageDigestAlgorithm :: String
cmdMessageDigestAlgorithm = "messageDigestAlgorithm"
cmdKeyAgreementAlgorithm :: String
cmdKeyAgreementAlgorithm = "keyAgreementAlgorithm"
cmdKeyAgreementKeyPairGenerationScheme :: String
cmdKeyAgreementKeyPairGenerationScheme = "keyAgreementKeyPairGenerationScheme"
cmdDHRndExpSize :: String
cmdDHRndExpSize = "dhRndExpSize"
cmdECGenParameterSpec :: String
cmdECGenParameterSpec = "ecGenParameterSpec"
cmdAsymCipherSchemeBlock :: String
cmdAsymCipherSchemeBlock  = "asymcipherSchemeBlock"
cmdSSLContext :: String
cmdSSLContext = "sslContext"
cmdSecurityProvider :: String
cmdSecurityProvider = "securityProvider"

cfgCrypto :: CryptoConfig -> String
cfgCrypto ce = lineSeparator ++
               "# Cryptographic Engine Settings" ++ "\n" ++
               lineSeparator ++
               "# Java Cryptography Architecture (JCA) Reference Guide" ++ "\n" ++
               "# For more information, refer to the JCA Reference Guide:" ++ "\n" ++
               "# " ++ urlBaseJCE ++ "\n" ++
               "# see names at" ++ "\n" ++
               "# Java " ++ javaVersion ++ " - " ++ urlBaseJava ++ "\n" ++
               "# Information about cryptographic specifications can also be found at:" ++ "\n" ++
               "# Bouncy Castle - " ++ urlBaseBouncyCastle ++ "\n" ++
               "#" ++ "\n" ++
               "# Note: Signature Algorithms and (Asymmetric Encryption) Cipher Algorithms" ++ "\n" ++
               "# are automatically detected from the keys used, which are pre-memorized in the keystore" ++ "\n" ++
               "#" ++ "\n" ++
               lineSeparator ++
               "# Cipher scheme used for encryption, including algorithm name, mode, and padding, separated by /" ++ "\n" ++
               "# " ++ urlBaseJava ++ "#cipher-algorithm-names" ++ "\n" ++
               "# " ++ urlBaseJava ++ "#cipher-algorithm-modes" ++ "\n" ++
               "# " ++ urlBaseJava ++ "#cipher-algorithm-paddings" ++ "\n" ++
               cmdCipherScheme ++ " = " ++ cipherScheme ce ++ "\n" ++
               "# Key length in bits for ciphers supporting different key lengths" ++ "\n" ++
               cmdKeySize ++ " = " ++ show (keySize ce) ++ "\n" ++
               lineSeparator ++
               "# Key generator algorithm for dynamic key generation in symmetric encryption" ++ "\n" ++
               cmdKeyGenerationScheme ++ " = " ++ keyGenerationScheme ce ++ "\n" ++
               "# Key length in bits for dynamic symmetric key generation, for ciphers supporting different key lengths " ++ "\n" ++
               "keyGenerationSize = " ++ show (keyGenerationSize ce) ++ "\n" ++
               lineSeparator ++
               "# Secret Key Factory algorithm used for Password-Based Encryption (PBE) dynamic symmetric key generation" ++ "\n" ++
               "# " ++ urlBaseJava ++ "d#secretkeyfactory-algorithms" ++ "\n" ++
               cmdKeyGenerationSchemePBE ++ " = " ++ keyGenerationSchemePBE ce ++ "\n" ++
               lineSeparator ++
               "# Key Pair Generator algorithm for dynamic creation of asymmetric key pairs" ++ "\n" ++
               "# " ++ urlBaseJava ++ "#keypairgenerator-algorithms" ++ "\n" ++
               cmdKeyPairGenerationScheme ++ " = " ++ keyPairGenerationScheme ce ++ "\n" ++
               "# Key length for dynamic creation of asymmetric key pairs" ++ "\n" ++
               cmdKeyPairGenerationSize ++ " = " ++ show (keyPairGenerationSize ce) ++ "\n" ++
               lineSeparator ++
               "# SecureRandom Number Generation Algorithm" ++ "\n" ++
               "# " ++ urlBaseJava ++ "#securerandom-number-generation-algorithms" ++ "\n" ++
               cmdSecureRandomAlgorithm ++ " = " ++ secureRandomAlgorithm ce ++ "\n" ++
               lineSeparator ++
               "# (H)MAC Algorithm, used for key generation" ++ "\n" ++
               "# " ++ urlBaseJava ++ "#mac-algorithms" ++ "\n" ++
               cmdHMacAlgorithm ++ " = " ++ hMacAlgorithm ce ++ "\n" ++
               lineSeparator ++
               "# MessageDigest Algorithm (Hash)" ++ "\n" ++
               "# " ++ urlBaseJava ++ "#messagedigest-algorithms" ++ "\n" ++
               cmdMessageDigestAlgorithm ++ " = " ++ messageDigestAlgorithm ce ++ "\n" ++
               lineSeparator ++
               "# Key Agreement Algorithm, used for key exchange (e.g., Diffie-Hellman)" ++ "\n" ++
               "# " ++ urlBaseJava ++ "#keyagreement-algorithms" ++ "\n" ++
               cmdKeyAgreementAlgorithm ++ " = " ++ keyAgreementAlgorithm ce ++ "\n" ++
               "# Key Pair Generation for Key Agreement Algorithm, used for key exchange (e.g., Diffie-Hellman)" ++ "\n" ++
               "# " ++ urlBaseJava ++ "#keypairgenerator-algorithms" ++ "\n" ++
               cmdKeyAgreementKeyPairGenerationScheme ++ " = " ++ keyAgreementKeyPairGenerationScheme ce ++ "\n" ++
               "# Length in bits for random exponents in Diffie-Hellman key agreement" ++ "\n" ++
               cmdDHRndExpSize ++ " = " ++ show (dhRndExpSize ce) ++ "\n" ++
               "# The elliptic curve used for ECDH key agreement" ++ "\n" ++
               "# " ++ urlBaseJava ++ "parameterspec-names" ++ "\n" ++
               cmdECGenParameterSpec ++ " = " ++ ecGenParameterSpec ce ++ "\n" ++
               lineSeparator ++
               "# Asymmetric encryption scheme block mode (experimental feature)" ++ "\n" ++
               cmdAsymCipherSchemeBlock ++ " = " ++ asymcipherSchemeBlock ce ++ "\n" ++
               "# SSLContext Algorithm" ++ "\n" ++
               cmdSSLContext ++ " = " ++ sslContext ce ++ "\n" ++
               lineSeparator ++
               "# Java Security provider: " ++ securityProvider cryptoConfigDefault ++ " uses the java.security settings (preferred option)" ++ "\n" ++
               "# Or select a specific provider (e.g., 'BC' for Bouncy Castle)" ++ "\n" ++
               cmdSecurityProvider ++ " = " ++ securityProvider ce ++ "\n" ++
               optionalSpecificProviders ce

optionalSpecificProviders :: CryptoConfig -> String
optionalSpecificProviders ce =
                            "# Optional: Specific Java Security providers for different schemes" ++ "\n" ++
                            "# These settings will override the securityProvider value if uncommented" ++ "\n" ++
                            "# cipherSchemeProvider = " ++ gp ++ "\n" ++
                            "# keyGenerationSchemeProvider = " ++ gp ++ "\n" ++
                            "# keyGenerationSchemePBEProvider = " ++ gp ++ "\n" ++
                            "# keyPairGenerationSchemeProvider = " ++ gp ++ "\n" ++
                            "# secureRandomProvider = " ++ rndp ++ "\n" ++
                            "# hmacProvider = " ++ gp ++ "\n" ++
                            "# messageDigestProvider = " ++ gp ++ "\n" ++
                            "# signatureProvider = " ++ gp ++ "\n" ++
                            "# asymEncProvider = " ++ gp ++ "\n" ++
                            "# keyAgreementProvider = " ++ gp ++ "\n" ++
                            "# sslContextProvider = " ++ gp ++ "\n"
                            where gp = securityProvider ce
                                  rndp = securityProvider cryptoConfigDefault -- in general better to stick to default provider for SecureRandom

--- some constants and functions ---

data Tag = Ptag | Atag | Ctag | Stag | Fatag | Fstag | NoTag deriving Eq
instance Show Tag where show :: Tag -> String
                        show a = case a of
                                                Ptag -> "plain"
                                                Ctag -> "ctag"
                                                Atag -> "atag"
                                                Stag -> "stag"
                                                Fatag -> "fatag"
                                                Fstag -> "fstag"
                                                NoTag -> ""

showTagMsg :: Tag -> String
showTagMsg NoTag = show NoTag
showTagMsg t = show t

data SpyerReserved = SpyerPub | SpyerPriv | SpyerEnc | SpyerDec | SpyerEncS | SpyerDecS deriving (Eq,Data,Typeable)
instance Show SpyerReserved where show :: SpyerReserved -> String
                                  show a = case a of
                                                SpyerPub -> "pub"
                                                SpyerPriv -> "priv"
                                                SpyerEnc -> "enc"
                                                SpyerDec -> "dec"
                                                SpyerEncS -> "encS"
                                                SpyerDecS -> "decS"

data AnBxPKeysFun = AnBxPK | AnBxSK | AnBxHK deriving (Eq,Data,Typeable,Ord)
instance Show AnBxPKeysFun where show :: AnBxPKeysFun -> String
                                 show a = case a of
                                                AnBxPK -> "pk"
                                                AnBxSK -> "sk"
                                                AnBxHK -> "hk"

showPKFun :: Maybe AnBxPKeysFun -> String
showPKFun = maybe "Nothing" show

type AnBxPKeyFunCfg = (AnBxPKeysFun,AnBxPKeysFun,AnBxPKeysFun)          -- encrypt -- sign -- keyd hash

stdPKcfg :: AnBxPKeyFunCfg
stdPKcfg = (AnBxPK,AnBxSK,AnBxHK)

chexpPKcfg :: AnBxPKeyFunCfg
chexpPKcfg = (AnBxPK,AnBxSK,AnBxHK)

data AnBxReserved = AnBxInv | AnBxHash | AnBxHmac | AnBxExp | AnBxXor | AnBxEmpty | AnBxShAgree | AnBxBlind | AnBxPKNone | AnBxZero | AnBxKas | AnBxKap | AnBxCertified deriving (Eq,Data,Typeable)
instance Show AnBxReserved where show :: AnBxReserved -> String
                                 show a = case a of
                                                AnBxInv -> "inv"
                                                AnBxHash -> "hash"
                                                AnBxHmac -> "hmac"
                                                AnBxExp -> "exp"
                                                AnBxXor -> "xor"
                                                AnBxEmpty -> "empty"
                                                AnBxZero -> "zero"      -- xor zero
                                                AnBxShAgree -> "shAgree"
                                                AnBxBlind -> "blind"
                                                AnBxKap -> "kap"
                                                AnBxKas -> "kas"
                                                AnBxPKNone -> ""
                                                AnBxCertified -> "Certified"
                                                -- AnBxPKeysFun -> show a

getReserved :: String -> AnBxReserved
getReserved id | id==show AnBxInv = AnBxInv
getReserved id | id==show AnBxHash = AnBxHash
getReserved id | id==show AnBxHmac = AnBxHmac
getReserved id | id==show AnBxExp = AnBxExp
getReserved id | id==show AnBxXor = AnBxXor
getReserved id | id==show AnBxEmpty = AnBxEmpty
getReserved id | id==show AnBxZero = AnBxZero
getReserved id | id==show AnBxShAgree = AnBxShAgree
getReserved id | id==show AnBxBlind = AnBxBlind
getReserved id | id==show AnBxKap = AnBxKap
getReserved id | id==show AnBxKas = AnBxKas
-- getReserved id | id==show AnBxPK = AnBxPKeysFun
getReserved id = error (id ++ " is not a reserved keyword")

isReserved :: String -> Bool
isReserved id | id==show AnBxInv = True
isReserved id | id==show AnBxHash = True
isReserved id | id==show AnBxHmac = True
isReserved id | id==show AnBxExp = True
isReserved id | id==show AnBxXor = True
isReserved id | id==show AnBxEmpty = True
isReserved id | id==show AnBxZero = True
isReserved id | id==show AnBxKap = True
isReserved id | id==show AnBxKas = True
isReserved id | id==show AnBxBlind = True
isReserved id | id==show AnBxShAgree = True
--isReserved id | id==show AnBxPKeysFun = True
isReserved _ = False

-- define the protocol type
data ProtType = PTAnBx | PTAnB
                deriving (Eq)

instance Show ProtType where
    show :: ProtType -> String
    show PTAnBx = "AnBx"
    show PTAnB = "AnB"

-- define the computation type
data ComType = CTAnB | CTAnBx
                deriving (Eq,Ord)

instance Show ComType where
    show :: ComType -> String
    show CTAnBx = show PTAnBx
    show CTAnB = show PTAnB

insertTag :: Tag -> Bool -> Tag
insertTag t True = t
insertTag _ False = NoTag

prefixNonce :: String
prefixNonce = "Nx"      -- Nonces

prefixKey :: String
prefixKey = "Kx"        -- Symmetric Keys

prefixDHG :: String
prefixDHG = "Dx"        -- Diffie-Hellman base

prefixDHX :: String
prefixDHX = "Xx"        -- Diffie-Hellman exponent

prefixDHY :: String
prefixDHY = "Yx"        -- Diffie-Hellman exponent

prefixSQN :: String
prefixSQN = "SQNx"      -- Sequence Numbers

prefixHK :: String
prefixHK ="Hx"          -- HMac keys

dhPar :: String
dhPar = "g"             -- Diffie-Hellman base

syncMsg :: String
syncMsg = show AnBxEmpty

nullPeerName :: String      -- null Peer Name
nullPeerName = "-"

tags :: [String]
tags = map show [Ptag,Atag,Ctag,Stag,Fatag,Fstag]

prefixofVar :: AnBVarType -> Ident
prefixofVar Nonce = prefixNonce
prefixofVar SymKey = prefixKey
prefixofVar DHG = prefixDHG
prefixofVar DHX = prefixDHX
prefixofVar DHY = prefixDHY
prefixofVar SQN = prefixSQN
prefixofVar HmacKey = prefixHK

isConstant :: Ident -> Bool
isConstant x = elem (head x) ['a'..'z']

isVariable :: Ident -> Bool
isVariable x = elem (head x) ['A'..'Z']

isDHPar :: String -> Bool
isDHPar id = id==dhPar

isVarofType :: AnBVarType -> Ident -> Bool
isVarofType _ [] = error "variable name too short!"

isVarofType t id@[_] = take lp id == prefixofVar t         -- prefix + ...
                                         where lp = length (prefixofVar t)

isVarofType t id = (take lp id == prefixofVar t) && isAlphaNum (id !! max 0 lp)        -- prefix + 1 alphanum + ... or idDigit or ...
                                         where lp = length (prefixofVar t)

isFreshlyGenerated :: Ident -> Bool
isFreshlyGenerated id | isVarofType SymKey id = True
                      | isVarofType SQN id = True
                      | isVarofType DHX id = True
                      | isVarofType DHY id = True
                      | isVarofType Nonce id = True
                      | isVarofType HmacKey id = True
                      | otherwise = False

isPKFunR :: AnBxPKeysFun -> Bool
isPKFunR pk = elem pk pkiFunList

isPKFun :: Ident -> Bool
isPKFun pk   | pk == show AnBxPK = True
             | pk == show AnBxSK = True
             | pk == show AnBxHK = True
             | otherwise = False

getKeyFun :: Ident -> AnBxPKeysFun
getKeyFun pk | pk==show AnBxPK = AnBxPK
getKeyFun pk | pk==show AnBxSK = AnBxSK
getKeyFun pk | pk==show AnBxHK = AnBxHK
getKeyFun pk = error ("unhandled key function: " ++ pk)

-- how hmac secret key is encrypted
enableHK :: Bool
enableHK = True

pkiFunList :: [AnBxPKeysFun]
pkiFunList = pkiEncFunList ++ pkiSigFunList
-- used in the implementation (workaround)

-- pkiFunListImpl = [AnBxPK,AnBxSK,AnBxHK]
pkHMacFun :: AnBxPKeysFun
pkHMacFun = if enableHK then AnBxHK else AnBxPK

pkiEncFunList :: [AnBxPKeysFun]
pkiEncFunList = if enableHK then [AnBxPK,AnBxHK] else [AnBxPK]

pkiSigFunList :: [AnBxPKeysFun]
pkiSigFunList = [AnBxSK]

findPos :: (Num a1, Enum a1, Eq a2) => [a2] -> a2 -> [a1]
findPos list elt = [index | (index, e) <- zip [0..] list, e == elt]

hideTypes :: Bool
hideTypes = True

ppXList :: (a -> String) -> String -> [a] -> String
ppXList ppX sep = intercalate sep . map ppX

ppId :: Ident -> String
ppId = filter (\x -> elem x (['a'..'z'] ++ ['A'..'Z'] ++ ['0'..'9'] ++ ['_']))

ppIdList :: [Ident] -> String
ppIdList = ppXList ppId ","

typeNames :: [String]
typeNames = ["typeAgent","typeNumber","typeSeqNumber","typePK","typeSK","typeFun","typePurpose","typeCustom"]

-- manage Types/Declarations in Anbx
-- example a = AnBxTypes [(a,[Ident])] = AnBxTypes

listTypes :: [(a,[Ident])] -> [a]
listTypes = map fst

identsOfType :: (Eq a) => a -> [(a,[Ident])] -> [Ident]
identsOfType _ [] =[]
identsOfType t ((at,ids):xs) | t==at = ids ++ identsOfType t xs
                             | otherwise = identsOfType t xs
---
nullVers :: [Ident]
nullVers = []

-- replace substring in string
-- usage: replace oldsub newsub full-string
replace :: (Eq a) => [a] -> [a] -> [a] -> [a]
replace _ _ [] = []
replace old new xs@(y:ys) =
  case stripPrefix old xs of
    Nothing -> y : replace old new ys
    Just ys' -> new ++ replace old new ys'

showSection :: String -> String -> Bool -> String
showSection "" _ _  = ""
showSection _ "" _ =  ""
showSection title@"Protocol" body False = title ++ ": " ++ body
showSection "Shares" body False = ";\n" ++ body
showSection "Where" body False = ";\n" ++ body
showSection title body False =  "\n\n" ++ title ++ ":\n" ++ body
showSection title body True = "\n\n" ++ title ++ ":\n" ++ body ++ "\n"

showAstList :: [a] -> (a -> String) -> String -> String
showAstList [] _ _  = ""
showAstList _ _ ""  = ""
showAstList [x] f _ = f x
showAstList (x:xs) f separator | null (f x) = showAstList xs f separator
                               | otherwise = f x ++ separator ++ showAstList xs f separator

-- split a CSV list(string)
-- example wordsWhen (==',') CSVlist

wordsWhen     :: (Char -> Bool) -> String -> [String]
wordsWhen p s =  case dropWhile p s of
                      "" -> []
                      s' -> w : wordsWhen p s''
                            where (w, s'') = break p s'

