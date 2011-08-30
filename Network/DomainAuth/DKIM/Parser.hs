{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.DKIM.Parser where

import Control.Applicative
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS
import Data.Maybe
import Network.DomainAuth.DKIM.Types
import Network.DomainAuth.Mail
import Prelude hiding (catch)

{-|
  Parsing DKIM-Signature:.
-}
parseDKIM :: RawFieldValue -> Maybe DKIM
parseDKIM val = toDKIM domkey
  where
    (ts,vs) = unzip $ parseTaggedValue val
    fs = map tagToSetter ts
    tagToSetter tag = fromMaybe (\_ mdkim -> mdkim) $ lookup (BS.unpack tag) dkimTagDB
    pfs = zipWith ($) fs vs
    domkey = foldr ($) initialMDKIM pfs
    toDKIM mdkim = do
        ver <- mdkimVersion     mdkim
        alg <- mdkimSigAlgo     mdkim
        sig <- mdkimSignature   mdkim
        bhs <- mdkimBodyHash    mdkim
        hca <- mdkimHeaderCanon mdkim
        bca <- mdkimBodyCanon   mdkim
        dom <- mdkimDomain      mdkim
        fld <- mdkimFields      mdkim
        sel <- mdkimSelector    mdkim
        return DKIM {
            dkimVersion     = ver
          , dkimSigAlgo     = alg
          , dkimSignature   = sig
          , dkimBodyHash    = bhs
          , dkimHeaderCanon = hca
          , dkimBodyCanon   = bca
          , dkimDomain0     = dom
          , dkimFields      = fld
          , dkimLength      = mdkimLength mdkim
          , dkimSelector0   = sel
          }

data MDKIM = MDKIM {
    mdkimVersion     :: Maybe ByteString
  , mdkimSigAlgo     :: Maybe DkimSigAlgo
  , mdkimSignature   :: Maybe ByteString
  , mdkimBodyHash    :: Maybe ByteString
  , mdkimHeaderCanon :: Maybe DkimCanonAlgo
  , mdkimBodyCanon   :: Maybe DkimCanonAlgo
  , mdkimDomain      :: Maybe ByteString
  , mdkimFields      :: Maybe [CanonFieldKey]
  , mdkimLength      :: Maybe Int
  , mdkimSelector    :: Maybe ByteString
  } deriving (Eq,Show)

initialMDKIM :: MDKIM
initialMDKIM = MDKIM {
    mdkimVersion     = Nothing
  , mdkimSigAlgo     = Nothing
  , mdkimSignature   = Nothing
  , mdkimBodyHash    = Nothing
  , mdkimHeaderCanon = Just DKIM_SIMPLE
  , mdkimBodyCanon   = Just DKIM_SIMPLE
  , mdkimDomain      = Nothing
  , mdkimFields      = Nothing
  , mdkimLength      = Nothing
  , mdkimSelector    = Nothing
  }

type DKIMSetter = ByteString -> MDKIM -> MDKIM

dkimTagDB :: [(String,DKIMSetter)]
dkimTagDB = [
    ("v",setDkimVersion)
  , ("a",setDkimSigAlgo)
  , ("b",setDkimSignature)
  , ("bh",setDkimBodyHash)
  , ("c",setDkimCanonAlgo)
  , ("d",setDkimDomain)
  , ("h",setDkimFields)
  , ("l",setDkimLength)
  , ("s",setDkimSelector)
  ]

setDkimVersion :: DKIMSetter
setDkimVersion ver dkim = dkim { mdkimVersion = Just ver }

setDkimSigAlgo :: DKIMSetter
setDkimSigAlgo "rsa-sha1" dkim = dkim { mdkimSigAlgo = Just RSA_SHA1 }
setDkimSigAlgo "rsa-sha256" dkim = dkim { mdkimSigAlgo = Just RSA_SHA256 }
setDkimSigAlgo _ _ = error "setDkimSigAlgo"

setDkimSignature :: DKIMSetter
setDkimSignature sig dkim = dkim { mdkimSignature = Just sig }

setDkimBodyHash :: DKIMSetter
setDkimBodyHash bh dkim = dkim { mdkimBodyHash = Just bh }

setDkimCanonAlgo :: DKIMSetter
setDkimCanonAlgo "relaxed" dkim = dkim {
    mdkimHeaderCanon = Just DKIM_RELAXED
  , mdkimBodyCanon   = Just DKIM_SIMPLE
  }
setDkimCanonAlgo "relaxed/relaxed" dkim = dkim {
    mdkimHeaderCanon = Just DKIM_RELAXED
  , mdkimBodyCanon   = Just DKIM_RELAXED
  }
setDkimCanonAlgo "relaxed/simple" dkim = dkim {
    mdkimHeaderCanon = Just DKIM_RELAXED
  , mdkimBodyCanon   = Just DKIM_SIMPLE
  }
setDkimCanonAlgo "simple/relaxed" dkim = dkim {
    mdkimHeaderCanon = Just DKIM_SIMPLE
  , mdkimBodyCanon   = Just DKIM_RELAXED
  }
setDkimCanonAlgo "simple/simple" dkim = dkim {
    mdkimHeaderCanon = Just DKIM_SIMPLE
  , mdkimBodyCanon   = Just DKIM_SIMPLE
  }
setDkimCanonAlgo _ _ = error "setDkimCanonAlgo"

setDkimDomain :: DKIMSetter
setDkimDomain dom dkim = dkim { mdkimDomain = Just dom }

setDkimFields :: DKIMSetter
setDkimFields keys dkim = dkim { mdkimFields = Just flds }
  where
    flds = map canonicalizeKey $ BS.split ':' keys

setDkimLength :: DKIMSetter
setDkimLength len dkim = dkim { mdkimLength = fst <$> BS.readInt len }

setDkimSelector :: DKIMSetter
setDkimSelector sel dkim = dkim { mdkimSelector = Just sel }
