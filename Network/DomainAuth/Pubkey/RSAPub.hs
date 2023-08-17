{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.Pubkey.RSAPub (
    lookupPublicKey
  ) where

import Crypto.PubKey.RSA (PublicKey)
import Data.ASN1.BinaryEncoding (DER)
import Data.ASN1.Encoding (decodeASN1')
import Data.ASN1.Types (fromASN1)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS ()
import Data.X509 (PubKey(PubKeyRSA))
import Network.DNS (Domain)
import qualified Network.DNS as DNS
import Network.DomainAuth.Mail
import qualified Network.DomainAuth.Pubkey.Base64 as B

-- | Looking up an RSA public key
lookupPublicKey :: DNS.Resolver -> Domain -> IO (Maybe PublicKey)
lookupPublicKey resolver domain = do
    mpub <- lookupPublicKey' resolver domain
    return $ case mpub of
      Nothing  -> Nothing
      Just pub -> Just $ decodeRSAPublicyKey pub

lookupPublicKey' :: DNS.Resolver -> Domain -> IO (Maybe ByteString)
lookupPublicKey' resolver domain = do
    ex <- DNS.lookupTXT resolver domain
    case ex of
        Left  _ -> return Nothing
        Right x -> return $ extractPub x

extractPub :: [ByteString] -> Maybe ByteString
extractPub = lookup "p" . parseTaggedValue . head

decodeRSAPublicyKey :: ByteString -> PublicKey
decodeRSAPublicyKey b64 = pub
  where
    der = B.decode b64
    Right ans1 = decodeASN1' (undefined :: DER) der
    Right (PubKeyRSA pub,[]) = fromASN1 ans1
