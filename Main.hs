{-# LANGUAGE OverloadedStrings #-}
import Web.Scotty.Hastache
import Web.Scotty.Trans
import qualified Web.Scotty as WS
import Network.Wai.Middleware.RequestLogger
import Model
import qualified Database.Persist as P
import qualified Database.Persist.Sqlite as S
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as LT
import qualified Crypto.BCrypt as BC
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Text.Lazy.Encoding as LT
import Data.ByteString (ByteString)
import Data.Maybe (fromJust)
import Control.Monad
import qualified Database.Redis as R
import System.Random
import qualified Data.Vault.Lazy as Vault
import Data.String
import Web.Scotty.Sessions
import Web.Scotty.Sessions.Redis

runDb query = liftIO $ S.runSqlite "db" query

type ActionM = ActionH LT.Text
 
main :: IO ()
main = scottyH' 3000 $ do
    runDb $ S.runMigration migrateAll
    conn <- liftIO $ R.connect R.defaultConnectInfo
    vaultKey <- liftIO $ Vault.newKey
    middleware $ session (redisBackend conn $ 60*60*2) vaultKey
    let getSess = getSession vaultKey
    let setSess = setSession vaultKey
    let sessRemove sess key = (filter ((/=) key . fst) sess)
    let sessInsert sess key val = (key, val) : sessRemove sess key
    let isAuthed = lookup "username"
    setTemplatesDir "templates"
    middleware logStdoutDev
    get "/unauthed" $ html "Unauthed"
    get "/login" $ hastache "login.mustache"
    get "/register" $ hastache "register.mustache"
    post "/register" $ do
            username <- param "username"
            password <- param "password"
            let shortUsername = "Usernames must be at least 4 characters. "
            let shortPassword = "Passwords must be at least 8 characters. " 
            case (4 <= length username, 8 <= length password) of
                (False, False) -> html $ LT.pack $ 
                                    shortPassword ++ shortUsername
                (False, True) -> html $ LT.pack shortUsername
                (True, False) -> html $ LT.pack shortPassword
                _ -> do
                    ment <- runDb $ 
                            P.selectFirst [UserUsername S.==. username] []
                    case ment of
                        Nothing -> do
                            hash <- liftIO $ BC.hashPasswordUsingPolicy 
                                        BC.slowerBcryptHashingPolicy 
                                            {BC.preferredHashCost = 10}
                                        (BS.pack password)
                            userID <- runDb $ P.insert $ User 
                                            username 
                                            (BS.unpack $ fromJust hash)
                            user <- runDb $ P.get userID
                            html $ LT.pack $ show user
                        Just _ -> html "User exists"
    post "/login" $ do
        username <- param "username"
        password <- param "password"
        ment <- runDb $ P.selectFirst [UserUsername S.==. username] []
        let mPasswordsMatch = do
            ent <- ment
            let user = S.entityVal ent
            let hash = userPassword user
            let passwordsMatch = BC.validatePassword (BS.pack hash) password
            return passwordsMatch
        case mPasswordsMatch of 
                    Just passwordsMatch -> do
                        req <- request
                        liftIO $ setSess req $ 
                            sessInsert (getSess req) "username" $ 
                                BS.pack username
                        html $ LT.pack $ show passwordsMatch
                    Nothing -> html "No such user"
    get "/logout" $ do
        req <- request
        liftIO $ setSess req $ sessRemove (getSess req) "username"
        redirect "/login"
    get "/get" $ do
        req <- request
        html $ LT.pack $ show $ getSess req
