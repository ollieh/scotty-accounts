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
import Network.Wai.Middleware.Static
import Text.Hastache
import Text.Hastache.Context

runDb query = liftIO $ S.runSqlite "db" query

type ActionM = ActionH LT.Text

main :: IO ()
main = scottyH' 3000 $ do
    middleware $ staticPolicy (noDots >-> addBase "static")
    runDb $ S.runMigration migrateAll
    conn <- liftIO $ R.connect R.defaultConnectInfo
    vaultKey <- liftIO $ Vault.newKey
    middleware $ session (redisBackend conn $ 60*60*2) vaultKey
    let getSess = getSession vaultKey
    let sessRemove key sess = (filter ((/=) key . fst) sess)
    let setSess = setSession vaultKey 
    let sessInsert key val sess = (key, val) : sessRemove key sess
    let showFlash sess req = do
            let mFlash = lookup "flash" sess
            case mFlash of
                Just flash -> do
                    let flashlist = read (BS.unpack flash) :: [String]
                    let mkListContext message = \x -> MuVariable message
                    setH "flash" $ MuList $ map (mkStrContext . mkListContext) flashlist
                Nothing -> return ()
            liftIO $ setSess req (sessRemove "flash" sess)
    setTemplatesDir "templates"
    setTemplateFileExt ".mustache"
    middleware logStdoutDev
    get "/" $ do
        req <- request
        let sess = getSess req
        let mUsername = lookup "username" sess
        case mUsername of
            Just username -> do 
                        setH "loggedIn" $ MuBool True
                        setH "username" $ MuVariable (BS.unpack username)
            Nothing -> setH "loggedIn" $ MuBool False
        showFlash sess req
        hastache "index"
    get "/login" $ do
        req <- request
        let sess = getSess req
        let mUsername = lookup "username" sess
        case mUsername of
            Just username -> do 
                        setH "loggedIn" $ MuBool True
                        setH "username" $ MuVariable (BS.unpack username)
            Nothing -> setH "loggedIn" $ MuBool False
        showFlash sess req
        hastache "login"
    get "/register" $ do
        req <- request
        let sess = getSess req
        let mUsername = lookup "username" sess
        case mUsername of
            Just username -> do 
                        setH "loggedIn" $ MuBool True
                        setH "username" $ MuVariable (BS.unpack username)
            Nothing -> setH "loggedIn" $ MuBool False
        showFlash sess req
        hastache "register"
    post "/register" $ do
            username <- param "username"
            password <- param "password"
            req <- request
            let shortUsername = "Usernames must be at least 4 characters. "
            let shortPassword = "Passwords must be at least 8 characters. " 
            case (4 <= length username, 8 <= length password) of
                (False, False) -> do
                    liftIO $ setSess req $ sessInsert 
                                "flash" 
                                (BS.pack $ show
                                    [shortPassword, shortUsername])
                                (getSess req)
                    redirect "/register"
                (False, True) -> do
                    liftIO $ setSess req $ sessInsert 
                                "flash" 
                                (BS.pack $ show
                                    [shortUsername])
                                (getSess req)
                    redirect "/register"
                (True, False) -> do
                    liftIO $ setSess req $ sessInsert 
                                "flash" 
                                (BS.pack $ show
                                    [shortPassword])
                                (getSess req)
                    redirect "/register"
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
        req <- request
        case mPasswordsMatch of 
                    Just passwordsMatch -> do
                        case passwordsMatch of
                            True -> liftIO $ setSess req $ 
                                        sessInsert 
                                            "flash" 
                                            (BS.pack $ show ["Log in successful"])
                                            $ sessInsert  
                                                "username" 
                                                (BS.pack username) 
                                                (getSess req)
                            False -> liftIO $ setSess req $
                                        sessInsert
                                            "flash"
                                            (BS.pack $ show ["Password incorrect"])
                                            (getSess req)
                        redirect "/"
                    Nothing -> do 
                            liftIO $ setSess req $
                                sessInsert
                                    "flash"
                                    (BS.pack $ show ["No such user"])
                                    (getSess req)
                            redirect "/"
    get "/logout" $ do
        req <- request
        liftIO $ setSess req $ sessInsert 
            "flash" 
            (BS.pack $ show ["Logged out successfully"]) 
            $ sessRemove "username" (getSess req)
        redirect "/login"
    get "/get" $ do
        req <- request
        html $ LT.pack $ show $ getSess req
