pub enum GeneralError {
    FieldsNotAvailable = -1,
    InvalidBodyLength = -2,
    MethodNotAllowed = -3,
    RateLimited = -4,
    InvalidTypes = -5,
    DbConnectionNotAvailable=0,
    ErrorGeneratingKeyPair=1,
    LimiterNotAvailable=2,
    RequestedFromOtherIp=3,
    SocketClosed=4,
    TokenNotFound=5,
    TypeNotFound=6,
    UsernameOrPasswordNotGiven=7,
    UserExists=8,
    PasswordTooLong=9,
    CantDecryptPassword=10,
    CantGenerateRsaKeypair=11,
    CantHashPassword=12,
    CantEncryptPrivateKey=13,
    CantGenerateIv=14,
    UserCreationError=15,
    CantGenerateTfaSecret=16,
    CantEncryptTfaSecret=17,
    ErrorAddingEncryptionKey=18,
    OtpNoUser=19,
    TfaAlreadyVerified=20,
    InvalidCredentials=21,
    CantDecryptTfaSecret=22,
    WrongTfaCode=23,
    CantAddLoginToken=24,
    InvalidLoginToken=25,
    LoginTokenUserNotFound=26,
    EncryptionConflictCheckTfa=27,
    UnknownError=28
}