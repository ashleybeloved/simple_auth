package services

import (
	"simple_auth/internal/repositories"
	"simple_auth/internal/utils"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type AuthError string

func (e AuthError) Error() string { return string(e) }

var (
	ErrInvalidInput               = AuthError("invalid login or password")
	ErrInvalidPassword            = AuthError("invalid password")
	ErrInvalidAuthorizationHeader = AuthError("invalid authorization header: Bearer <token>")
	ErrInvalidUserID              = AuthError("invalid user_id from claims")
	ErrInvalidClaims              = AuthError("invalid jwt claims")
	ErrInvalidExp                 = AuthError("invalid exp claims")
	ErrUserExist                  = AuthError("user already exists")
	ErrUserNotExist               = AuthError("user not exists")
	ErrAddUser                    = AuthError("can't add user in database")
	ErrHashPassword               = AuthError("can't hash password")
	ErrCompareHashAndPassword     = AuthError("can't compare hash and password")
	ErrTokenRevoked               = AuthError("JWT token revoked")
	ErrUnknownToken               = AuthError("unknown token")
	ErrGenerateJWT                = AuthError("can't generate JWT token")
)

func Register(login string, password string) (string, error) {
	if len(login) < 3 || len(password) < 6 {
		return "", ErrInvalidInput
	}

	exists, err := repositories.FindUserByLogin(login)
	if err != nil || exists {
		return "", ErrUserExist
	}

	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		return "", ErrHashPassword
	}

	err = repositories.AddUser(login, hashedPassword)
	if err != nil {
		return "", ErrAddUser
	}

	id, err := repositories.GetUserIDFromLogin(login)
	if err != nil {
		return "", ErrUserNotExist
	}
	token, err := utils.GenerateJWT(id)
	if err != nil {
		return "", ErrGenerateJWT
	}

	return token, nil
}

func Login(login string, password string) (string, error) {
	exists, err := repositories.FindUserByLogin(login)
	if err != nil || !exists {
		return "", ErrUserNotExist
	}

	compared, err := repositories.CheckUserPassword(login, password)
	if compared == false {
		return "", ErrInvalidPassword
	}
	if err != nil {
		return "", ErrCompareHashAndPassword
	}

	id, err := repositories.GetUserIDFromLogin(login)
	if err != nil {
		return "", ErrUserNotExist
	}
	token, err := utils.GenerateJWT(id)
	if err != nil {
		return "", ErrGenerateJWT
	}

	return token, nil
}

func Logout(authHeader string) error {
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return ErrInvalidAuthorizationHeader
	}

	tokenString := authHeader[len(bearerPrefix):]

	token, err := utils.ValidateJWT(tokenString)
	if err != nil {
		return ErrUnknownToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return ErrInvalidClaims
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return ErrInvalidExp
	}

	repositories.RevokeJWT(tokenString, exp)

	return nil
}

func Test(authHeader string) (string, error) {
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", ErrInvalidAuthorizationHeader
	}

	tokenString := authHeader[len(bearerPrefix):]

	exists, err := repositories.CheckForRevokeJWT(tokenString)
	if exists {
		return "", ErrTokenRevoked
	}

	token, err := utils.ValidateJWT(tokenString)
	if err != nil {
		return "", ErrUnknownToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", ErrInvalidClaims
	}

	id, ok := claims["user_id"].(float64)
	if !ok {
		return "", ErrInvalidUserID
	}

	login, err := repositories.GetUserLoginFromID(int(id))

	return login, nil
}
