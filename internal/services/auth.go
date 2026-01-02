package services

import (
	"todomanager/internal/repositories"
	"todomanager/internal/utils"
)

// В service происходит вся бизнес-логика (создание, генерация и т.п.)

type AuthError string

func (e AuthError) Error() string { return string(e) }

var (
	ErrInvalidInput           = AuthError("invalid login or password")
	ErrInvalidPassword        = AuthError("invalid password")
	ErrUserExist              = AuthError("user already exists")
	ErrUserNotExist           = AuthError("user not exists")
	ErrAddUser                = AuthError("can't add user in database")
	ErrHashPassword           = AuthError("can't hash password")
	ErrCompareHashAndPassword = AuthError("can't compare hash and password")
	ErrGenerateJWT            = AuthError("can't generate JWT token")
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

	// Генерируем JWT-токен по ID только что зарегистрировавшемуся пользователю

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
	// Если не существует - пропускаем запрос дальше

	exists, err := repositories.FindUserByLogin(login)
	if err != nil || !exists {
		return "", ErrUserNotExist
	}

	// Проверка на совпадение пароля

	compared, err := repositories.CheckUserPassword(login, password)
	if compared == false {
		return "", ErrInvalidPassword
	}
	if err != nil {
		return "", ErrCompareHashAndPassword
	}

	// Генерируем JWT-токен по ID

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
