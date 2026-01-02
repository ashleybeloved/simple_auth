package handlers

import (
	"log"
	"net/http"
	"strings"

	"todomanager/internal/models"
	"todomanager/internal/repositories"
	"todomanager/internal/services"
	"todomanager/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func Register(c *gin.Context) {
	var req models.ReqRegistration
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	token, err := services.Register(req.Login, req.Password)
	if err != nil {
		switch err {
		case services.ErrInvalidInput:
			c.JSON(http.StatusBadRequest, gin.H{"error": err})
			return
		case services.ErrUserExist:
			c.JSON(http.StatusConflict, gin.H{"error": err})
			return
		case services.ErrAddUser:
			c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			return
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Unknown Error"})
			log.Println(err)
			return
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":      "User registered",
		"access_token": token,
		"token_type":   "Bearer",
	})
}

func Login(c *gin.Context) {
	var req models.ReqLogin
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	token, err := services.Login(req.Login, req.Password)
	if err != nil {
		switch err {
		case services.ErrUserNotExist:
			c.JSON(http.StatusNotFound, gin.H{"error": err})
			return
		case services.ErrInvalidPassword:
			c.JSON(http.StatusForbidden, gin.H{"error": err})
			return
		case services.ErrCompareHashAndPassword:
			c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			return
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Unknown Error"})
			return
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":      "You are logged in " + req.Login,
		"access_token": token,
		"token_type":   "Bearer",
	})
}

func Logout(c *gin.Context) {
	// Получаем заголовок Authorization

	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "You are not authorized"})
		return
	}

	// Проверяем формат: "Bearer <token>"

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header must be Bearer <token>"})
		return
	}

	tokenString := authHeader[len(bearerPrefix):] // извлекаем сам токен

	token, err := utils.ValidateJWT(tokenString)
	if err != nil {
		log.Print(err)
		c.JSON(http.StatusForbidden, gin.H{"error": "Unknown token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid claims"})
		return
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid exp"})
		return
	}

	repositories.RevokeJWT(tokenString, exp)

	c.JSON(http.StatusOK, "Bye!")
}

func Test(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "You are not authorized"})
		return
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header must be Bearer <token>"})
		return
	}

	tokenString := authHeader[len(bearerPrefix):]

	// Сначала проверка на ревоук

	exists, err := repositories.CheckForRevokeJWT(tokenString)
	if exists {
		c.JSON(http.StatusNotAcceptable, gin.H{"error": "Your JWT token revoked"})
		return
	}

	token, err := utils.ValidateJWT(tokenString)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "Unknown token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid claims"})
		return
	}

	id, ok := claims["user_id"].(float64)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user_id"})
		return
	}

	login, err := repositories.GetUserLoginFromID(int(id))

	c.JSON(http.StatusOK, "You are logged in "+login)
}
