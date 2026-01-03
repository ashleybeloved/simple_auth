package handlers

import (
	"log"
	"net/http"

	"todomanager/internal/models"
	"todomanager/internal/services"

	"github.com/gin-gonic/gin"
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

	err := services.Logout(authHeader)
	if err != nil {
		switch err {
		case services.ErrInvalidAuthorizationHeader:
			c.JSON(http.StatusBadRequest, gin.H{"error": err})
			return
		case services.ErrUnknownToken:
			c.JSON(http.StatusBadRequest, gin.H{"error": err})
			return
		case services.ErrInvalidClaims:
			c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			return
		case services.ErrInvalidExp:
			c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			return
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Unknown Error"})
			return
		}
	}

	c.JSON(http.StatusOK, "Bye!")
}

func Test(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "You are not authorized"})
		return
	}

	login, err := services.Test(authHeader)
	if err != nil {
		switch err {
		case services.ErrInvalidAuthorizationHeader:
			c.JSON(http.StatusBadRequest, gin.H{"error": err})
			return
		case services.ErrTokenRevoked:
			c.JSON(http.StatusBadRequest, gin.H{"error": err})
			return
		case services.ErrUnknownToken:
			c.JSON(http.StatusBadRequest, gin.H{"error": err})
			return
		case services.ErrInvalidClaims:
			c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			return
		case services.ErrInvalidUserID:
			c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			return
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Unknown Error"})
			return
		}
	}

	c.JSON(http.StatusOK, "You are logged in "+login)
}
