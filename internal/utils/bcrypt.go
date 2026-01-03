package utils

import (
	"log"
	"os"
	"strconv"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) ([]byte, error) {
	digits, err := strconv.Atoi(os.Getenv("COST_FOR_BCRYPT"))
	if err != nil {
		return nil, err
	}

	if len(os.Getenv("COST_FOR_BCRYPT")) == 0 {
		digits = 10
		log.Println("Invalid COST_FOR_DIGITS in .env file, set to default = 10")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), digits)
	if err != nil {
		return nil, err
	}

	return hashedPassword, nil
}

func CompareHashAndPassword(password string, hashedPassword []byte) (bool, error) {
	err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	if err != nil {
		return false, err
	}

	return true, nil
}
