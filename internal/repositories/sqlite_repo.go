package repositories

import (
	"database/sql"
	"log"
	"os"
	"todomanager/internal/utils"

	_ "github.com/glebarez/sqlite"
)

var db *sql.DB

func OpenSQLite() *sql.DB {
	if err := os.MkdirAll("./data", 0755); err != nil {
		log.Fatal("Cannot create directory ./data:", err)
	}

	var err error
	db, err = sql.Open("sqlite", "./data/users.db")
	if err != nil {
		log.Fatal("Error open SQLite users.db:", err)
	}

	if err := db.Ping(); err != nil {
		log.Fatal("Error connecting to SQLite:", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	login TEXT UNIQUE NOT NULL,
	password TEXT NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		log.Fatal("Error creating table for SQLite:", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS jwt_blacklist (
	jti TEXT PRIMARY KEY,
	exp INTEGER NOT NULL,
	revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		log.Fatal("Error creating table for SQLite:", err)
	}

	log.Println("Подключение к SQLite успешно!")

	return db
}

func FindUserByLogin(login string) (exists bool, err error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE login = ?)`

	err = db.QueryRow(query, login).Scan(&exists)
	if err != nil {
		return true, err
	}

	return exists, nil
}

func AddUser(login string, hashedPassword []byte) (err error) {
	query := `INSERT INTO users (login, password) VALUES (?, ?)`

	_, err = db.Exec(query, login, hashedPassword)
	if err != nil {
		return err
	}

	return nil
}

func CheckUserPassword(login string, password string) (bool, error) {
	var hashedPassword string
	query := `SELECT password FROM users WHERE login = ?`

	err := db.QueryRow(query, login).Scan(&hashedPassword)
	if err != nil {
		return false, err
	}

	compared, err := utils.CompareHashAndPassword(password, []byte(hashedPassword))

	if err != nil || !compared {
		return false, nil
	}

	return true, nil
}

func GetUserIDFromLogin(login string) (int, error) {
	query := `SELECT id FROM users WHERE login = ?`

	var id int

	err := db.QueryRow(query, login).Scan(&id)
	if err != nil {
		return 0, err
	}

	return id, nil
}

func GetUserLoginFromID(id int) (string, error) {
	query := `SELECT login FROM users WHERE id = ?`

	var login string

	err := db.QueryRow(query, id).Scan(&login)
	if err != nil {
		return "", err
	}

	return login, nil
}

func RevokeJWT(jti string, exp float64) error {
	query := `INSERT INTO jwt_blacklist (jti, exp) VALUES (?, ?)`

	_, err := db.Exec(query, jti, exp)
	if err != nil {
		return err
	}

	return nil
}

func CheckForRevokeJWT(tokenString string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM jwt_blacklist WHERE jti = ?)`

	var exists bool

	err := db.QueryRow(query, tokenString).Scan(&exists)
	if err != nil {
		log.Println(err)
		return true, err
	}

	return exists, nil
}
