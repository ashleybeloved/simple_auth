package models

import "time"

type User struct {
	ID        int
	Login     string
	Password  string
	CreatedAt time.Time
}

type ReqRegistration struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type ReqLogin struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}
