package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatal("usage: go run ./cmd/regadmin <db-path> <username> <password>")
	}
	db, err := sql.Open("sqlite3", os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(os.Args[3]), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO admin (username, password_hash) VALUES (?, ?)`, os.Args[2], string(hash)); err != nil {
		log.Fatal(err)
	}
	fmt.Println("admin registered")
}
