package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatal("usage: go run ./cmd/regadmin <database-url> <username> <password>")
	}
	db, err := sql.Open("postgres", os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(os.Args[3]), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO admin (username, password_hash) VALUES ($1, $2)`, os.Args[2], string(hash)); err != nil {
		log.Fatal(err)
	}
	fmt.Println("admin registered")
}
