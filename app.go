package main

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

var db *sqlx.DB

func main() {
	dbInit, err := sqlx.Connect("postgres", "host=34.101.216.10 user=skilvul password=skilvul123apa dbname=skilvul-groupchat sslmode=disable")
	if err != nil {
		log.Fatalln(err)
	}

	db = dbInit

	r := gin.Default()
	r.POST("/register", register)
	r.POST("/login", login)
	r.PUT("/editprofile", changeProfile)
	r.Run()
}

func register(c *gin.Context) {
	username := c.Request.FormValue("username")
	password := c.Request.FormValue("password")
	confirmPassword := c.Request.FormValue("confirm_password")

	if confirmPassword != password {
		c.JSON(400, StandardAPIResponse{
			Err: "Confirmed password is not matched",
		})
		return
	}
	salt := RandStringBytes(32)
	password += salt

	h := sha256.New()
	h.Write([]byte(password))
	password = fmt.Sprintf("%x", h.Sum(nil))

	query := `
		INSERT INTO
			account
		(
			username,
			password,
			salt,
			created_at,
			profile_pic
		)
		VALUES
		(
			$1,
			$2,
			$3,
			$4,
			$5
		)
	`

	_, err := db.Exec(query, username, password, salt, time.Now(), "")
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	c.JSON(201, StandardAPIResponse{
		Err:     "null",
		Message: "Success create new user",
	})
}

func login(c *gin.Context) {
	username := c.Request.FormValue("username")
	password := c.Request.FormValue("password")

	query := `
	SELECT 
		user_id,
		username,
		password,
		salt,
		created_at,
		profile_pic
	FROM
		account
	WHERE
		username = $1
	`

	var user UserDB
	err := db.Get(&user, query, username)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(400, StandardAPIResponse{
				Err: "Not authorized",
			})
			return
		}

		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	password += user.Salt.String
	h := sha256.New()
	h.Write([]byte(password))
	hashedPassword := fmt.Sprintf("%x", h.Sum(nil))

	if user.Password.String != hashedPassword {
		c.JSON(401, StandardAPIResponse{
			Err: "password mismatch",
		})
		return
	}

	resp := User{
		Username:   user.UserName.String,
		ProfilePic: user.ProfilePic.String,
		CreatedAt:  user.CreatedAt.UnixNano(),
	}

	c.JSON(200, StandardAPIResponse{
		Err:  "null",
		Data: resp,
	})
}

func changeProfile(c *gin.Context) {
	var userDB UserDB
	username := c.Request.FormValue("username")
	newProfilePicture := c.Request.FormValue("profile_picture")

	query := `
	UPDATE
		account
	SET
		profile_pic = $1
	WHERE
		username = $2
	`
	_, err := db.Exec(query, newProfilePicture, username)
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	resp := User{
		Username:   userDB.UserName.String,
		ProfilePic: userDB.ProfilePic.String,
		CreatedAt:  userDB.CreatedAt.UnixNano(),
	}

	c.JSON(200, StandardAPIResponse{
		Err:  "null",
		Data: resp,
	})
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

type StandardAPIResponse struct {
	Err     string      `json:"err"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

type User struct {
	Username   string `json:"username"`
	ProfilePic string `json:"profile_pic"`
	CreatedAt  int64  `json:"created_at"`
}

type UserDB struct {
	UserID     sql.NullInt64  `db:"user_id"`
	UserName   sql.NullString `db:"username"`
	ProfilePic sql.NullString `db:"profile_pic"`
	Salt       sql.NullString `db:"salt"`
	Password   sql.NullString `db:"password"`
	CreatedAt  time.Time      `db:"created_at"`
}

type Room struct {
	RoomID int64 `json:"room_id"`
}
