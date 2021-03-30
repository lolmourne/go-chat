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
	r.PUT("/editpassword", changePassword)
	// r.GET("/search", getOtherProfile)
	r.GET("/id/:user_id", getOtherProfile)
	r.PUT("/join", joinRoom)
	r.POST("/createroom", createRoom)
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
	username := c.Request.FormValue("username")
	newUsername := c.Request.FormValue("newUsername")
	newProfilePicture := c.Request.FormValue("profile_picture")

	query := `
	UPDATE
		account
	SET
		username = $1
		profile_pic = $2
	WHERE
		username = $3
	`
	_, err := db.Exec(query, newUsername, newProfilePicture, username)
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	c.JSON(200, StandardAPIResponse{
		Err:     "null",
		Message: "Success change profile!",
	})
}

func updateRoom(c *gin.Context) {
	c.String(200, "%v", "test")
}

// Want to add a feature to block if new password
// is same with the old password,
// but it means the new salt is also same with
// the old one, isn't it?
func changePassword(c *gin.Context) {
	username := c.Request.FormValue("username")
	newPassword := c.Request.FormValue("new_password")

	salt := RandStringBytes(32)
	newPassword += salt
	h := sha256.New()
	h.Write([]byte(newPassword))
	newPassword = fmt.Sprintf("%x", h.Sum(nil))

	queryUpdate := `
	UPDATE
		account
	SET
		password = $1
	WHERE
		username = $2	
	`

	_, err := db.Exec(queryUpdate, newPassword, username)
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	c.JSON(201, StandardAPIResponse{
		Err:     "null",
		Message: "Success change password",
	})
}

func getOtherProfile(c *gin.Context) {
	userID := c.Param("user_id")
	// username := c.Request.FormValue("username")

	query := `
	SELECT
		user_id,
		username,
		created_at,
		profile_pic
	FROM
		account
	WHERE
		user_id = $1
	`

	var user UserDB
	err := db.Get(&user, query, userID)
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

func joinRoom(c *gin.Context) {
	userID := c.Request.FormValue("user_id")
	roomID := c.Request.FormValue("room_id")

	query := `
	INSERT INTO
		room_participant
		(
			room_id, 
			user_id
		)
	VALUES
		(
			$1,
			$2
		)
	`

	_, err := db.Exec(query, roomID, userID)
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	c.JSON(200, StandardAPIResponse{
		Err:     "null",
		Message: "Success join the group",
	})
}

func createRoom(c *gin.Context) {
	roomName := c.Request.FormValue("room_name")
	adminID := c.Request.FormValue("admin_id")
	categoryID := c.Request.FormValue("category_id")

	query := `
	INSERT INTO
		room
		(
			name,
			admin_user_id,
			description,
			category_id,
			created_at
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

	_, err := db.Exec(query, roomName, adminID, "", categoryID, time.Now())
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	c.JSON(201, StandardAPIResponse{
		Err:     "null",
		Message: "Room created!",
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
	RoomName    string `json:"name"`
	CategoryID  int64  `json:"category_id"`
	Description string `json:"description"`
	CreatedAt   int64  `json:"created_at"`
}

type RoomDB struct {
	RoomID      sql.NullInt64  `db:"room_id"`
	Name        sql.NullString `db:"name"`
	AdminID     sql.NullInt64  `db:"admin_user_id"`
	Description sql.NullString `db:"description"`
	CategoryID  sql.NullString `db:"category_id"`
	CreatedAt   time.Time      `db:"created_at"`
}
