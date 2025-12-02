package main

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	UserID   int    `json:"uid"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

var jwtSecret = []byte("dev_secret_change_me")

func authMiddleware(c *gin.Context) {
	tokenStr, err := c.Cookie("auth_token")
	if err != nil || tokenStr == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	claims, err := parseJWT(tokenStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// Зберігаємо дані користувача у контекст (для подальшого використання)
	c.Set("userID", claims.UserID)
	c.Set("username", claims.Username)

	c.Next()
}

func main() {
	// DB
	db, err := sql.Open("sqlite3", "../database/app.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}
	if err := migrate(db); err != nil {
		log.Fatal(err)
	}

	r := gin.Default()

	// CORS for dev; with Vite proxy we keep same-origin feel, but allow credentials just in case
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"},
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"Content-Type"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	api := r.Group("/api")
	{
		api.POST("/register", func(c *gin.Context) { handleRegister(c, db) })
		api.POST("/login", func(c *gin.Context) { handleLogin(c, db) })
		api.POST("/logout", handleLogout)
		api.GET("/me", func(c *gin.Context) { handleMe(c, db) })

		// protected
		api.GET("/users", authMiddleware, func(c *gin.Context) {
			rows, err := db.Query("SELECT id, username FROM users ORDER BY id")
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			defer rows.Close()
			users := make([]User, 0)
			for rows.Next() {
				var u User
				if err := rows.Scan(&u.ID, &u.Username); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				users = append(users, u)
			}
			if err := rows.Err(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, users)
		})
	}

	log.Println("API listening on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL
    );`)
	return err
}

func handleRegister(c *gin.Context, db *sql.DB) {
	var creds Credentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return
	}
	if len(creds.Username) < 3 || len(creds.Password) < 6 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username >=3, password >=6"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash error"})
		return
	}
	_, err = db.Exec("INSERT INTO users(username, password_hash) VALUES(?, ?)", creds.Username, string(hash))
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "username already exists"})
		return
	}
	c.Status(http.StatusCreated)
}

func handleLogin(c *gin.Context, db *sql.DB) {
	var creds Credentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return
	}
	id, hash, err := getUserAuth(db, creds.Username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(creds.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	token, err := makeJWT(id, creds.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "jwt error"})
		return
	}
	setAuthCookie(c, token)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func handleLogout(c *gin.Context) {
	// Clear cookie
	httpOnly := true
	secure := false // dev over http; set true when using https
	c.SetCookie("auth_token", "", -1, "/", "", secure, httpOnly)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func handleMe(c *gin.Context, db *sql.DB) {
	tokenStr, err := c.Cookie("auth_token")
	if err != nil || tokenStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	claims, err := parseJWT(tokenStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var u User
	row := db.QueryRow("SELECT id, username FROM users WHERE id = ?", claims.UserID)
	if err := row.Scan(&u.ID, &u.Username); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	c.JSON(http.StatusOK, u)
}

func getUserAuth(db *sql.DB, username string) (int, string, error) {
	var id int
	var hash string
	err := db.QueryRow("SELECT id, password_hash FROM users WHERE username = ?", username).Scan(&id, &hash)
	if err != nil {
		return 0, "", err
	}
	return id, hash, nil
}

func makeJWT(userID int, username string) (string, error) {
	exp := time.Now().Add(24 * time.Hour)
	claims := Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "practice-api",
			Subject:   username,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func parseJWT(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}

func setAuthCookie(c *gin.Context, token string) {
	httpOnly := true
	secure := false // set true if behind HTTPS in prod
	// SameSite=Lax default via SetCookie; Gin uses net/http default (Lax). For strict control use raw header.
	c.SetCookie("auth_token", token, int((24 * time.Hour).Seconds()), "/", "", secure, httpOnly)
	// If you reverse-proxy under same domain in prod, keep path=/, domain default
	_ = os.Setenv("GIN_MODE", gin.ReleaseMode)
}
