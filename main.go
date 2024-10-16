package main

import (
	"database/sql"
	"net/http"
	"time"

	_ "github.com/go-sql-driver/mysql" // Import MySQL driver
	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/bcrypt" // Untuk hashing password
)

var jwtSecret = []byte("secret-key") // Ganti ini dengan secret key yang lebih aman

// Struktur untuk User
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"` // Pastikan untuk hashing password
	Role     string `json:"role"`
}

// Fungsi login untuk menghasilkan token JWT
func login(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	// Validasi pengguna (sementara hardcoded)
	if username == "admin" && password == "password" {
		// Membuat token JWT
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": username,
			"role":     "admin", // Set role admin
			"exp":      time.Now().Add(time.Hour * 72).Unix(),
		})

		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, "Could not generate token")
		}

		return c.JSON(http.StatusOK, echo.Map{
			"token": tokenString,
		})
	}

	return c.JSON(http.StatusUnauthorized, "Invalid credentials")
}

// Middleware untuk memverifikasi role pengguna
func isAuthorized(role string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user := c.Get("user").(*jwt.Token)
			claims := user.Claims.(jwt.MapClaims)
			userRole := claims["role"].(string)

			if userRole != role {
				return c.JSON(http.StatusForbidden, "You don't have access")
			}

			return next(c)
		}
	}
}

// Fungsi untuk menambahkan todo baru
func createTodo(c echo.Context) error {
	title := c.FormValue("title")
	description := c.FormValue("description")
	editorID := c.FormValue("editor_id")

	// Lakukan validasi jika diperlukan
	if title == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"message": "Title is required",
		})
	}

	// Koneksi ke database
	db, err := sql.Open("mysql", "username:password@tcp(localhost:3306)/project_database")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"message": "Database connection error",
		})
	}
	defer db.Close()

	// Insert ke database
	_, err = db.Exec("INSERT INTO todos (title, description, editor_id) VALUES (?, ?, ?)", title, description, editorID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"message": "Error inserting todo",
		})
	}

	return c.JSON(http.StatusCreated, echo.Map{
		"message": "Todo created successfully",
	})
}

// Fungsi untuk mendapatkan semua todo
func getTodos(c echo.Context) error {
	db, err := sql.Open("mysql", "username:password@tcp(localhost:3306)/project_database")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"message": "Database connection error",
		})
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, title, description FROM todos")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"message": "Error fetching todos",
		})
	}
	defer rows.Close()

	var todos []map[string]interface{}
	for rows.Next() {
		var id int
		var title, description string
		if err := rows.Scan(&id, &title, &description); err != nil {
			return c.JSON(http.StatusInternalServerError, echo.Map{
				"message": "Error scanning todo",
			})
		}
		todos = append(todos, map[string]interface{}{
			"id":          id,
			"title":       title,
			"description": description,
		})
	}

	return c.JSON(http.StatusOK, todos)
}

// Fungsi untuk memperbarui todo
func updateTodo(c echo.Context) error {
	id := c.Param("id")
	title := c.FormValue("title")
	description := c.FormValue("description")

	db, err := sql.Open("mysql", "username:password@tcp(localhost:3306)/project_database")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"message": "Database connection error",
		})
	}
	defer db.Close()

	_, err = db.Exec("UPDATE todos SET title = ?, description = ? WHERE id = ?", title, description, id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"message": "Error updating todo",
		})
	}

	return c.JSON(http.StatusOK, echo.Map{
		"message": "Todo updated successfully",
	})
}

// Fungsi untuk menghapus todo
func deleteTodo(c echo.Context) error {
	id := c.Param("id")

	db, err := sql.Open("mysql", "username:password@tcp(localhost:3306)/project_database")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"message": "Database connection error",
		})
	}
	defer db.Close()

	_, err = db.Exec("DELETE FROM todos WHERE id = ?", id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"message": "Error deleting todo",
		})
	}

	return c.JSON(http.StatusOK, echo.Map{
		"message": "Todo deleted successfully",
	})
}

// Fungsi untuk membuat pengguna (Hanya untuk Admin)
func createUser(c echo.Context) error {
	user := User{}
	if err := c.Bind(&user); err != nil {
		return c.JSON(http.StatusBadRequest, "Invalid input")
	}

	// Hash password sebelum menyimpannya
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Could not hash password")
	}
	user.Password = string(hashedPassword)

	// Koneksi ke database
	db, err := sql.Open("mysql", "username:password@tcp(localhost:3306)/project_database")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Database connection error")
	}
	defer db.Close()

	// Insert ke database
	_, err = db.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", user.Username, user.Password, user.Role)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Error inserting user")
	}

	return c.JSON(http.StatusCreated, user)
}

// Fungsi untuk mendapatkan semua pengguna (Hanya untuk Admin)
func getUsers(c echo.Context) error {
	db, err := sql.Open("mysql", "username:password@tcp(localhost:3306)/project_database")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Database connection error")
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, username, role FROM users")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Error fetching users")
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.Role); err != nil {
			return c.JSON(http.StatusInternalServerError, "Error scanning user")
		}
		users = append(users, user)
	}

	return c.JSON(http.StatusOK, users)
}

// Fungsi untuk memperbarui pengguna (Hanya untuk Admin)
func updateUser(c echo.Context) error {
	id := c.Param("id")
	user := User{}
	if err := c.Bind(&user); err != nil {
		return c.JSON(http.StatusBadRequest, "Invalid input")
	}

	// Koneksi ke database
	db, err := sql.Open("mysql", "username:password@tcp(localhost:3306)/project_database")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Database connection error")
	}
	defer db.Close()

	// Update data pengguna
	_, err = db.Exec("UPDATE users SET username = ?, role = ? WHERE id = ?", user.Username, user.Role, id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Error updating user")
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "User updated successfully"})
}

// Fungsi untuk menghapus pengguna (Hanya untuk Admin)
func deleteUser(c echo.Context) error {
	id := c.Param("id")

	db, err := sql.Open("mysql", "username:password@tcp(localhost:3306)/project_database")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Database connection error")
	}
	defer db.Close()

	_, err = db.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Error deleting user")
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "User deleted successfully"})
}

func main() {
	e := echo.New()

	// Middleware untuk logging
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Endpoint login
	e.POST("/login", login)

	// Endpoint CRUD Todo
	todoGroup := e.Group("/todos")
	todoGroup.Use(middleware.JWT([]byte("secret-key"))) // Ganti dengan secret key Anda
	todoGroup.Use(isAuthorized("editor"))               // Memastikan hanya editor yang dapat mengakses

	todoGroup.POST("", createTodo)
	todoGroup.GET("", getTodos)
	todoGroup.PUT("/:id", updateTodo)
	todoGroup.DELETE("/:id", deleteTodo)

	// Endpoint CRUD User
	userGroup := e.Group("/users")
	userGroup.Use(middleware.JWT([]byte("secret-key"))) // Ganti dengan secret key Anda
	userGroup.Use(isAuthorized("admin"))                // Memastikan hanya admin yang dapat mengakses

	userGroup.POST("", createUser)
	userGroup.GET("", getUsers)
	userGroup.PUT("/:id", updateUser)
	userGroup.DELETE("/:id", deleteUser)

	e.Logger.Fatal(e.Start(":8080"))
}
