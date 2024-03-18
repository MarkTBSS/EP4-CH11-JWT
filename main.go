package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/MarkTBSS/EP4-CH11-JWT/pretty"
	"github.com/golang-jwt/jwt/v5"

	"github.com/labstack/echo/v4"
)

type User struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Age  int    `json:"age"`
}

type Err struct {
	Message string `json:"message"`
}

type jwtCustomClaims struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
	jwt.RegisteredClaims
}

var users = []User{
	{ID: 1, Name: "A", Age: 10},
}

func createUserHandler(c echo.Context) error {
	user := User{}
	err := c.Bind(&user)
	if err != nil {
		return c.JSON(http.StatusBadRequest, Err{Message: err.Error()})
	}
	users = append(users, user)
	fmt.Println("id : % #v\n", user)
	return c.JSON(http.StatusCreated, user)
}

func getUsersHandler(context echo.Context) error {
	user := context.Get("user").(*jwt.Token)
	claims := user.Claims.(*jwtCustomClaims)
	pretty.PrettyPrint(claims)
	//name := claims.Name
	//fmt.Printf("User Name : %#v\n", claims)
	return context.JSON(http.StatusOK, users)
}

func jwtMiddleWare(next echo.HandlerFunc) echo.HandlerFunc {
	return func(context echo.Context) error {
		token := context.Request().Header.Get("Authorization")
		//pretty.PrettyPrint(token)
		if token == "" {
			return echo.ErrUnauthorized
		}
		parts := strings.Split(token, " ")
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			return echo.ErrUnauthorized
		}
		//fmt.Println(parts[0])
		//fmt.Println(parts[1])
		token = parts[1]
		token2, err := jwt.ParseWithClaims(token, &jwtCustomClaims{}, func(t *jwt.Token) (interface{}, error) {
			return []byte("secret"), nil
		})
		//pretty.PrettyPrint(token2)
		if err != nil {
			return echo.ErrUnauthorized
		}
		// for dump
		claims, ok := token2.Claims.(*jwtCustomClaims)
		if !ok {
			return echo.ErrUnauthorized
		}
		pretty.PrettyPrint(claims)
		//fmt.Printf("claims : %#v\n", claims)
		context.Set("user", token2)
		//pretty.PrettyPrint(context)
		return next(context)
	}
}

func login(context echo.Context) error {
	username := context.FormValue("username")
	password := context.FormValue("password")
	// Throws unauthorized error
	if username != "mark" || password != "1234" {
		return echo.ErrUnauthorized
	}
	// Set custom claims
	claims := &jwtCustomClaims{
		"Mark Zuck",
		true,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * 100)),
		},
	}
	//pretty.PrettyPrint(claims)
	// Create token with claims
	tokenNewWithClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	//pretty.PrettyPrint(tokenNewWithClaims)
	// Generate encoded token and send it as response.
	tokenSignedString, err := tokenNewWithClaims.SignedString([]byte("secret"))
	if err != nil {
		return err
	}
	//fmt.Println(tokenSignedString)
	return context.JSON(http.StatusOK, echo.Map{
		"token": tokenSignedString,
	})
}

func main() {
	echoInstance := echo.New()
	//echoInstance.Use(middleware.Logger())
	//echoInstance.Use(middleware.Recover())

	echoInstance.GET("/health", func(context echo.Context) error {
		return context.String(http.StatusOK, "OK")
	})

	group := echoInstance.Group("/api")
	group.POST("/login", login)

	group.Use(jwtMiddleWare)
	group.POST("/users", createUserHandler)
	group.GET("/users", getUsersHandler)

	log.Fatal(echoInstance.Start(":2567"))
}
