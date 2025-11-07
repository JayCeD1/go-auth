package main

import (
	"go-auth/database"
	"go-auth/routes"

	"github.com/gofiber/fiber/v2"
)

func main() {

	database.Connect()
	app := fiber.New()

	routes.Setup(app)

	err := app.Listen(":8000")
	if err != nil {
		return
	}
}
