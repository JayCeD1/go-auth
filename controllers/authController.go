package controllers

import (
	"go-auth/database/models"

	"github.com/gofiber/fiber/v2"
)

func Register(c *fiber.Ctx) error {
	var data map[string]string

	if err := c.BodyParser(&data); err != nil {
		return err
	}

	user := models.User{
		Name:     data["name"],
		Email:    data["email"],
		Password: data["password"],
	}

	return c.JSON(user)
}
