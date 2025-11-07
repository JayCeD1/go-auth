package database

import (
	"go-auth/database/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func Connect() {
	dsn := "host=localhost user=gorm password=addidas1 dbname=gormdb port=5432 sslmode=disable"
	conn, er := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if er != nil {
		panic("could not connect to database")
	}

	if err := conn.AutoMigrate(&models.User{}); err != nil {
		panic("could not migrate database")
	}

}
