package main

import (
	"log"
	"univoting-backend/config"
	"univoting-backend/models"
	"univoting-backend/routes"
)

func main() {
	// Load environment variables and config
	config.LoadConfig()
	config.ConnectDatabase()

	// Migrate models
	config.DB.AutoMigrate(&models.Voter{}, &models.Vote{}, &models.Poll{}, &models.Option{},  &models.VoteShare{})

	// Start the router
	router := routes.SetupRouter()
	log.Println("Starting server on http://localhost:8080")
	router.Run(":8080")
}