package routes

import (
	"univoting-backend/controllers"
	"univoting-backend/middleware"
	"github.com/gin-gonic/gin"
)

func SetupRouter() *gin.Engine {
	router := gin.Default()

	// Auth routes
	router.POST("/register", controllers.RegisterVoter)
	router.POST("/login", controllers.LoginVoter)

	// Protected routes
	votingRoutes := router.Group("/")
	votingRoutes.Use(middleware.JWTAuthMiddleware())
	votingRoutes.POST("/vote", controllers.CastVote)
	votingRoutes.POST("/polls", controllers.CreatePoll)

	return router
}
