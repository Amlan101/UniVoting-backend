package routes

import (
	"univoting-backend/controllers"
	"univoting-backend/middleware"
	"github.com/gin-gonic/gin"
)

func SetupRouter() *gin.Engine {
	router := gin.Default()

    router.GET("/", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "message": "Welcome to the Univoting Backend!",
        })
    })

    // Auth routes
    router.POST("/register", controllers.RegisterVoter)
    router.POST("/login", controllers.LoginVoter)

    // Public route for viewing active polls
    router.GET("/polls", controllers.GetActivePolls)
    router.GET("/polls/:poll_id", controllers.GetPollDetails)

    // Protected routes for voting and poll management
    votingRoutes := router.Group("/")
    votingRoutes.Use(middleware.JWTAuthMiddleware())
    votingRoutes.POST("/vote", controllers.CastVote)
    votingRoutes.POST("/polls", controllers.CreatePoll)
    votingRoutes.PUT("/polls/:poll_id/deactivate", controllers.DeactivatePoll) 
    votingRoutes.DELETE("/polls/:poll_id", controllers.DeletePoll)              
	votingRoutes.GET("/polls/:poll_id/results", controllers.GetPollResults)
	votingRoutes.GET("/polls/:poll_id/tally", controllers.TallyVotes)

    return router
}
