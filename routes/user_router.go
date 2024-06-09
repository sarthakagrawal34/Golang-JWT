package routes

import (
	"golang-jwt/controllers"
	"golang-jwt/middleware"

	"github.com/gin-gonic/gin"
)

func UserRoutes(in *gin.Engine){
	in.Use(middleware.Authenticate())
	in.GET("/users", controllers.GetAllUsers())
	in.GET("/users/:user_id", controllers.GetUser())
}
