package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// User represents the structure of a user in the database
type User struct {
	ID        string    `bson:"_id,omitempty"`
	Username  string    `bson:"username"`
	Password  string    `bson:"password"`
	CreatedAt time.Time `bson:"createdAt"`
}

type Candidates struct {
	ID                string    `bson:"_id,omitempty"`
	Candidatename     string    `bson:"name"`
	InterviewStatus   bool      `bson:"InterviewStatus"`
	InterviewFeedback string    `bson:"InetrviewFeedback"`
	InterviewRating   int       `bson:"InterviewRating"`
	User              string    `bson:"Username"`
	CreatedAt         time.Time `bson:"createdAt"`
}

// JWTClaims represents the claims included in the JWT token
type JWTClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// MongoDB configuration
// var mongoURL="mongodb+srv://yashguptayg318:"+os.Getenv("GJZYEnmAUr6S3Aa7")+"@cluster0.9tqqtyr.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

var (
	mongoURI                         string
	dbName                           = "sample_mflix"
	collectionNameUsers              = "Users"
	collectionNameCandidateFeedbacks = "CandidateFeedbacks"
	secretKey                        string
)

var client *mongo.Client
var userCollection *mongo.Collection
var candidateFeedbackCollection *mongo.Collection

func init() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
}

func initMongoDB() {
	// Set client options
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI(mongoURI).SetServerAPIOptions(serverAPI)
	// Create a new client and connect to the server
	client, err := mongo.Connect(context.TODO(), opts)
	if err != nil {
		panic(err)
	}

	// Check the connection
	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to MongoDB!")

	// Accessing a collection
	userCollection = client.Database(dbName).Collection(collectionNameUsers)
	candidateFeedbackCollection = client.Database(dbName).Collection(collectionNameCandidateFeedbacks)
}

// GenerateJWT generates a JWT token for the given user
func GenerateJWT(user User) (string, error) {
	claims := JWTClaims{
		user.Username,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // Token expires in 24 hours
			Issuer:    "your-issuer",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// SignUpHandler handles user registration (sign-up)
func SignUpHandler(c *gin.Context) {
	var user User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if the username already exists
	existingUser := userCollection.FindOne(context.Background(), bson.M{"username": user.Username})
	if existingUser.Err() == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	}

	// Hash the password before storing it
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	user.Password = string(hashedPassword)

	// Set the creation timestamp
	user.CreatedAt = time.Now()

	// Insert the user into the MongoDB collection
	_, err = userCollection.InsertOne(context.Background(), user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully"})
}

// SignInHandler handles user authentication (sign-in)
func SignInHandler(c *gin.Context) {
	var user User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Find the user by username
	result := userCollection.FindOne(context.Background(), bson.M{"username": user.Username})
	if result.Err() != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Decode the user document from the database
	var foundUser User
	if err := result.Decode(&foundUser); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode user data"})
		return
	}

	// Compare the hashed password stored in the database with the provided password
	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(user.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// User authenticated successfully, generate JWT token
	token, err := GenerateJWT(foundUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func JWTMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		tokenString := authHeader[len("Bearer "):]
		token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(secretKey), nil
		})
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(*JWTClaims)
		if !ok || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("username", claims.Username)
		c.Next()
	}
}

// AddCandidate handles the creation of a new candidate
func AddCandidateHandler(c *gin.Context) {
	// Bind JSON request body to Candidates struct
	var candidate Candidates
	if err := c.BindJSON(&candidate); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set the creation timestamp
	candidate.CreatedAt = time.Now()
	candidate.User = c.GetString("username")
	// Insert the candidate into the MongoDB collection
	insertResult, err := candidateFeedbackCollection.InsertOne(context.Background(), candidate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Return the ID of the newly created candidate
	c.JSON(http.StatusCreated, gin.H{"id": insertResult.InsertedID})
}

// UpdateCandidate handles updating an existing candidate
func UpdateCandidateHandler(c *gin.Context) {
	// Get candidate ID from URL parameter
	candidateID := c.Param("id")

	// Convert candidateID to ObjectID
	objID, err := primitive.ObjectIDFromHex(candidateID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid candidate ID"})
		return
	}

	// Bind JSON request body to Candidates struct
	var candidate Candidates
	if err := c.BindJSON(&candidate); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update the candidate in the MongoDB collection
	filter := bson.M{"_id": objID}
	update := bson.M{
		"$set": bson.M{
			"name":              candidate.Candidatename,
			"InterviewStatus":   candidate.InterviewStatus,
			"InterviewFeedback": candidate.InterviewFeedback,
			"InterviewRating":   candidate.InterviewRating,
		},
	}

	_, err = candidateFeedbackCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Candidate updated successfully"})
}

func DeleteCandidateHandler(c *gin.Context) {
	// Get candidate ID from URL parameter
	candidateID := c.Param("id")

	// Convert candidateID to ObjectID
	objID, err := primitive.ObjectIDFromHex(candidateID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid candidate ID"})
		return
	}

	// Delete the candidate from the MongoDB collection
	filter := bson.M{"_id": objID}
	_, err = candidateFeedbackCollection.DeleteOne(context.Background(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Candidate deleted successfully"})
}
func GetCandidatesForUser(c *gin.Context) {
	// Get user ID from URL parameter
	user := c.GetString("username")

	// Query the MongoDB collection for candidates belonging to the specified user
	filter := bson.M{"Username": user}
	cursor, err := candidateFeedbackCollection.Find(context.Background(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer cursor.Close(context.Background())

	// Iterate over the cursor and store candidates in a slice
	var candidates []Candidates
	if err := cursor.All(context.Background(), &candidates); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, candidates)
}
func main() {
	// Initialize MongoDB connection
	mongoURI = os.Getenv("MONGO_URI")
	secretKey = os.Getenv("JWT_SECRET")
	initMongoDB()

	// Initialize Gin router
	router := gin.Default()
	// Configure CORS middleware
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"*"}                            // Allow all origins (change as needed)
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE"} // Allow specified HTTP methods
	config.AllowHeaders = []string{"*"}
	router.Use(cors.New(config))

	// Define routes
	router.POST("/signup", SignUpHandler)
	router.POST("/signin", SignInHandler)
	router.POST("/addcandidate", JWTMiddleware(), AddCandidateHandler)
	router.DELETE("/candidates/:id", JWTMiddleware(), DeleteCandidateHandler)
	router.PUT("/candidates/:id", JWTMiddleware(), UpdateCandidateHandler)
	router.GET("/candidates", JWTMiddleware(), GetCandidatesForUser)
	router.GET("/", JWTMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "middleware worked", "user": c.GetString("username")})
	})
	// Start the server
	fmt.Println("Server listening on port 8080...")
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	if err := router.Run(":" + port); err != nil {
		log.Panicf("error: %s", err)
	}
}
