package jwt

import (
	"sso/sso/internal/domain/models"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestNewToken(t *testing.T) {
	// Arrange
	user := models.User{
		ID:    1,
		Email: "user@example.com",
	}
	app := models.App{
		ID:     2,
		Secret: "secret",
	}
	duration := time.Hour

	// Act
	tokenString, err := NewToken(user, app, duration)
	if err != nil {
		t.Errorf("Error creating token: %v", err)
		return
	}

	// Assert
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(app.Secret), nil
	})
	if err != nil {
		t.Errorf("Error parsing token: %v", err)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Error("Invalid claims type")
		return
	}

	if claims["uid"] != float64(user.ID) {
		t.Errorf("Incorrect uid claim. Expected: %d, Got: %v", user.ID, claims["uid"])
	}
	if claims["email"] != user.Email {
		t.Errorf("Incorrect email claim. Expected: %s, Got: %v", user.Email, claims["email"])
	}
	if claims["app_id"] != float64(app.ID) {
		t.Errorf("Incorrect app_id claim. Expected: %d, Got: %v", app.ID, claims["app_id"])
	}
}

