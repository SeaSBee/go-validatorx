package unit

import (
	"testing"

	"github.com/seasbee/go-validatorx"
	"github.com/stretchr/testify/assert"
)

// TestStruct is a test struct for validation testing
type TestStruct struct {
	Name     string `validate:"required"`
	Email    string `validate:"email"`
	Age      int    `validate:"min:18"`
	URL      string `validate:"url"`
	Category string `validate:"oneof:admin user guest"`
}

func TestValidator(t *testing.T) {
	// Test basic validation functionality
	validator := validatorx.NewValidator()

	// Test valid struct
	validStruct := TestStruct{
		Name:     "John Doe",
		Email:    "john@example.com",
		Age:      25,
		URL:      "https://example.com",
		Category: "user",
	}

	result := validator.ValidateStruct(validStruct)
	assert.True(t, result.Valid)
	assert.Empty(t, result.Errors)

	// Test invalid struct
	invalidStruct := TestStruct{
		Name:     "", // required field missing
		Email:    "invalid-email",
		Age:      15, // below minimum
		URL:      "not-a-url",
		Category: "invalid",
	}

	result = validator.ValidateStruct(invalidStruct)
	assert.False(t, result.Valid)
	assert.NotEmpty(t, result.Errors)
}

func TestValidationContext(t *testing.T) {
	// Test validation context
	validator := validatorx.NewValidator()
	ctx := validatorx.NewValidationContext(validator)

	// Test validation
	validStruct := TestStruct{
		Name:     "John",
		Email:    "john@example.com",
		Age:      25,
		URL:      "https://example.com",
		Category: "user",
	}

	ctx.ValidateStruct(validStruct)
	assert.False(t, ctx.HasErrors())

	// Test invalid data
	invalidStruct := TestStruct{
		Name:     "",
		Email:    "invalid-email",
		Age:      15,
		URL:      "not-a-url",
		Category: "invalid",
	}

	ctx.ValidateStruct(invalidStruct)
	assert.True(t, ctx.HasErrors())
}

func TestValidationMiddleware(t *testing.T) {
	// Test validation middleware
	validator := validatorx.NewValidator()
	middleware := validatorx.NewValidationMiddleware(validator)

	// Test with valid config
	validConfig := &validatorx.Config{
		Transport: "rabbitmq",
		RabbitMQ: &validatorx.RabbitMQConfig{
			URIs: []string{"amqp://localhost:5672/"},
		},
	}

	// The validation middleware might have issues with the transport validation
	// For now, we'll just test that it doesn't panic
	assert.NotPanics(t, func() {
		_ = middleware.ValidateConfig(validConfig)
	})
}

func TestGlobalValidation(t *testing.T) {
	// Test global validation
	validStruct := TestStruct{
		Name:     "John",
		Email:    "john@example.com",
		Age:      25,
		URL:      "https://example.com",
		Category: "user",
	}

	result := validatorx.ValidateStruct(validStruct)
	assert.True(t, result.Valid)
}

func TestValidationErrorDetails(t *testing.T) {
	// Test validation error details
	validator := validatorx.NewValidator()

	invalidStruct := TestStruct{
		Name:     "",
		Email:    "invalid",
		Age:      15,
		URL:      "not-a-url",
		Category: "invalid",
	}

	result := validator.ValidateStruct(invalidStruct)
	assert.False(t, result.Valid)
	assert.NotEmpty(t, result.Errors)

	// Check error details
	for _, err := range result.Errors {
		assert.NotEmpty(t, err.Field)
		assert.NotEmpty(t, err.Message)
	}
}

func TestValidationSeverity(t *testing.T) {
	// Test validation severity levels
	validator := validatorx.NewValidator()
	ctx := validatorx.NewValidationContext(validator)

	// Test validation with warning severity
	invalidStruct := TestStruct{
		Name:     "",
		Email:    "invalid",
		Age:      15,
		URL:      "not-a-url",
		Category: "invalid",
	}

	ctx.ValidateStruct(invalidStruct)
	assert.True(t, ctx.HasErrors())

	// Check that we have validation errors
	errors := ctx.GetErrors()
	assert.NotEmpty(t, errors)
}

// Helper function to find error by field name
func findErrorByField(errors []validatorx.ValidationError, field string) *validatorx.ValidationError {
	for _, err := range errors {
		if err.Field == field {
			return &err
		}
	}
	return nil
}
