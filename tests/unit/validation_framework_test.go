package unit

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/SeaSBee/go-validatorx"
	"github.com/stretchr/testify/assert"
)

// TestValidationRuleInterface tests the ValidationRule interface
func TestValidationRuleInterface(t *testing.T) {
	t.Run("CustomValidationRule", func(t *testing.T) {
		// Create a custom validation rule
		customRule := &CustomValidationRule{
			name:        "custom_rule",
			description: "A custom validation rule for testing",
		}

		// Verify interface compliance
		var _ validatorx.ValidationRule = customRule

		// Test rule properties
		assert.Equal(t, "custom_rule", customRule.GetName())
		assert.Equal(t, "A custom validation rule for testing", customRule.GetDescription())

		// Test validation
		err := customRule.Validate("valid_value")
		assert.NoError(t, err)

		err = customRule.Validate("invalid_value")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid value")
	})

	t.Run("NilValidationRule", func(t *testing.T) {
		validator := validatorx.NewValidator()

		// Test registering nil rule
		validator.RegisterRule(nil)

		// Should not panic and should ignore nil rule
		rule, exists := validator.GetRule("nil_rule")
		assert.False(t, exists)
		assert.Nil(t, rule)
	})
}

// CustomValidationRule implements ValidationRule for testing
type CustomValidationRule struct {
	name        string
	description string
}

func (r *CustomValidationRule) Validate(value interface{}) error {
	if value == "invalid_value" {
		return validatorx.NewError(validatorx.ErrorCodeValidation, "validation", "invalid value")
	}
	return nil
}

func (r *CustomValidationRule) GetName() string {
	return r.name
}

func (r *CustomValidationRule) GetDescription() string {
	return r.description
}

// TestValidatorCore tests the core Validator functionality
func TestValidatorCore(t *testing.T) {
	t.Run("NewValidator", func(t *testing.T) {
		validator := validatorx.NewValidator()
		assert.NotNil(t, validator)
	})

	t.Run("RegisterAndGetRule", func(t *testing.T) {
		validator := validatorx.NewValidator()
		customRule := &CustomValidationRule{name: "test_rule", description: "test"}

		validator.RegisterRule(customRule)

		rule, exists := validator.GetRule("test_rule")
		assert.True(t, exists)
		assert.Equal(t, customRule, rule)
	})

	t.Run("GetRuleEmptyName", func(t *testing.T) {
		validator := validatorx.NewValidator()
		rule, exists := validator.GetRule("")
		assert.False(t, exists)
		assert.Nil(t, rule)
	})

	t.Run("ValidateUnknownRule", func(t *testing.T) {
		validator := validatorx.NewValidator()
		err := validator.Validate("unknown_rule", "value")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown validation rule")
	})

	t.Run("ValidateEmptyRuleName", func(t *testing.T) {
		validator := validatorx.NewValidator()
		err := validator.Validate("", "value")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation rule name cannot be empty")
	})
}

// TestValidationResult tests the ValidationResult structure
func TestValidationResult(t *testing.T) {
	t.Run("ValidationResultCreation", func(t *testing.T) {
		result := &validatorx.ValidationResult{
			Valid:    true,
			Errors:   []*validatorx.ValidationError{},
			Warnings: []*validatorx.ValidationWarning{},
		}

		assert.True(t, result.Valid)
		assert.Empty(t, result.Errors)
		assert.Empty(t, result.Warnings)
	})

	t.Run("ValidationResultWithErrors", func(t *testing.T) {
		error1 := &validatorx.ValidationError{
			Field:       "field1",
			Value:       "invalid_value",
			Rule:        "required",
			Message:     "field is required",
			Description: "Field must not be empty",
			Severity:    validatorx.ValidationSeverityError,
		}

		result := &validatorx.ValidationResult{
			Valid:    false,
			Errors:   []*validatorx.ValidationError{error1},
			Warnings: []*validatorx.ValidationWarning{},
		}

		assert.False(t, result.Valid)
		assert.Len(t, result.Errors, 1)
		assert.Equal(t, "field1", result.Errors[0].Field)
		assert.Equal(t, "required", result.Errors[0].Rule)
		assert.Equal(t, validatorx.ValidationSeverityError, result.Errors[0].Severity)
	})
}

// TestValidationError tests the ValidationError structure
func TestValidationError(t *testing.T) {
	t.Run("ValidationErrorCreation", func(t *testing.T) {
		err := &validatorx.ValidationError{
			Field:       "test_field",
			Value:       "invalid_value",
			Rule:        "required",
			Message:     "field is required",
			Description: "Field must not be empty",
			Severity:    validatorx.ValidationSeverityError,
		}

		assert.Equal(t, "test_field", err.Field)
		assert.Equal(t, "invalid_value", err.Value)
		assert.Equal(t, "required", err.Rule)
		assert.Equal(t, "field is required", err.Message)
		assert.Equal(t, "Field must not be empty", err.Description)
		assert.Equal(t, validatorx.ValidationSeverityError, err.Severity)
	})

	t.Run("ValidationSeverityValues", func(t *testing.T) {
		assert.Equal(t, validatorx.ValidationSeverity("error"), validatorx.ValidationSeverityError)
		assert.Equal(t, validatorx.ValidationSeverity("warning"), validatorx.ValidationSeverityWarning)
		assert.Equal(t, validatorx.ValidationSeverity("info"), validatorx.ValidationSeverityInfo)
	})
}

// TestValidationWarning tests the ValidationWarning structure
func TestValidationWarning(t *testing.T) {
	t.Run("ValidationWarningCreation", func(t *testing.T) {
		warning := &validatorx.ValidationWarning{
			Field:       "test_field",
			Value:       "suspicious_value",
			Rule:        "custom",
			Message:     "suspicious value detected",
			Description: "Value might cause issues",
		}

		assert.Equal(t, "test_field", warning.Field)
		assert.Equal(t, "suspicious_value", warning.Value)
		assert.Equal(t, "custom", warning.Rule)
		assert.Equal(t, "suspicious value detected", warning.Message)
		assert.Equal(t, "Value might cause issues", warning.Description)
	})
}

// TestValidationContextFramework tests the ValidationContext functionality
func TestValidationContextFramework(t *testing.T) {
	t.Run("NewValidationContext", func(t *testing.T) {
		validator := validatorx.NewValidator()
		ctx := validatorx.NewValidationContext(validator)
		assert.NotNil(t, ctx)
		assert.False(t, ctx.HasErrors())
		assert.False(t, ctx.HasWarnings())
	})

	t.Run("NewValidationContextWithNilValidator", func(t *testing.T) {
		ctx := validatorx.NewValidationContext(nil)
		assert.NotNil(t, ctx)
		assert.False(t, ctx.HasErrors())
		assert.False(t, ctx.HasWarnings())
	})

	t.Run("ValidationContextAddError", func(t *testing.T) {
		ctx := validatorx.NewValidationContext(nil)

		error1 := &validatorx.ValidationError{
			Field:    "field1",
			Value:    "invalid",
			Rule:     "required",
			Message:  "field is required",
			Severity: validatorx.ValidationSeverityError,
		}

		ctx.AddError(error1)
		assert.True(t, ctx.HasErrors())
		assert.Len(t, ctx.GetErrors(), 1)
		assert.Equal(t, "field1", ctx.GetErrors()[0].Field)
	})

	t.Run("ValidationContextAddWarning", func(t *testing.T) {
		ctx := validatorx.NewValidationContext(nil)

		warning1 := &validatorx.ValidationWarning{
			Field:   "field1",
			Value:   "suspicious",
			Rule:    "custom",
			Message: "suspicious value",
		}

		ctx.AddWarning(warning1)
		assert.True(t, ctx.HasWarnings())
		assert.Len(t, ctx.GetWarnings(), 1)
		assert.Equal(t, "field1", ctx.GetWarnings()[0].Field)
	})

	t.Run("ValidationContextClear", func(t *testing.T) {
		ctx := validatorx.NewValidationContext(nil)

		// Add some errors and warnings
		ctx.AddError(&validatorx.ValidationError{Field: "field1", Message: "error"})
		ctx.AddWarning(&validatorx.ValidationWarning{Field: "field1", Message: "warning"})

		assert.True(t, ctx.HasErrors())
		assert.True(t, ctx.HasWarnings())

		ctx.Clear()
		assert.False(t, ctx.HasErrors())
		assert.False(t, ctx.HasWarnings())
		assert.Empty(t, ctx.GetErrors())
		assert.Empty(t, ctx.GetWarnings())
	})

	t.Run("ValidationContextToError", func(t *testing.T) {
		ctx := validatorx.NewValidationContext(nil)

		// No errors
		err := ctx.ToError()
		assert.NoError(t, err)

		// Single error
		ctx.AddError(&validatorx.ValidationError{Field: "field1", Message: "error1"})
		err = ctx.ToError()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error1")

		// Multiple errors
		ctx.AddError(&validatorx.ValidationError{Field: "field2", Message: "error2"})
		err = ctx.ToError()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error1")
		assert.Contains(t, err.Error(), "error2")
		assert.Contains(t, err.Error(), "field1: error1")
		assert.Contains(t, err.Error(), "field2: error2")
	})

	t.Run("ValidationContextNilHandling", func(t *testing.T) {
		var ctx *validatorx.ValidationContext

		// All methods should handle nil gracefully
		ctx.Validate("rule", "value", "field")
		ctx.ValidateStruct("struct")
		ctx.AddError(&validatorx.ValidationError{})
		ctx.AddWarning(&validatorx.ValidationWarning{})
		ctx.Clear()

		assert.False(t, ctx.HasErrors())
		assert.False(t, ctx.HasWarnings())
		assert.Empty(t, ctx.GetErrors())
		assert.Empty(t, ctx.GetWarnings())
		assert.NoError(t, ctx.ToError())
	})
}

// TestValidationContextThreadSafety tests concurrent access to ValidationContext
func TestValidationContextThreadSafety(t *testing.T) {
	t.Run("ConcurrentValidationContextAccess", func(t *testing.T) {
		ctx := validatorx.NewValidationContext(nil)
		var wg sync.WaitGroup
		const numGoroutines = 10

		// Test concurrent error addition
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				ctx.AddError(&validatorx.ValidationError{
					Field:   fmt.Sprintf("field_%d", id),
					Message: fmt.Sprintf("error_%d", id),
				})
			}(i)
		}

		wg.Wait()
		assert.True(t, ctx.HasErrors())
		assert.Len(t, ctx.GetErrors(), numGoroutines)

		// Test concurrent warning addition
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				ctx.AddWarning(&validatorx.ValidationWarning{
					Field:   fmt.Sprintf("field_%d", id),
					Message: fmt.Sprintf("warning_%d", id),
				})
			}(i)
		}

		wg.Wait()
		assert.True(t, ctx.HasWarnings())
		assert.Len(t, ctx.GetWarnings(), numGoroutines)
	})
}

// TestGlobalValidationFramework tests the global validation functions
func TestGlobalValidationFramework(t *testing.T) {
	t.Run("SetGlobalValidator", func(t *testing.T) {
		customValidator := validatorx.NewValidator()
		customRule := &CustomValidationRule{name: "global_rule", description: "global"}
		customValidator.RegisterRule(customRule)

		validatorx.SetGlobalValidator(customValidator)

		// Test that global validator is used
		err := validatorx.ValidateField("global_rule", "invalid_value")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid value")
	})

	t.Run("SetGlobalValidatorNil", func(t *testing.T) {
		// Should not panic when setting nil validator
		assert.NotPanics(t, func() {
			validatorx.SetGlobalValidator(nil)
		})
	})

	t.Run("ValidateField", func(t *testing.T) {
		// Test with unknown rule
		err := validatorx.ValidateField("unknown_rule", "value")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown validation rule")
	})
}

// TestValidationMiddlewareFramework tests the ValidationMiddleware functionality
func TestValidationMiddlewareFramework(t *testing.T) {
	t.Run("NewValidationMiddleware", func(t *testing.T) {
		validator := validatorx.NewValidator()
		middleware := validatorx.NewValidationMiddleware(validator)
		assert.NotNil(t, middleware)
	})

	t.Run("NewValidationMiddlewareWithNilValidator", func(t *testing.T) {
		middleware := validatorx.NewValidationMiddleware(nil)
		assert.NotNil(t, middleware)
	})

	t.Run("ValidateConfig", func(t *testing.T) {
		middleware := validatorx.NewValidationMiddleware(nil)

		// Test with nil config
		err := middleware.ValidateConfig(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "config cannot be nil")

		// Test with valid config
		validConfig := &validatorx.Config{
			Transport: "rabbitmq",
			RabbitMQ: &validatorx.RabbitMQConfig{
				URIs: []string{"amqp://localhost:5672/"},
			},
		}
		err = middleware.ValidateConfig(validConfig)
		assert.NoError(t, err) // Should not error for valid config
	})

	t.Run("ValidateMessage", func(t *testing.T) {
		middleware := validatorx.NewValidationMiddleware(nil)

		// Test with nil message
		err := middleware.ValidateMessage(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "message cannot be nil")

		// Test with valid message
		validMessage := &validatorx.Message{
			ID:          "test-id",
			Key:         "test-key",
			Body:        []byte("test"),
			ContentType: "application/json",
			Timestamp:   time.Now(),
		}
		err = middleware.ValidateMessage(validMessage)
		assert.NoError(t, err) // Should not error for valid message
	})

	t.Run("ValidateDelivery", func(t *testing.T) {
		middleware := validatorx.NewValidationMiddleware(nil)

		// Test with nil delivery
		err := middleware.ValidateDelivery(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "delivery cannot be nil")

		// Test with valid delivery
		validDelivery := &validatorx.Delivery{
			Message: validatorx.Message{
				ID:          "test-id",
				Key:         "test-key",
				Body:        []byte("test"),
				ContentType: "application/json",
				Timestamp:   time.Now(),
			},
			Queue:       "test-queue",
			DeliveryTag: 123,
		}
		err = middleware.ValidateDelivery(validDelivery)
		assert.NoError(t, err) // Should not error for valid delivery
	})

	t.Run("ValidationMiddlewareNilHandling", func(t *testing.T) {
		var middleware *validatorx.ValidationMiddleware

		// All methods should handle nil gracefully
		err := middleware.ValidateConfig(&validatorx.Config{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation middleware is nil")

		err = middleware.ValidateMessage(&validatorx.Message{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation middleware is nil")

		err = middleware.ValidateDelivery(&validatorx.Delivery{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation middleware is nil")
	})
}

// TestStructTagParsing tests the struct tag parsing functionality
func TestStructTagParsing(t *testing.T) {
	t.Run("SimpleValidationTags", func(t *testing.T) {
		type SimpleStruct struct {
			Field1 string `validate:"required"`
			Field2 int    `validate:"min:10"`
			Field3 string `validate:"email"`
		}

		validator := validatorx.NewValidator()

		// Valid struct
		valid := SimpleStruct{
			Field1: "value",
			Field2: 15,
			Field3: "test@example.com",
		}
		result := validator.ValidateStruct(valid)
		assert.True(t, result.Valid)

		// Invalid struct
		invalid := SimpleStruct{
			Field1: "",
			Field2: 5,
			Field3: "invalid-email",
		}
		result = validator.ValidateStruct(invalid)
		assert.False(t, result.Valid)
		assert.Len(t, result.Errors, 3)
	})

	t.Run("MultipleValidationTags", func(t *testing.T) {
		type MultiTagStruct struct {
			Field1 string `validate:"required,min:3,max:10"`
			Field2 int    `validate:"min:10,max:100"`
		}

		validator := validatorx.NewValidator()

		// Valid struct
		valid := MultiTagStruct{
			Field1: "valid",
			Field2: 50,
		}
		result := validator.ValidateStruct(valid)
		assert.True(t, result.Valid)

		// Invalid struct - too short
		invalid1 := MultiTagStruct{
			Field1: "ab", // too short
			Field2: 50,
		}
		result = validator.ValidateStruct(invalid1)
		assert.False(t, result.Valid)

		// Invalid struct - too long
		invalid2 := MultiTagStruct{
			Field1: "toolongvalue", // too long
			Field2: 50,
		}
		result = validator.ValidateStruct(invalid2)
		assert.False(t, result.Valid)
	})

	t.Run("EmptyValidationTags", func(t *testing.T) {
		type EmptyTagStruct struct {
			Field1 string `validate:""`
			Field2 string `validate:"   "`
			Field3 string `validate:","`
		}

		validator := validatorx.NewValidator()
		valid := EmptyTagStruct{
			Field1: "value1",
			Field2: "value2",
			Field3: "value3",
		}
		result := validator.ValidateStruct(valid)
		assert.True(t, result.Valid)
	})

	t.Run("NilStructHandling", func(t *testing.T) {
		validator := validatorx.NewValidator()

		// Test with nil
		result := validator.ValidateStruct(nil)
		assert.False(t, result.Valid)
		assert.Len(t, result.Errors, 1)
		assert.Contains(t, result.Errors[0].Message, "cannot be nil")

		// Test with nil pointer
		var ptr *struct{}
		result = validator.ValidateStruct(ptr)
		assert.False(t, result.Valid)
		assert.Len(t, result.Errors, 1)
		assert.Contains(t, result.Errors[0].Message, "cannot be nil pointer")
	})

	t.Run("NonStructHandling", func(t *testing.T) {
		validator := validatorx.NewValidator()

		// Test with string
		result := validator.ValidateStruct("not a struct")
		assert.False(t, result.Valid)
		assert.Len(t, result.Errors, 1)
		assert.Contains(t, result.Errors[0].Message, "must be a struct")

		// Test with int
		result = validator.ValidateStruct(123)
		assert.False(t, result.Valid)
		assert.Len(t, result.Errors, 1)
		assert.Contains(t, result.Errors[0].Message, "must be a struct")
	})
}
