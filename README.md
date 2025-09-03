# go-validatorx

A comprehensive Go validation library that provides flexible, extensible validation capabilities with support for struct tags, custom validation rules, and thread-safe validation contexts.

## Features

- **Struct Tag Validation**: Validate structs using `validate` tags
- **Custom Validation Rules**: Create and register custom validation rules
- **Built-in Validators**: Comprehensive set of built-in validation rules
- **Context Support**: Context-aware validation with cancellation support
- **Validation Info**: Support for informational validation messages
- **Thread-Safe**: All operations are thread-safe for concurrent use
- **Validation Context**: Collect and manage validation errors and warnings
- **Global Validator**: Global validator instance for convenience
- **Middleware Support**: Validation middleware for integration
- **Error Code Constants**: Standardized error codes for consistent error handling

## Recent Improvements

### **New Validation Rules**
- **UUID Validation**: Support for UUID v4 and v5 format validation
- **Alpha Validation**: Alphabetic characters only validation
- **Alphanumeric Validation**: Alphanumeric characters validation
- **Numeric Validation**: Numeric characters only validation

### **Context Support**
- **Context-Aware Validation**: Support for Go context with cancellation
- **Timeout Handling**: Automatic validation cancellation on context timeout
- **Cancellation Support**: Graceful handling of context cancellation

### **Enhanced Error Handling**
- **Standardized Error Codes**: 20+ specific error codes for different validation failures
- **Consistent Error Messages**: Uniform error message format across all rules
- **Better Debugging**: Specific error codes for easier troubleshooting

### **Validation Info Support**
- **Informational Messages**: Support for non-error validation information
- **Structured Info**: Organized collection of validation information
- **Flexible Reporting**: Rich validation result reporting

## Installation

```bash
go get github.com/SeaSBee/go-validatorx
```

## Quick Start

### Basic Usage

```go
package main

import (
    "fmt"
    "github.com/SeaSBee/go-validatorx"
)

type User struct {
    Name     string `validate:"required,min:2,max:50"`
    Email    string `validate:"required,email"`
    Age      int    `validate:"min:18,max:120"`
    Password string `validate:"required,min:8"`
}

func main() {
    user := User{
        Name:     "John",
        Email:    "john@example.com",
        Age:      25,
        Password: "secret123",
    }

    validator := validatorx.NewValidator()
    result := validator.ValidateStruct(user)

    if !result.Valid {
        fmt.Println("Validation errors:")
        for _, err := range result.Errors {
            fmt.Printf("- %s: %s\n", err.Field, err.Message)
        }
    } else {
        fmt.Println("User is valid!")
    }
}
```

### Context-Aware Validation

The library supports context-aware validation for cancellation and timeout scenarios:

```go
import "context"

// Create a context with timeout
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

// Validate struct with context
result := validator.ValidateStructWithContext(ctx, user)

// Validate field with context
err := validator.ValidateFieldWithContext(ctx, "email", "test@example.com")

// Global context functions
result = validatorx.ValidateStructWithContext(ctx, user)
err = validatorx.ValidateFieldWithContext(ctx, "email", "test@example.com")
```

### Using Global Validator

```go
// Use the global validator instance
result := validatorx.ValidateStruct(user)

// Validate individual fields
err := validatorx.ValidateField("email", "invalid-email")
if err != nil {
    fmt.Println("Email validation failed:", err)
}
```

### Custom Validation Rules

```go
type CustomValidationRule struct {
    name        string
    description string
}

func (r *CustomValidationRule) Validate(value interface{}) error {
    str, ok := value.(string)
    if !ok {
        return validatorx.NewError(validatorx.ErrorCodeValidation, "validation", "value must be a string")
    }
    
    if len(str) < 5 {
        return validatorx.NewError(validatorx.ErrorCodeValidation, "validation", "string must be at least 5 characters")
    }
    
    return nil
}

func (r *CustomValidationRule) GetName() string {
    return r.name
}

func (r *CustomValidationRule) GetDescription() string {
    return r.description
}

// Register custom rule
validator := validatorx.NewValidator()
validator.RegisterRule(&CustomValidationRule{
    name:        "min_length_5",
    description: "Validates that string has minimum length of 5",
})

// Use in struct tags
type MyStruct struct {
    Field string `validate:"min_length_5"`
}
```

### Validation Context

```go
ctx := validatorx.NewValidationContext(validator)

// Add validation errors
ctx.AddError(&validatorx.ValidationError{
    Field:   "email",
    Message: "Invalid email format",
    Severity: validatorx.ValidationSeverityError,
})

// Add warnings
ctx.AddWarning(&validatorx.ValidationWarning{
    Field:   "password",
    Message: "Password might be too weak",
})

// Check for errors
if ctx.HasErrors() {
    err := ctx.ToError()
    fmt.Println("Validation failed:", err)
}
```

## Built-in Validation Rules

### Basic Rules

- `required` - Field must not be empty
- `omitempty` - Skip validation if field is empty

### String Rules

- `min:N` - Minimum length
- `max:N` - Maximum length
- `len:N` - Exact length
- `email` - Valid email format
- `url` - Valid URL format
- `regexp:pattern` - Match regular expression
- `uuid` - Valid UUID format (v4 and v5)
- `alpha` - Alphabetic characters only
- `alphanumeric` - Alphanumeric characters only
- `numeric` - Numeric characters only

### Numeric Rules

- `min:N` - Minimum value
- `max:N` - Maximum value
- `gte:N` - Greater than or equal
- `lte:N` - Less than or equal
- `gt:N` - Greater than
- `lt:N` - Less than

### Collection Rules

- `min:N` - Minimum length
- `max:N` - Maximum length
- `len:N` - Exact length

### Enumeration Rules

- `oneof:value1 value2 value3` - Must be one of the specified values

## API Reference

### Validator

```go
// Create a new validator
validator := validatorx.NewValidator()

// Register a custom rule
validator.RegisterRule(rule)

// Get a registered rule
rule, exists := validator.GetRule("rule_name")

// Validate a value with a specific rule
err := validator.Validate("rule_name", value)

// Validate a struct
result := validator.ValidateStruct(obj)
```

### ValidationResult

```go
type ValidationResult struct {
    Valid    bool
    Errors   []*ValidationError
    Warnings []*ValidationWarning
}
```

### ValidationError

```go
type ValidationError struct {
    Field       string
    Value       interface{}
    Rule        string
    Message     string
    Description string
    Severity    ValidationSeverity
}
```

### ValidationResult

```go
type ValidationResult struct {
    Valid    bool
    Errors   []*ValidationError
    Warnings []*ValidationWarning
    Info     []*ValidationInfo  // New: informational messages
}

// Add informational messages
result.AddInfo("field", "rule", "value", "message", "code")

// Check for info messages
hasInfo := result.HasInfo()

// Get all info messages
infoMessages := result.GetInfo()
```

### ValidationInfo

```go
type ValidationInfo struct {
    Field   string
    Rule    string
    Value   interface{}
    Message string
    Code    string
}

// Create validation info
info := validatorx.NewValidationInfo("field", "rule", "value", "message", "code")
```

### ValidationContext

```go
// Create a validation context
ctx := validatorx.NewValidationContext(validator)

// Add errors and warnings
ctx.AddError(error)
ctx.AddWarning(warning)

// Check status
hasErrors := ctx.HasErrors()
hasWarnings := ctx.HasWarnings()

// Get all errors and warnings
errors := ctx.GetErrors()
warnings := ctx.GetWarnings()

// Clear all errors and warnings
ctx.Clear()

// Convert to error
err := ctx.ToError()
```

### ValidationMiddleware

```go
// Create middleware
middleware := validatorx.NewValidationMiddleware(validator)

// Validate configuration
err := middleware.ValidateConfig(config)

// Validate message
err := middleware.ValidateMessage(message)

// Validate delivery
err := middleware.ValidateDelivery(delivery)
```

## Thread Safety

All validator operations are thread-safe and can be used concurrently:

```go
var wg sync.WaitGroup
validator := validatorx.NewValidator()

for i := 0; i < 10; i++ {
    wg.Add(1)
    go func(id int) {
        defer wg.Done()
        result := validator.ValidateStruct(user)
        // Safe to use concurrently
    }(i)
}

wg.Wait()
```

## Error Handling

The library provides structured error handling with standardized error codes:

```go
// Create custom errors
err := validatorx.NewError("CODE", "domain", "message")
err := validatorx.NewErrorf("CODE", "domain", "format %s", "args")

// Error structure
type Error struct {
    Code    string
    Domain  string
    Message string
}
```

### Standard Error Codes

The library provides consistent error codes for all validation rules:

```go
// Core validation errors
validatorx.ErrorCodeValidation     // General validation error
validatorx.ErrorCodeRequired       // Required field missing
validatorx.ErrorCodeContext        // Context cancellation/timeout

// String validation errors
validatorx.ErrorCodeEmail          // Invalid email format
validatorx.ErrorCodeURL            // Invalid URL format
validatorx.ErrorCodeUUID           // Invalid UUID format
validatorx.ErrorCodeAlpha          // Invalid alpha characters
validatorx.ErrorCodeAlphanumeric  // Invalid alphanumeric characters
validatorx.ErrorCodeNumeric        // Invalid numeric characters
validatorx.ErrorCodeRegex          // Regex pattern mismatch

// Numeric validation errors
validatorx.ErrorCodeMin            // Value below minimum
validatorx.ErrorCodeMax            // Value above maximum
validatorx.ErrorCodeLen            // Length mismatch
validatorx.ErrorCodeGTE            // Value not greater than or equal
validatorx.ErrorCodeLTE            // Value not less than or equal
validatorx.ErrorCodeGT             // Value not greater than
validatorx.ErrorCodeLT             // Value not less than

// Other validation errors
validatorx.ErrorCodeOneOf          // Value not in allowed set
validatorx.ErrorCodeOmitEmpty      // Empty value not allowed
```

## Testing

Run the test suite:

```bash
go test ./...
```

Run tests with coverage:

```bash
go test -cover ./...
```

### Comprehensive Test Coverage

The library includes extensive test coverage for all functionality:

#### **Test Suites (67+ Test Cases)**

- **Core Validation Tests**: Basic validation functionality and edge cases
- **New Validation Rules**: UUID, Alpha, Alphanumeric, and Numeric validation
- **Context Support**: Context-aware validation with cancellation testing
- **Validation Info**: Information message handling and management
- **Error Code Constants**: All 20+ error code constants validation
- **Thread Safety**: Concurrent access and race condition testing
- **Struct Tag Parsing**: Complex validation tag scenarios
- **Built-in Rules**: All validation rules (required, min, max, email, URL, etc.)
- **Comparison Rules**: GTE, LTE, GT, LT validation
- **Middleware Framework**: Validation middleware functionality
- **Global Validator**: Global validator instance management
- **Validation Context**: Error and warning collection
- **Edge Cases**: Nil values, empty strings, invalid types
- **Message Validation**: Complex message structure validation
- **Configuration Validation**: Publisher/consumer config validation

#### **Test Categories**

- **Unit Tests**: Individual function and method testing
- **Integration Tests**: End-to-end validation scenarios
- **Concurrency Tests**: Thread safety and race condition testing
- **Error Handling Tests**: Error conditions and edge cases
- **API Contract Tests**: Method signatures and return values
- **Performance Tests**: Validation performance under load

#### **Test Results**

All tests pass consistently with comprehensive coverage of:
- ✅ **67+ test cases** across multiple test suites
- ✅ **100% functionality coverage** for new features
- ✅ **Thread safety validation** for concurrent operations
- ✅ **Error handling validation** for all error conditions
- ✅ **Edge case coverage** for robust validation
- ✅ **API consistency** across all validation methods

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.