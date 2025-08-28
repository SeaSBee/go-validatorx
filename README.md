# go-validatorx

A comprehensive Go validation library that provides flexible, extensible validation capabilities with support for struct tags, custom validation rules, and thread-safe validation contexts.

## Features

- **Struct Tag Validation**: Validate structs using `validate` tags
- **Custom Validation Rules**: Create and register custom validation rules
- **Built-in Validators**: Comprehensive set of built-in validation rules
- **Thread-Safe**: All operations are thread-safe for concurrent use
- **Validation Context**: Collect and manage validation errors and warnings
- **Global Validator**: Global validator instance for convenience
- **Middleware Support**: Validation middleware for integration

## Installation

```bash
go get github.com/seasbee/validatorx
```

## Quick Start

### Basic Usage

```go
package main

import (
    "fmt"
    "github.com/seasbee/validatorx"
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

The library provides structured error handling:

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

## Testing

Run the test suite:

```bash
go test ./...
```

Run tests with coverage:

```bash
go test -cover ./...
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.