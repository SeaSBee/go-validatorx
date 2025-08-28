// Package messaging provides transport-agnostic interfaces for messaging systems.
package validatorx

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Error codes for validation
const (
	ErrorCodeValidation = "VALIDATION_ERROR"
)

// Error represents a validation error
type Error struct {
	Code    string
	Domain  string
	Message string
}

// Error returns the error message
func (e *Error) Error() string {
	return e.Message
}

// NewError creates a new error
func NewError(code, domain, message string) error {
	return &Error{
		Code:    code,
		Domain:  domain,
		Message: message,
	}
}

// NewErrorf creates a new formatted error
func NewErrorf(code, domain, format string, args ...interface{}) error {
	return &Error{
		Code:    code,
		Domain:  domain,
		Message: fmt.Sprintf(format, args...),
	}
}

// Config represents configuration for messaging
type Config struct {
	Transport string          `validate:"required,oneof:rabbitmq kafka redis"`
	RabbitMQ  *RabbitMQConfig `validate:"omitempty"`
	Kafka     *KafkaConfig    `validate:"omitempty"`
	Redis     *RedisConfig    `validate:"omitempty"`
}

// RabbitMQConfig represents RabbitMQ configuration
type RabbitMQConfig struct {
	URIs []string `validate:"required,min:1"`
}

// KafkaConfig represents Kafka configuration
type KafkaConfig struct {
	Brokers []string `validate:"required,min:1"`
}

// RedisConfig represents Redis configuration
type RedisConfig struct {
	Addresses []string `validate:"required,min:1"`
}

// Message constants
const (
	MaxMessageIDLength      = 255
	MaxMessageSize          = 1024 * 1024 // 1MB
	MaxRoutingKeyLength     = 255
	MaxIdempotencyKeyLength = 255
	MaxHeaderKeyLength      = 255
	MaxHeaderValueLength    = 1024
	MaxHeaderSize           = 1024
	MaxPriority             = uint8(255)
	MaxCorrelationIDLength  = 255
	MaxReplyToLength        = 255
	MaxTimeout              = 24 * time.Hour
	MaxInFlightMessages     = 1000
	MaxPrefetchCount        = 1000
)

// SupportedContentTypes returns the list of supported content types
func SupportedContentTypes() []string {
	return []string{
		"application/json",
		"application/xml",
		"text/plain",
	}
}

// Message represents a message
type Message struct {
	ID             string            `validate:"required,max:255,regexp:^[a-zA-Z0-9_-]+$"`
	Key            string            `validate:"required,max:255,regexp:^[a-zA-Z0-9._-]+$"`
	Body           []byte            `validate:"required,min:1,max:1048576"`
	ContentType    string            `validate:"required,oneof:application/json application/xml text/plain"`
	Timestamp      time.Time         `validate:"omitempty"`
	Headers        map[string]string `validate:"omitempty"`
	Priority       uint8             `validate:"omitempty,max:255"`
	IdempotencyKey string            `validate:"omitempty,max:255,regexp:^[a-zA-Z0-9_-]*$"`
	CorrelationID  string            `validate:"omitempty,max:255,regexp:^[a-zA-Z0-9_-]*$"`
	ReplyTo        string            `validate:"omitempty,max:255,regexp:^[a-zA-Z0-9._-]*$"`
	Expiration     time.Duration     `validate:"omitempty,min:0,max:86400000000000"`
}

// Delivery represents a message delivery
type Delivery struct {
	Message     Message           `validate:"required"`
	Queue       string            `validate:"required"`
	DeliveryTag uint64            `validate:"required"`
	Headers     map[string]string `validate:"omitempty"`
}

// PublisherConfig represents publisher configuration
type PublisherConfig struct {
	MaxInFlight    int           `validate:"required,min:1,max:1000"`
	WorkerCount    int           `validate:"required,min:1,max:100"`
	PublishTimeout time.Duration `validate:"required,min:1000000000,max:300000000000"` // 1s to 5m
}

// ConsumerConfig represents consumer configuration
type ConsumerConfig struct {
	Queue                 string        `validate:"required,min:1,max:255"`
	Prefetch              int           `validate:"required,min:1,max:1000"`
	MaxConcurrentHandlers int           `validate:"required,min:1,max:1000"`
	HandlerTimeout        time.Duration `validate:"required,min:1000000000,max:300000000000"` // 1s to 5m
}

// Regex cache for validation patterns to avoid repeated compilation
var (
	regexCache      = make(map[string]*regexp.Regexp)
	regexCacheMutex sync.RWMutex
)

// getCachedRegex returns a cached regex pattern or compiles and caches a new one
func getCachedRegex(pattern string) (*regexp.Regexp, error) {
	// Check cache first
	regexCacheMutex.RLock()
	if regex, exists := regexCache[pattern]; exists {
		regexCacheMutex.RUnlock()
		return regex, nil
	}
	regexCacheMutex.RUnlock()

	// Compile and cache
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	regexCacheMutex.Lock()
	regexCache[pattern] = regex
	regexCacheMutex.Unlock()

	return regex, nil
}

// ValidationRule represents a validation rule.
type ValidationRule interface {
	Validate(value interface{}) error
	GetName() string
	GetDescription() string
}

// ValidationResult represents the result of a validation.
type ValidationResult struct {
	Valid    bool
	Errors   []*ValidationError
	Warnings []*ValidationWarning
}

// ValidationError represents a validation error.
type ValidationError struct {
	Field       string
	Value       interface{}
	Rule        string
	Message     string
	Description string
	Severity    ValidationSeverity
}

// ValidationWarning represents a validation warning.
type ValidationWarning struct {
	Field       string
	Value       interface{}
	Rule        string
	Message     string
	Description string
}

// ValidationSeverity represents the severity of a validation error.
type ValidationSeverity string

const (
	// ValidationSeverityError represents an error severity
	ValidationSeverityError ValidationSeverity = "error"
	// ValidationSeverityWarning represents a warning severity
	ValidationSeverityWarning ValidationSeverity = "warning"
	// ValidationSeverityInfo represents an info severity
	ValidationSeverityInfo ValidationSeverity = "info"
)

// Validator provides validation functionality.
type Validator struct {
	rules map[string]ValidationRule
	mu    sync.RWMutex
}

// NewValidator creates a new validator.
func NewValidator() *Validator {
	validator := &Validator{
		rules: make(map[string]ValidationRule),
	}
	validator.registerDefaultRules()
	return validator
}

// RegisterRule registers a validation rule.
func (v *Validator) RegisterRule(rule ValidationRule) {
	if rule == nil {
		return // Ignore nil rules
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.rules[rule.GetName()] = rule
}

// GetRule retrieves a validation rule.
func (v *Validator) GetRule(name string) (ValidationRule, bool) {
	if name == "" {
		return nil, false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	rule, exists := v.rules[name]
	return rule, exists
}

// Validate validates a value using a specific rule.
func (v *Validator) Validate(ruleName string, value interface{}) error {
	if ruleName == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "validation rule name cannot be empty")
	}

	// Parse rule name and parameters
	baseRuleName, params := v.parseRuleName(ruleName)

	// Try to get the rule
	rule, exists := v.GetRule(baseRuleName)
	if !exists {
		return NewErrorf(ErrorCodeValidation, "validation", "unknown validation rule: %s", baseRuleName)
	}

	if rule == nil {
		return NewErrorf(ErrorCodeValidation, "validation", "validation rule is nil: %s", baseRuleName)
	}

	// For parameterized rules, we need to handle them specially
	if params != "" {
		return v.validateWithParams(baseRuleName, params, value)
	}

	// For rules that expect parameters but got none, return an error
	if baseRuleName == "min" || baseRuleName == "max" || baseRuleName == "len" ||
		baseRuleName == "regexp" || baseRuleName == "oneof" || baseRuleName == "gte" ||
		baseRuleName == "lte" || baseRuleName == "gt" || baseRuleName == "lt" {
		return NewErrorf(ErrorCodeValidation, "validation", "%s parameter cannot be empty", baseRuleName)
	}

	return rule.Validate(value)
}

// parseRuleName parses a rule name and returns the base rule name and parameters.
func (v *Validator) parseRuleName(ruleName string) (string, string) {
	if idx := strings.Index(ruleName, ":"); idx != -1 {
		return ruleName[:idx], ruleName[idx+1:]
	}
	return ruleName, ""
}

// validateWithParams validates a value using a parameterized rule.
func (v *Validator) validateWithParams(ruleName, params string, value interface{}) error {
	// Use a default field name for direct validation calls
	fieldName := "value"

	switch ruleName {
	case "min":
		return v.validateMin(value, params, fieldName)
	case "max":
		return v.validateMax(value, params, fieldName)
	case "len":
		return v.validateLen(value, params, fieldName)
	case "regexp":
		return v.validateRegexp(value, params, fieldName)
	case "oneof":
		return v.validateOneOf(value, params, fieldName)
	case "gte":
		return v.validateGTE(value, params, fieldName)
	case "lte":
		return v.validateLTE(value, params, fieldName)
	case "gt":
		return v.validateGT(value, params, fieldName)
	case "lt":
		return v.validateLT(value, params, fieldName)
	default:
		return NewErrorf(ErrorCodeValidation, "validation", "unknown parameterized validation rule: %s", ruleName)
	}
}

// ValidateStruct validates a struct using validation tags.
func (v *Validator) ValidateStruct(obj interface{}) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   make([]*ValidationError, 0),
		Warnings: make([]*ValidationWarning, 0),
	}

	// Check for nil input
	if obj == nil {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:    "root",
			Value:    nil,
			Rule:     "struct",
			Message:  "value cannot be nil",
			Severity: ValidationSeverityError,
		})
		return result
	}

	val := reflect.ValueOf(obj)
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Field:    "root",
				Value:    obj,
				Rule:     "struct",
				Message:  "value cannot be nil pointer",
				Severity: ValidationSeverityError,
			})
			return result
		}
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:    "root",
			Value:    obj,
			Rule:     "struct",
			Message:  "value must be a struct",
			Severity: ValidationSeverityError,
		})
		return result
	}

	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		// Get validation tags
		validationTag := fieldType.Tag.Get("validate")
		if validationTag == "" {
			continue
		}

		// Parse validation rules
		rules := strings.Split(validationTag, ",")

		// Check if field has omitempty rule and is empty
		hasOmitEmpty := false
		isEmpty := false
		for _, ruleStr := range rules {
			ruleStr = strings.TrimSpace(ruleStr)
			if ruleStr == "omitempty" {
				hasOmitEmpty = true
				break
			}
		}

		if hasOmitEmpty {
			// Check if field is empty
			val := reflect.ValueOf(field.Interface())
			switch val.Kind() {
			case reflect.String:
				isEmpty = val.String() == ""
			case reflect.Slice, reflect.Array, reflect.Map:
				isEmpty = val.Len() == 0
			case reflect.Ptr, reflect.Interface:
				isEmpty = val.IsNil()
			}
		}

		// If field has omitempty and is empty, skip all validation except omitempty itself
		// But if omitempty is the only rule, apply it as a validation rule
		if hasOmitEmpty && isEmpty {
			// Check if omitempty is the only rule
			onlyOmitEmpty := len(rules) == 1 && strings.TrimSpace(rules[0]) == "omitempty"
			if onlyOmitEmpty {
				// For nil values, always skip validation (even with omitempty)
				if field.IsNil() {
					continue
				}
				// Apply omitempty as a validation rule for non-nil empty values
				if err := v.applyRule("omitempty", "", field.Interface(), fieldType.Name, result); err != nil {
					result.Valid = false
					result.Errors = append(result.Errors, &ValidationError{
						Field:    fieldType.Name,
						Value:    field.Interface(),
						Rule:     "omitempty",
						Message:  err.Error(),
						Severity: ValidationSeverityError,
					})
				}
			}
			continue
		}

		for _, ruleStr := range rules {
			ruleStr = strings.TrimSpace(ruleStr)
			if ruleStr == "" {
				continue
			}

			// Parse rule and parameters - support both : and = separators
			var ruleName, ruleParams string
			if strings.Contains(ruleStr, ":") {
				ruleParts := strings.SplitN(ruleStr, ":", 2)
				ruleName = ruleParts[0]
				if len(ruleParts) > 1 {
					ruleParams = ruleParts[1]
				}
			} else if strings.Contains(ruleStr, "=") {
				ruleParts := strings.SplitN(ruleStr, "=", 2)
				ruleName = ruleParts[0]
				if len(ruleParts) > 1 {
					ruleParams = ruleParts[1]
				}
			} else {
				ruleName = ruleStr
			}

			// Apply validation rule
			if err := v.applyRule(ruleName, ruleParams, field.Interface(), fieldType.Name, result); err != nil {
				result.Valid = false
				result.Errors = append(result.Errors, &ValidationError{
					Field:    fieldType.Name,
					Value:    field.Interface(),
					Rule:     ruleName,
					Message:  err.Error(),
					Severity: ValidationSeverityError,
				})
			}
		}
	}

	return result
}

// applyRule applies a validation rule to a value.
func (v *Validator) applyRule(ruleName, params string, value interface{}, fieldName string, result *ValidationResult) error {
	if ruleName == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "rule name cannot be empty")
	}

	switch ruleName {
	case "required":
		return v.validateRequired(value, fieldName)
	case "omitempty":
		return v.validateOmitEmpty(value, fieldName)
	case "min":
		return v.validateMin(value, params, fieldName)
	case "max":
		return v.validateMax(value, params, fieldName)
	case "len":
		return v.validateLen(value, params, fieldName)
	case "email":
		return v.validateEmail(value, fieldName)
	case "url":
		return v.validateURL(value, fieldName)
	case "regexp":
		return v.validateRegexp(value, params, fieldName)
	case "oneof":
		return v.validateOneOf(value, params, fieldName)
	case "gte":
		return v.validateGTE(value, params, fieldName)
	case "lte":
		return v.validateLTE(value, params, fieldName)
	case "gt":
		return v.validateGT(value, params, fieldName)
	case "lt":
		return v.validateLT(value, params, fieldName)
	default:
		// Check if custom rule exists before calling it
		if _, exists := v.GetRule(ruleName); !exists {
			return NewErrorf(ErrorCodeValidation, "validation", "unknown validation rule: %s", ruleName)
		}
		return v.Validate(ruleName, value)
	}
}

// validateRequired validates that a value is not empty.
func (v *Validator) validateRequired(value interface{}, fieldName string) error {
	if fieldName == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "field name cannot be empty")
	}

	if value == nil {
		return NewErrorf(ErrorCodeValidation, "validation", "field '%s' is required", fieldName)
	}

	val := reflect.ValueOf(value)
	switch val.Kind() {
	case reflect.String:
		if strings.TrimSpace(val.String()) == "" {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' is required", fieldName)
		}
	case reflect.Slice, reflect.Array, reflect.Map:
		if val.Len() == 0 {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' is required", fieldName)
		}
	case reflect.Ptr, reflect.Interface:
		if val.IsNil() {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' is required", fieldName)
		}
	}

	return nil
}

// validateOmitEmpty validates that a value is not empty, but only if it's a struct or map.
func (v *Validator) validateOmitEmpty(value interface{}, fieldName string) error {
	if fieldName == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "field name cannot be empty")
	}

	if value == nil {
		return nil // Skip if nil (use required rule for that)
	}

	val := reflect.ValueOf(value)
	switch val.Kind() {
	case reflect.String:
		// For strings, omitempty means the field can be empty
		// This is typically used for optional fields, so we don't validate them
		return nil
	case reflect.Struct:
		if val.IsZero() {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must not be empty", fieldName)
		}
	case reflect.Map:
		// For maps, omitempty means the field can be nil or empty
		// This is typically used for optional fields, so we don't validate them
		return nil
	case reflect.Slice, reflect.Array:
		if val.Len() == 0 {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must not be empty", fieldName)
		}
	}

	return nil
}

// validateMin validates minimum value.
func (v *Validator) validateMin(value interface{}, params string, fieldName string) error {
	if fieldName == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "field name cannot be empty")
	}

	if params == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "min parameter cannot be empty")
	}

	if value == nil {
		return nil
	}

	val := reflect.ValueOf(value)

	// Handle time.Duration specially
	if val.Type() == reflect.TypeOf(time.Duration(0)) {
		duration, ok := value.(time.Duration)
		if !ok {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' is not a valid duration", fieldName)
		}

		// Try to parse the parameter as a duration
		if paramDuration, err := time.ParseDuration(params); err == nil {
			if duration < paramDuration {
				return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be >= %v", fieldName, paramDuration)
			}
			return nil
		}
	}

	// Handle numeric values
	minVal, err := strconv.ParseFloat(params, 64)
	if err != nil {
		return NewErrorf(ErrorCodeValidation, "validation", "invalid min parameter: %s", params)
	}

	// Check for integer overflow
	if minVal > float64(1<<31-1) {
		return NewErrorf(ErrorCodeValidation, "validation", "min parameter too large: %s", params)
	}

	switch val.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if float64(val.Int()) < minVal {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be >= %v", fieldName, minVal)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if float64(val.Uint()) < minVal {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be >= %v", fieldName, minVal)
		}
	case reflect.Float32, reflect.Float64:
		if val.Float() < minVal {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be >= %v", fieldName, minVal)
		}
	case reflect.String:
		if val.Len() < int(minVal) {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' length must be >= %v", fieldName, minVal)
		}
	case reflect.Slice, reflect.Array, reflect.Map:
		if val.Len() < int(minVal) {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' length must be >= %v", fieldName, minVal)
		}
	}

	return nil
}

// validateMax validates maximum value.
func (v *Validator) validateMax(value interface{}, params string, fieldName string) error {
	if fieldName == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "field name cannot be empty")
	}

	if params == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "max parameter cannot be empty")
	}

	if value == nil {
		return nil
	}

	val := reflect.ValueOf(value)

	// Handle time.Duration specially
	if val.Type() == reflect.TypeOf(time.Duration(0)) {
		duration, ok := value.(time.Duration)
		if !ok {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' is not a valid duration", fieldName)
		}

		// Try to parse the parameter as a duration
		if paramDuration, err := time.ParseDuration(params); err == nil {
			if duration > paramDuration {
				return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be <= %v", fieldName, paramDuration)
			}
			return nil
		}
	}

	// Handle numeric values
	maxVal, err := strconv.ParseFloat(params, 64)
	if err != nil {
		return NewErrorf(ErrorCodeValidation, "validation", "invalid max parameter: %s", params)
	}

	// Check for integer overflow - allow larger values for int64 fields
	if maxVal > float64(1<<63-1) {
		return NewErrorf(ErrorCodeValidation, "validation", "max parameter too large: %s", params)
	}

	switch val.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if float64(val.Int()) > maxVal {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be <= %v", fieldName, maxVal)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if float64(val.Uint()) > maxVal {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be <= %v", fieldName, maxVal)
		}
	case reflect.Float32, reflect.Float64:
		if val.Float() > maxVal {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be <= %v", fieldName, maxVal)
		}
	case reflect.String:
		if val.Len() > int(maxVal) {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' length must be <= %v", fieldName, maxVal)
		}
	case reflect.Slice, reflect.Array, reflect.Map:
		if val.Len() > int(maxVal) {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' length must be <= %v", fieldName, maxVal)
		}
	}

	return nil
}

// validateLen validates length.
func (v *Validator) validateLen(value interface{}, params string, fieldName string) error {
	if fieldName == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "field name cannot be empty")
	}

	if params == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "len parameter cannot be empty")
	}

	if value == nil {
		return nil
	}

	expectedLen, err := strconv.Atoi(params)
	if err != nil {
		return NewErrorf(ErrorCodeValidation, "validation", "invalid len parameter: %s", params)
	}

	val := reflect.ValueOf(value)
	var actualLen int

	switch val.Kind() {
	case reflect.String:
		actualLen = val.Len()
	case reflect.Slice, reflect.Array, reflect.Map:
		actualLen = val.Len()
	default:
		return NewErrorf(ErrorCodeValidation, "validation", "field '%s' does not support length validation", fieldName)
	}

	if actualLen != expectedLen {
		return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must have length %d, got %d", fieldName, expectedLen, actualLen)
	}

	return nil
}

// validateEmail validates email format.
func (v *Validator) validateEmail(value interface{}, fieldName string) error {
	if fieldName == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "field name cannot be empty")
	}

	if value == nil {
		return nil // Skip if nil (use required rule for that)
	}

	str, ok := value.(string)
	if !ok {
		return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be a string", fieldName)
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(str) {
		return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be a valid email address", fieldName)
	}

	return nil
}

// validateURL validates URL format.
func (v *Validator) validateURL(value interface{}, fieldName string) error {
	if fieldName == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "field name cannot be empty")
	}

	if value == nil {
		return nil // Skip if nil (use required rule for that)
	}

	str, ok := value.(string)
	if !ok {
		return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be a string", fieldName)
	}

	urlRegex := regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`)
	if !urlRegex.MatchString(str) {
		return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be a valid URL", fieldName)
	}

	return nil
}

// validateRegexp validates against a regular expression.
func (v *Validator) validateRegexp(value interface{}, params string, fieldName string) error {
	if fieldName == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "field name cannot be empty")
	}

	if params == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "regexp parameter cannot be empty")
	}

	if value == nil {
		return nil // Skip if nil (use required rule for that)
	}

	str, ok := value.(string)
	if !ok {
		return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be a string", fieldName)
	}

	regex, err := getCachedRegex(params)
	if err != nil {
		return NewErrorf(ErrorCodeValidation, "validation", "invalid regexp pattern for field '%s': %v", fieldName, err)
	}

	if !regex.MatchString(str) {
		return NewErrorf(ErrorCodeValidation, "validation", "field '%s' does not match pattern", fieldName)
	}

	return nil
}

// validateOneOf validates that a value is one of the specified values.
func (v *Validator) validateOneOf(value interface{}, params string, fieldName string) error {
	if fieldName == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "field name cannot be empty")
	}

	if params == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "oneof parameter cannot be empty")
	}

	if value == nil {
		return nil // Skip if nil (use required rule for that)
	}

	allowedValues := strings.Split(params, " ")
	valueStr := fmt.Sprintf("%v", value)

	for _, allowed := range allowedValues {
		if valueStr == allowed {
			return nil
		}
	}

	return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be one of: %s", fieldName, params)
}

// validateGTE validates greater than or equal.
func (v *Validator) validateGTE(value interface{}, params string, fieldName string) error {
	if fieldName == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "field name cannot be empty")
	}

	if params == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "gte parameter cannot be empty")
	}

	if value == nil {
		return nil
	}

	gteVal, err := strconv.ParseFloat(params, 64)
	if err != nil {
		return NewErrorf(ErrorCodeValidation, "validation", "invalid gte parameter: %s", params)
	}

	val := reflect.ValueOf(value)
	switch val.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if float64(val.Int()) < gteVal {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be >= %v", fieldName, gteVal)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if float64(val.Uint()) < gteVal {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be >= %v", fieldName, gteVal)
		}
	case reflect.Float32, reflect.Float64:
		if val.Float() < gteVal {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be >= %v", fieldName, gteVal)
		}
	}

	return nil
}

// validateLTE validates less than or equal.
func (v *Validator) validateLTE(value interface{}, params string, fieldName string) error {
	if fieldName == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "field name cannot be empty")
	}

	if params == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "lte parameter cannot be empty")
	}

	if value == nil {
		return nil
	}

	lteVal, err := strconv.ParseFloat(params, 64)
	if err != nil {
		return NewErrorf(ErrorCodeValidation, "validation", "invalid lte parameter: %s", params)
	}

	val := reflect.ValueOf(value)
	switch val.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if float64(val.Int()) > lteVal {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be <= %v", fieldName, lteVal)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if float64(val.Uint()) > lteVal {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be <= %v", fieldName, lteVal)
		}
	case reflect.Float32, reflect.Float64:
		if val.Float() > lteVal {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be <= %v", fieldName, lteVal)
		}
	}

	return nil
}

// validateGT validates greater than.
func (v *Validator) validateGT(value interface{}, params string, fieldName string) error {
	if fieldName == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "field name cannot be empty")
	}

	if params == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "gt parameter cannot be empty")
	}

	if value == nil {
		return nil
	}

	gtVal, err := strconv.ParseFloat(params, 64)
	if err != nil {
		return NewErrorf(ErrorCodeValidation, "validation", "invalid gt parameter: %s", params)
	}

	val := reflect.ValueOf(value)
	switch val.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if float64(val.Int()) <= gtVal {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be > %v", fieldName, gtVal)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if float64(val.Uint()) <= gtVal {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be > %v", fieldName, gtVal)
		}
	case reflect.Float32, reflect.Float64:
		if val.Float() <= gtVal {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be > %v", fieldName, gtVal)
		}
	}

	return nil
}

// validateLT validates less than.
func (v *Validator) validateLT(value interface{}, params string, fieldName string) error {
	if fieldName == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "field name cannot be empty")
	}

	if params == "" {
		return NewErrorf(ErrorCodeValidation, "validation", "lt parameter cannot be empty")
	}

	if value == nil {
		return nil
	}

	ltVal, err := strconv.ParseFloat(params, 64)
	if err != nil {
		return NewErrorf(ErrorCodeValidation, "validation", "invalid lt parameter: %s", params)
	}

	val := reflect.ValueOf(value)
	switch val.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if float64(val.Int()) >= ltVal {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be < %v", fieldName, ltVal)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if float64(val.Uint()) >= ltVal {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be < %v", fieldName, ltVal)
		}
	case reflect.Float32, reflect.Float64:
		if val.Float() >= ltVal {
			return NewErrorf(ErrorCodeValidation, "validation", "field '%s' must be < %v", fieldName, ltVal)
		}
	}

	return nil
}

// RequiredValidationRule validates that a value is not empty.
type RequiredValidationRule struct{}

func (r *RequiredValidationRule) Validate(value interface{}) error {
	if value == nil {
		return NewError(ErrorCodeValidation, "required", "value cannot be nil")
	}

	val := reflect.ValueOf(value)
	switch val.Kind() {
	case reflect.String:
		if strings.TrimSpace(val.String()) == "" {
			return NewError(ErrorCodeValidation, "required", "value cannot be empty")
		}
	case reflect.Slice, reflect.Array, reflect.Map:
		if val.Len() == 0 {
			return NewError(ErrorCodeValidation, "required", "value cannot be empty")
		}
	}
	return nil
}

func (r *RequiredValidationRule) GetName() string {
	return "required"
}

func (r *RequiredValidationRule) GetDescription() string {
	return "validates that a value is not empty"
}

// OmitEmptyValidationRule validates that a value is not empty (for non-empty values).
type OmitEmptyValidationRule struct{}

func (r *OmitEmptyValidationRule) Validate(value interface{}) error {
	if value == nil {
		return nil // Nil values are skipped
	}

	val := reflect.ValueOf(value)
	switch val.Kind() {
	case reflect.String:
		if strings.TrimSpace(val.String()) == "" {
			return NewError(ErrorCodeValidation, "omitempty", "value cannot be empty")
		}
	case reflect.Slice, reflect.Array, reflect.Map:
		if val.Len() == 0 {
			return NewError(ErrorCodeValidation, "omitempty", "value cannot be empty")
		}
	}
	return nil
}

func (r *OmitEmptyValidationRule) GetName() string {
	return "omitempty"
}

func (r *OmitEmptyValidationRule) GetDescription() string {
	return "validates that a non-empty value is not empty"
}

// MinValidationRule validates that a value is greater than or equal to a minimum.
type MinValidationRule struct{}

func (r *MinValidationRule) Validate(value interface{}) error {
	// This rule requires parameters, so we'll just check for nil
	if value == nil {
		return NewError(ErrorCodeValidation, "min", "value cannot be nil")
	}
	return nil
}

func (r *MinValidationRule) GetName() string {
	return "min"
}

func (r *MinValidationRule) GetDescription() string {
	return "validates that a value is greater than or equal to a minimum"
}

// MaxValidationRule validates that a value is less than or equal to a maximum.
type MaxValidationRule struct{}

func (r *MaxValidationRule) Validate(value interface{}) error {
	// This rule requires parameters, so we'll just check for nil
	if value == nil {
		return NewError(ErrorCodeValidation, "max", "value cannot be nil")
	}
	return nil
}

func (r *MaxValidationRule) GetName() string {
	return "max"
}

func (r *MaxValidationRule) GetDescription() string {
	return "validates that a value is less than or equal to a maximum"
}

// LenValidationRule validates that a value has a specific length.
type LenValidationRule struct{}

func (r *LenValidationRule) Validate(value interface{}) error {
	// This rule requires parameters, so we'll just check for nil
	if value == nil {
		return NewError(ErrorCodeValidation, "len", "value cannot be nil")
	}
	return nil
}

func (r *LenValidationRule) GetName() string {
	return "len"
}

func (r *LenValidationRule) GetDescription() string {
	return "validates that a value has a specific length"
}

// EmailValidationRule validates that a value is a valid email address.
type EmailValidationRule struct{}

func (r *EmailValidationRule) Validate(value interface{}) error {
	if value == nil {
		return nil // Nil values should be skipped
	}

	val := reflect.ValueOf(value)
	if val.Kind() != reflect.String {
		return NewError(ErrorCodeValidation, "email", "value must be a string")
	}

	email := val.String()
	if email == "" {
		return NewError(ErrorCodeValidation, "email", "email cannot be empty")
	}

	// More permissive email validation regex that allows shorter domains
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]+$`)
	if !emailRegex.MatchString(email) {
		return NewError(ErrorCodeValidation, "email", "invalid email format")
	}

	// Additional checks for common invalid patterns
	if strings.Contains(email, "..") {
		return NewError(ErrorCodeValidation, "email", "invalid email format")
	}

	return nil
}

func (r *EmailValidationRule) GetName() string {
	return "email"
}

func (r *EmailValidationRule) GetDescription() string {
	return "validates that a value is a valid email address"
}

// URLValidationRule validates that a value is a valid URL.
type URLValidationRule struct{}

func (r *URLValidationRule) Validate(value interface{}) error {
	if value == nil {
		return nil // Nil values should be skipped
	}

	val := reflect.ValueOf(value)
	if val.Kind() != reflect.String {
		return NewError(ErrorCodeValidation, "url", "value must be a string")
	}

	url := val.String()
	if url == "" {
		return NewError(ErrorCodeValidation, "url", "url cannot be empty")
	}

	// URL validation regex that only allows http/https protocols
	urlRegex := regexp.MustCompile(`^https?://[a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})?(:\d+)?(/[^\s]*)?$`)
	if !urlRegex.MatchString(url) {
		return NewError(ErrorCodeValidation, "url", "invalid url format")
	}

	return nil
}

func (r *URLValidationRule) GetName() string {
	return "url"
}

func (r *URLValidationRule) GetDescription() string {
	return "validates that a value is a valid URL"
}

// RegexpValidationRule validates that a value matches a regular expression.
type RegexpValidationRule struct{}

func (r *RegexpValidationRule) Validate(value interface{}) error {
	// This rule requires parameters, so we'll just check for nil
	if value == nil {
		return NewError(ErrorCodeValidation, "regexp", "value cannot be nil")
	}
	return nil
}

func (r *RegexpValidationRule) GetName() string {
	return "regexp"
}

func (r *RegexpValidationRule) GetDescription() string {
	return "validates that a value matches a regular expression"
}

// OneOfValidationRule validates that a value is one of the allowed values.
type OneOfValidationRule struct{}

func (r *OneOfValidationRule) Validate(value interface{}) error {
	// This rule requires parameters, so we'll just check for nil
	if value == nil {
		return NewError(ErrorCodeValidation, "oneof", "value cannot be nil")
	}
	return nil
}

func (r *OneOfValidationRule) GetName() string {
	return "oneof"
}

func (r *OneOfValidationRule) GetDescription() string {
	return "validates that a value is one of the allowed values"
}

// GTEValidationRule validates that a value is greater than or equal to a threshold.
type GTEValidationRule struct{}

func (r *GTEValidationRule) Validate(value interface{}) error {
	// This rule requires parameters, so we'll just check for nil
	if value == nil {
		return NewError(ErrorCodeValidation, "gte", "value cannot be nil")
	}
	return nil
}

func (r *GTEValidationRule) GetName() string {
	return "gte"
}

func (r *GTEValidationRule) GetDescription() string {
	return "validates that a value is greater than or equal to a threshold"
}

// LTEValidationRule validates that a value is less than or equal to a threshold.
type LTEValidationRule struct{}

func (r *LTEValidationRule) Validate(value interface{}) error {
	// This rule requires parameters, so we'll just check for nil
	if value == nil {
		return NewError(ErrorCodeValidation, "lte", "value cannot be nil")
	}
	return nil
}

func (r *LTEValidationRule) GetName() string {
	return "lte"
}

func (r *LTEValidationRule) GetDescription() string {
	return "validates that a value is less than or equal to a threshold"
}

// GTValidationRule validates that a value is greater than a threshold.
type GTValidationRule struct{}

func (r *GTValidationRule) Validate(value interface{}) error {
	// This rule requires parameters, so we'll just check for nil
	if value == nil {
		return NewError(ErrorCodeValidation, "gt", "value cannot be nil")
	}
	return nil
}

func (r *GTValidationRule) GetName() string {
	return "gt"
}

func (r *GTValidationRule) GetDescription() string {
	return "validates that a value is greater than a threshold"
}

// LTValidationRule validates that a value is less than a threshold.
type LTValidationRule struct{}

func (r *LTValidationRule) Validate(value interface{}) error {
	// This rule requires parameters, so we'll just check for nil
	if value == nil {
		return NewError(ErrorCodeValidation, "lt", "value cannot be nil")
	}
	return nil
}

func (r *LTValidationRule) GetName() string {
	return "lt"
}

func (r *LTValidationRule) GetDescription() string {
	return "validates that a value is less than a threshold"
}

// registerDefaultRules registers default validation rules.
func (v *Validator) registerDefaultRules() {
	// Register built-in validation rules
	v.RegisterRule(&RequiredValidationRule{})
	v.RegisterRule(&OmitEmptyValidationRule{})
	v.RegisterRule(&MinValidationRule{})
	v.RegisterRule(&MaxValidationRule{})
	v.RegisterRule(&LenValidationRule{})
	v.RegisterRule(&EmailValidationRule{})
	v.RegisterRule(&URLValidationRule{})
	v.RegisterRule(&RegexpValidationRule{})
	v.RegisterRule(&OneOfValidationRule{})
	v.RegisterRule(&GTEValidationRule{})
	v.RegisterRule(&LTEValidationRule{})
	v.RegisterRule(&GTValidationRule{})
	v.RegisterRule(&LTValidationRule{})
}

// ValidationContext provides context for validation operations.
type ValidationContext struct {
	validator *Validator
	errors    []*ValidationError
	warnings  []*ValidationWarning
	mu        sync.RWMutex
}

// NewValidationContext creates a new validation context.
func NewValidationContext(validator *Validator) *ValidationContext {
	if validator == nil {
		validator = NewValidator()
	}
	return &ValidationContext{
		validator: validator,
		errors:    make([]*ValidationError, 0),
		warnings:  make([]*ValidationWarning, 0),
	}
}

// Validate validates a value and adds errors to the context.
func (vc *ValidationContext) Validate(ruleName string, value interface{}, fieldName string) {
	if vc == nil {
		return
	}

	// Acquire lock before checking for error to prevent race condition
	vc.mu.Lock()
	defer vc.mu.Unlock()

	if err := vc.validator.Validate(ruleName, value); err != nil {
		vc.errors = append(vc.errors, &ValidationError{
			Field:    fieldName,
			Value:    value,
			Rule:     ruleName,
			Message:  err.Error(),
			Severity: ValidationSeverityError,
		})
	}
}

// ValidateStruct validates a struct and adds errors to the context.
func (vc *ValidationContext) ValidateStruct(obj interface{}) {
	if vc == nil {
		return
	}

	result := vc.validator.ValidateStruct(obj)

	vc.mu.Lock()
	defer vc.mu.Unlock()

	vc.errors = append(vc.errors, result.Errors...)
	vc.warnings = append(vc.warnings, result.Warnings...)
}

// AddError adds a validation error to the context.
func (vc *ValidationContext) AddError(err *ValidationError) {
	if vc == nil || err == nil {
		return
	}

	vc.mu.Lock()
	defer vc.mu.Unlock()
	vc.errors = append(vc.errors, err)
}

// AddWarning adds a validation warning to the context.
func (vc *ValidationContext) AddWarning(warning *ValidationWarning) {
	if vc == nil || warning == nil {
		return
	}

	vc.mu.Lock()
	defer vc.mu.Unlock()
	vc.warnings = append(vc.warnings, warning)
}

// HasErrors returns true if there are validation errors.
func (vc *ValidationContext) HasErrors() bool {
	if vc == nil {
		return false
	}

	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return len(vc.errors) > 0
}

// HasWarnings returns true if there are validation warnings.
func (vc *ValidationContext) HasWarnings() bool {
	if vc == nil {
		return false
	}

	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return len(vc.warnings) > 0
}

// GetErrors returns all validation errors.
func (vc *ValidationContext) GetErrors() []*ValidationError {
	if vc == nil {
		return make([]*ValidationError, 0)
	}

	vc.mu.RLock()
	defer vc.mu.RUnlock()

	result := make([]*ValidationError, len(vc.errors))
	copy(result, vc.errors)
	return result
}

// GetWarnings returns all validation warnings.
func (vc *ValidationContext) GetWarnings() []*ValidationWarning {
	if vc == nil {
		return make([]*ValidationWarning, 0)
	}

	vc.mu.RLock()
	defer vc.mu.RUnlock()

	result := make([]*ValidationWarning, len(vc.warnings))
	copy(result, vc.warnings)
	return result
}

// Clear clears all errors and warnings.
func (vc *ValidationContext) Clear() {
	if vc == nil {
		return
	}

	vc.mu.Lock()
	defer vc.mu.Unlock()

	// Properly free memory by creating new slices
	vc.errors = make([]*ValidationError, 0)
	vc.warnings = make([]*ValidationWarning, 0)
}

// ToError returns a combined error if there are validation errors.
func (vc *ValidationContext) ToError() error {
	if vc == nil || !vc.HasErrors() {
		return nil
	}

	errors := vc.GetErrors()
	if len(errors) == 0 {
		return nil
	}

	if len(errors) == 1 {
		return NewError(ErrorCodeValidation, "validation", errors[0].Message)
	}

	// Create a combined error
	errorMessages := make([]string, len(errors))
	for i, err := range errors {
		if err != nil {
			errorMessages[i] = fmt.Sprintf("%s: %s", err.Field, err.Message)
		}
	}

	return NewErrorf(ErrorCodeValidation, "validation", "validation failed: %s", strings.Join(errorMessages, "; "))
}

// ValidationMiddleware provides middleware for automatic validation.
type ValidationMiddleware struct {
	validator *Validator
}

// NewValidationMiddleware creates a new validation middleware.
func NewValidationMiddleware(validator *Validator) *ValidationMiddleware {
	if validator == nil {
		validator = NewValidator()
	}
	return &ValidationMiddleware{
		validator: validator,
	}
}

// ValidateConfig validates configuration.
func (vm *ValidationMiddleware) ValidateConfig(cfg *Config) error {
	if vm == nil {
		return NewError(ErrorCodeValidation, "validation", "validation middleware is nil")
	}

	if cfg == nil {
		return NewError(ErrorCodeValidation, "validation", "config cannot be nil")
	}

	ctx := NewValidationContext(vm.validator)
	ctx.ValidateStruct(cfg)
	return ctx.ToError()
}

// ValidateMessage validates a message.
func (vm *ValidationMiddleware) ValidateMessage(msg *Message) error {
	if vm == nil {
		return NewError(ErrorCodeValidation, "validation", "validation middleware is nil")
	}

	if msg == nil {
		return NewError(ErrorCodeValidation, "validation", "message cannot be nil")
	}

	ctx := NewValidationContext(vm.validator)

	// Validate required fields
	ctx.Validate("required", msg.ID, "ID")
	ctx.Validate("required", msg.Body, "Body")
	ctx.Validate("required", msg.ContentType, "ContentType")

	// Validate content type - use the struct validation instead
	ctx.ValidateStruct(msg)

	return ctx.ToError()
}

// ValidateDelivery validates a delivery.
func (vm *ValidationMiddleware) ValidateDelivery(delivery *Delivery) error {
	if vm == nil {
		return NewError(ErrorCodeValidation, "validation", "validation middleware is nil")
	}

	if delivery == nil {
		return NewError(ErrorCodeValidation, "validation", "delivery cannot be nil")
	}

	ctx := NewValidationContext(vm.validator)

	// Validate required fields
	ctx.Validate("required", delivery.Message, "Message")
	ctx.Validate("required", delivery.Queue, "Queue")
	ctx.Validate("required", delivery.DeliveryTag, "DeliveryTag")

	return ctx.ToError()
}

// Global validator instance with thread safety
var (
	globalValidator     = NewValidator()
	globalValidatorOnce sync.Once
	globalValidatorMu   sync.RWMutex
)

// getGlobalValidator returns the global validator instance with thread safety.
func getGlobalValidator() *Validator {
	globalValidatorMu.RLock()
	defer globalValidatorMu.RUnlock()
	return globalValidator
}

// SetGlobalValidator sets the global validator instance.
func SetGlobalValidator(validator *Validator) {
	if validator == nil {
		return
	}
	globalValidatorMu.Lock()
	defer globalValidatorMu.Unlock()
	globalValidator = validator
}

// ValidateStruct validates a struct using the global validator.
func ValidateStruct(obj interface{}) *ValidationResult {
	return getGlobalValidator().ValidateStruct(obj)
}

// ValidateField validates a field using the global validator.
func ValidateField(ruleName string, value interface{}) error {
	return getGlobalValidator().Validate(ruleName, value)
}

// MessageOption represents a message option function
type MessageOption func(*Message)

// WithKey sets the routing key for a message
func WithKey(key string) MessageOption {
	return func(msg *Message) {
		msg.Key = key
	}
}

// WithPriority sets the priority for a message
func WithPriority(priority uint8) MessageOption {
	return func(msg *Message) {
		msg.Priority = priority
	}
}

// WithIdempotencyKey sets the idempotency key for a message
func WithIdempotencyKey(key string) MessageOption {
	return func(msg *Message) {
		msg.IdempotencyKey = key
	}
}

// WithID sets the ID for a message
func WithID(id string) MessageOption {
	return func(msg *Message) {
		msg.ID = id
	}
}

// WithContentType sets the content type for a message
func WithContentType(contentType string) MessageOption {
	return func(msg *Message) {
		msg.ContentType = contentType
	}
}

// WithCorrelationID sets the correlation ID for a message
func WithCorrelationID(correlationID string) MessageOption {
	return func(msg *Message) {
		msg.CorrelationID = correlationID
	}
}

// WithReplyTo sets the reply-to field for a message
func WithReplyTo(replyTo string) MessageOption {
	return func(msg *Message) {
		msg.ReplyTo = replyTo
	}
}

// WithExpiration sets the expiration for a message
func WithExpiration(expiration time.Duration) MessageOption {
	return func(msg *Message) {
		msg.Expiration = expiration
	}
}

// WithHeaders sets the headers for a message
func WithHeaders(headers map[string]string) MessageOption {
	return func(msg *Message) {
		msg.Headers = headers
	}
}

// NewMessage creates a new message with the given body and options
func NewMessage(body []byte, opts ...MessageOption) *Message {
	msg := &Message{
		ID:          generateMessageID(),
		Body:        body,
		ContentType: "application/json",
		Timestamp:   time.Now(),
		Headers:     make(map[string]string),
	}

	for _, opt := range opts {
		opt(msg)
	}

	// Validate the message and panic if validation fails
	validator := NewValidator()
	result := validator.ValidateStruct(msg)
	if !result.Valid {
		panic(fmt.Sprintf("invalid message: %v", result.Errors))
	}

	// Additional header validation
	if err := validateHeaders(msg.Headers); err != nil {
		panic(fmt.Sprintf("invalid headers: %v", err))
	}

	return msg
}

// generateMessageID generates a unique message ID
func generateMessageID() string {
	return fmt.Sprintf("msg_%d", time.Now().UnixNano())
}

// isValidRoutingKey validates if a routing key is valid
func isValidRoutingKey(key string) bool {
	if key == "" {
		return false
	}

	// Check length
	if len(key) > MaxRoutingKeyLength {
		return false
	}

	// Check format using regex
	regex, err := getCachedRegex(`^[a-zA-Z0-9._-]+$`)
	if err != nil {
		return false
	}

	return regex.MatchString(key)
}

// isValidMessageID validates if a message ID is valid
func isValidMessageID(id string) bool {
	if id == "" {
		return false
	}

	// Check length
	if len(id) > MaxMessageIDLength {
		return false
	}

	// Check format using regex
	regex, err := getCachedRegex(`^[a-zA-Z0-9_-]+$`)
	if err != nil {
		return false
	}

	return regex.MatchString(id)
}

// isValidTopicName validates if a topic name is valid
func isValidTopicName(topic string) bool {
	if topic == "" {
		return false
	}

	// Check format using regex
	regex, err := getCachedRegex(`^[a-zA-Z0-9._-]+$`)
	if err != nil {
		return false
	}

	return regex.MatchString(topic)
}

// isValidQueueName validates if a queue name is valid
func isValidQueueName(queue string) bool {
	if queue == "" {
		return false
	}

	// Check format using regex
	regex, err := getCachedRegex(`^[a-zA-Z0-9._-]+$`)
	if err != nil {
		return false
	}

	return regex.MatchString(queue)
}

// isValidContentType validates if a content type is supported
func isValidContentType(contentType string) bool {
	for _, supported := range SupportedContentTypes() {
		if contentType == supported {
			return true
		}
	}
	return false
}

// validateHeaders validates message headers
func validateHeaders(headers map[string]string) error {
	if headers == nil {
		return nil
	}

	// Check number of headers
	if len(headers) > 100 {
		return fmt.Errorf("too many headers: %d > 100", len(headers))
	}

	// Check each header key and value
	for key, value := range headers {
		if len(key) > 255 {
			return fmt.Errorf("header key too long: %d > 255", len(key))
		}
		if len(value) > MaxHeaderSize {
			return fmt.Errorf("header value too large: %d > %d", len(value), MaxHeaderSize)
		}
	}

	return nil
}
