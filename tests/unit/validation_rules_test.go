package unit

import (
	"testing"
	"time"

	"github.com/SeaSBee/go-validatorx"
	"github.com/stretchr/testify/assert"
)

// TestValidateRequired tests the validateRequired function
func TestValidateRequired(t *testing.T) {
	validator := validatorx.NewValidator()

	t.Run("ValidValues", func(t *testing.T) {
		testCases := []interface{}{
			"non-empty string",
			"0", // string "0" is not empty
			[]string{"item1", "item2"},
			[]int{1, 2, 3},
			map[string]string{"key": "value"},
			&struct{}{},
		}

		for _, value := range testCases {
			err := validator.Validate("required", value)
			assert.NoError(t, err, "Value %v should be valid", value)
		}
	})

	t.Run("InvalidValues", func(t *testing.T) {
		testCases := []interface{}{
			nil,
			"",
			"   ", // whitespace only
			[]string{},
			[]int{},
			map[string]string{},
		}

		for _, value := range testCases {
			err := validator.Validate("required", value)
			assert.Error(t, err, "Value %v should be invalid", value)
		}
	})

	t.Run("EmptyFieldName", func(t *testing.T) {
		// This tests the internal validateRequired function indirectly
		// by using a struct with empty field name
		type TestStruct struct {
			Field string `validate:"required"`
		}

		invalid := TestStruct{Field: ""}
		result := validator.ValidateStruct(invalid)
		assert.False(t, result.Valid)
		assert.Len(t, result.Errors, 1)
	})
}

// TestValidateOmitEmpty tests the validateOmitEmpty function
func TestValidateOmitEmpty(t *testing.T) {
	validator := validatorx.NewValidator()

	t.Run("ValidValues", func(t *testing.T) {
		testCases := []interface{}{
			"non-empty string",
			[]string{"item1"},
			[]int{1, 2, 3},
			map[string]string{"key": "value"},
		}

		for _, value := range testCases {
			err := validator.Validate("omitempty", value)
			assert.NoError(t, err, "Value %v should be valid", value)
		}
	})

	t.Run("NilValue", func(t *testing.T) {
		// Nil values should be skipped (not validated)
		err := validator.Validate("omitempty", nil)
		assert.NoError(t, err)
	})

	t.Run("EmptyValues", func(t *testing.T) {
		testCases := []interface{}{
			[]string{},
			[]int{},
		}

		for _, value := range testCases {
			err := validator.Validate("omitempty", value)
			assert.Error(t, err, "Empty value %v should be invalid", value)
		}
	})

	t.Run("StructTagUsage", func(t *testing.T) {
		type TestStruct struct {
			Field1 []string `validate:"omitempty"`
			Field2 []string `validate:"omitempty"`
		}

		// Valid struct
		valid := TestStruct{
			Field1: []string{"item"},
			Field2: nil, // nil should be skipped
		}
		result := validator.ValidateStruct(valid)
		assert.True(t, result.Valid)

		// Invalid struct
		invalid := TestStruct{
			Field1: []string{},
			Field2: nil,
		}
		result = validator.ValidateStruct(invalid)
		assert.False(t, result.Valid)
		assert.Len(t, result.Errors, 1)
	})
}

// TestValidateMin tests the validateMin function
func TestValidateMin(t *testing.T) {
	validator := validatorx.NewValidator()

	t.Run("NumericValues", func(t *testing.T) {
		testCases := []struct {
			value    interface{}
			min      string
			expected bool
		}{
			{10, "5", true},
			{5, "5", true},
			{3, "5", false},
			{10.5, "5.0", true},
			{5.0, "5.0", true},
			{3.5, "5.0", false},
			{uint(10), "5", true},
			{uint(5), "5", true},
			{uint(3), "5", false},
		}

		for _, tc := range testCases {
			err := validator.Validate("min:"+tc.min, tc.value)
			if tc.expected {
				assert.NoError(t, err, "Value %v should be >= %s", tc.value, tc.min)
			} else {
				assert.Error(t, err, "Value %v should not be >= %s", tc.value, tc.min)
			}
		}
	})

	t.Run("StringLength", func(t *testing.T) {
		testCases := []struct {
			value    string
			min      string
			expected bool
		}{
			{"hello", "3", true},
			{"hi", "3", false},
			{"test", "4", true},
			{"", "0", true},
			{"", "1", false},
		}

		for _, tc := range testCases {
			err := validator.Validate("min:"+tc.min, tc.value)
			if tc.expected {
				assert.NoError(t, err, "String '%s' length should be >= %s", tc.value, tc.min)
			} else {
				assert.Error(t, err, "String '%s' length should not be >= %s", tc.value, tc.min)
			}
		}
	})

	t.Run("SliceLength", func(t *testing.T) {
		testCases := []struct {
			value    interface{}
			min      string
			expected bool
		}{
			{[]string{"a", "b", "c"}, "2", true},
			{[]string{"a"}, "2", false},
			{[]int{1, 2, 3, 4}, "3", true},
			{[]int{1, 2}, "3", false},
		}

		for _, tc := range testCases {
			err := validator.Validate("min:"+tc.min, tc.value)
			if tc.expected {
				assert.NoError(t, err, "Slice %v length should be >= %s", tc.value, tc.min)
			} else {
				assert.Error(t, err, "Slice %v length should not be >= %s", tc.value, tc.min)
			}
		}
	})

	t.Run("DurationValues", func(t *testing.T) {
		testCases := []struct {
			value    time.Duration
			min      string
			expected bool
		}{
			{10 * time.Second, "5s", true},
			{5 * time.Second, "5s", true},
			{3 * time.Second, "5s", false},
			{1 * time.Minute, "30s", true},
			{15 * time.Second, "30s", false},
		}

		for _, tc := range testCases {
			err := validator.Validate("min:"+tc.min, tc.value)
			if tc.expected {
				assert.NoError(t, err, "Duration %v should be >= %s", tc.value, tc.min)
			} else {
				assert.Error(t, err, "Duration %v should not be >= %s", tc.value, tc.min)
			}
		}
	})

	t.Run("InvalidParameters", func(t *testing.T) {
		// Test with invalid min parameter
		err := validator.Validate("min:invalid", 10)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid min parameter")

		// Test with empty min parameter
		err = validator.Validate("min:", 10)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "min parameter cannot be empty")
	})

	t.Run("NilValue", func(t *testing.T) {
		// Nil values should be skipped
		err := validator.Validate("min:5", nil)
		assert.NoError(t, err)
	})
}

// TestValidateMax tests the validateMax function
func TestValidateMax(t *testing.T) {
	validator := validatorx.NewValidator()

	t.Run("NumericValues", func(t *testing.T) {
		testCases := []struct {
			value    interface{}
			max      string
			expected bool
		}{
			{3, "5", true},
			{5, "5", true},
			{10, "5", false},
			{3.5, "5.0", true},
			{5.0, "5.0", true},
			{10.5, "5.0", false},
			{uint(3), "5", true},
			{uint(5), "5", true},
			{uint(10), "5", false},
		}

		for _, tc := range testCases {
			err := validator.Validate("max:"+tc.max, tc.value)
			if tc.expected {
				assert.NoError(t, err, "Value %v should be <= %s", tc.value, tc.max)
			} else {
				assert.Error(t, err, "Value %v should not be <= %s", tc.value, tc.max)
			}
		}
	})

	t.Run("StringLength", func(t *testing.T) {
		testCases := []struct {
			value    string
			max      string
			expected bool
		}{
			{"hi", "3", true},
			{"hello", "3", false},
			{"test", "4", true},
			{"", "0", true},
			{"a", "0", false},
		}

		for _, tc := range testCases {
			err := validator.Validate("max:"+tc.max, tc.value)
			if tc.expected {
				assert.NoError(t, err, "String '%s' length should be <= %s", tc.value, tc.max)
			} else {
				assert.Error(t, err, "String '%s' length should not be <= %s", tc.value, tc.max)
			}
		}
	})

	t.Run("DurationValues", func(t *testing.T) {
		testCases := []struct {
			value    time.Duration
			max      string
			expected bool
		}{
			{3 * time.Second, "5s", true},
			{5 * time.Second, "5s", true},
			{10 * time.Second, "5s", false},
			{15 * time.Second, "30s", true},
			{45 * time.Second, "30s", false},
		}

		for _, tc := range testCases {
			err := validator.Validate("max:"+tc.max, tc.value)
			if tc.expected {
				assert.NoError(t, err, "Duration %v should be <= %s", tc.value, tc.max)
			} else {
				assert.Error(t, err, "Duration %v should not be <= %s", tc.value, tc.max)
			}
		}
	})
}

// TestValidateLen tests the validateLen function
func TestValidateLen(t *testing.T) {
	validator := validatorx.NewValidator()

	t.Run("StringLength", func(t *testing.T) {
		testCases := []struct {
			value    string
			len      string
			expected bool
		}{
			{"hello", "5", true},
			{"hi", "5", false},
			{"", "0", true},
			{"a", "0", false},
		}

		for _, tc := range testCases {
			err := validator.Validate("len:"+tc.len, tc.value)
			if tc.expected {
				assert.NoError(t, err, "String '%s' should have length %s", tc.value, tc.len)
			} else {
				assert.Error(t, err, "String '%s' should not have length %s", tc.value, tc.len)
			}
		}
	})

	t.Run("SliceLength", func(t *testing.T) {
		testCases := []struct {
			value    interface{}
			len      string
			expected bool
		}{
			{[]string{"a", "b", "c"}, "3", true},
			{[]string{"a", "b"}, "3", false},
			{[]int{1, 2, 3, 4}, "4", true},
			{[]int{1, 2}, "4", false},
		}

		for _, tc := range testCases {
			err := validator.Validate("len:"+tc.len, tc.value)
			if tc.expected {
				assert.NoError(t, err, "Slice %v should have length %s", tc.value, tc.len)
			} else {
				assert.Error(t, err, "Slice %v should not have length %s", tc.value, tc.len)
			}
		}
	})

	t.Run("UnsupportedTypes", func(t *testing.T) {
		// Test with unsupported types
		err := validator.Validate("len:5", 123)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "does not support length validation")
	})

	t.Run("NilValue", func(t *testing.T) {
		// Nil values should be skipped
		err := validator.Validate("len:5", nil)
		assert.NoError(t, err)
	})
}

// TestValidateEmail tests the validateEmail function
func TestValidateEmail(t *testing.T) {
	validator := validatorx.NewValidator()

	t.Run("ValidEmails", func(t *testing.T) {
		validEmails := []string{
			"test@example.com",
			"user.name@domain.co.uk",
			"user+tag@example.org",
			"user123@test-domain.com",
			"a@b.c",
		}

		for _, email := range validEmails {
			err := validator.Validate("email", email)
			assert.NoError(t, err, "Email '%s' should be valid", email)
		}
	})

	t.Run("InvalidEmails", func(t *testing.T) {
		invalidEmails := []string{
			"invalid-email",
			"@example.com",
			"user@",
			"user@.com",
			"user..name@example.com",
			"user@example..com",
			"user name@example.com",
		}

		for _, email := range invalidEmails {
			err := validator.Validate("email", email)
			assert.Error(t, err, "Email '%s' should be invalid", email)
		}
	})

	t.Run("NonStringValues", func(t *testing.T) {
		// Test with non-string values
		err := validator.Validate("email", 123)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be a string")
	})

	t.Run("NilValue", func(t *testing.T) {
		// Nil values should be skipped
		err := validator.Validate("email", nil)
		assert.NoError(t, err)
	})
}

// TestValidateURL tests the validateURL function
func TestValidateURL(t *testing.T) {
	validator := validatorx.NewValidator()

	t.Run("ValidURLs", func(t *testing.T) {
		validURLs := []string{
			"https://example.com",
			"http://example.com",
			"https://example.com/path",
			"https://example.com/path?param=value",
			"https://example.com:8080",
		}

		for _, url := range validURLs {
			err := validator.Validate("url", url)
			assert.NoError(t, err, "URL '%s' should be valid", url)
		}
	})

	t.Run("InvalidURLs", func(t *testing.T) {
		invalidURLs := []string{
			"not-a-url",
			"ftp://example.com", // only http/https supported
			"example.com",
			"https://",
			"http://",
		}

		for _, url := range invalidURLs {
			err := validator.Validate("url", url)
			assert.Error(t, err, "URL '%s' should be invalid", url)
		}
	})

	t.Run("NonStringValues", func(t *testing.T) {
		// Test with non-string values
		err := validator.Validate("url", 123)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be a string")
	})
}

// TestValidateRegexp tests the validateRegexp function
func TestValidateRegexp(t *testing.T) {
	validator := validatorx.NewValidator()

	t.Run("ValidPatterns", func(t *testing.T) {
		testCases := []struct {
			value   string
			pattern string
		}{
			{"hello", "^h.*o$"},
			{"123", "^[0-9]+$"},
			{"abc123", "^[a-z0-9]+$"},
			{"test@example.com", "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"},
		}

		for _, tc := range testCases {
			err := validator.Validate("regexp:"+tc.pattern, tc.value)
			assert.NoError(t, err, "Value '%s' should match pattern '%s'", tc.value, tc.pattern)
		}
	})

	t.Run("InvalidPatterns", func(t *testing.T) {
		testCases := []struct {
			value   string
			pattern string
		}{
			{"world", "^h.*o$"},
			{"abc", "^[0-9]+$"},
			{"ABC123", "^[a-z0-9]+$"},
		}

		for _, tc := range testCases {
			err := validator.Validate("regexp:"+tc.pattern, tc.value)
			assert.Error(t, err, "Value '%s' should not match pattern '%s'", tc.value, tc.pattern)
		}
	})

	t.Run("InvalidRegexpPattern", func(t *testing.T) {
		// Test with invalid regexp pattern
		err := validator.Validate("regexp:[invalid", "test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid regexp pattern")
	})

	t.Run("EmptyPattern", func(t *testing.T) {
		// Test with empty pattern
		err := validator.Validate("regexp:", "test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "regexp parameter cannot be empty")
	})

	t.Run("NonStringValues", func(t *testing.T) {
		// Test with non-string values
		err := validator.Validate("regexp:^[0-9]+$", 123)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be a string")
	})
}

// TestValidateOneOf tests the validateOneOf function
func TestValidateOneOf(t *testing.T) {
	validator := validatorx.NewValidator()

	t.Run("ValidValues", func(t *testing.T) {
		testCases := []struct {
			value    interface{}
			allowed  string
			expected bool
		}{
			{"admin", "admin user guest", true},
			{"user", "admin user guest", true},
			{"guest", "admin user guest", true},
			{"invalid", "admin user guest", false},
			{123, "123 456 789", true},
			{456, "123 456 789", true},
			{999, "123 456 789", false},
		}

		for _, tc := range testCases {
			err := validator.Validate("oneof:"+tc.allowed, tc.value)
			if tc.expected {
				assert.NoError(t, err, "Value %v should be one of: %s", tc.value, tc.allowed)
			} else {
				assert.Error(t, err, "Value %v should not be one of: %s", tc.value, tc.allowed)
			}
		}
	})

	t.Run("EmptyAllowedValues", func(t *testing.T) {
		// Test with empty allowed values
		err := validator.Validate("oneof:", "test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "oneof parameter cannot be empty")
	})

	t.Run("NilValue", func(t *testing.T) {
		// Nil values should be skipped
		err := validator.Validate("oneof:admin user", nil)
		assert.NoError(t, err)
	})
}

// TestValidateComparisonRules tests the GTE, LTE, GT, LT validation rules
func TestValidateComparisonRules(t *testing.T) {
	validator := validatorx.NewValidator()

	t.Run("ValidateGTE", func(t *testing.T) {
		testCases := []struct {
			value    interface{}
			param    string
			expected bool
		}{
			{10, "5", true},
			{5, "5", true},
			{3, "5", false},
			{10.5, "5.0", true},
			{5.0, "5.0", true},
			{3.5, "5.0", false},
		}

		for _, tc := range testCases {
			err := validator.Validate("gte:"+tc.param, tc.value)
			if tc.expected {
				assert.NoError(t, err, "Value %v should be >= %s", tc.value, tc.param)
			} else {
				assert.Error(t, err, "Value %v should not be >= %s", tc.value, tc.param)
			}
		}
	})

	t.Run("ValidateLTE", func(t *testing.T) {
		testCases := []struct {
			value    interface{}
			param    string
			expected bool
		}{
			{3, "5", true},
			{5, "5", true},
			{10, "5", false},
			{3.5, "5.0", true},
			{5.0, "5.0", true},
			{10.5, "5.0", false},
		}

		for _, tc := range testCases {
			err := validator.Validate("lte:"+tc.param, tc.value)
			if tc.expected {
				assert.NoError(t, err, "Value %v should be <= %s", tc.value, tc.param)
			} else {
				assert.Error(t, err, "Value %v should not be <= %s", tc.value, tc.param)
			}
		}
	})

	t.Run("ValidateGT", func(t *testing.T) {
		testCases := []struct {
			value    interface{}
			param    string
			expected bool
		}{
			{10, "5", true},
			{5, "5", false},
			{3, "5", false},
			{10.5, "5.0", true},
			{5.0, "5.0", false},
			{3.5, "5.0", false},
		}

		for _, tc := range testCases {
			err := validator.Validate("gt:"+tc.param, tc.value)
			if tc.expected {
				assert.NoError(t, err, "Value %v should be > %s", tc.value, tc.param)
			} else {
				assert.Error(t, err, "Value %v should not be > %s", tc.value, tc.param)
			}
		}
	})

	t.Run("ValidateLT", func(t *testing.T) {
		testCases := []struct {
			value    interface{}
			param    string
			expected bool
		}{
			{3, "5", true},
			{5, "5", false},
			{10, "5", false},
			{3.5, "5.0", true},
			{5.0, "5.0", false},
			{10.5, "5.0", false},
		}

		for _, tc := range testCases {
			err := validator.Validate("lt:"+tc.param, tc.value)
			if tc.expected {
				assert.NoError(t, err, "Value %v should be < %s", tc.value, tc.param)
			} else {
				assert.Error(t, err, "Value %v should not be < %s", tc.value, tc.param)
			}
		}
	})

	t.Run("InvalidParameters", func(t *testing.T) {
		// Test with invalid parameters
		err := validator.Validate("gte:invalid", 10)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid gte parameter")

		err = validator.Validate("lte:invalid", 10)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid lte parameter")

		err = validator.Validate("gt:invalid", 10)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid gt parameter")

		err = validator.Validate("lt:invalid", 10)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid lt parameter")
	})

	t.Run("NilValues", func(t *testing.T) {
		// Nil values should be skipped
		assert.NoError(t, validator.Validate("gte:5", nil))
		assert.NoError(t, validator.Validate("lte:5", nil))
		assert.NoError(t, validator.Validate("gt:5", nil))
		assert.NoError(t, validator.Validate("lt:5", nil))
	})
}
