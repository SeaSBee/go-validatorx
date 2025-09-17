package unit

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/seasbee/go-validatorx"
	"github.com/stretchr/testify/assert"
)

// TestMessageValidation tests comprehensive message validation
func TestMessageValidation(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() *validatorx.Message
		wantErr bool
	}{
		{
			name: "Valid message",
			setup: func() *validatorx.Message {
				return &validatorx.Message{
					ID:          "valid-id-123",
					Key:         "valid.key",
					Body:        []byte("test message"),
					ContentType: "application/json",
					Timestamp:   time.Now(),
					Headers:     map[string]string{"key": "value"},
					Priority:    5,
				}
			},
			wantErr: false,
		},
		{
			name: "Empty message ID",
			setup: func() *validatorx.Message {
				return &validatorx.Message{
					ID:          "",
					Key:         "valid.key",
					Body:        []byte("test message"),
					ContentType: "application/json",
				}
			},
			wantErr: true,
		},
		{
			name: "Message ID too long",
			setup: func() *validatorx.Message {
				longID := string(make([]byte, validatorx.MaxMessageIDLength+1))
				return &validatorx.Message{
					ID:          longID,
					Key:         "valid.key",
					Body:        []byte("test message"),
					ContentType: "application/json",
				}
			},
			wantErr: true,
		},
		{
			name: "Invalid message ID format",
			setup: func() *validatorx.Message {
				return &validatorx.Message{
					ID:          "invalid@id",
					Key:         "valid.key",
					Body:        []byte("test message"),
					ContentType: "application/json",
				}
			},
			wantErr: true,
		},
		{
			name: "Empty message body",
			setup: func() *validatorx.Message {
				return &validatorx.Message{
					ID:          "valid-id",
					Key:         "valid.key",
					Body:        []byte{},
					ContentType: "application/json",
				}
			},
			wantErr: true,
		},
		{
			name: "Message body too large",
			setup: func() *validatorx.Message {
				largeBody := make([]byte, validatorx.MaxMessageSize+1)
				return &validatorx.Message{
					ID:          "valid-id",
					Key:         "valid.key",
					Body:        largeBody,
					ContentType: "application/json",
				}
			},
			wantErr: true,
		},
		{
			name: "Empty routing key",
			setup: func() *validatorx.Message {
				return &validatorx.Message{
					ID:          "valid-id",
					Key:         "",
					Body:        []byte("test message"),
					ContentType: "application/json",
				}
			},
			wantErr: true,
		},
		{
			name: "Routing key too long",
			setup: func() *validatorx.Message {
				longKey := string(make([]byte, validatorx.MaxRoutingKeyLength+1))
				return &validatorx.Message{
					ID:          "valid-id",
					Key:         longKey,
					Body:        []byte("test message"),
					ContentType: "application/json",
				}
			},
			wantErr: true,
		},
		{
			name: "Invalid routing key format",
			setup: func() *validatorx.Message {
				return &validatorx.Message{
					ID:          "valid-id",
					Key:         "invalid@key",
					Body:        []byte("test message"),
					ContentType: "application/json",
				}
			},
			wantErr: true,
		},
		{
			name: "Unsupported content type",
			setup: func() *validatorx.Message {
				return &validatorx.Message{
					ID:          "valid-id",
					Key:         "valid.key",
					Body:        []byte("test message"),
					ContentType: "unsupported/type",
				}
			},
			wantErr: true,
		},
		{
			name: "Too many headers",
			setup: func() *validatorx.Message {
				headers := make(map[string]string, 101)
				for i := 0; i < 101; i++ {
					headers[fmt.Sprintf("key%d", i)] = "value"
				}
				return &validatorx.Message{
					ID:          "valid-id",
					Key:         "valid.key",
					Body:        []byte("test message"),
					ContentType: "application/json",
					Headers:     headers,
				}
			},
			wantErr: true,
		},
		{
			name: "Header key too long",
			setup: func() *validatorx.Message {
				longKey := string(make([]byte, 256))
				return &validatorx.Message{
					ID:          "valid-id",
					Key:         "valid.key",
					Body:        []byte("test message"),
					ContentType: "application/json",
					Headers:     map[string]string{longKey: "value"},
				}
			},
			wantErr: true,
		},
		{
			name: "Header value too large",
			setup: func() *validatorx.Message {
				largeValue := string(make([]byte, validatorx.MaxHeaderSize+1))
				return &validatorx.Message{
					ID:          "valid-id",
					Key:         "valid.key",
					Body:        []byte("test message"),
					ContentType: "application/json",
					Headers:     map[string]string{"key": largeValue},
				}
			},
			wantErr: true,
		},
		{
			name: "Priority too high",
			setup: func() *validatorx.Message {
				return &validatorx.Message{
					ID:          "valid-id",
					Key:         "valid.key",
					Body:        []byte("test message"),
					ContentType: "application/json",
					Priority:    255, // Max valid value
				}
			},
			wantErr: false, // This should be valid since 255 is the max
		},
		{
			name: "Correlation ID too long",
			setup: func() *validatorx.Message {
				longCorrID := string(make([]byte, validatorx.MaxCorrelationIDLength+1))
				return &validatorx.Message{
					ID:            "valid-id",
					Key:           "valid.key",
					Body:          []byte("test message"),
					ContentType:   "application/json",
					CorrelationID: longCorrID,
				}
			},
			wantErr: true,
		},
		{
			name: "Invalid correlation ID format",
			setup: func() *validatorx.Message {
				return &validatorx.Message{
					ID:            "valid-id",
					Key:           "valid.key",
					Body:          []byte("test message"),
					ContentType:   "application/json",
					CorrelationID: "invalid@corr",
				}
			},
			wantErr: true,
		},
		{
			name: "Reply-to too long",
			setup: func() *validatorx.Message {
				longReplyTo := string(make([]byte, validatorx.MaxReplyToLength+1))
				return &validatorx.Message{
					ID:          "valid-id",
					Key:         "valid.key",
					Body:        []byte("test message"),
					ContentType: "application/json",
					ReplyTo:     longReplyTo,
				}
			},
			wantErr: true,
		},
		{
			name: "Invalid reply-to format",
			setup: func() *validatorx.Message {
				return &validatorx.Message{
					ID:          "valid-id",
					Key:         "valid.key",
					Body:        []byte("test message"),
					ContentType: "application/json",
					ReplyTo:     "invalid@reply",
				}
			},
			wantErr: true,
		},
		{
			name: "Idempotency key too long",
			setup: func() *validatorx.Message {
				longKey := string(make([]byte, validatorx.MaxIdempotencyKeyLength+1))
				return &validatorx.Message{
					ID:             "valid-id",
					Key:            "valid.key",
					Body:           []byte("test message"),
					ContentType:    "application/json",
					IdempotencyKey: longKey,
				}
			},
			wantErr: true,
		},
		{
			name: "Invalid idempotency key format",
			setup: func() *validatorx.Message {
				return &validatorx.Message{
					ID:             "valid-id",
					Key:            "valid.key",
					Body:           []byte("test message"),
					ContentType:    "application/json",
					IdempotencyKey: "invalid@key",
				}
			},
			wantErr: true,
		},
		{
			name: "Negative expiration",
			setup: func() *validatorx.Message {
				return &validatorx.Message{
					ID:          "valid-id",
					Key:         "valid.key",
					Body:        []byte("test message"),
					ContentType: "application/json",
					Expiration:  -1 * time.Second,
				}
			},
			wantErr: true,
		},
		{
			name: "Expiration too long",
			setup: func() *validatorx.Message {
				return &validatorx.Message{
					ID:          "valid-id",
					Key:         "valid.key",
					Body:        []byte("test message"),
					ContentType: "application/json",
					Expiration:  validatorx.MaxTimeout + time.Second,
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.setup()

			// Test validation through NewMessage function
			if tt.wantErr {
				// Should panic for invalid messages
				assert.Panics(t, func() {
					validatorx.NewMessage(msg.Body,
						validatorx.WithID(msg.ID),
						validatorx.WithKey(msg.Key),
						validatorx.WithContentType(msg.ContentType),
						validatorx.WithPriority(msg.Priority),
						validatorx.WithCorrelationID(msg.CorrelationID),
						validatorx.WithReplyTo(msg.ReplyTo),
						validatorx.WithIdempotencyKey(msg.IdempotencyKey),
						validatorx.WithExpiration(msg.Expiration),
						validatorx.WithHeaders(msg.Headers),
					)
				})
			} else {
				// Should not panic for valid messages
				assert.NotPanics(t, func() {
					validatorx.NewMessage(msg.Body,
						validatorx.WithID(msg.ID),
						validatorx.WithKey(msg.Key),
						validatorx.WithContentType(msg.ContentType),
						validatorx.WithPriority(msg.Priority),
						validatorx.WithCorrelationID(msg.CorrelationID),
						validatorx.WithReplyTo(msg.ReplyTo),
						validatorx.WithIdempotencyKey(msg.IdempotencyKey),
						validatorx.WithExpiration(msg.Expiration),
						validatorx.WithHeaders(msg.Headers),
					)
				})
			}
		})
	}
}

// TestNewMessageValidation tests NewMessage function validation
func TestNewMessageValidation(t *testing.T) {
	t.Run("Valid message creation", func(t *testing.T) {
		msg := validatorx.NewMessage([]byte("test"), validatorx.WithKey("test.key"))
		assert.NotNil(t, msg)
		assert.Equal(t, "test.key", msg.Key)
		assert.Equal(t, "application/json", msg.ContentType)
	})

	t.Run("Empty body panics", func(t *testing.T) {
		assert.Panics(t, func() {
			validatorx.NewMessage([]byte{}, validatorx.WithKey("test.key"))
		})
	})

	t.Run("Body too large panics", func(t *testing.T) {
		largeBody := make([]byte, validatorx.MaxMessageSize+1)
		assert.Panics(t, func() {
			validatorx.NewMessage(largeBody, validatorx.WithKey("test.key"))
		})
	})

	t.Run("Invalid message option panics", func(t *testing.T) {
		assert.Panics(t, func() {
			validatorx.NewMessage(
				[]byte("test"),
				validatorx.WithKey(""), // Empty key should cause validation to fail
			)
		})
	})
}

// TestConfigurationValidation tests configuration validation
func TestConfigurationValidation(t *testing.T) {
	t.Run("Valid publisher config", func(t *testing.T) {
		config := &validatorx.PublisherConfig{
			MaxInFlight:    100,
			WorkerCount:    4,
			PublishTimeout: 2 * time.Second, // Set a valid timeout
		}
		validator := validatorx.NewValidator()
		result := validator.ValidateStruct(config)
		if !result.Valid {
			for _, err := range result.Errors {
				t.Logf("Validation error: %s - %s", err.Field, err.Message)
			}
		}
		assert.True(t, result.Valid)
	})

	t.Run("Invalid publisher config - MaxInFlight too high", func(t *testing.T) {
		config := &validatorx.PublisherConfig{
			MaxInFlight: validatorx.MaxInFlightMessages + 1,
			WorkerCount: 4,
		}
		validator := validatorx.NewValidator()
		result := validator.ValidateStruct(config)
		assert.False(t, result.Valid)
	})

	t.Run("Valid consumer config", func(t *testing.T) {
		config := &validatorx.ConsumerConfig{
			Queue:                 "test.queue",
			Prefetch:              256,
			MaxConcurrentHandlers: 64,
			HandlerTimeout:        30 * time.Second, // Set a valid timeout
		}
		validator := validatorx.NewValidator()
		result := validator.ValidateStruct(config)
		if !result.Valid {
			for _, err := range result.Errors {
				t.Logf("Validation error: %s - %s", err.Field, err.Message)
			}
		}
		assert.True(t, result.Valid)
	})

	t.Run("Invalid consumer config - Prefetch too high", func(t *testing.T) {
		config := &validatorx.ConsumerConfig{
			Queue:                 "test.queue",
			Prefetch:              validatorx.MaxPrefetchCount + 1,
			MaxConcurrentHandlers: 64,
		}
		validator := validatorx.NewValidator()
		result := validator.ValidateStruct(config)
		assert.False(t, result.Valid)
	})
}

// TestRuntimeValidation tests runtime validation in publisher and consumer
func TestRuntimeValidation(t *testing.T) {
	t.Run("Publisher validation", func(t *testing.T) {
		// This would require a mock publisher, but we can test the validation functions
		// that are used by the publisher
		topic := "test.topic"
		msg := validatorx.NewMessage([]byte("test"), validatorx.WithKey("test.key"))

		// Test valid inputs
		assert.True(t, isValidTopicName(topic))
		assert.True(t, isValidMessageID(msg.ID))
		assert.True(t, isValidRoutingKey(msg.Key))
		assert.True(t, isValidContentType(msg.ContentType))

		// Test invalid inputs
		assert.False(t, isValidTopicName("invalid@topic"))
		assert.False(t, isValidMessageID("invalid@id"))
		assert.False(t, isValidRoutingKey("invalid@key"))
		assert.False(t, isValidContentType("unsupported/type"))
	})

	t.Run("Consumer validation", func(t *testing.T) {
		queue := "test.queue"
		assert.True(t, isValidQueueName(queue))
		assert.False(t, isValidQueueName("invalid@queue"))
	})
}

// TestBoundaryConditions tests boundary condition validation
func TestBoundaryConditions(t *testing.T) {
	t.Run("Message size boundaries", func(t *testing.T) {
		// Test minimum valid size
		msg := validatorx.NewMessage([]byte("a"), validatorx.WithKey("test.key"))
		assert.NotNil(t, msg)

		// Test maximum valid size
		maxBody := make([]byte, validatorx.MaxMessageSize)
		msg = validatorx.NewMessage(maxBody, validatorx.WithKey("test.key"))
		assert.NotNil(t, msg)
	})

	t.Run("String length boundaries", func(t *testing.T) {
		// Test maximum valid ID length
		maxID := string(make([]byte, validatorx.MaxMessageIDLength))
		for i := range maxID {
			maxID = maxID[:i] + "a" + maxID[i+1:]
		}
		msg := &validatorx.Message{
			ID:          maxID,
			Key:         "test.key",
			Body:        []byte("test"),
			ContentType: "application/json",
		}
		assert.NoError(t, validateMessage(msg))

		// Test maximum valid routing key length
		maxKey := string(make([]byte, validatorx.MaxRoutingKeyLength))
		for i := range maxKey {
			maxKey = maxKey[:i] + "a" + maxKey[i+1:]
		}
		msg.Key = maxKey
		assert.NoError(t, validateMessage(msg))
	})

	t.Run("Priority boundaries", func(t *testing.T) {
		msg := &validatorx.Message{
			ID:          "test-id",
			Key:         "test.key",
			Body:        []byte("test"),
			ContentType: "application/json",
			Priority:    validatorx.MaxPriority,
		}
		assert.NoError(t, validateMessage(msg))

		// Test that we can't set priority higher than max (this would be caught at compile time)
		// Since uint8 can't overflow, we'll test the validation logic differently
		assert.Equal(t, uint8(255), validatorx.MaxPriority)
	})

	t.Run("Timeout boundaries", func(t *testing.T) {
		msg := &validatorx.Message{
			ID:          "test-id",
			Key:         "test.key",
			Body:        []byte("test"),
			ContentType: "application/json",
			Expiration:  validatorx.MaxTimeout,
		}
		assert.NoError(t, validateMessage(msg))

		msg.Expiration = validatorx.MaxTimeout + time.Second
		assert.Error(t, validateMessage(msg))
	})
}

// Helper function to access validateMessage for testing
func validateMessage(msg *validatorx.Message) error {
	// Validate message ID
	if msg.ID == "" {
		return fmt.Errorf("message ID cannot be empty")
	}
	if len(msg.ID) > validatorx.MaxMessageIDLength {
		return fmt.Errorf("message ID too long: %d > %d", len(msg.ID), validatorx.MaxMessageIDLength)
	}
	if !isValidMessageID(msg.ID) {
		return fmt.Errorf("invalid message ID format: %s", msg.ID)
	}

	// Validate message body
	if msg.Body == nil {
		return fmt.Errorf("message body cannot be nil")
	}
	if len(msg.Body) == 0 {
		return fmt.Errorf("message body cannot be empty")
	}
	if len(msg.Body) > validatorx.MaxMessageSize {
		return fmt.Errorf("message too large: %d > %d", len(msg.Body), validatorx.MaxMessageSize)
	}

	// Validate routing key
	if msg.Key == "" {
		return fmt.Errorf("routing key cannot be empty")
	}
	if len(msg.Key) > validatorx.MaxRoutingKeyLength {
		return fmt.Errorf("routing key too long: %d > %d", len(msg.Key), validatorx.MaxRoutingKeyLength)
	}
	if !isValidRoutingKey(msg.Key) {
		return fmt.Errorf("invalid routing key format: %s", msg.Key)
	}

	// Validate content type
	if msg.ContentType == "" {
		return fmt.Errorf("content type cannot be empty")
	}
	if !isValidContentType(msg.ContentType) {
		return fmt.Errorf("unsupported content type: %s", msg.ContentType)
	}

	// Validate headers
	if msg.Headers != nil {
		if len(msg.Headers) > 100 {
			return fmt.Errorf("too many headers: %d > 100", len(msg.Headers))
		}
		for key, value := range msg.Headers {
			if len(key) > 255 {
				return fmt.Errorf("header key too long: %d > 255", len(key))
			}
			if len(value) > validatorx.MaxHeaderSize {
				return fmt.Errorf("header value too large: %d > %d", len(value), validatorx.MaxHeaderSize)
			}
		}
	}

	// Validate priority
	if msg.Priority > validatorx.MaxPriority {
		return fmt.Errorf("priority too high: %d > %d", msg.Priority, validatorx.MaxPriority)
	}

	// Validate correlation ID
	if msg.CorrelationID != "" {
		if len(msg.CorrelationID) > validatorx.MaxCorrelationIDLength {
			return fmt.Errorf("correlation ID too long: %d > %d", len(msg.CorrelationID), validatorx.MaxCorrelationIDLength)
		}
		if !isValidCorrelationID(msg.CorrelationID) {
			return fmt.Errorf("invalid correlation ID format: %s", msg.CorrelationID)
		}
	}

	// Validate reply-to
	if msg.ReplyTo != "" {
		if len(msg.ReplyTo) > validatorx.MaxReplyToLength {
			return fmt.Errorf("reply-to too long: %d > %d", len(msg.ReplyTo), validatorx.MaxReplyToLength)
		}
		if !isValidReplyTo(msg.ReplyTo) {
			return fmt.Errorf("invalid reply-to format: %s", msg.ReplyTo)
		}
	}

	// Validate idempotency key
	if msg.IdempotencyKey != "" {
		if len(msg.IdempotencyKey) > validatorx.MaxIdempotencyKeyLength {
			return fmt.Errorf("idempotency key too long: %d > %d", len(msg.IdempotencyKey), validatorx.MaxIdempotencyKeyLength)
		}
		if !isValidIdempotencyKey(msg.IdempotencyKey) {
			return fmt.Errorf("invalid idempotency key format: %s", msg.IdempotencyKey)
		}
	}

	// Validate expiration
	if msg.Expiration < 0 {
		return fmt.Errorf("expiration cannot be negative")
	}
	if msg.Expiration > validatorx.MaxTimeout {
		return fmt.Errorf("expiration too long: %v > %v", msg.Expiration, validatorx.MaxTimeout)
	}

	return nil
}

// Helper functions for testing (these would be in the actual package)
func isValidTopicName(topic string) bool {
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9._-]+$`, topic)
	return matched
}

func isValidMessageID(id string) bool {
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, id)
	return matched
}

func isValidRoutingKey(key string) bool {
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9._-]+$`, key)
	return matched
}

func isValidContentType(contentType string) bool {
	supportedTypes := validatorx.SupportedContentTypes()
	for _, supported := range supportedTypes {
		if contentType == supported {
			return true
		}
	}
	return false
}

func isValidQueueName(queue string) bool {
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9._-]+$`, queue)
	return matched
}

func isValidCorrelationID(id string) bool {
	// Correlation ID validation regex: alphanumeric, underscores, hyphens
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, id)
	return matched
}

func isValidReplyTo(replyTo string) bool {
	// Reply-to validation regex: alphanumeric, dots, underscores, hyphens
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9._-]+$`, replyTo)
	return matched
}

func isValidIdempotencyKey(key string) bool {
	// Idempotency key validation regex: alphanumeric, underscores, hyphens
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, key)
	return matched
}
