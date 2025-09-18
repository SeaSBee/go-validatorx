# Release Notes - go-validatorx v1.1.1

## 🎉 Enhanced Duration Validation

We're excited to announce **go-validatorx v1.1.1** with major improvements to duration validation!

### ✨ What's New

#### **Human-Readable Duration Strings**
No more confusing nanosecond values! You can now use intuitive duration strings in your validation tags:

```go
type Config struct {
    Timeout     time.Duration `validate:"required,min:1s,max:30s"`
    Expiration  time.Duration `validate:"omitempty,min:0,max:24h"`
    RetryDelay  time.Duration `validate:"required,min:100ms,max:5m"`
}
```

#### **Supported Duration Formats**
- ✅ **Seconds**: `"1s"`, `"30s"`, `"5s"`
- ✅ **Minutes**: `"1m"`, `"5m"`, `"30m"`
- ✅ **Hours**: `"1h"`, `"2h"`, `"24h"`
- ✅ **Milliseconds**: `"100ms"`, `"500ms"`
- ✅ **Decimal**: `"1.5s"`, `"0.5s"` (Go's built-in support)
- ✅ **Mixed**: `"1h30m"`, `"90s"`

#### **Backward Compatibility**
Existing code with nanosecond values continues to work:

```go
// Still works!
Timeout time.Duration `validate:"required,min:1000000000,max:300000000000"`
```

### 🔧 Technical Improvements

- **Enhanced Parsing Logic**: Better duration string parsing with fallback support
- **Improved Error Messages**: Clear, helpful error messages for invalid duration parameters
- **Comprehensive Testing**: 40+ new test cases covering all duration formats
- **Type Safety**: Proper `time.Duration` type checking

### 📊 Test Coverage

```bash
=== RUN   TestValidateMin/DurationStringFormats
=== RUN   TestValidateMin/DurationNanosecondBackwardCompatibility  
=== RUN   TestValidateMin/DurationInvalidParameters
=== RUN   TestValidateMin/DurationValidDecimalFormats
=== RUN   TestValidateMax/DurationStringFormats
=== RUN   TestValidateMax/DurationNanosecondBackwardCompatibility
=== RUN   TestValidateMax/DurationInvalidParameters
=== RUN   TestValidateMax/DurationValidDecimalFormats
--- PASS: All duration validation tests
```

### 🚀 Migration Guide

**Before (v1.0.0):**
```go
type Message struct {
    Expiration time.Duration `validate:"omitempty,min:0,max:86400000000000"`
}

type PublisherConfig struct {
    PublishTimeout time.Duration `validate:"required,min:1000000000,max:300000000000"`
}
```

**After (v1.1.1):**
```go
type Message struct {
    Expiration time.Duration `validate:"omitempty,min:0,max:24h"`
}

type PublisherConfig struct {
    PublishTimeout time.Duration `validate:"required,min:1s,max:5m"`
}
```

### 🐛 Bug Fixes

- Fixed confusion with nanosecond values in validation tags
- Improved error handling for invalid duration parameters
- Enhanced validation logic for better user experience

### 📈 Performance

- No performance impact
- Maintained all existing functionality
- Added comprehensive test coverage

### 🔄 Breaking Changes

**None!** This release is fully backward compatible.

### 📦 Installation

```bash
go get github.com/seasbee/go-validatorx@v1.1.1
```

### 🎯 What's Next

- More validation rule types
- Enhanced struct validation
- Performance optimizations
- Additional test coverage

---

**Full Changelog**: https://github.com/seasbee/go-validatorx/compare/v1.0.0...v1.1.1

**Documentation**: https://github.com/seasbee/go-validatorx/blob/main/README.md

**Issues & Feedback**: https://github.com/seasbee/go-validatorx/issues
