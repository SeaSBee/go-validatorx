# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2024-12-19

### Added
- **Enhanced Duration Validation**: Added support for human-readable duration strings in validation tags
- **Duration String Formats**: Support for `1s`, `30s`, `5m`, `1h`, `100ms`, `24h`, etc.
- **Decimal Duration Support**: Support for decimal durations like `1.5s`, `0.5s`
- **Comprehensive Test Coverage**: Added 40+ test cases for duration validation
- **Backward Compatibility**: Maintained support for nanosecond values for existing code

### Changed
- **Improved Error Messages**: More user-friendly error messages for duration validation
- **Updated Examples**: Changed struct examples to use human-readable duration strings instead of nanosecond values
- **Enhanced Validation Logic**: Better parsing logic with fallback support

### Fixed
- **Duration Validation Issue**: Fixed confusion with nanosecond values in validation tags
- **Error Handling**: Improved error handling for invalid duration parameters

### Examples

**Before (confusing nanosecond values):**
```go
type Config struct {
    Timeout time.Duration `validate:"required,min:1000000000,max:300000000000"`
}
```

**After (clear duration strings):**
```go
type Config struct {
    Timeout time.Duration `validate:"required,min:1s,max:5m"`
}
```

**Supported Duration Formats:**
- `"1s"` - 1 second
- `"30s"` - 30 seconds  
- `"5m"` - 5 minutes
- `"1h"` - 1 hour
- `"100ms"` - 100 milliseconds
- `"24h"` - 24 hours
- `"1.5s"` - 1.5 seconds (decimal support)
- Nanosecond values (backward compatibility)

## [1.0.0] - Initial Release

### Added
- Core validation framework
- Struct tag validation
- Built-in validation rules (required, min, max, email, url, etc.)
- Custom validation rule support
- Context-aware validation
- Comprehensive test suite
