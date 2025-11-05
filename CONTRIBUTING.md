# Contributing to rkik-nts

Thank you for your interest in contributing to rkik-nts!

## Development Setup

1. Install Rust (stable): https://rustup.rs/
2. Clone the repository
3. Run tests: `cargo test`
4. Run examples: `cargo run --example simple_client --features tracing-subscriber`

## Project Structure

```
rkik-nts/
├── src/
│   ├── lib.rs           # Main library entry point
│   ├── client.rs        # High-level NTS client
│   ├── config.rs        # Configuration types
│   ├── error.rs         # Error types
│   ├── nts_ke.rs        # NTS key exchange implementation
│   └── types.rs         # Common types
├── examples/            # Example programs
└── tests/              # Integration tests
```

## Building

```bash
# Build the library
cargo build

# Build with all features
cargo build --all-features

# Run tests
cargo test

# Run examples
cargo run --example simple_client --features tracing-subscriber
```

## Code Style

- Follow the [Rust Style Guide](https://doc.rust-lang.org/1.0.0/style/)
- Run `cargo fmt` before committing
- Run `cargo clippy` and address warnings
- Add documentation for public APIs
- Write tests for new functionality

## Testing

All contributions should include appropriate tests:

```bash
# Run all tests
cargo test

# Run tests with logging
RUST_LOG=debug cargo test

# Run a specific test
cargo test test_name
```

## Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Add tests
5. Run `cargo fmt` and `cargo clippy`
6. Commit with a clear message
7. Push and create a pull request

## Integration with rkik

This library is designed for integration with rkik. When making changes:

- Keep the public API simple and ergonomic
- Ensure backward compatibility
- Document any breaking changes
- Consider performance implications

## Questions?

Feel free to open an issue for questions or discussions!
