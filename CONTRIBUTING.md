# Contributing to GServer-RS

Thank you for your interest in contributing to GServer-RS! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on what is best for the community
- Show empathy towards other community members

## Getting Started

### Prerequisites

- Rust 1.70 or later
- Git
- A text editor or IDE (VSCode, IntelliJ IDEA, etc.)

### Setting Up Your Development Environment

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/gserver-rs.git
   cd gserver-rs
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/vinvicta/gserver-rs.git
   ```
4. Create a branch for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Workflow

### Making Changes

1. Make your changes in your branch
2. Write tests for new functionality
3. Ensure all tests pass:
   ```bash
   cargo test
   ```
4. Format your code:
   ```bash
   cargo fmt
   ```
5. Run clippy:
   ```bash
   cargo clippy -- -D warnings
   ```

### Commit Messages

Follow conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:
```
feat(protocol): add support for PLO_SHOWIMG packet

Implement the showimg command for displaying dynamic image
overlays on players. Includes full parsing of the packet
format and proper handling of all parameters.

Closes #123
```

```
fix(connection): handle GEN_5 decryption order correctly

The decrypt step must happen before decompression for GEN_5 packets.
This was causing immediate disconnections for modern clients.

Fixes #456
```

### Pull Requests

1. Push your changes to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
2. Open a pull request on GitHub
3. Fill out the pull request template
4. Wait for review and address any feedback

### Pull Request Checklist

- [ ] Code compiles without warnings
- [ ] All tests pass
- [ ] New features include tests
- [ ] Documentation is updated
- [ ] Commit messages follow conventions
- [ ] Only one feature/fix per PR (unless related)

## Coding Standards

### Rust Style

- Follow standard Rust style guidelines (`cargo fmt`)
- Use `clippy` suggestions (`cargo clippy`)
- Prefer idiomatic Rust patterns
- Avoid `unsafe` code unless absolutely necessary

### Documentation

- Document all public items with `///` or `//!`
- Include examples for complex functions
- Add `# C++ Equivalence` comments when referencing the C++ implementation
- Document the purpose of modules and structs

### Example Documentation

```rust
/// Handle a packet from the client
///
/// # Purpose
/// Processes incoming packets and routes them to the appropriate handler.
///
/// # C++ Equivalence
/// Matches `IPacketHandler::handlePacket()` in IPacketHandler.cpp
///
/// # Arguments
/// * `packet` - The packet to process
///
/// # Returns
/// - `Ok(())` if the packet was handled successfully
/// - `Err(e)` if an error occurred during processing
///
/// # Example
/// ```rust,no_run
/// let result = connection.handle_packet(packet).await;
/// match result {
///     Ok(()) => println!("Packet handled"),
///     Err(e) => eprintln!("Error: {:?}", e),
/// }
/// ```
pub async fn handle_packet(&self, packet: PacketIn) -> Result<()> {
    // ...
}
```

## Testing

### Unit Tests

Write unit tests for all non-trivial functions:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_name() {
        let result = function_to_test();
        assert_eq!(result, expected_value);
    }
}
```

### Integration Tests

Add integration tests in the `tests/` directory for testing multiple components together.

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run tests for specific crate
cargo test -p gserver-protocol

# Run specific test
cargo test test_function_name
```

## Areas Needing Help

### High Priority

- [ ] NPC AI system
- [ ] Weapon script execution
- [ ] Board modification handling
- [ ] File upload/download
- [ ] Integration tests

### Medium Priority

- [ ] GS2 scripting language
- [ ] Guild system
- [ ] Translation system
- [ ] Performance benchmarks

### Low Priority

- [ ] Documentation improvements
- [ ] Example configurations
- [ ] Docker setup
- [ ] Monitoring/metrics

## Questions?

Feel free to open an issue for discussion or ask questions in your pull request.

## License

By contributing, you agree that your contributions will be licensed under the GNU General Public License v3.0.
