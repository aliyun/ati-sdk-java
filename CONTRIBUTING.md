# Contributing

## Prerequisites

- Java 17+
- Gradle 8.5+

## Build

```bash
./gradlew clean build
```

## Code Style

- [Checkstyle](config/checkstyle/checkstyle.xml) is enforced on every build
- Maximum warnings allowed: **0**
- Run checkstyle manually:

```bash
./gradlew checkstyleMain checkstyleTest
```

## Commit Format

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description
```

**Types:**

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `refactor` | Code refactoring |
| `chore` | Build, deps, config |
| `docs` | Documentation |
| `test` | Tests |

**Examples:**

```
feat(agent-client): add TLSA port override for proxy connections
fix(transparency): handle empty badge URL
refactor(core): simplify HTTP client factory
docs: update README installation section
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Make your changes
4. Ensure all tests pass: `./gradlew clean build`
5. Ensure checkstyle passes (0 warnings)
6. Create a pull request with a clear description

## Module Structure

| Module | Path | Description |
|--------|------|-------------|
| ati-sdk-core | `ati-sdk-core/` | Configuration, auth, HTTP, utilities |
| ati-sdk-discovery | `ati-sdk-discovery/` | Agent resolution via DNS TXT |
| ati-sdk-transparency | `ati-sdk-transparency/` | Transparency log verification (+ SCITT infrastructure, planned) |
| ati-sdk-agent-client | `ati-sdk-agent-client/` | Secure agent-to-agent connections |
| ati-sdk-spring-boot-starter | `ati-sdk-spring-boot-starter/` | Spring Boot auto-configuration |
