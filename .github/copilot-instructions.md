# Copilot Instructions

## Project structure overview

This repository is a Quarkus Java application for authentication and token generation.

Main layout:
- `pom.xml`: Maven build and dependency management.
- `src/main/java/quantum/...`: application code (services, resources, repositories, models).
- `src/main/resources/...`: runtime configuration and key material used by the app.
- `src/test/java/quantum/...`: unit/integration tests.
- `src/test/resources/application.properties`: test configuration.
- `.github/workflows/...`: CI workflows (tests, security analysis, release).

Testing stack and style:
- JUnit 5 + Quarkus test (`@QuarkusTest`).
- Mutiny (`Uni`) for async/reactive flows.
- Mockito for repository mocking (`@InjectMock`).

## Test guidelines for reactive `Uni` code

When testing service methods that return `Uni`, do not use `.await().indefinitely()`.

Use `UniAssertSubscriber` as the standard pattern.

### Success path pattern

```java
var response = service.call(args)
    .subscribe()
    .withSubscriber(UniAssertSubscriber.create())
    .awaitItem()
    .assertCompleted()
    .getItem();

assertNotNull(response);
// ... other asserts ...
```

### Exception path pattern

```java
service.call(args)
    .subscribe()
    .withSubscriber(UniAssertSubscriber.create())
    .awaitFailure()
    .assertFailedWith(UnauthorizedException.class);
```

## Additional notes

- Keep tests deterministic and focused on behavior.
- Mock external dependencies (for example repositories) using `@InjectMock`.
- Assert domain outcomes (token content, status, validation behavior), not implementation details.
- Prefer one behavior per test and clear test names (`should...When...`).

