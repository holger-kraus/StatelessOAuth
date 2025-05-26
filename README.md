# Stateless Spring Security Demo

This project demonstrates how to implement a fully stateless authentication mechanism in a Spring Security application using JWT tokens stored in cookies. The implementation eliminates server-side sessions entirely while maintaining security and OAuth2 integration.

## Overview

Traditional Spring Security applications rely on server-side sessions to maintain authentication state. This project replaces these sessions with stateless JWT-based authentication where:

1. Authentication state is stored entirely in JWT tokens
2. Tokens are transmitted via HTTP-only cookies
3. No server-side sessions are maintained

## Key Components

### Stateless Session Configuration

The application configures Spring Security to operate without sessions:

```java
// SecurityConfig.java
http.sessionManagement()
    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
    .sessionAuthenticationStrategy(new NullAuthenticatedSessionStrategy());
```

### JWT Token Management

- **JwtTokenProvider**: Handles token creation, validation, and extraction of authentication details
- Tokens are created upon successful authentication and stored in cookies
- Each request is authenticated by validating the token present in the cookie

### Authentication Flow

1. **Login**:
   - User authenticates via OAuth2 (e.g., Keycloak)
   - Upon successful authentication, a JWT token is generated
   - Token is stored in an HTTP-only cookie named "access_token"

2. **Request Processing**:
   - `TokenAuthenticationFilter` intercepts each request
   - Extracts JWT from the cookie
   - Validates token and creates Authentication object
   - Populates SecurityContext without creating a session

3. **OAuth2 Flow**:
   - OAuth2 authorization requests are stored in temporary cookies
   - No server-side session state is maintained during the flow

## Benefits

- **Scalability**: No need to replicate session state across servers
- **Resilience**: No session synchronization issues in clustered environments
- **Statelessness**: True RESTful stateless architecture
- **Security**: HTTP-only cookies protect tokens from XSS attacks

## Implementation Details

- JWT cookies are configured with appropriate security attributes (HTTP-only, Secure, SameSite)
- CSRF protection is disabled as it's not needed with proper cookie configuration
- Token expiration is handled automatically, requiring re-authentication after expiry

This implementation allows for horizontal scaling of the application while maintaining security best practices.