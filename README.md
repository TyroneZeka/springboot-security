
# Spring Boot Security Example Project

This project demonstrates how to implement security in a Spring Boot application using Spring Security. It covers various security aspects, including user authentication, role-based authorization, password hashing, JWT (JSON Web Token) for stateless authentication, and securing endpoints with HTTP Basic and OAuth2.

## Features

- **User Authentication:** Manage user login using Spring Security with customizable authentication providers.
- **Role-based Authorization:** Restrict access to endpoints based on user roles such as `USER`, `ADMIN`, etc.
- **Password Encryption:** Hash passwords using BCrypt.
- **JWT Authentication:** Secure endpoints using stateless authentication with JSON Web Tokens.
- **HTTP Basic Authentication:** Demonstrates basic authentication over HTTP.
- **OAuth2 Authorization:** Example of securing endpoints using OAuth2 for third-party authorization.
- **Custom Authentication & Authorization Filters:** Allows flexibility in the security flow.
- **Security Context Management:** Demonstrates how to maintain security context in a web session.

## Prerequisites

Ensure you have the following installed:
- Java 17+
- Maven 3.x+
- Spring Boot 3.x+
- IDE (IntelliJ, Eclipse, etc.)

## Getting Started

### Clone the repository

```bash
git clone https://github.com/TyroneZeka/springboot-security.git
cd springboot-security-example
```

### Configure Application Properties

Update the `application.yml` or `application.properties` file to include database credentials, secret keys for JWT, and OAuth2 client details if applicable.

```yaml
# Example application.yml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/dbname
    username: root
    password: root

security:
  jwt:
    secret: your_secret_key
    expiration: 86400000  # 1 day
```

### Database Setup

Ensure the database is set up and tables are created. If using JPA, entities will automatically map to tables.

```sql
CREATE TABLE users (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) NOT NULL UNIQUE,
  password VARCHAR(100) NOT NULL,
  role VARCHAR(50) NOT NULL
);
```

### Build & Run the Application

To build the project:

```bash
mvn clean install
```

To run the project:

```bash
mvn spring-boot:run
```

The application will start on `http://localhost:8080`.

## Authentication

### 1. In-memory Authentication

In-memory users are defined directly in the Spring Security configuration. You can check the commit for InMemoryAuthentication. You can create sample users as follows:

```java
@Bean
public UserDetailsService inMemoryUserDetailsManager() {
    UserDetails user = User.withUsername("user")
        .password(passwordEncoder().encode("password"))
        .roles("USER")
        .build();

    UserDetails admin = User.withUsername("admin")
        .password(passwordEncoder().encode("admin"))
        .roles("ADMIN")
        .build();

    return new InMemoryUserDetailsManager(user, admin);
}
```

### 2. JWT Authentication

JWT (JSON Web Token) allows for stateless authentication. When a user successfully logs in, a token is generated and sent back to the client. The client will then use this token for subsequent requests to protected endpoints.

#### Generating JWT

JWT is generated after successful login. Below is the JWT filter that intercepts the login request and generates the token:

```java
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        // Parsing request and authenticating
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) {
        // Generate JWT token and add it to the response header
    }
}
```

### 3. Role-based Authorization

Secure different endpoints using roles.

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .antMatchers("/api/admin/**").hasRole("ADMIN")
        .antMatchers("/api/user/**").hasRole("USER")
        .anyRequest().authenticated()
        .and()
        .httpBasic();
}
```

## Password Encryption

Passwords are encrypted using BCrypt to ensure security:

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

## Securing Endpoints

### 1. Securing with JWT

Endpoints can be secured using JWT by adding a filter in the Spring Security configuration.

```java
http.addFilterBefore(new JwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
```

### 2. Securing with OAuth2

For OAuth2 authorization, Spring Security can integrate with OAuth2 providers like Google or GitHub.

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: YOUR_CLIENT_ID
            client-secret: YOUR_CLIENT_SECRET
            scope: profile, email
            redirect-uri: "{baseUrl}/login/oauth2/code/google"
```

## Example Endpoints

- `/login`: To authenticate the user and receive a JWT token.
- `/api/admin`: Requires `ADMIN` role.
- `/api/user`: Requires `USER` role.
- `/api/public`: Public endpoint accessible to anyone.

## Postman Collection

A sample Postman collection is available in the `postman/` folder to help test the application.

## Running Tests

To run unit tests:

```bash
mvn test
```

## Technologies Used

- **Spring Boot**
- **Spring Security**
- **JWT**
- **OAuth2**
- **BCrypt**
- **Maven**

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
