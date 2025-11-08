# 🛡️ Spring Boot 3 JWT Authentication

This project implements a modern **JWT-based authentication system** using **Spring Boot 3** and **Spring Security 6**.

It provides a clean and production-ready structure for securing REST APIs with JSON Web Tokens (JWT).

---

## 🚀 Features

- ✅ User Registration and Login (JWT issued on login)
- ✅ Stateless Authentication (no sessions)
- ✅ Role-based Authorization (using `GrantedAuthority`)
- ✅ Custom JWT Filter integrated with Spring Security
- ✅ Secure password hashing using BCrypt
- ✅ Spring Boot 3 & Spring Security 6 configuration style (no deprecated `WebSecurityConfigurerAdapter`)
- ✅ H2 Database for quick testing (replaceable with PostgreSQL/MySQL)

---


---

## ⚙️ Tech Stack

| Layer | Technology |
|-------|-------------|
| Backend Framework | Spring Boot 3 |
| Security | Spring Security 6, JWT |
| ORM | Spring Data JPA |
| Database | H2 (in-memory) |
| Build Tool | Maven / Gradle |
| Language | Java 17+ |

---

## 🔐 JWT Flow

1. **Register/Login**
    - User sends credentials to `/api/v1/auth/register` or `/api/v1/auth/authenticate`.
    - Backend verifies credentials and returns a JWT token.

2. **Access Protected Endpoints**
    - User includes `Authorization: Bearer <token>` in the header.
    - `JwtAuthenticationFilter`:
        - Extracts and validates token.
        - Loads user details.
        - Sets authentication in the `SecurityContextHolder`.
    - Request continues to controller if token is valid.

---

## 🧩 Core Classes

### 🔸 JwtAuthenticationFilter
Custom filter that runs **once per request**:
```java
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        String jwt = authHeader.substring(7);
        String userEmail = jwtService.extractUsername(jwt);

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
            if (jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        chain.doFilter(request, response);
    }
}
```

### 🔸 Security Configuration
```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .authorizeHttpRequests()
            .requestMatchers("/api/v1/auth/**").permitAll()
            .anyRequest().authenticated()
            .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authenticationProvider(authenticationProvider)
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
```

## 🧾 API Endpoints
| Method | Endpoint                    | Description                | Auth Required |
| ------ | --------------------------- | -------------------------- | ------------- |
| `POST` | `/api/v1/auth/register`     | Register a new user        | ❌             |
| `POST` | `/api/v1/auth/authenticate` | Login and receive JWT      | ❌             |
| `GET`  | `/api/v1/demo`              | Example protected endpoint | ✅             |

## ⚡ Running the App

1. Clone the repo
```bash
  git clone https://github.com/yourusername/spring-jwt-auth.git
  cd spring-jwt-auth
```
2. Configure database (optional). Default is H2 in-memory DB. To use PostgreSQL/MySQL, update application.yml.
3. Run
```bash
  mvn spring-boot:run
```
4. Access the app at http://localhost:8080

## 🧩 Future Improvements

- Refresh tokens
- Logout endpoint
- Role-based access control (ADMIN/USER)
- Integration with PostgreSQL and Docker

## 🙌 Credits

Inspired by Amigoscode’s Spring Boot JWT tutorial
