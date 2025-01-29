# KotJWT

KotJWT is a lightweight Kotlin Multiplatform library designed for encoding, decoding, and managing JSON Web Tokens (JWT) and refresh tokens. It supports a variety of cryptographic algorithms, including HMAC SHA-256, ECDSA, and RSA, while providing essential features like token expiration validation, blacklist management, and secure token handling.

## ✨ Features

- **JWT Support** – Encode and decode JWTs with HMAC SHA-256, ECDSA, and RSA signing.
- **Refresh Token Support** – Securely generate and validate refresh tokens.
- **Expiration Handling** – Automatically checks if a token is expired.
- **Token Blacklist** – Prevent the use of revoked tokens.
- **base64 URL-Safe Encoding** – Secure encoding and decoding for JWTs and refresh tokens.
- **Multiple Signing Algorithms** – Supports HMAC, ECDSA, and RSA for signing JWTs.
- **Kotlin Multiplatform Support** – Now available for JVM, iOS, macOS, and other platforms.

## 🚀 Usage

### Encoding a JWT

To encode a JWT, you need to create a `JwtPayload` and use the `encodeJwt` function:

```kotlin
import com.jonathansteele.kojwt.*

val payload = JwtPayload(
    sub = "user123",
    exp = System.currentTimeMillis() / 1000 + 3600  // Expire in 1 hour
)
val secret = "your-secret-key"

val jwt = encodeJwt(payload, secret)
println("Encoded JWT: $jwt")
```

### Decoding a JWT

To decode a JWT, use the `decodeJwt` function:

```kotlin
val decodedPayload = decodeJwt(jwt, secret)
println("Decoded Payload: $decodedPayload")
```

### Encoding a Refresh Token

You can encode a refresh token using the `encodeRefreshToken` function:

```kotlin
val refreshTokenPayload = RefreshTokenPayload(
    sub = "user123",
    exp = System.currentTimeMillis() / 1000 + 86400  // Expire in 24 hours
)
val refreshToken = encodeRefreshToken(refreshTokenPayload, secret)
println("Encoded Refresh Token: $refreshToken")
```

### Decoding a Refresh Token

To decode a refresh token, use the decodeRefreshToken function:

```kotlin
val decodedRefreshToken = decodeRefreshToken(refreshToken, secret)
println("Decoded Refresh Token: $decodedRefreshToken")
```

### Blacklisting Tokens

You can add tokens to the blacklist to prevent further use:

```kotlin
TokenBlacklist.revoke(jwt)
TokenBlacklist.revoke(refreshToken)
```

## 🛣 Roadmap

- Kotlin Multiplatform support for additional targets

## Contributions 🤝

This project is a work in progress, and contributions are welcome! Feel free to:

- Submit issues for bugs or feature suggestions
- Open pull requests to contribute directly
