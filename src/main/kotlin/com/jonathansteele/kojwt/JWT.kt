package com.jonathansteele.kojwt

import java.util.concurrent.ConcurrentHashMap
import kotlinx.serialization.*
import kotlinx.serialization.json.*
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlinx.datetime.Clock
import org.kotlincrypto.macs.hmac.sha2.HmacSHA256

// JWT Header
@Serializable
data class JwtHeader(val alg: String = "HS256", val typ: String = "JWT")

// JWT Payload
@Serializable
data class JwtPayload(
    val sub: String,
    val exp: Long,
    val iat: Long = Clock.System.now().epochSeconds,
    val claims: Map<String, String> = emptyMap()
)

// Refresh Token Payload
@Serializable
data class RefreshTokenPayload(
    val sub: String,
    val exp: Long,
    val iat: Long = Clock.System.now().epochSeconds
)

// Generalized Token Blacklist for all token types
object TokenBlacklist {
    private val revokedTokens = ConcurrentHashMap.newKeySet<String>()

    // Add a token to the blacklist
    fun revoke(token: String) {
        revokedTokens.add(token)
    }

    // Check if a token is revoked
    fun isRevoked(token: String): Boolean {
        return token in revokedTokens
    }
}

// Function to sign data with HMACSHA256
fun signHMACSHA256(data: String, secret: String): ByteArray {
    val mac = HmacSHA256(secret.toByteArray(Charsets.UTF_8))
    return mac.doFinal(data.toByteArray(Charsets.UTF_8))
}

// Base64 URL-safe encoding functions using kotlinx-io
@OptIn(ExperimentalEncodingApi::class)
private fun base64UrlEncode(input: String): String {
    return Base64.UrlSafe.encode(input.toByteArray(Charsets.UTF_8))
}

@OptIn(ExperimentalEncodingApi::class)
private fun base64UrlEncode(input: ByteArray): String {
    return Base64.UrlSafe.encode(input)
}

// Base64 URL-safe decoding functions using kotlinx-io
@OptIn(ExperimentalEncodingApi::class)
fun base64UrlDecode(input: String): String {
    return Base64.UrlSafe.decode(input).decodeToString()
}

@OptIn(ExperimentalEncodingApi::class)
fun base64UrlDecodeToBytes(input: String): ByteArray {
    return Base64.UrlSafe.decode(input)
}

// Utility to check expiration
fun <T> checkExpiration(payload: T, validateExpiration: Boolean): Boolean {
    if (!validateExpiration) return true

    val currentTime = Clock.System.now().epochSeconds
    val expirationTime = when (payload) {
        is JwtPayload -> payload.exp
        is RefreshTokenPayload -> payload.exp
        else -> throw IllegalArgumentException("Unsupported token type for expiration check")
    }

    return currentTime < expirationTime
}

// Function to encode JWT
fun encodeJwt(payload: JwtPayload, secret: String): String {
    // Header and payload in JSON form
    val headerJson = Json.encodeToString(JwtHeader())
    val payloadJson = Json.encodeToString(payload)

    // Base64 URL encoding of both the header and payload
    val base64Header = base64UrlEncode(headerJson)
    val base64Payload = base64UrlEncode(payloadJson)

    // Concatenate header and payload for signing
    val dataToSign = "$base64Header.$base64Payload"

    // Generate signature using HMACSHA256
    val signature = signHMACSHA256(dataToSign, secret)
    val base64Signature = base64UrlEncode(signature)

    // Return the complete JWT token
    return "$base64Header.$base64Payload.$base64Signature"
}

// Function to decode and validate JWT
fun decodeJwt(jwt: String, secret: String, validateExpiration: Boolean = true): JwtPayload {
    if (TokenBlacklist.isRevoked(jwt)) throw IllegalArgumentException("JWT has been revoked")

    val parts = jwt.split(".")
    if (parts.size != 3) {
        throw IllegalArgumentException("Invalid JWT format")
    }

    val base64Header = parts[0]
    val base64Payload = parts[1]
    val base64Signature = parts[2]

    // Decode the payload
    val decodedPayload = base64UrlDecode(base64Payload)

    // Validate the signature by recomputing it
    val dataToSign = "$base64Header.$base64Payload"
    val expectedSignature = signHMACSHA256(dataToSign, secret)
    val decodedSignature = base64UrlDecodeToBytes(base64Signature)

    // Compare the generated signature with the one from the token
    if (!decodedSignature.contentEquals(expectedSignature)) {
        throw IllegalArgumentException("Invalid token signature")
    }

    // Expiration validation
    val payload = Json.decodeFromString<JwtPayload>(decodedPayload)
    if (!checkExpiration(payload, validateExpiration)) {
        throw IllegalArgumentException("JWT token has expired")
    }

    return payload
}

// Function to encode Refresh Token
fun encodeRefreshToken(payload: RefreshTokenPayload, secret: String): String {
    val payloadJson = Json.encodeToString(payload)

    // Base64 URL encoding and signing
    val base64Payload = base64UrlEncode(payloadJson)
    val signature = signHMACSHA256(base64Payload, secret)
    val base64Signature = base64UrlEncode(signature)

    return "$base64Payload.$base64Signature"
}

// Function to decode Refresh Token
fun decodeRefreshToken(refreshToken: String, secret: String): RefreshTokenPayload {
    if (TokenBlacklist.isRevoked(refreshToken)) throw IllegalArgumentException("Refresh token has been revoked")

    val parts = refreshToken.split(".")
    if (parts.size != 2) {
        throw IllegalArgumentException("Invalid refresh token format")
    }

    val base64Payload = parts[0]
    val base64Signature = parts[1]

    // Decode the payload
    val decodedPayload = base64UrlDecode(base64Payload)

    // Validate the signature
    val expectedSignature = signHMACSHA256(base64Payload, secret)
    val decodedSignature = base64UrlDecodeToBytes(base64Signature)

    if (!decodedSignature.contentEquals(expectedSignature)) {
        throw IllegalArgumentException("Invalid refresh token signature")
    }

    // Expiration check for refresh token
    val payload = Json.decodeFromString<RefreshTokenPayload>(decodedPayload)
    if (!checkExpiration(payload, validateExpiration = true)) {
        throw IllegalArgumentException("Refresh token has expired")
    }

    return payload
}
