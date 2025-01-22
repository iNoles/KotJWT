package com.github.inoles.kojwt

import kotlinx.datetime.Clock
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlinx.coroutines.runBlocking
import kotlinx.atomicfu.atomic
import kotlinx.atomicfu.update

// JWT Header
@Serializable
data class JwtHeader(
    val alg: String,
    val typ: String = "JWT",
)

// JWT Payload
@Serializable
data class JwtPayload(
    val sub: String,
    val exp: Long,
    val iat: Long = Clock.System.now().epochSeconds,
    val claims: Map<String, String> = emptyMap(),
)

// Refresh Token Payload
@Serializable
data class RefreshTokenPayload(
    val sub: String,
    val exp: Long,
    val iat: Long = Clock.System.now().epochSeconds,
)

// Generalized Token Blacklist for all token types
object TokenBlacklist {
    private val revokedTokens = atomic(mutableSetOf<String>())

    // Add a token to the blacklist
    fun revoke(token: String) {
        revokedTokens.update { currentSet ->
            currentSet.toMutableSet().apply { add(token) }
        }
    }

    // Check if a token is revoked
    fun isRevoked(token: String): Boolean = token in revokedTokens.value
}

// Base64 URL-safe encoding functions using kotlinx-io
@OptIn(ExperimentalEncodingApi::class)
private fun base64UrlEncode(input: String): String = Base64.UrlSafe.encode(input.toByteArray(Charsets.UTF_8))

@OptIn(ExperimentalEncodingApi::class)
private fun base64UrlEncode(input: ByteArray): String = Base64.UrlSafe.encode(input)

// Base64 URL-safe decoding functions using kotlinx-io
@OptIn(ExperimentalEncodingApi::class)
fun base64UrlDecode(input: String): String = Base64.UrlSafe.decode(input).decodeToString()

@OptIn(ExperimentalEncodingApi::class)
fun base64UrlDecodeToBytes(input: String): ByteArray = Base64.UrlSafe.decode(input)

// Utility to check expiration
fun <T> checkExpiration(
    payload: T,
    validateExpiration: Boolean,
): Boolean {
    if (!validateExpiration) return true

    val currentTime = Clock.System.now().epochSeconds
    val expirationTime =
        when (payload) {
            is JwtPayload -> payload.exp
            is RefreshTokenPayload -> payload.exp
            else -> throw IllegalArgumentException("Unsupported token type for expiration check")
        }

    return currentTime < expirationTime
}

// Function to encode JWT
fun encodeJwt(
    payload: JwtPayload,
    secret: String,
    signer: JwtSigner,
): String = runBlocking {
    // Header and payload in JSON form
    val headerJson = Json.encodeToString(JwtHeader(alg = signer.alg))
    val payloadJson = Json.encodeToString(payload)

    // Base64 URL encoding of both the header and payload
    val base64Header = base64UrlEncode(headerJson)
    val base64Payload = base64UrlEncode(payloadJson)

    // Concatenate header and payload for signing
    val dataToSign = "$base64Header.$base64Payload"

    // Generate signature using HMACSHA256
    val signature = signer.sign(dataToSign, secret)
    val base64Signature = base64UrlEncode(signature)

    // Return the complete JWT token
    return@runBlocking "$base64Header.$base64Payload.$base64Signature"
}

fun decodeJwt(
    jwt: String,
    secret: String,
    signer: JwtSigner,
    validateExpiration: Boolean = true,
): JwtPayload = runBlocking {
    // Check if the JWT is revoked before proceeding
    if (TokenBlacklist.isRevoked(jwt)) {
        throw IllegalArgumentException("JWT has been revoked")
    }

    val parts = jwt.split(".")
    if (parts.size != 3) throw IllegalArgumentException("Invalid JWT format")

    val base64Header = parts[0]
    val base64Payload = parts[1]
    val base64Signature = parts[2]

    val dataToSign = "$base64Header.$base64Payload"
    val expectedSignature = base64UrlDecodeToBytes(base64Signature)

    if (!signer.verify(dataToSign, expectedSignature, secret)) {
        throw IllegalArgumentException("Invalid token signature")
    }

    val decodedPayload = base64UrlDecode(base64Payload)
    val payload = Json.decodeFromString<JwtPayload>(decodedPayload)

    if (!checkExpiration(payload, validateExpiration)) {
        throw IllegalArgumentException("JWT token has expired")
    }

    return@runBlocking payload
}

// Function to encode Refresh Token
fun encodeRefreshToken(
    payload: RefreshTokenPayload,
    secret: String,
    signer: JwtSigner,
): String = runBlocking {
    val payloadJson = Json.encodeToString(payload)

    // Base64 URL encoding and signing
    val base64Payload = base64UrlEncode(payloadJson)
    val signature = signer.sign(base64Payload, secret)
    val base64Signature = base64UrlEncode(signature)

    return@runBlocking "$base64Payload.$base64Signature"
}

// Function to decode Refresh Token
fun decodeRefreshToken(
    refreshToken: String,
    secret: String,
    signer: JwtSigner,
): RefreshTokenPayload = runBlocking {
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
    val decodedSignature = base64UrlDecodeToBytes(base64Signature)

    if (!signer.verify(base64Payload, decodedSignature, secret)) {
        throw IllegalArgumentException("Invalid refresh token signature")
    }

    // Expiration check for refresh token
    val payload = Json.decodeFromString<RefreshTokenPayload>(decodedPayload)
    if (!checkExpiration(payload, validateExpiration = true)) {
        throw IllegalArgumentException("Refresh token has expired")
    }
    return@runBlocking payload
}
