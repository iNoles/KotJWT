package com.github.inoles.kojwt

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.RSA
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Clock
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.DurationUnit
import kotlin.time.toDuration

class JwtTests {
    private val secret = "mysecretkey"
    private val sub = "user123"
    private val refreshTokenExpiration = Clock.System.now().epochSeconds + 86400 // Refresh token expires in 1 day

    @Test
    fun `test JWT encoding and decoding with HS256`() {
        val hmacSigner = HmacSigner()
        // Create a sample payload with a 1-hour expiration
        val payload =
            JwtPayload(
                sub = sub,
                exp =
                    Clock.System
                        .now()
                        .plus(3600.toDuration(DurationUnit.SECONDS))
                        .epochSeconds,
            )

        // Encode JWT
        val jwt = encodeJwt(payload, secret, signer = hmacSigner)

        // Decode JWT and verify payload matches
        val decodedPayload = decodeJwt(jwt, secret, signer = hmacSigner)
        assertEquals(payload.sub, decodedPayload.sub, "JWT subject should match")
        assertEquals(payload.exp, decodedPayload.exp, "JWT expiration should match")
    }

    @Test
    fun `test JWT expiration with HS384`() {
        val hmacSigner = HmacSigner(HmacAlgorithm.HS384)

        // Create an expired payload (expired 1 hour ago)
        val expiredPayload =
            JwtPayload(
                sub = sub,
                exp =
                    Clock.System
                        .now()
                        .minus(3600.toDuration(DurationUnit.SECONDS))
                        .epochSeconds,
            )
        val expiredJwt = encodeJwt(expiredPayload, secret, hmacSigner)

        // Ensure decoding the expired JWT throws an exception
        assertFailsWith<IllegalArgumentException>("JWT token has expired") {
            decodeJwt(expiredJwt, secret, signer = hmacSigner)
        }
    }

    @Test
    fun `test revocation of JWT with HS512`() {
        val hmacSigner = HmacSigner(HmacAlgorithm.HS512)

        // Create and encode a new JWT
        val payload =
            JwtPayload(
                sub = sub,
                exp =
                    Clock.System
                        .now()
                        .plus(3600.toDuration(DurationUnit.SECONDS))
                        .epochSeconds,
            )
        val jwt = encodeJwt(payload, secret, hmacSigner)

        // Log the JWT being revoked
        println("Revoking JWT: $jwt")

        // Revoke the JWT
        TokenBlacklist.revoke(jwt)

        // Check if the JWT is in the blacklist
        assertTrue(TokenBlacklist.isRevoked(jwt), "JWT should be revoked")

        // Log after revocation check
        println("JWT revoked check: ${TokenBlacklist.isRevoked(jwt)}")

        // Attempt to decode a revoked JWT (should throw an exception)
        assertFailsWith<IllegalArgumentException>("JWT has been revoked") {
            decodeJwt(jwt, secret, signer = hmacSigner)
        }
    }

    @Test
    fun `test encode and decode refresh token with EC256`() {
        val ecSigner = ECSigner(ECAlgorithm.ES256)

        // Create the refresh token payload with a 1-day expiration
        val refreshTokenPayload = RefreshTokenPayload(sub = sub, exp = refreshTokenExpiration)

        // Encode the refresh token
        val refreshToken = encodeRefreshToken(refreshTokenPayload, secret, ecSigner)

        // Revoke the refresh token
        TokenBlacklist.revoke(refreshToken)

        // Try to decode the revoked refresh token (should throw exception)
        assertFailsWith<IllegalArgumentException>("Refresh token has been revoked") {
            decodeRefreshToken(refreshToken, secret, ecSigner)
        }
    }

    @Test
    fun `test refresh token revocation with EC512`() {
        val ecSigner = ECSigner(ECAlgorithm.ES512)

        // Create the refresh token payload with a 1-day expiration
        val refreshTokenPayload = RefreshTokenPayload(sub = sub, exp = refreshTokenExpiration)

        // Encode the refresh token
        val refreshToken = encodeRefreshToken(refreshTokenPayload, secret, ecSigner)

        // Revoke the refresh token
        TokenBlacklist.revoke(refreshToken)

        // Try to decode the revoked refresh token (should throw exception)
        assertFailsWith<IllegalArgumentException>("Refresh token has been revoked") {
            decodeRefreshToken(refreshToken, secret, ecSigner)
        }
    }

    @Test
    fun `test refresh token expiration with HS512`() {
        val hmacSigner = HmacSigner(HmacAlgorithm.HS512)

        // Create an expired refresh token payload (expired 10 seconds ago)
        val expiredRefreshTokenPayload = RefreshTokenPayload(sub = sub, exp = Clock.System.now().epochSeconds - 10)

        // Encode the expired refresh token
        val expiredRefreshToken = encodeRefreshToken(expiredRefreshTokenPayload, secret, hmacSigner)

        // Try to decode the expired refresh token (should throw exception)
        assertFailsWith<IllegalArgumentException>("Refresh token has expired") {
            decodeRefreshToken(expiredRefreshToken, secret, hmacSigner)
        }
    }

    @Test
    fun `test JWT encoding and decoding with RSA256`() =
        runTest {
            // Generate RSA key pair using the cryptography provider
            val provider = CryptographyProvider.Default
            val keyPair = provider.get(RSA.PKCS1).keyPairGenerator().generateKey()
            val privateKey = keyPair.privateKey
            val publicKey = keyPair.publicKey

            val rsaSigner = RSASigner(RSAAlgorithm.RS256, privateKey, publicKey)

            // Create a sample payload with a 1-hour expiration
            val payload =
                JwtPayload(
                    sub = sub,
                    exp =
                        Clock.System
                            .now()
                            .plus(3600.toDuration(DurationUnit.SECONDS))
                            .epochSeconds,
                )

            // Encode JWT
            val jwt = encodeJwt(payload, secret, signer = rsaSigner)

            // Decode JWT and verify payload matches
            val decodedPayload = decodeJwt(jwt, secret, signer = rsaSigner)
            assertEquals(payload.sub, decodedPayload.sub, "JWT subject should match")
            assertEquals(payload.exp, decodedPayload.exp, "JWT expiration should match")
        }

    @Test
    fun `test JWT expiration with RS512`() =
        runTest {
            // Generate RSA key pair using the cryptography provider
            val provider = CryptographyProvider.Default
            val keyPair = provider.get(RSA.PKCS1).keyPairGenerator().generateKey()
            val privateKey = keyPair.privateKey
            val publicKey = keyPair.publicKey

            val rsaSigner = RSASigner(RSAAlgorithm.RS512, privateKey, publicKey)

            // Create an expired payload (expired 1 hour ago)
            val expiredPayload =
                JwtPayload(
                    sub = sub,
                    exp =
                        Clock.System
                            .now()
                            .minus(3600.toDuration(DurationUnit.SECONDS))
                            .epochSeconds,
                )
            val expiredJwt = encodeJwt(expiredPayload, secret, rsaSigner)

            // Ensure decoding the expired JWT throws an exception
            assertFailsWith<IllegalArgumentException>("JWT token has expired") {
                decodeJwt(expiredJwt, secret, signer = rsaSigner)
            }
        }

    @Test
    fun `test mismatched algorithm`() {
        val hmacSignerHS256 = HmacSigner(HmacAlgorithm.HS256)
        val hmacSignerHS512 = HmacSigner(HmacAlgorithm.HS512)

        // Create and encode a valid JWT with HS256
        val payload =
            JwtPayload(
                sub = sub,
                exp =
                    Clock.System
                        .now()
                        .plus(3600.toDuration(DurationUnit.SECONDS))
                        .epochSeconds,
            )
        val jwt = encodeJwt(payload, secret, hmacSignerHS256)

        // Attempt to decode the JWT with HS512
        assertFailsWith<IllegalArgumentException>("JWT algorithm mismatch") {
            decodeJwt(jwt, secret, hmacSignerHS512)
        }
    }
}
