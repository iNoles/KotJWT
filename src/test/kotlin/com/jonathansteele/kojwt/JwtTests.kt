package com.jonathansteele.kojwt

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.DurationUnit
import kotlin.time.toDuration
import kotlinx.datetime.Clock

class JwtTests {

    private val secret = "mysecretkey"
    private val sub = "user123"
    private val refreshTokenExpiration = Clock.System.now().epochSeconds + 86400  // Refresh token expires in 1 day

    @Test
    fun `test JWT encoding and decoding`() {
        // Create a sample payload with a 1-hour expiration
        val payload = JwtPayload(sub = sub, exp = Clock.System.now().plus(3600.toDuration(DurationUnit.SECONDS)).epochSeconds)

        // Encode JWT
        val jwt = encodeJwt(payload, secret)

        // Decode JWT and verify payload matches
        val decodedPayload = decodeJwt(jwt, secret)
        assertEquals(payload.sub, decodedPayload.sub, "JWT subject should match")
        assertEquals(payload.exp, decodedPayload.exp, "JWT expiration should match")
    }

    @Test
    fun `test JWT expiration`() {
        // Create an expired payload (expired 1 hour ago)
        val expiredPayload = JwtPayload(sub = sub, exp = Clock.System.now().minus(3600.toDuration(DurationUnit.SECONDS)).epochSeconds)
        val expiredJwt = encodeJwt(expiredPayload, secret)

        // Ensure decoding the expired JWT throws an exception
        assertFailsWith<IllegalArgumentException>("JWT token has expired") {
            decodeJwt(expiredJwt, secret)
        }
    }

    @Test
    fun `test revocation of JWT`() {
        // Create and encode a new JWT
        val payload = JwtPayload(sub = sub, exp = Clock.System.now().plus(3600.toDuration(DurationUnit.SECONDS)).epochSeconds)
        val jwt = encodeJwt(payload, secret)

        // Revoke the JWT
        TokenBlacklist.revoke(jwt)

        // Ensure the token is revoked
        assertTrue(TokenBlacklist.isRevoked(jwt), "JWT should be revoked")

        // Attempt to decode a revoked JWT (should throw an exception)
        assertFailsWith<IllegalArgumentException>("JWT has been revoked") {
            decodeJwt(jwt, secret)
        }
    }

    @Test
    fun `test encode and decode refresh token`() {
        // Create the refresh token payload with a 1-day expiration
        val refreshTokenPayload = RefreshTokenPayload(sub = sub, exp = refreshTokenExpiration)

        // Encode the refresh token
        val refreshToken = encodeRefreshToken(refreshTokenPayload, secret)

        // Revoke the refresh token
        TokenBlacklist.revoke(refreshToken)

        // Try to decode the revoked refresh token (should throw exception)
        assertFailsWith<IllegalArgumentException>("Refresh token has been revoked") {
            decodeRefreshToken(refreshToken, secret)
        }
    }

    @Test
    fun `test refresh token revocation`() {
        // Create the refresh token payload with a 1-day expiration
        val refreshTokenPayload = RefreshTokenPayload(sub = sub, exp = refreshTokenExpiration)

        // Encode the refresh token
        val refreshToken = encodeRefreshToken(refreshTokenPayload, secret)

        // Revoke the refresh token
        TokenBlacklist.revoke(refreshToken)

        // Try to decode the revoked refresh token (should throw exception)
        assertFailsWith<IllegalArgumentException>("Refresh token has been revoked") {
            decodeRefreshToken(refreshToken, secret)
        }
    }

    @Test
    fun `test refresh token expiration`() {
        // Create an expired refresh token payload (expired 10 seconds ago)
        val expiredRefreshTokenPayload = RefreshTokenPayload(sub = sub, exp = Clock.System.now().epochSeconds - 10)

        // Encode the expired refresh token
        val expiredRefreshToken = encodeRefreshToken(expiredRefreshTokenPayload, secret)

        // Try to decode the expired refresh token (should throw exception)
        assertFailsWith<IllegalArgumentException>("Refresh token has expired") {
            decodeRefreshToken(expiredRefreshToken, secret)
        }
    }
}