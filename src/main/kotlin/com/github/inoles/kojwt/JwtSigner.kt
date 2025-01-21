package com.github.inoles.kojwt

interface JwtSigner {
    val alg: String

    suspend fun sign(
        data: String,
        secret: String,
    ): ByteArray

    suspend fun verify(
        data: String,
        signature: ByteArray,
        secret: String,
    ): Boolean
}
