package com.jonathansteele.kojwt

interface JwtSigner {
    fun sign(data: String, secret: String): ByteArray
    fun verify(data: String, signature: ByteArray, secret: String): Boolean
}