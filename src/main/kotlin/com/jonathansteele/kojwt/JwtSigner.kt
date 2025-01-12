package com.jonathansteele.kojwt

interface JwtSigner {
    val alg: String
    fun sign(data: String, secret: String): ByteArray
    fun verify(data: String, signature: ByteArray, secret: String): Boolean
}