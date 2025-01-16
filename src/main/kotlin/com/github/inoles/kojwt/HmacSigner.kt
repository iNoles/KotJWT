package com.github.inoles.kojwt

import org.kotlincrypto.core.mac.Mac
import org.kotlincrypto.macs.hmac.sha2.HmacSHA256
import org.kotlincrypto.macs.hmac.sha2.HmacSHA384
import org.kotlincrypto.macs.hmac.sha2.HmacSHA512

typealias HmacConstructor = (ByteArray) -> Mac

enum class HmacAlgorithm(
    val hmacConstructor: HmacConstructor,
) {
    HS256({ secret -> HmacSHA256(secret) }),
    HS384({ secret -> HmacSHA384(secret) }),
    HS512({ secret -> HmacSHA512(secret) }),
}

class HmacSigner(
    private val algorithm: HmacAlgorithm = HmacAlgorithm.HS256,
) : JwtSigner {
    override val alg: String = algorithm.name

    override fun sign(
        data: String,
        secret: String,
    ): ByteArray {
        val mac = algorithm.hmacConstructor(secret.toByteArray())
        return mac.doFinal(data.toByteArray())
    }

    override fun verify(
        data: String,
        signature: ByteArray,
        secret: String,
    ): Boolean = sign(data, secret).contentEquals(signature)
}
