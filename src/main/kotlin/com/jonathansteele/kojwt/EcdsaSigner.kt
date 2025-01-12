package com.jonathansteele.kojwt

import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

enum class ESAlgorithm(
    val alg: String,
) {
    ES256("SHA256withECDSA"),
    ES512("SHA512withECDSA"),
    ;

    companion object {
        fun fromString(alg: String) =
            entries.find { it.name == alg }
                ?: throw IllegalArgumentException("Unsupported algorithm: $alg")
    }
}

class EcdsaSigner(
    private val privateKey: PrivateKey,
    private val publicKey: PublicKey,
    private val algorithm: ESAlgorithm,
) : JwtSigner {
    override val alg: String = algorithm.name

    override fun sign(
        data: String,
        secret: String,
    ): ByteArray {
        val signature =
            Signature.getInstance(algorithm.alg).apply {
                initSign(privateKey)
                update(data.toByteArray())
            }
        return signature.sign()
    }

    override fun verify(
        data: String,
        signature: ByteArray,
        secret: String,
    ): Boolean {
        val verifier =
            Signature.getInstance(algorithm.alg).apply {
                initVerify(publicKey)
                update(data.toByteArray())
            }
        return verifier.verify(signature)
    }
}
