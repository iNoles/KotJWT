package com.jonathansteele.kojwt

import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

enum class RsaAlgorithm(
    val alg: String,
) {
    RS256("SHA256withRSA"),
    RS512("SHA512withRSA"),
    ;

    companion object {
        fun fromString(alg: String) =
            entries.find { it.name == alg }
                ?: throw IllegalArgumentException("Unsupported algorithm: $alg")
    }
}

class RsaSigner(
    private val privateKey: PrivateKey,
    private val publicKey: PublicKey,
    private val rsaAlgorithm: RsaAlgorithm,
) : JwtSigner {
    override val alg: String = rsaAlgorithm.name

    override fun sign(
        data: String,
        secret: String,
    ): ByteArray {
        val signature =
            Signature.getInstance(rsaAlgorithm.alg).apply {
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
            Signature.getInstance(rsaAlgorithm.alg).apply {
                initVerify(publicKey)
                update(data.toByteArray())
            }
        return verifier.verify(signature)
    }
}
