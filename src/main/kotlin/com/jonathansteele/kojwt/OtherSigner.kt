package com.jonathansteele.kojwt

import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

enum class OtherAlgorithm(
    val alg: String,
) {
    RS256("SHA256withRSA"),
    RS512("SHA512withRSA"),
    ES256("SHA256withECDSA"),
    ES512("SHA512withECDSA");

    companion object {
        fun fromString(alg: String) =
            entries.find { it.name == alg }
                ?: throw IllegalArgumentException("Unsupported algorithm: $alg")
    }
}

class OtherSigner(
    private val privateKey: PrivateKey,
    private val publicKey: PublicKey,
    private val otherAlgorithm: OtherAlgorithm
) : JwtSigner {
    override val alg: String = otherAlgorithm.name

    override fun sign(
        data: String,
        secret: String,
    ): ByteArray {
        val signature =
            Signature.getInstance(otherAlgorithm.alg).apply {
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
            Signature.getInstance(otherAlgorithm.alg).apply {
                initVerify(publicKey)
                update(data.toByteArray())
            }
        return verifier.verify(signature)
    }
}
