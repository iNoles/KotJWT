package com.github.inoles.kojwt

import dev.whyoleg.cryptography.CryptographyAlgorithmId
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.Digest
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512

enum class HmacAlgorithm(val alg: String, val digest: CryptographyAlgorithmId<Digest>) {
    HS256("HS256", SHA256),
    HS384("HS384", SHA384),
    HS512("HS512", SHA512),
}

class HmacSigner(
    algorithm: HmacAlgorithm = HmacAlgorithm.HS256,
) : JwtSigner {
    private val provider = CryptographyProvider.Default
    private val hmac = provider.get(HMAC)
    private val keyDecoder = hmac.keyDecoder(algorithm.digest)

    override val alg: String = algorithm.alg

    override suspend fun sign(data: String, secret: String): ByteArray {
        // Generate HMAC key from the secret
        val key = keyDecoder.decodeFromByteArray(HMAC.Key.Format.RAW, secret.toByteArray(Charsets.UTF_8))

        // Generate the HMAC signature
        return key.signatureGenerator().generateSignature(data.toByteArray(Charsets.UTF_8))
    }

    override suspend fun verify(data: String, signature: ByteArray, secret: String): Boolean {
        // Generate HMAC key from the secret
        val key = keyDecoder.decodeFromByteArray(HMAC.Key.Format.RAW, secret.toByteArray(Charsets.UTF_8))

        // Verify the HMAC signature
        return key.signatureVerifier().tryVerifySignature(data.toByteArray(Charsets.UTF_8), signature)
    }
}
