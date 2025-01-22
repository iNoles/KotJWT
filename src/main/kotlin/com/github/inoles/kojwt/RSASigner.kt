package com.github.inoles.kojwt

import dev.whyoleg.cryptography.CryptographyAlgorithmId
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.Digest
import dev.whyoleg.cryptography.algorithms.RSA.PKCS1
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA512

enum class RSAAlgorithm(
    val alg: String,
    val digest: CryptographyAlgorithmId<Digest>,
) {
    RS256("SHA256withRSA", SHA256),
    RS512("SHA512withRSA", SHA512),
}

class RSASigner(
    algorithm: RSAAlgorithm,
    // Pass the private key
    private val privateKey: PKCS1.PrivateKey,
    // Pass the public key
    private val publicKey: PKCS1.PublicKey,
) : JwtSigner {
    override val alg: String = algorithm.alg

    private val provider = CryptographyProvider.Default // Access the default provider
    private val hasher = provider.get(algorithm.digest).hasher()

    override suspend fun sign(
        data: String,
        secret: String,
    ): ByteArray {
        // Hash the data using the selected digest
        val hashedData = hasher.hash(data.encodeToByteArray())

        // Generate the signature using the private key
        return privateKey.signatureGenerator().generateSignature(hashedData)
    }

    override suspend fun verify(
        data: String,
        signature: ByteArray,
        secret: String,
    ): Boolean {
        // Hash the data using the selected digest
        val hashedData = hasher.hash(data.encodeToByteArray())

        // Verify the signature using the public key
        return publicKey.signatureVerifier().tryVerifySignature(hashedData, signature)
    }
}
