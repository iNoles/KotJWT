package com.github.inoles.kojwt

import dev.whyoleg.cryptography.CryptographyAlgorithmId
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.Digest
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA512

enum class ECAlgorithm(
    val alg: String,
    val digest: CryptographyAlgorithmId<Digest>
) {
    ES256("SHA256withECDSA", SHA256),
    ES512("SHA512withECDSA", SHA512);
}

class ECSigner(
    private val algorithm: ECAlgorithm
) : JwtSigner {
    // getting default provider
    private val provider = CryptographyProvider.Default
    // getting ECDSA algorithm
    private val ecdsa = provider.get(ECDSA)

    override val alg: String = algorithm.alg

    override suspend fun sign(data: String, secret: String): ByteArray {
        // Getting the private key from the key pair
        val keyPair = ecdsa.keyPairGenerator(EC.Curve.P521).generateKey()

        // Generating the signature using the private key
        return keyPair.privateKey.signatureGenerator(algorithm.digest, ECDSA.SignatureFormat.DER)
            .generateSignature(data.encodeToByteArray())
    }

    override suspend fun verify(data: String, signature: ByteArray, secret: String): Boolean {
        // Getting the public key from the key pair
        val keyPair = ecdsa.keyPairGenerator(EC.Curve.P521).generateKey()

        // Verifying the signature using the public key
        return keyPair.publicKey.signatureVerifier(algorithm.digest, ECDSA.SignatureFormat.DER)
            .tryVerifySignature(data.encodeToByteArray(), signature)
    }
}
