plugins {
    kotlin("multiplatform") version "2.3.10"
    kotlin("plugin.serialization") version "2.3.10"
}

group = "org.github.inoles"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

kotlin {
    jvm()
    iosX64()
    iosArm64()
    macosArm64()
    macosX64()
    iosSimulatorArm64()

    explicitApi()

    sourceSets {
        commonMain.dependencies {
            implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.10.0")
            implementation("org.jetbrains.kotlinx:kotlinx-io-core:0.9.0")
            implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.7.1")
            implementation("dev.whyoleg.cryptography:cryptography-core:0.5.0")
            implementation("org.jetbrains.kotlinx:atomicfu:0.31.0")
            implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
        }

        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
        }

        jvmMain.dependencies {
            implementation("dev.whyoleg.cryptography:cryptography-provider-jdk:0.5.0")
        }
        appleMain.dependencies {
            implementation("dev.whyoleg.cryptography:cryptography-provider-apple:0.5.0")
            // or openssl3 provider with better algorithms coverage and other native targets support
            // implementation("dev.whyoleg.cryptography:cryptography-provider-openssl3-prebuilt:0.4.0")
        }
    }
}
