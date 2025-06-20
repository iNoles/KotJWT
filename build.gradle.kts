plugins {
    kotlin("multiplatform") version "2.1.21"
    kotlin("plugin.serialization") version "2.1.21"
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
            implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.1")
            implementation("org.jetbrains.kotlinx:kotlinx-io-core:0.7.0")
            implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.6.2")
            implementation("dev.whyoleg.cryptography:cryptography-core:0.4.0")
            implementation("org.jetbrains.kotlinx:atomicfu:0.28.0")
            implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
        }

        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
        }

        jvmMain.dependencies {
            implementation("dev.whyoleg.cryptography:cryptography-provider-jdk:0.4.0")
        }
        appleMain.dependencies {
            implementation("dev.whyoleg.cryptography:cryptography-provider-apple:0.4.0")
            // or openssl3 provider with better algorithms coverage and other native targets support
            // implementation("dev.whyoleg.cryptography:cryptography-provider-openssl3-prebuilt:0.4.0")
        }
    }
}
