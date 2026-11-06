plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Gradle 外殼（路線 A）：只承載 Kotlin 孤島＋資源＋manifest；
// nsh 產物（三 ABI libnsh.so、assets、runtime dex）由 build.sh 餵進來。
android {
    namespace = "io.bitward.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.bitward.android"
        // 與 nsh package 產的 APK 一致（假設 1 實測）
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    sourceSets {
        getByName("main") {
            // build.sh 從 .nsh/out/bitward.apk 解出的 jniLibs 與 assets
            // （放 android-shell/build/ 下：app/build/ 會被 AGP 任務掃掉未知檔）
            jniLibs.setSrcDirs(listOf("../build/nsh-stage/libs"))
            assets.setSrcDirs(listOf("src/main/assets", "../build/nsh-stage/assets"))
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        jniLibs {
            // nsh 的 APK 就是 extractNativeLibs=false（未壓縮＋對齊）
            useLegacyPackaging = false
        }
    }
}
