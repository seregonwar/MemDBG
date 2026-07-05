// MemDBG - Android app module. Copyright (C) 2026 SeregonWar
// SPDX-License-Identifier: GPL-3.0-or-later

import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Read the MemDBG release version exactly like the iOS CMake build.
val memdbgVersion: String = run {
    val versionFile = rootProject.file("../../VERSION")
    if (versionFile.exists()) {
        versionFile.readText().trim().removePrefix("v").removePrefix("V")
    } else {
        "0.0.0"
    }
}

android {
    namespace = "io.github.seregonwar.memdbg.mobile"
    compileSdk = 34
    ndkVersion = "26.1.10909125"

    defaultConfig {
        applicationId = "io.github.seregonwar.memdbg.mobile"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = memdbgVersion

        externalNativeBuild {
            cmake {
                arguments += listOf(
                    "-DANDROID_STL=c++_shared",
                    "-DANDROID_PLATFORM=android-24",
                    "-DMEMDBG_RELEASE_VERSION=$memdbgVersion"
                )
                cFlags += "-DMEMDBG_PLATFORM_ANDROID"
                cppFlags += listOf("-std=c++17", "-DMEMDBG_PLATFORM_ANDROID", "-DIMGUI_DEFINE_MATH_OPERATORS")
            }
        }

        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            isShrinkResources = false
            // Use the debug keystore so the CI release APK is installable out of the box.
            signingConfig = signingConfigs.getByName("debug")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        getByName("debug") {
            isJniDebuggable = true
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        buildConfig = true
    }

    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
        resources {
            excludes += listOf("/META-INF/{AL2.0,LGPL2.1}", "/META-INF/DEPENDENCIES")
        }
    }

    lint {
        abortOnError = false
        checkReleaseBuilds = false
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.activity:activity-ktx:1.9.0")
}