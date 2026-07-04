# Android Shell

The Android shell should be a Gradle project with an app module and NDK CMake
library.

Planned stack:

- Kotlin or Java activity for lifecycle, permissions, and system integration.
- NDK C++ library for the MemDBG client, trainer, scanner, and UI bridge.
- OpenGL ES 3 renderer first, because it is simpler to bring up across devices.
- Vulkan renderer later once the UI shell is stable.
- APK release artifact first; AAB can be added for Play-style distribution.

Release workflow expectation:

```sh
cd mobile/android
./gradlew --no-daemon assembleRelease
```

The CI job copies `app/build/outputs/apk/release/*.apk` into the release
artifacts when `mobile/android/gradlew` exists.
