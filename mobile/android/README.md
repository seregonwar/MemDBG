# Android Shell

Native Android shell built with **Gradle + NDK CMake + OpenGL ES 3 + Dear
ImGui**. The shell reuses the desktop frontend's UI code (`draw_app()` /
`draw_mobile_app()`) and renders through the ImGui OpenGL ES 3 backend
(`imgui_impl_opengl3.cpp` compiled with `IMGUI_IMPL_OPENGL_ES3`).

It is the feature-equivalent of the iOS shell: the same `draw_mobile_app()`
touch layout, the same `set_mobile_safe_area()` insets bridge, and the same
embedded Lua 5.4 plugin runtime (`MEMDBG_ENABLE_EMBEDDED_LUA`).

## Stack

- Gradle 8.7 + Android Gradle Plugin 8.5.2 (Kotlin 1.9).
- `GLSurfaceView` provides the EGL context and render thread (mirrors
  `MTKView`/`MTKView` from iOS).
- Dear ImGui v1.90.9 with `backends/imgui_impl_opengl3.cpp` (GLES3).
- Touch input is mapped to a single left-mouse-button ImGui pointer model,
  matching the iOS ViewController.
- WindowInsets (system bars + display cutout) are forwarded to the shared
  mobile layout every frame via `set_mobile_safe_area`.
- Embedded Lua 5.4 runtime so plugins run on-device without an external
  interpreter (Windows/Linux `system()`/`popen` paths are gated out exactly as
  on iOS).
- The native library `libmemdbg.so` is compiled in mobile mode: the shared
  frontend sources currently reuse the `MEMDBG_PLATFORM_IOS` guards so they
  build identically to the iPhone/iPad binary. A follow-up can promote this to a
  `MEMDBG_PLATFORM_MOBILE` umbrella macro.

## Files

| Path | Purpose |
|---|---|
| `settings.gradle.kts` / `build.gradle.kts` | Root Gradle project wiring |
| `gradle/wrapper/gradle-wrapper.jar` + `gradlew` | Gradle 8.7 wrapper |
| `app/build.gradle.kts` | App module: NDK CMake, ABIs (arm64-v8a, x86_64), release signing |
| `app/src/main/cpp/CMakeLists.txt` | Fetches imgui/stb/nlohmann_json/lua, builds the ImGui GLES3 lib, the embedded Lua lib and the `memdbg` shared lib |
| `app/src/main/cpp/native_android.cpp` | JNI bridge: ImGui init, per-frame render, touch queue, safe-area |
| `app/src/main/java/.../MainActivity.kt` | Single_activity host |
| `.../MemDBGGLSurfaceView.kt` | EGL config chooser, touch → ImGui, WindowInsets capture |
| `.../MemDBGRenderer.kt` | GLSurfaceView.Renderer forwarding surface lifecycle |
| `.../MemDBGJNI.kt` | `external` declarations for `libmemdbg.so` |
| `app/src/main/AndroidManifest.xml` | Permissions (INTERNET/Wi-Fi), GLES3, touch |
| `app/src/main/res/values/{strings,themes}.xml` | App name + fullscreen theme |

## Local build

```sh
cd mobile/android
./gradlew --no-daemon assembleRelease
```

The release APK is signed with the debug keystore by default so it is
installable out of the box; supply a real signing config for Play Store
distribution. Output lives at
`app/build/outputs/apk/release/app-release.apk`.

A connected device/emulator install:

```sh
./gradlew --no-daemon installRelease
# or
adb install -r app/build/outputs/apk/release/app-release.apk
```

## Release workflow

The `mobile-android` job in `.github/workflows/release.yml` already runs
`./gradlew --no-daemon assembleRelease` and uploads
`dist/MemDBG-mobile-android*.apk` once a Gradle wrapper is present (which it now
is). The job copies every `*/build/outputs/apk/release/*.apk` into `dist/`.