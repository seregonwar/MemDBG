# Keep the JNI native bridge symbols and ImGui/Kotlin entry points.
-keep class io.github.seregonwar.memdbg.mobile.** { *; }
-keepclassmembers class * {
    native <methods>;
}