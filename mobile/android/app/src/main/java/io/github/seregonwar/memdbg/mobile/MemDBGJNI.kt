package io.github.seregonwar.memdbg.mobile

/**
 * Native bridge exposed by libmemdbg.so. All GL work happens on the
 * GLSurfaceView render thread; touch events are buffered in native code and
 * flushed at the start of each frame. This mirrors the iOS ViewController which
 * drives the same shared frontend (draw_mobile_app + set_mobile_safe_area).
 */
object MemDBGJNI {
    init {
        System.loadLibrary("memdbg")
    }

    const val ACTION_DOWN = 0
    const val ACTION_UP = 1
    const val ACTION_MOVE = 2
    const val ACTION_CANCEL = 3

    @JvmStatic external fun nativeInit(density: Float, isTablet: Boolean)
    @JvmStatic external fun nativeOnSurfaceChanged(widthPx: Int, heightPx: Int)
    @JvmStatic external fun nativeSetSafeArea(left: Float, top: Float, right: Float, bottom: Float)
    @JvmStatic external fun nativeDrawFrame()
    @JvmStatic external fun nativeOnTouch(action: Int, xPx: Float, yPx: Float)
    @JvmStatic external fun nativePollKeyboard(): Boolean
    @JvmStatic external fun nativeAddKeyboardChar(codepoint: Char)
    @JvmStatic external fun nativeSendKeyboardBackspace()
    @JvmStatic external fun nativeSendKeyboardEnter()
    @JvmStatic external fun nativeOnDestroy()
}