package io.github.seregonwar.memdbg.mobile

import android.content.Context
import android.graphics.Insets
import android.opengl.GLSurfaceView
import android.os.Build
import android.util.AttributeSet
import android.view.MotionEvent
import android.view.WindowInsets

/**
 * EGL-backed OpenGL ES 3 surface that owns the MemDBG render loop.
 *
 * Mirrors the iOS ViewController:
 *  - EGL context + render-thread lifecycle is handled by GLSurfaceView.
 *  - The native renderer (libmemdbg.so) is initialized once the surface is
 *    created and torn down when the surface is destroyed.
 *  - Touch input is forwarded to ImGui's single-pointer / left-button model.
 *  - System bar insets are forwarded every frame via WindowInsets so the shared
 *    mobile layout can honour the device safe areas (notches, gesture nav bar).
 */
class MemDBGGLSurfaceView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null
) : GLSurfaceView(context, attrs) {

    private val density: Float = context.resources.displayMetrics.density
    private val isTablet: Boolean =
        (context.resources.configuration.smallestScreenWidthDp >= 600)

    @Volatile private var safeLeft: Float = 0f
    @Volatile private var safeTop: Float = 0f
    @Volatile private var safeRight: Float = 0f
    @Volatile private var safeBottom: Float = 0f
    @Volatile private var safeDirty: Boolean = true

    init {
        setEGLContextClientVersion(3)
        setEGLConfigChooser(8, 8, 8, 0, 16, 0)
        preserveEGLContextOnPause = true
        setRenderer(MemDBGRenderer(this))
        renderMode = RENDERMODE_CONTINUOUSLY

        setOnApplyWindowInsetsListener { _, insets ->
            captureSafeArea(insets)
            insets
        }
        // Force an insets pass so we get the initial values before the first frame.
        requestApplyInsets()
    }

    fun density(): Float = density
    fun isTablet(): Boolean = isTablet

    /** Called on the render thread before each frame draws. */
    fun applyPendingSafeArea() {
        if (!safeDirty) return
        MemDBGJNI.nativeSetSafeArea(safeLeft, safeTop, safeRight, safeBottom)
        safeDirty = false
    }

    private fun captureSafeArea(insets: WindowInsets?) {
        if (insets == null) return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val sys: Insets = insets.getInsets(
                WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout()
            )
            safeLeft = sys.left.toFloat()
            safeTop = sys.top.toFloat()
            safeRight = sys.right.toFloat()
            safeBottom = sys.bottom.toFloat()
        } else {
            @Suppress("DEPRECATION")
            val left = insets.systemWindowInsetLeft
            @Suppress("DEPRECATION")
            val top = insets.systemWindowInsetTop
            @Suppress("DEPRECATION")
            val right = insets.systemWindowInsetRight
            @Suppress("DEPRECATION")
            val bottom = insets.systemWindowInsetBottom
            safeLeft = left.toFloat(); safeTop = top.toFloat()
            safeRight = right.toFloat(); safeBottom = bottom.toFloat()
        }
        safeDirty = true
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        val action: Int = when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> MemDBGJNI.ACTION_DOWN
            MotionEvent.ACTION_UP -> MemDBGJNI.ACTION_UP
            MotionEvent.ACTION_MOVE -> MemDBGJNI.ACTION_MOVE
            MotionEvent.ACTION_CANCEL -> MemDBGJNI.ACTION_CANCEL
            else -> return false
        }
        MemDBGJNI.nativeOnTouch(action, event.x, event.y)
        return true
    }
}