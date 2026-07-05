package io.github.seregonwar.memdbg.mobile

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity

/**
 * Single-activity MemDBG shell. Hosts the EGL OpenGL ES 3 surface that runs the
 * shared ImGui frontend (identical mobile layout to the iOS build). Lifecycle
 * is plumbed through GLSurfaceView onPause/onResume, which suspends the render
 * loop without tearing down the native ImGui context (preserveEGLContextOnPause
 * is enabled in the view).
 */
class MainActivity : AppCompatActivity() {

    private var glView: MemDBGGLSurfaceView? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val view = MemDBGGLSurfaceView(this)
        glView = view
        setContentView(view)
    }

    override fun onPause() {
        super.onPause()
        glView?.onPause()
    }

    override fun onResume() {
        super.onResume()
        glView?.onResume()
    }
}