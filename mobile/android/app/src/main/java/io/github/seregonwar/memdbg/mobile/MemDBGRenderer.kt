package io.github.seregonwar.memdbg.mobile

import android.opengl.GLSurfaceView
import javax.microedition.khronos.egl.EGLConfig
import javax.microedition.khronos.opengles.GL10

/**
 * Renders the MemDBG ImGui UI each frame on the GLSurfaceView render thread.
 *
 * The native renderer keeps ownership of the ImGui context and AppState. We
 * only bridge surface lifecycle + safe-area forwarding from the view, exactly
 * like the iOS ViewController pairs MTKView + drawInMTKView.
 */
class MemDBGRenderer(private val view: MemDBGGLSurfaceView) : GLSurfaceView.Renderer {

    override fun onSurfaceCreated(gl: GL10?, config: EGLConfig?) {
        MemDBGJNI.nativeInit(view.density(), view.isTablet())
    }

    override fun onSurfaceChanged(gl: GL10?, width: Int, height: Int) {
        MemDBGJNI.nativeOnSurfaceChanged(width, height)
    }

    override fun onDrawFrame(gl: GL10?) {
        view.applyPendingSafeArea()
        MemDBGJNI.nativeDrawFrame()
    }
}