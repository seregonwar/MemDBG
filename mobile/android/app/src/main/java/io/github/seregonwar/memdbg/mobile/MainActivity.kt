package io.github.seregonwar.memdbg.mobile

import android.os.Bundle
import android.text.InputType
import android.view.KeyEvent
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.widget.EditText
import android.widget.FrameLayout
import androidx.appcompat.app.AppCompatActivity

/**
 * Single-activity MemDBG shell. Hosts the EGL OpenGL ES 3 surface that runs the
 * shared ImGui frontend (identical mobile layout to the iOS build). Lifecycle
 * is plumbed through GLSurfaceView onPause/onResume, which suspends the render
 * loop without tearing down the native ImGui context (preserveEGLContextOnPause
 * is enabled in the view).
 *
 * Also owns a hidden 1×1 EditText that bridges the Android IME (soft keyboard)
 * to ImGui's WantTextInput — equivalent to the UIKeyInput bridge on iOS.
 */
class MainActivity : AppCompatActivity() {

    private var glView: MemDBGGLSurfaceView? = null
    private var keyboardEditText: EditText? = null

    /** Track keyboard visibility locally (mirrors iOS gKeyboardVisible). */
    private var keyboardVisible: Boolean = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Root layout: FrameLayout stacks the GL surface and hidden EditText
        val root = FrameLayout(this)
        val view = MemDBGGLSurfaceView(this)
        glView = view
        root.addView(view)

        // Hidden 1×1 EditText for IME bridging (mirrors iOS UIKeyInput view)
        keyboardEditText = EditText(this).apply {
            layoutParams = FrameLayout.LayoutParams(1, 1)
            setBackgroundColor(0x00000000)            // fully transparent
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            imeOptions = EditorInfo.IME_FLAG_NO_FULLSCREEN
            // Hide cursor / selection
            isCursorVisible = false
            setTextIsSelectable(false)
            // Silence max-length complaints from some IMEs
            filters = arrayOf(android.text.InputFilter.LengthFilter(256))

            setOnEditorActionListener { _, actionId, event ->
                if (actionId == EditorInfo.IME_ACTION_DONE ||
                    actionId == EditorInfo.IME_ACTION_NEXT ||
                    (event != null && event.keyCode == KeyEvent.KEYCODE_ENTER)) {
                    MemDBGJNI.nativeSendKeyboardEnter()
                    // Clear the text so the IME doesn't accumulate it
                    text?.clear()
                    true
                } else false
            }

            setOnKeyListener { _, keyCode, event ->
                if (event.action == KeyEvent.ACTION_DOWN &&
                    keyCode == KeyEvent.KEYCODE_DEL) {
                    MemDBGJNI.nativeSendKeyboardBackspace()
                    true
                } else false
            }

            // TextWatcher: forward each new character to native, then clear
            addTextChangedListener(object : android.text.TextWatcher {
                private var lastLength = 0
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {
                    lastLength = s?.length ?: 0
                }
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                    val current = s?.toString() ?: ""
                    if (current.length > lastLength) {
                        // New character(s) added — forward each to native
                        for (i in lastLength until current.length) {
                            MemDBGJNI.nativeAddKeyboardChar(current[i])
                        }
                    }
                }
                override fun afterTextChanged(s: android.text.Editable?) {
                    // Keep the buffer small to avoid IME accumulation issues
                    if ((s?.length ?: 0) > 128) s?.clear()
                }
            })
        }
        root.addView(keyboardEditText)

        setContentView(root)
    }

    override fun onPause() {
        super.onPause()
        glView?.onPause()
    }

    override fun onResume() {
        super.onResume()
        glView?.onResume()
    }

    /**
     * Called by the GLSurfaceView every frame (from the GL render thread)
     * to synchronize the soft keyboard visibility with ImGui's WantTextInput.
     *
     * IME operations (showSoftInput / hideSoftInputFromWindow) must run on
     * the UI thread, so we dispatch them via runOnUiThread.
     */
    fun syncKeyboardState() {
        val editText = keyboardEditText ?: return

        val wantKeyboard = MemDBGJNI.nativePollKeyboard()

        // Recover from external keyboard dismissal (e.g., user pressed Back).
        // imm.isActive() is a cheap local check — no IPC, safe from any thread.
        if (keyboardVisible && wantKeyboard) {
            val imm = getSystemService(INPUT_METHOD_SERVICE) as? InputMethodManager
            if (imm != null && !imm.isActive(editText)) {
                keyboardVisible = false  // force re-show on next iteration
            }
        }

        if (wantKeyboard == keyboardVisible) return

        keyboardVisible = wantKeyboard
        runOnUiThread {
            val imm = getSystemService(INPUT_METHOD_SERVICE) as? InputMethodManager ?: return@runOnUiThread
            if (wantKeyboard) {
                editText.requestFocus()
                imm.showSoftInput(editText, InputMethodManager.SHOW_IMPLICIT)
            } else {
                imm.hideSoftInputFromWindow(editText.windowToken, 0)
                editText.clearFocus()
            }
        }
    }
}
