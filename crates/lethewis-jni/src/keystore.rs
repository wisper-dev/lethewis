// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::ffi::CStr;
use core::marker::PhantomData;
use core::ptr;
use std::ffi::CString;

use jni_sys::{
    JNIEnv, JNINativeInterface_, JNINativeInterface__1_6, jbyte, jbyteArray, jclass, jint,
    jmethodID, jobject, jsize, jstring, jvalue,
};
use lethewis_android::{Failure, Keystore, Level, Watchable, Watched};
use zeroize::Zeroize;

use crate::codes;

/// The class of the Java layer.
const CLASS: &CStr = c"com/alanwisper/lethewis/Keystore";
/// Local references one call holds at most: a name and two arrays, or two strings.
const FRAME: jint = 3;
/// The length of an answer of HMAC-SHA256.
const MAC_LEN: usize = 32;

/// The keystore of the device through the Java layer, on the thread whose JNI environment it holds.
///
/// A call leaves no local reference and no pending exception behind, and never starts with one
/// pending: it then fails as [`Failure::Unknown`].
pub struct JniKeystore<'env> {
    env: *mut JNIEnv,
    class: jclass,
    /// Whether `class` is a local reference this value made, and so deletes.
    owned: bool,
    api: u32,
    methods: Methods,
    _env: PhantomData<&'env mut JNIEnv>,
}

struct Methods {
    contains: jmethodID,
    generate: jmethodID,
    generate_watched: jmethodID,
    watchable: jmethodID,
    watched: jmethodID,
    mac: jmethodID,
    aliases: jmethodID,
    delete: jmethodID,
}

impl JniKeystore<'_> {
    /// Finds the Java layer through the class loader of the native method under way.
    ///
    /// # Safety
    ///
    /// `env` is the JNI environment of the current thread, valid for `'env`, inside a native
    /// method the JVM called.
    ///
    /// # Errors
    ///
    /// [`Failure::Unknown`] if the class or one of its methods is missing, the API level cannot
    /// be read, or an exception is pending.
    #[allow(unsafe_code)]
    pub unsafe fn find(env: *mut JNIEnv) -> Result<Self, Failure> {
        // SAFETY: the environment is valid, as the caller promises.
        let functions = unsafe { table(env) };
        // SAFETY: as above; ExceptionCheck may be called with an exception pending.
        if unsafe { (functions.ExceptionCheck)(env) } {
            return Err(Failure::Unknown);
        }
        // SAFETY: as above, with no exception pending; the name ends in NUL.
        let class = unsafe { (functions.FindClass)(env, CLASS.as_ptr()) };
        if class.is_null() {
            // SAFETY: as above; FindClass failed and left its exception pending.
            unsafe { (functions.ExceptionClear)(env) };
            return Err(Failure::Unknown);
        }
        // SAFETY: the environment is valid for `'env`, and `class` is a local reference to the
        // class, valid until the native method under way returns.
        match unsafe { Self::with_class(env, class) } {
            Ok(mut keystore) => {
                keystore.owned = true;
                Ok(keystore)
            }
            Err(failure) => {
                // SAFETY: as above; DeleteLocalRef may be called with an exception pending, and
                // nothing uses `class` after it.
                unsafe { (functions.DeleteLocalRef)(env, class) };
                Err(failure)
            }
        }
    }

    /// Reaches the Java layer through `class`.
    ///
    /// # Safety
    ///
    /// `env` is the JNI environment of the current thread, valid for `'env`. `class` refers to
    /// `com.alanwisper.lethewis.Keystore` for all of `'env`: a global reference, or a local one
    /// within the native method under way.
    ///
    /// # Errors
    ///
    /// [`Failure::Unknown`] if one of the methods is missing, the API level cannot be read, or
    /// an exception is pending.
    #[allow(unsafe_code)]
    pub unsafe fn with_class(env: *mut JNIEnv, class: jclass) -> Result<Self, Failure> {
        let mut keystore = Self {
            env,
            class,
            owned: false,
            api: 0,
            methods: Methods {
                contains: ptr::null_mut(),
                generate: ptr::null_mut(),
                generate_watched: ptr::null_mut(),
                watchable: ptr::null_mut(),
                watched: ptr::null_mut(),
                mac: ptr::null_mut(),
                aliases: ptr::null_mut(),
                delete: ptr::null_mut(),
            },
            _env: PhantomData,
        };
        if keystore.pending() {
            return Err(Failure::Unknown);
        }
        let api_level = keystore.method(c"apiLevel", c"()I")?;
        // SAFETY: `apiLevel` belongs to the class and takes no arguments.
        let api = unsafe { keystore.call(api_level, &[])? };
        keystore.api = u32::try_from(api).map_err(|_| Failure::Unknown)?;
        keystore.methods = Methods {
            contains: keystore.method(c"contains", c"(Ljava/lang/String;)I")?,
            generate: keystore.method(c"generate", c"(Ljava/lang/String;ZZ)I")?,
            generate_watched: keystore.method(c"generateWatched", c"(Ljava/lang/String;Z)I")?,
            watchable: keystore.method(c"watchable", c"()I")?,
            watched: keystore.method(c"watched", c"(Ljava/lang/String;)I")?,
            mac: keystore.method(c"mac", c"(Ljava/lang/String;[B[B)I")?,
            aliases: keystore.method(c"aliases", c"(Ljava/lang/String;)Ljava/lang/String;")?,
            delete: keystore.method(c"delete", c"(Ljava/lang/String;)I")?,
        };
        Ok(keystore)
    }

    #[allow(unsafe_code)]
    pub(crate) fn table(&self) -> &JNINativeInterface__1_6 {
        // SAFETY: the environment is valid for the life of `self`, as its constructor required.
        unsafe { table(self.env) }
    }

    /// Whether an exception is pending.
    #[allow(unsafe_code)]
    fn pending(&self) -> bool {
        // SAFETY: the environment is valid; ExceptionCheck may be called with one pending.
        unsafe { (self.table().ExceptionCheck)(self.env) }
    }

    /// Clears a pending exception, and tells whether there was one.
    #[allow(unsafe_code)]
    pub(crate) fn thrown(&self) -> bool {
        let pending = self.pending();
        if pending {
            // SAFETY: the environment is valid, and ExceptionClear is meant for a pending one.
            unsafe { (self.table().ExceptionClear)(self.env) };
        }
        pending
    }

    #[allow(unsafe_code)]
    fn method(&self, name: &CStr, signature: &CStr) -> Result<jmethodID, Failure> {
        // SAFETY: the environment and the class are valid, no exception is pending, and both
        // strings end in NUL.
        let method = unsafe {
            (self.table().GetStaticMethodID)(
                self.env,
                self.class,
                name.as_ptr(),
                signature.as_ptr(),
            )
        };
        let thrown = self.thrown();
        if method.is_null() || thrown {
            Err(Failure::Unknown)
        } else {
            Ok(method)
        }
    }

    /// Runs `work` in a frame of its own, which frees every local reference it makes.
    #[allow(unsafe_code)]
    fn framed<R>(
        &mut self,
        work: impl FnOnce(&mut Self) -> Result<R, Failure>,
    ) -> Result<R, Failure> {
        if self.pending() {
            return Err(Failure::Unknown);
        }
        // SAFETY: the environment is valid and no exception is pending.
        if unsafe { (self.table().PushLocalFrame)(self.env, FRAME) } != 0 {
            self.thrown();
            return Err(Failure::Unknown);
        }
        let result = work(self);
        self.thrown();
        // SAFETY: the frame pushed above is popped, keeping no reference; no exception is
        // pending.
        unsafe { (self.table().PopLocalFrame)(self.env, ptr::null_mut()) };
        result
    }

    /// Calls a static method of the layer that returns an `int`.
    ///
    /// # Safety
    ///
    /// `method` belongs to the class, and `arguments` match its signature.
    #[allow(unsafe_code)]
    unsafe fn call(&self, method: jmethodID, arguments: &[jvalue]) -> Result<jint, Failure> {
        // SAFETY: the environment and the class are valid, no exception is pending, and the
        // method and its arguments are as the caller promises.
        let result = unsafe {
            (self.table().CallStaticIntMethodA)(self.env, self.class, method, arguments.as_ptr())
        };
        if self.thrown() {
            Err(Failure::Unknown)
        } else {
            Ok(result)
        }
    }

    /// Calls a static method of the layer that returns an object.
    ///
    /// # Safety
    ///
    /// `method` belongs to the class, returns an object, and `arguments` match its signature.
    #[allow(unsafe_code)]
    unsafe fn call_object(
        &self,
        method: jmethodID,
        arguments: &[jvalue],
    ) -> Result<jobject, Failure> {
        // SAFETY: the environment and the class are valid, no exception is pending, and the
        // method and its arguments are as the caller promises.
        let result = unsafe {
            (self.table().CallStaticObjectMethodA)(self.env, self.class, method, arguments.as_ptr())
        };
        if self.thrown() {
            Err(Failure::Unknown)
        } else {
            Ok(result)
        }
    }

    /// The Java string `string` as UTF-8, if it is one; for ASCII the JVM's modified UTF-8 is the
    /// same.
    #[allow(unsafe_code)]
    pub(crate) fn text(&self, string: jstring) -> Option<String> {
        if string.is_null() || self.pending() {
            return None;
        }
        // SAFETY: the environment is valid, no exception is pending, and `string` is a string.
        let characters = unsafe { (self.table().GetStringLength)(self.env, string) };
        // SAFETY: as above.
        let length = unsafe { (self.table().GetStringUTFLength)(self.env, string) };
        let mut bytes = vec![0_u8; usize::try_from(length).ok()?.checked_add(1)?];
        // SAFETY: as above; `bytes` takes the modified UTF-8 of all `characters` and the NUL after
        // it.
        unsafe {
            (self.table().GetStringUTFRegion)(
                self.env,
                string,
                0,
                characters,
                bytes.as_mut_ptr().cast(),
            );
        }
        if self.thrown() {
            return None;
        }
        bytes.truncate(usize::try_from(length).ok()?);
        String::from_utf8(bytes).ok()
    }

    /// A new Java string of `text`, which is ASCII: the same in the JVM's modified UTF-8.
    #[allow(unsafe_code)]
    pub(crate) fn string(&self, text: &str) -> Result<jstring, Failure> {
        if !text.is_ascii() {
            return Err(Failure::Unknown);
        }
        let text = CString::new(text).map_err(|_| Failure::Unknown)?;
        // SAFETY: the environment is valid, no exception is pending, and the string ends in NUL.
        let string = unsafe { (self.table().NewStringUTF)(self.env, text.as_ptr()) };
        let thrown = self.thrown();
        if string.is_null() || thrown {
            Err(Failure::Unknown)
        } else {
            Ok(string)
        }
    }

    /// A new Java array of `length` zero bytes.
    #[allow(unsafe_code)]
    fn array(&self, length: usize) -> Result<jbyteArray, Failure> {
        let length = jsize::try_from(length).map_err(|_| Failure::Unknown)?;
        // SAFETY: the environment is valid, no exception is pending, and the length is not
        // negative.
        let array = unsafe { (self.table().NewByteArray)(self.env, length) };
        let thrown = self.thrown();
        if array.is_null() || thrown {
            Err(Failure::Unknown)
        } else {
            Ok(array)
        }
    }

    /// Writes `data` into `array` from `start`.
    #[allow(unsafe_code)]
    fn write(&self, array: jbyteArray, start: usize, data: &[u8]) -> Result<(), Failure> {
        let start = jsize::try_from(start).map_err(|_| Failure::Unknown)?;
        let length = jsize::try_from(data.len()).map_err(|_| Failure::Unknown)?;
        // SAFETY: the environment is valid and no exception is pending; `data` is valid for reads
        // of `length` bytes, and a byte and a jbyte have one layout. A range past the end of the
        // array throws instead of writing.
        unsafe {
            (self.table().SetByteArrayRegion)(
                self.env,
                array,
                start,
                length,
                data.as_ptr().cast::<jbyte>(),
            );
        }
        if self.thrown() {
            Err(Failure::Unknown)
        } else {
            Ok(())
        }
    }

    /// Reads the answer of HMAC-SHA256 from `array` into `out`, which is left as it was on failure.
    #[allow(unsafe_code)]
    fn read(&self, array: jbyteArray, out: &mut [u8; MAC_LEN]) -> Result<(), Failure> {
        // SAFETY: the environment is valid, no exception is pending, and `array` is an array.
        let length = unsafe { (self.table().GetArrayLength)(self.env, array) };
        if self.thrown() || usize::try_from(length) != Ok(MAC_LEN) {
            return Err(Failure::Unknown);
        }
        let mut copy = [0; MAC_LEN];
        // SAFETY: the environment is valid, no exception is pending, the array holds `MAC_LEN`
        // bytes, and `copy` takes as many; a byte and a jbyte have one layout.
        unsafe {
            (self.table().GetByteArrayRegion)(
                self.env,
                array,
                0,
                length,
                copy.as_mut_ptr().cast::<jbyte>(),
            );
        }
        let read = if self.thrown() {
            Err(Failure::Unknown)
        } else {
            out.copy_from_slice(&copy);
            Ok(())
        };
        copy.zeroize();
        read
    }

    /// Overwrites the first `length` bytes of `array` with zeros; copies the JVM's collector made
    /// are beyond reach.
    fn wipe(&self, array: jbyteArray, length: usize) {
        const ZEROS: [u8; 64] = [0; 64];
        for start in (0..length).step_by(ZEROS.len()) {
            let count = length.saturating_sub(start).min(ZEROS.len());
            if let Some(zeros) = ZEROS.get(..count) {
                // A failure leaves nothing more to do: the array is freed with its frame.
                let _ = self.write(array, start, zeros);
            }
        }
    }
}

impl Drop for JniKeystore<'_> {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: the environment is valid, `class` is the local reference `find` made and
            // nothing uses it after this; DeleteLocalRef may be called with an exception pending.
            unsafe { (self.table().DeleteLocalRef)(self.env, self.class) };
        }
    }
}

impl Keystore for JniKeystore<'_> {
    fn api_level(&self) -> u32 {
        self.api
    }

    #[allow(unsafe_code)]
    fn contains(&mut self, alias: &str) -> Result<bool, Failure> {
        let method = self.methods.contains;
        self.framed(|this| {
            let name = this.string(alias)?;
            // SAFETY: `contains` takes a String.
            codes::presence(unsafe { this.call(method, &[jvalue { l: name }])? })
        })
    }

    #[allow(unsafe_code)]
    fn generate(
        &mut self,
        alias: &str,
        strong_box: bool,
        unlocked: bool,
    ) -> Result<Level, Failure> {
        let method = self.methods.generate;
        self.framed(|this| {
            let name = this.string(alias)?;
            let arguments = [
                jvalue { l: name },
                jvalue { z: strong_box },
                jvalue { z: unlocked },
            ];
            // SAFETY: `generate` takes a String and two booleans.
            codes::level(unsafe { this.call(method, &arguments)? })
        })
    }

    #[allow(unsafe_code)]
    fn generate_watched(&mut self, alias: &str, strong_box: bool) -> Result<Level, Failure> {
        let method = self.methods.generate_watched;
        self.framed(|this| {
            let name = this.string(alias)?;
            let arguments = [jvalue { l: name }, jvalue { z: strong_box }];
            // SAFETY: `generateWatched` takes a String and a boolean.
            codes::level(unsafe { this.call(method, &arguments)? })
        })
    }

    #[allow(unsafe_code)]
    fn watchable(&mut self) -> Result<Watchable, Failure> {
        let method = self.methods.watchable;
        // SAFETY: `watchable` takes no arguments.
        self.framed(|this| codes::watchable(unsafe { this.call(method, &[])? }))
    }

    #[allow(unsafe_code)]
    fn watched(&mut self, alias: &str) -> Result<Watched, Failure> {
        let method = self.methods.watched;
        self.framed(|this| {
            let name = this.string(alias)?;
            // SAFETY: `watched` takes a String.
            codes::watched(unsafe { this.call(method, &[jvalue { l: name }])? })
        })
    }

    #[allow(unsafe_code)]
    fn mac(&mut self, alias: &str, data: &[u8], out: &mut [u8; 32]) -> Result<(), Failure> {
        let method = self.methods.mac;
        self.framed(|this| {
            let name = this.string(alias)?;
            let input = this.array(data.len())?;
            let answered = this.write(input, 0, data).and_then(|()| {
                let output = this.array(MAC_LEN)?;
                let arguments = [
                    jvalue { l: name },
                    jvalue { l: input },
                    jvalue { l: output },
                ];
                // SAFETY: `mac` takes a String and two byte arrays.
                let called = unsafe { this.call(method, &arguments) }
                    .and_then(codes::status)
                    .and_then(|()| this.read(output, out));
                this.wipe(output, MAC_LEN);
                called
            });
            this.wipe(input, data.len());
            answered
        })
    }

    #[allow(unsafe_code)]
    fn aliases(&mut self, prefix: &str) -> Result<Vec<String>, Failure> {
        let method = self.methods.aliases;
        self.framed(|this| {
            let prefix = this.string(prefix)?;
            // SAFETY: `aliases` takes a String and returns one, or null when the keystore throws.
            let listed = unsafe { this.call_object(method, &[jvalue { l: prefix }])? };
            let text = this.text(listed).ok_or(Failure::Unknown)?;
            Ok(text
                .split('\n')
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect())
        })
    }

    #[allow(unsafe_code)]
    fn delete(&mut self, alias: &str) -> Result<(), Failure> {
        let method = self.methods.delete;
        self.framed(|this| {
            let name = this.string(alias)?;
            // SAFETY: `delete` takes a String.
            codes::status(unsafe { this.call(method, &[jvalue { l: name }])? })
        })
    }
}

/// The JNI 1.6 functions of the JVM `env` belongs to.
///
/// # Safety
///
/// `env` is a valid JNI environment of the current thread.
#[allow(unsafe_code)]
unsafe fn table<'table>(env: *mut JNIEnv) -> &'table JNINativeInterface__1_6 {
    // SAFETY: a valid environment points to the pointer to the JVM's table of functions.
    let functions: *const JNINativeInterface_ = unsafe { *env };
    // SAFETY: that table lives as long as the JVM, which outlives every thread using it. The union
    // is `repr(C)`, so its JNI 1.6 part starts where it does. Android's JVM implements JNI 1.6,
    // and only that part is referenced: the later functions of the union are not there.
    unsafe { &*functions.cast::<JNINativeInterface__1_6>() }
}
