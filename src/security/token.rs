//! Process and thread security token manipulation.

use std::{marker::PhantomData, mem, ptr, slice};

use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, GetLastError, HANDLE, LUID,
            SetLastError, WIN32_ERROR,
        },
        Security::{
            AdjustTokenPrivileges, DuplicateTokenEx, GetSidSubAuthority, GetSidSubAuthorityCount,
            GetTokenInformation, ImpersonateLoggedOnUser, IsTokenRestricted, IsValidSid,
            LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, RevertToSelf, SE_PRIVILEGE_ENABLED,
            SID_AND_ATTRIBUTES, SecurityImpersonation, SetTokenInformation, TOKEN_ACCESS_MASK,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS, TOKEN_ELEVATION, TOKEN_GROUPS,
            TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY,
            TOKEN_USER, TokenElevation, TokenGroups, TokenImpersonation, TokenIntegrityLevel,
            TokenPrimary, TokenPrivileges, TokenSessionId, TokenUser,
        },
        System::{
            SystemServices::{MAXIMUM_ALLOWED, SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY},
            Threading::{
                GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
            },
        },
    },
    core::PCWSTR,
};

use super::{guard::HandleGuard, privilege::Privilege, sid::Sid, win32};
use crate::error::ElevateError;

/// Target token type when duplicating an existing security token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    /// Primary token for launching new process instances.
    Primary,
    /// Impersonation token for thread-level security context borrowing.
    Impersonation,
}

/// Strongly-typed RAII guard holding an open process or thread token handle.
pub struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

impl Token {
    /// Open the token belonging to the current application process.
    pub(crate) fn current() -> Result<Self, ElevateError> {
        let mut handle = HANDLE::default();
        win32!(OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &raw mut handle
        ))?;
        Ok(Self(handle))
    }

    /// Open the security token belonging to an arbitrary running process by PID.
    pub(crate) fn from_pid(pid: u32) -> Result<Self, ElevateError> {
        let process = HandleGuard(win32!(OpenProcess(PROCESS_QUERY_INFORMATION, false, pid))?);
        let mut token = HANDLE::default();
        win32!(OpenProcessToken(
            process.0,
            TOKEN_ACCESS_MASK(MAXIMUM_ALLOWED),
            &raw mut token
        ))?;
        Ok(Self(token))
    }

    /// Borrow the underlying raw Win32 `HANDLE`.
    pub const fn as_raw(&self) -> HANDLE {
        self.0
    }

    /// Duplicate this token as either a Primary or Impersonation token.
    pub(crate) fn duplicate(&self, token_type: TokenType) -> Result<Self, ElevateError> {
        let access = match token_type {
            TokenType::Primary => TOKEN_ALL_ACCESS,
            TokenType::Impersonation => TOKEN_ACCESS_MASK(MAXIMUM_ALLOWED),
        };
        let raw_type = match token_type {
            TokenType::Primary => TokenPrimary,
            TokenType::Impersonation => TokenImpersonation,
        };

        let mut dup = HANDLE::default();
        win32!(DuplicateTokenEx(
            self.0,
            access,
            None,
            SecurityImpersonation,
            raw_type,
            &raw mut dup
        ))?;
        Ok(Self(dup))
    }

    /// Enable the specified administrative privileges on this token.
    ///
    /// If the token does not hold the privilege (e.g. running as non-elevated user),
    /// this returns [`ElevateError::PrivilegeNotHeld`].
    pub(crate) fn enable_privileges(&self, privileges: &[Privilege]) -> Result<(), ElevateError> {
        for &privilege in privileges {
            let mut luid = LUID::default();
            win32!(LookupPrivilegeValueW(
                PCWSTR::null(),
                privilege.as_pcwstr(),
                &raw mut luid
            ))?;

            let privileges = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };

            unsafe { SetLastError(WIN32_ERROR(0)) };
            win32!(AdjustTokenPrivileges(
                self.0,
                false,
                Some(ptr::from_ref(&privileges)),
                mem::size_of::<TOKEN_PRIVILEGES>() as u32,
                None,
                None,
            ))?;

            // AdjustTokenPrivileges returns TRUE even if privileges were not assigned
            // (ERROR_NOT_ALL_ASSIGNED), which indicates the token does not hold this privilege.
            if unsafe { GetLastError() } != ERROR_SUCCESS {
                return Err(ElevateError::PrivilegeNotHeld {
                    privilege: privilege.as_str(),
                });
            }
        }
        Ok(())
    }

    /// Check whether this token is running with elevated Administrator privileges.
    pub(crate) fn is_elevated_admin(&self) -> Result<bool, ElevateError> {
        let mut elevation = TOKEN_ELEVATION::default();
        let mut bytes_needed = 0u32;

        win32!(GetTokenInformation(
            self.0,
            TokenElevation,
            Some(ptr::from_mut(&mut elevation).cast()),
            mem::size_of::<TOKEN_ELEVATION>() as u32,
            &raw mut bytes_needed
        ))?;

        Ok(elevation.TokenIsElevated != 0)
    }

    /// Checks whether this token is a restricted (sandboxed) token.
    ///
    /// # The Bizarre Win32 Calling Convention Trap
    /// Most Win32 APIs return `TRUE` for success and `FALSE` for failure.
    /// `IsTokenRestricted` does something completely backwards:
    /// - **Token IS restricted**: It returns `TRUE` (treated as `Ok(())` by the `windows` crate).
    /// - **Token IS NOT restricted**: It returns `FALSE`!
    ///
    /// The `windows` crate treats any `FALSE` return as an error (`Err(source)`).
    /// But returning `FALSE` does NOT mean the API failed! It literally just means:
    /// *"No, this token is completely normal and unrestricted."*
    ///
    /// # What blows up if we write normal code?
    /// If we used standard error handling like `unsafe { IsTokenRestricted(self.0) }?`:
    /// Every healthy, normal system process (like `services.exe`) would return `Err`!
    /// Our process scanner would falsely reject perfectly valid SYSTEM tokens,
    /// report that no usable system process exists, and completely fail to elevate.
    ///
    /// # How we handle this madness
    /// 1. We clear `LastError` to `0` before the call.
    /// 2. If the API returns `FALSE` (which lands in `Err`), we inspect `GetLastError()`.
    /// 3. If `GetLastError()` is still `0` (`ERROR_SUCCESS`), this was NOT a crash—it was Windows
    ///    saying: *"The token is unrestricted."* We catch this and return `Ok(false)`.
    /// 4. Only if `GetLastError()` is a non-zero error code (like `ERROR_INVALID_HANDLE`) do we
    ///    actually treat it as a real system failure and return an error.
    pub(crate) fn is_restricted(&self) -> Result<bool, ElevateError> {
        // Clear any leftover error code from prior Win32 calls so we don't read stale garbage.
        unsafe { SetLastError(WIN32_ERROR(0)) };

        match unsafe { IsTokenRestricted(self.0) } {
            // Windows returned TRUE -> The token has restricted SIDs or stripped privileges.
            Ok(()) => Ok(true),

            // Windows returned FALSE -> The `windows` crate maps this to Err, but we must check why.
            Err(source) => {
                let err = unsafe { GetLastError() };

                // Error code 0 (ERROR_SUCCESS) means the API succeeded; the token is just NOT restricted.
                if err == ERROR_SUCCESS {
                    Ok(false)
                } else {
                    // Non-zero error means a genuine OS crash (e.g., invalid token handle, access denied).
                    Err(ElevateError::Win32 {
                        operation: "IsTokenRestricted",
                        source,
                    })
                }
            }
        }
    }

    /// Extracts the numeric Integrity Level RID from the token (e.g., `0x4000` = SYSTEM, `0x3000` = HIGH).
    ///
    /// # The Bizarre Windows Architecture Trap: Why are we parsing a SID here?
    /// An integrity level is literally just a single 32-bit number.
    /// But when Microsoft introduced Mandatory Integrity Control (MIC) in Windows Vista, they
    /// refused to add a clean, standalone integer field to the security API.
    ///
    /// Instead, they crammed the number into a "fake SID" (an integrity pseudo-SID):
    /// - `S-1-16-0x4000` -> SYSTEM
    /// - `S-1-16-0x3000` -> HIGH (Elevated Administrator)
    /// - `S-1-16-0x2000` -> MEDIUM (Standard User)
    /// - `S-1-16-0x1000` -> LOW (Sandbox)
    ///
    /// The actual numeric altitude we need (`0x4000`, `0x3000`, etc.) is stored as the
    /// very last `SubAuthority` number at the tail end of this fake SID.
    ///
    /// # What blows up if we write normal code?
    /// If we blindly dereference the SID without checking, or assume it has standard user-account SIDs:
    /// - Malicious API hooks or corrupted kernel buffers can hand back a null/dangling pointer,
    ///   causing our process to crash instantly with an Access Violation (Segfault).
    /// - We must peel the SID pointer layer-by-layer: first verify the pointer is structurally a valid SID,
    ///   then fetch how many numbers it contains, and finally extract the last number.
    pub(crate) fn integrity_level(&self) -> Result<u32, ElevateError> {
        let buf = self.query_info_buffer(TokenIntegrityLevel)?;
        let label: &TOKEN_MANDATORY_LABEL = Self::cast_buffer(&buf);
        let sid = label.Label.Sid;

        // Step 1: Reject null pointers and structurally corrupt SIDs.
        // NOTE: `IsValidSid` cannot protect against unmapped dangling pointers (it will crash
        // if the pointer itself is unmapped memory), but it guarantees that readable memory
        // actually matches the valid Windows SID revision and format rules before we inspect it.
        if sid.0.is_null() || !unsafe { IsValidSid(sid) }.as_bool() {
            return Err(ElevateError::InvalidSid);
        }

        // Step 2: Ask Windows how many sub-authority numbers are packed inside this SID.
        // SAFETY: `sid` was validated by `IsValidSid` above, guaranteeing a readable SID header.
        let count_ptr = unsafe { GetSidSubAuthorityCount(sid) };
        if count_ptr.is_null() {
            return Err(ElevateError::InvalidSid);
        }

        // SAFETY: `count_ptr` is a valid pointer to a `u8` inside the verified SID structure.
        let count = unsafe { *count_ptr };
        // A valid integrity pseudo-SID (like S-1-16-0x4000) MUST contain at least 1 sub-authority number!
        // A count of 0 is an impossible, corrupted SID state.
        if count == 0 {
            return Err(ElevateError::InvalidSid);
        }

        // Step 3: Fetch the very LAST sub-authority number (using 0-based array index: `count - 1`).
        // Why `count - 1`?
        // `GetSidSubAuthorityCount` returned the total COUNT of sub-authorities (e.g. 1),
        // but `GetSidSubAuthority` expects a 0-based ARRAY INDEX!
        // If we forgot to subtract 1 and passed `count`, we would read `array[count]`,
        // immediately reading out of bounds past the end of the SID.
        //
        // Note on SID format: In `S-1-16-0x4000`, the `1` is the revision, `16` is the authority,
        // and `0x4000` is the ONLY sub-authority in the array (at index `0`).
        // Thus, index `count - 1` (1 - 1 = 0) lands directly on `0x4000`!
        //
        // SAFETY: We verified `count > 0` above, so index `count - 1` is strictly within valid array bounds.
        let sub_auth_ptr = unsafe { GetSidSubAuthority(sid, count as u32 - 1) };
        if sub_auth_ptr.is_null() {
            return Err(ElevateError::InvalidSid);
        }

        // SAFETY: `sub_auth_ptr` points to the last verified 32-bit sub-authority integer inside the valid SID.
        Ok(unsafe { *sub_auth_ptr })
    }

    /// Checks if a privilege physically exists in this token's table (even if it's currently disabled).
    ///
    /// # The "Why": Two things you must know before reading this code
    ///
    /// 1. Why resolve strings into LUIDs first?
    ///    We talk in human strings like `"SeDebugPrivilege"`. But the Windows kernel refuses
    ///    to do slow string comparisons inside performance-critical security checks.
    ///    Instead, Windows assigns every privilege a 64-bit integer ID called an `LUID`.
    ///    We must first ask the OS: *"What 64-bit number does `SeDebugPrivilege` have on this machine?"*
    ///    Once we have that number, matching is just a lightning-fast integer comparison (`==`).
    ///
    /// 2. Why do we ignore whether it's enabled?
    ///    On elevated Administrator tokens, high-power privileges (like `SeDebugPrivilege`)
    ///    are already present in the table, but Windows keeps them **switched off (disabled)**
    ///    by default until you explicitly turn them on.
    ///    We only care about **presence** here. As long as the LUID is in the table,
    ///    we can flip the switch anytime via `AdjustTokenPrivileges`.
    pub(crate) fn has_privilege_present(&self, privilege: Privilege) -> Result<bool, ElevateError> {
        // Step 1: Translate the human string ("SeDebugPrivilege") into the kernel's internal 64-bit number (LUID).
        let mut luid = LUID::default();
        win32!(LookupPrivilegeValueW(
            PCWSTR::null(),
            privilege.as_pcwstr(),
            &raw mut luid
        ))?;

        // Step 2: Grab the raw privileges buffer from the Windows kernel.
        let buf = self.query_info_buffer(TokenPrivileges)?;

        // Step 3: Parse the header to see how many privileges were returned.
        let privs: &TOKEN_PRIVILEGES = Self::cast_buffer(&buf);
        let count = privs.PrivilegeCount as usize;
        if count == 0 {
            return Ok(false);
        }

        // Step 4: The C Flexible Array Trap (Why manual byte offset calculation?)
        // In the Windows SDK, `TOKEN_PRIVILEGES` defines the array as `Privileges: [LUID_AND_ATTRIBUTES; 1]`.
        // That size of 1 is an ancient C-era lie used to fake a variable-length struct.
        //
        // In Rust, a type's size is a sacred compile-time contract!
        // Because the type is declared as `[T; 1]`, Rust strictly measures this struct's footprint
        // as holding EXACTLY ONE element.
        // If we access this field directly through Rust's type system:
        // - Rust's type model completely ignores the memory beyond that single element!
        // - The kernel might have written 10 privileges into our buffer, but Rust strictly truncates
        //   the array at index 0, tossing out and abandoning all data past the first element!
        // - Trying to index past 0 (`privs.Privileges[i]`) will trigger an immediate bounds-check panic.
        //
        // Therefore, we must escape Rust's rigid `[T; 1]` type boundary:
        // *"How many bytes do we need to walk forward to reach the `Privileges` field?"*
        let privs_offset = mem::offset_of!(TOKEN_PRIVILEGES, Privileges);

        // SAFETY:
        // 1. Pointer arithmetic: `ptr::from_ref(privs)` points to our aligned buffer.
        //    Offsetting by `privs_offset` lands us directly on the `Privileges` field.
        // 2. Safe slice reconstruction:
        //    The `PrivilegeCount` field is literally the official Win32 solution for this flexible array:
        //    it tells us exactly how many real elements the kernel wrote into memory.
        //    We just take the pointer to `Privileges` and combine it with `count` to build
        //    a standard fat pointer slice (`from_raw_parts`), cleanly exposing all elements without overflow.
        let privs_ptr = unsafe {
            ptr::from_ref(privs)
                .byte_add(privs_offset)
                .cast::<LUID_AND_ATTRIBUTES>()
        };
        let slice = unsafe { slice::from_raw_parts(privs_ptr, count) };

        // Step 5: Fast integer scan. If the 64-bit LUID matches, the privilege is present.
        Ok(slice.iter().any(|p| p.Luid == luid))
    }

    /// Query the Windows Session ID currently associated with this token.
    pub(crate) fn session_id(&self) -> Result<u32, ElevateError> {
        let mut session_id = 0u32;
        let mut bytes_needed = 0u32;
        win32!(GetTokenInformation(
            self.0,
            TokenSessionId,
            Some(ptr::from_mut(&mut session_id).cast()),
            mem::size_of::<u32>() as u32,
            &raw mut bytes_needed
        ))?;
        Ok(session_id)
    }

    /// Explicitly assign a Windows Session ID to this token.
    pub(crate) fn set_session_id(&self, session_id: u32) -> Result<(), ElevateError> {
        win32!(SetTokenInformation(
            self.0,
            TokenSessionId,
            ptr::from_ref(&session_id).cast(),
            mem::size_of::<u32>() as u32
        ))?;
        Ok(())
    }

    /// Execute a scoped operation while impersonating this token on the current OS thread.
    ///
    /// Guarantees that the impersonation context is bound to the enclosing scope and
    /// will always revert (`RevertToSelf`) on normal return or during panic unwinding.
    pub(crate) fn with_impersonation<F, R>(&self, f: F) -> Result<R, ElevateError>
    where
        F: FnOnce() -> Result<R, ElevateError>,
    {
        let _guard = self.impersonate()?;
        f()
    }

    /// Internal helper returning an RAII revert guard.
    pub(crate) fn impersonate(&self) -> Result<ImpersonationGuard, ElevateError> {
        win32!(ImpersonateLoggedOnUser(self.0))?;
        Ok(ImpersonationGuard {
            _marker: PhantomData,
        })
    }

    /// Gets the token owner's SID as a readable string (e.g. `"S-1-5-18"` for SYSTEM).
    pub(crate) fn user_sid(&self) -> Result<String, ElevateError> {
        let buf = self.query_info_buffer(TokenUser)?;
        let user: &TOKEN_USER = Self::cast_buffer(&buf);
        Sid::string_from_raw(user.User.Sid)
    }

    /// Check whether this token holds membership in the specified string SID.
    pub fn has_sid(&self, sid: PCWSTR) -> Result<bool, ElevateError> {
        let sid = Sid::parse(sid)?;
        let buf = self.query_info_buffer(TokenGroups)?;

        let groups: &TOKEN_GROUPS = Self::cast_buffer(&buf);
        let count = groups.GroupCount as usize;
        if count == 0 {
            return Ok(false);
        }

        let groups_offset = mem::offset_of!(TOKEN_GROUPS, Groups);
        let groups_ptr = unsafe {
            ptr::from_ref(groups)
                .byte_add(groups_offset)
                .cast::<SID_AND_ATTRIBUTES>()
        };
        let slice = unsafe { slice::from_raw_parts(groups_ptr, count) };

        for group in slice {
            if unsafe { Sid::equal(group.Sid, sid.as_raw()) }? {
                let attrs = group.Attributes;
                let is_enabled = (attrs & (SE_GROUP_ENABLED as u32)) != 0;
                let is_deny_only = (attrs & (SE_GROUP_USE_FOR_DENY_ONLY as u32)) != 0;

                if is_enabled && !is_deny_only {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Queries low-level token data into a memory buffer with guaranteed pointer alignment.
    ///
    /// # The Architecture Trap: Why `Vec<usize>` instead of `Vec<u8>`?
    /// If we naively allocated an unaligned byte buffer (`Vec<u8>`):
    /// - **On x86/x64**: For normal read instructions, the CPU hardware forgives unaligned pointers
    ///   by splitting the read into two memory cycles (eating a big performance penalty).
    ///   However, creating an unaligned reference (`&*`) is Undefined Behavior in Rust! When compiling
    ///   in `--release` mode, LLVM's optimizer assumes the pointer is aligned and generates fast SIMD
    ///   instructions (like `movdqa`). Those vector instructions strictly require alignment—if the
    ///   pointer is misaligned, the CPU throws an instant hardware crash (`#GP` fault)!
    /// - **On ARM64 (Surface / Snapdragon PCs)**: The CPU has zero tolerance for unaligned struct
    ///   reads even on normal instructions, straight-up crashing with a hardware Alignment Fault.
    ///
    /// The structs Windows hands back (like `TOKEN_USER` or `TOKEN_PRIVILEGES`) are packed with 64-bit
    /// pointers and `LUID`s that strictly demand 8-byte alignment.
    /// By allocating as `Vec<usize>`, we guarantee the buffer naturally sits on proper native pointer
    /// boundaries (8 bytes on 64-bit systems), ensuring all downstream struct casts are 100% sound.
    fn query_info_buffer(
        &self,
        class: TOKEN_INFORMATION_CLASS,
    ) -> Result<Vec<usize>, ElevateError> {
        let mut bytes_needed = 0u32;

        // Step 1: Intentionally pass a dummy null buffer with size 0,
        // specifically to make Windows scream at us: "Hey, your buffer is too small! Here's how much you actually need."
        unsafe {
            SetLastError(WIN32_ERROR(0));
            let _ = GetTokenInformation(self.0, class, None, 0, &raw mut bytes_needed);
            let last_error = GetLastError();

            // Sanity check:
            // Failing with `ERROR_INSUFFICIENT_BUFFER` is our "happy path"—it means the OS did its math.
            // But if it blows up with Access Denied or an Invalid Handle, something is legitimately broken.
            // We must bail out immediately instead of pretending everything is fine!
            if last_error != ERROR_INSUFFICIENT_BUFFER {
                return Err(ElevateError::Win32 {
                    operation: "GetTokenInformation (probe size)",
                    source: windows::core::Error::from_win32(),
                });
            }
        }

        // Defensive check: If the OS complained our buffer was too small, it better ask for > 0 bytes.
        // Getting 0 here means the kernel went crazy or handed back bogus garbage.
        if bytes_needed == 0 {
            return Err(ElevateError::InvalidTokenBuffer);
        }

        // Step 2: Calculate how many `usize` slots we need.
        // Windows gave us `bytes_needed` in raw bytes, but our buffer stores 8-byte chunks (`usize`).
        // Why `div_ceil` instead of normal division `/`?
        // Normal integer division truncates towards zero! If Windows asks for 13 bytes:
        // - `13 / 8 = 1` slot (only 8 bytes allocated!). Windows writes 13 bytes, buffer overflows, instant memory corruption!
        // - `13.div_ceil(8) = 2` slots (16 bytes allocated!). Windows safely writes 13 bytes with room to spare.
        let count = (bytes_needed as usize).div_ceil(mem::size_of::<usize>());
        let mut buf: Vec<usize> = vec![0; count];

        // Step 3: Now that we gave Windows a properly aligned and safely rounded buffer,
        // call it again to fetch the real data.
        win32!(GetTokenInformation(
            self.0,
            class,
            Some(buf.as_mut_ptr().cast()),
            bytes_needed,
            &raw mut bytes_needed
        ))?;

        Ok(buf)
    }

    /// Casts an aligned `usize` buffer slice into an immutable reference of a Win32 struct `&T`.
    ///
    /// # The "Why": Why `&*` instead of keeping it as a raw pointer `*const T`?
    /// 1. **Taming the Wild Pointer (Lifetime Safety)**:
    ///    A raw pointer (`*const T`) has no lifetime. If you pass it around, the compiler can't stop you
    ///    from reading it even after `buf` is dropped (instant Use-After-Free bug!).
    ///    By turning it into a real Rust reference (`&T`) via `&*`, the compiler ties its lifetime directly
    ///    to `buf`. As long as `buf` lives, `user` is guaranteed safe to read.
    ///
    /// 2. **Avoiding Stack Copy Bloat**:
    ///    Why not just `let user = *ptr`? Because Win32 structs implement `Copy`!
    ///    Dereferencing without `&` causes Rust to bitwise-copy the ENTIRE struct onto the local stack frame.
    ///    The `&*` pattern gives us an in-place borrow: zero copies, zero overhead.
    #[inline]
    fn cast_buffer<T>(buf: &[usize]) -> &T {
        // ! CRITICAL WIN32 SAFETY CHECK:
        // In the crazy world of the Windows API, sizes are almost never "what they seem":
        //
        // 1. The Flexible Array Trap (Variable-length Structs):
        //    Structs like `TOKEN_PRIVILEGES` lie about their size! `mem::size_of::<T>()` only reports
        //    the base static size (e.g., 16 bytes for 1 count + 1 element). But if the kernel writes back
        //    10 privileges, the physical data is actually 160 bytes! We must ensure our byte buffer
        //    is at least large enough to safely embrace this variable-length payload.
        //
        // 2. The Integer Division Trap vs. `div_ceil`:
        //    When allocating the buffer up-stream, we converted raw bytes into 8-byte pointer chunks
        //    using `div_ceil()`. If Windows asked for 13 bytes, normal division (`13 / 8`) would truncate
        //    to 1 slot (8 bytes allocated). Writing 13 bytes into an 8-byte box causes a catastrophic
        //    buffer overflow! `div_ceil` rounds it up to 2 slots (16 bytes allocated).
        //    Therefore, our physical `buf` will often be slightly "fatter" than the static struct `T`.
        //
        // This `>=` check draws a firm red line: as long as our physical memory box (`mem::size_of_val`)
        // is greater than or equal to the minimum required struct shape (`mem::size_of`), the downstream
        // pointer cast is 100% sound and will never leak into random memory garbage!
        debug_assert!(
            mem::size_of_val(buf) >= mem::size_of::<T>(),
            "Buffer too small for requested struct cast"
        );

        // SAFETY: `buf` is guaranteed to be 8-byte pointer aligned by `query_info_buffer`,
        // and holds at least `sizeof(T)` bytes as asserted above.
        unsafe { &*buf.as_ptr().cast::<T>() }
    }
}

/// RAII guard representing temporary thread-level privilege impersonation.
///
/// When instantiated, the calling OS thread adopts elevated privileges (such as `SYSTEM`).
/// When dropped, it automatically calls [`RevertToSelf`] to drop those privileges and
/// return the thread to the process's primary security context.
///
/// # Critical Architectural Guarantees
///
/// 1. Why `!Send` is strictly mandatory (Thread-Affinity & Async Poisoning):
///    In the Windows NT architecture, thread impersonation tokens are strictly stored inside
///    the kernel's thread object (the calling thread's `ETHREAD`).
///    - **The Asymmetric Cleanup Trap**: `RevertToSelf()` operates *only* on the thread currently
///      calling it. If this guard were `Send` and moved from Thread A to Thread B:
///      - Thread A would permanently retain its `SYSTEM` token because no one ever calls `RevertToSelf` on it.
///      - Thread B would drop the guard, calling `RevertToSelf` on itself, which does nothing for Thread A
///        and instead accidentally strips Thread B's own legitimate security context.
///    - **The Tokio / Work-Stealing Disaster**: Multi-threaded async runtimes frequently suspend tasks
///      at `.await` points on Thread A and resume them on Thread B. Marking this struct `!Send` forces
///      the Rust compiler to reject any attempt to hold an active impersonation scope across an `.await`,
///      stopping ghost privilege leaks at compile time.
///
/// 2. The Flat Reversion Trap (No Nested Scopes):
///    `RevertToSelf()` unconditionally wipes out the calling thread's impersonation token, reverting
///    all the way back to the process primary token. It does not maintain an internal stack:
///    if this thread was already running under an existing impersonated identity prior to entering
///    this scope, dropping this guard will clear that prior identity too, rather than restoring it.
pub(crate) struct ImpersonationGuard {
    _marker: PhantomData<*const ()>,
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        // SAFETY: `RevertToSelf` takes no pointer arguments, performs no memory allocations,
        // and cannot cause buffer overruns or memory corruption.
        //
        // ! FAIL-CLOSED SECURITY POLICY:
        // If `RevertToSelf` fails (e.g. extreme kernel resource exhaustion or hostile API hook interception),
        // this OS thread would quietly continue executing downstream application code while still holding
        // unrestricted SYSTEM privileges.
        // Because `Drop::drop` cannot return a `Result`, our only secure course of action is to immediately
        // abort the process (`std::process::abort()`). Terminating the application instantly is far safer
        // than letting an un-reverted thread run wild with a leaked high-privilege token!
        if unsafe { RevertToSelf() }.is_err() {
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::w;
    static_assertions::assert_not_impl_any!(ImpersonationGuard: Send, Sync);

    // =======================================================================
    // Non-elevated tests — safe to run in standard / CI environments
    // =======================================================================

    // Ensure we can always open the security token of the currently running process.
    #[test]
    fn current_token_opens_successfully() {
        let current_token = Token::current();
        assert!(
            current_token.is_ok(),
            "Opening the current process token should always succeed"
        );
    }

    // Ensure we can read the Windows Session ID from the token (Session 0 for services, 1+ for desktop).
    #[test]
    fn current_token_session_id_is_valid() {
        let current_token = Token::current().unwrap();
        let session = current_token.session_id();
        assert!(session.is_ok(), "Reading session ID must not fail");
    }

    // Ensure the token owner SID is valid and starts with the standard Windows SID prefix "S-1-".
    #[test]
    fn current_token_user_sid_is_nonempty_and_valid() {
        let current_token = Token::current().unwrap();
        let sid = current_token.user_sid().unwrap();
        assert!(
            sid.starts_with("S-1-"),
            "User SID must be a valid SID string starting with S-1-, got: {sid}"
        );
    }

    // Ensure the boolean elevation flag strictly aligns with the Mandatory Integrity Level:
    // Elevated Admin must be High/System (>= 0x3000), standard user must be Medium or lower (< 0x3000).
    #[test]
    fn is_elevated_admin_matches_integrity_level() {
        let current_token = Token::current().unwrap();

        let is_admin = current_token.is_elevated_admin().unwrap();
        let integrity_level = current_token.integrity_level().unwrap();

        if is_admin {
            assert!(
                integrity_level >= 0x3000,
                "Elevated admin must possess High/System integrity level (>= 0x3000), got: 0x{integrity_level:04X}"
            );
        } else {
            assert!(
                integrity_level < 0x3000,
                "Non-elevated user must possess Medium or lower integrity level (< 0x3000), got: 0x{integrity_level:04X}"
            );
        }
    }

    // Normal developer processes and test runners should never be running with a restricted sandbox token.
    #[test]
    fn current_token_is_not_restricted() {
        let current_token = Token::current().unwrap();

        let is_restricted = current_token.is_restricted().unwrap();
        assert!(
            !is_restricted,
            "Current development/test process should not be a restricted token"
        );
    }

    // Ensure checking membership for a non-existent or fake SID safely returns false instead of failing.
    #[test]
    fn has_sid_with_bogus_sid_returns_false() {
        let current_token = Token::current().unwrap();
        let has = current_token
            .has_sid(w!("S-1-5-80-0-0-0-0-999999"))
            .unwrap();
        assert!(
            !has,
            "Token should not claim membership in a fake, non-existent SID"
        );
    }
}
