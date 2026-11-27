#![cfg(windows)]
//! `privileged_fence`: the host is LocalSystem, not merely an elevated
//! administrator; the nextest parent starts its own child under a scheduled
//! SYSTEM task. `session_fence`: the host is the runner's elevated
//! administrator token, which is not SYSTEM, so the elevated session fence.
use etd_contract::InstanceId;
use etd_sysfx::*;
use etd_sysfx_os::{OsConfig, adapters};
use etd_testkit::no_window::NoWindow;
use std::{
    process::Command,
    time::{Duration, Instant},
};

fn ps(script: &str) -> String {
    let output = Command::new("powershell.exe")
        .no_window()
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().into()
}
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn assert_wfp_container_absent() {
    use ::windows::{
        Win32::{
            Foundation::{FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE},
            NetworkManagement::WindowsFilteringPlatform::*,
        },
        core::{GUID, PCWSTR},
    };
    // Independent BFE handle and direct queries for both container keys.
    unsafe {
        let mut handle = HANDLE::default();
        assert_eq!(
            FwpmEngineOpen0(PCWSTR::null(), 10, None, None, &mut handle),
            0
        );
        let mut provider = std::ptr::null_mut();
        let mut sublayer = std::ptr::null_mut();
        let p = FwpmProviderGetByKey0(
            handle,
            &GUID::from_u128(0x51e7d001_7bc3_43b9_a795_7b80c196382f),
            &mut provider,
        );
        let s = FwpmSubLayerGetByKey0(
            handle,
            &GUID::from_u128(0x51e7d002_7bc3_43b9_a795_7b80c196382f),
            &mut sublayer,
        );
        if !provider.is_null() {
            FwpmFreeMemory0((&mut provider as *mut *mut FWPM_PROVIDER0).cast());
        }
        if !sublayer.is_null() {
            FwpmFreeMemory0((&mut sublayer as *mut *mut FWPM_SUBLAYER0).cast());
        }
        FwpmEngineClose0(handle);
        assert_eq!(p, FWP_E_PROVIDER_NOT_FOUND.0 as u32);
        assert_eq!(s, FWP_E_SUBLAYER_NOT_FOUND.0 as u32);
    }
}

#[tokio::test]
#[ignore = "requires LocalSystem and a disposable Windows CI runner"]
async fn privileged_fence() {
    assert_eq!(std::env::var("CI").as_deref(), Ok("true"));
    let sid = ps("[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value");
    if sid != "S-1-5-18" {
        let exe = std::env::current_exe().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("child.log");
        let result = dir.path().join("exit.txt");
        let script = dir.path().join("run.ps1");
        let second_dir = std::env::var("ETD_O1_SECOND_DIR").unwrap();
        std::fs::write(&script,format!("$env:CI='true'\n$env:ETD_O1_SECOND_DIR={}\n& {} --exact privileged_fence --ignored --nocapture *> {}\n$LASTEXITCODE | Set-Content {}",quote(&second_dir),quote(&exe.to_string_lossy()),quote(&log.to_string_lossy()),quote(&result.to_string_lossy()))).unwrap();
        let task = format!("ETD-O1-System-{}", uuid::Uuid::new_v4());
        ps(&format!(
            "$ErrorActionPreference='Stop'; $a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{}\"'; $p=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest; Register-ScheduledTask -TaskName '{task}' -Action $a -Principal $p | Out-Null; Start-ScheduledTask -TaskName '{task}'",
            script.display()
        ));
        let deadline = Instant::now() + Duration::from_secs(240);
        while !result.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(250));
        }
        ps(&format!(
            "Stop-ScheduledTask -TaskName '{task}' -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName '{task}' -Confirm:$false"
        ));
        let output = std::fs::read(&log).unwrap_or_default();
        // PowerShell 5 redirects native stdout to a UTF-16 LE file.
        let log = if output.starts_with(&[255, 254]) {
            String::from_utf16_lossy(
                &output[2..]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .collect::<Vec<_>>(),
            )
        } else {
            String::from_utf8_lossy(&output).into_owned()
        };
        println!("{log}");
        assert_eq!(std::fs::read_to_string(&result).unwrap().trim(), "0");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let os = adapters(&OsConfig {
        state_dir: dir.path().into(),
        run_dir: dir.path().join("run"),
        core_store_dir: dir.path().join("core"),
    })
    .unwrap();
    let fence = os.fence.unwrap();
    for loopback in ["127.0.0.1:0", "[::1]:0"] {
        let listener = tokio::net::TcpListener::bind(loopback).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let spec = FenceSpec {
            instance: InstanceId::from("o1-fence"),
            epoch: Epoch(1),
            address: addr,
        };
        let intent = fence.plan(&spec);
        let second = || {
            let folder = std::path::PathBuf::from(std::env::var("ETD_O1_SECOND_DIR").unwrap());
            let file = folder.join("results/verdict.txt");
            let _ = std::fs::remove_file(&file);
            std::fs::write(folder.join("endpoint.tmp"), addr.to_string()).unwrap();
            std::fs::rename(folder.join("endpoint.tmp"), folder.join("endpoint.txt")).unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if let Ok(s) = std::fs::read_to_string(&file)
                    && !s.trim().is_empty()
                {
                    return s.trim().to_owned();
                }
                assert!(Instant::now() < deadline, "second account probe timed out");
                std::thread::sleep(Duration::from_millis(100));
            }
        };
        assert_eq!(second(), "connected");
        let observation = fence.install(&spec).await.unwrap();
        assert!(matches!(
            observation.credential,
            Some(Credential::ExclusiveContainer { .. })
        ));
        let reclaim = os
            .reclaimers
            .iter()
            .find(|r| r.kind() == EffectKind::WinFenceFilter)
            .unwrap();
        let effect = Effect {
            id: EffectId("fence".into()),
            scope: intent.scope,
            kind: intent.kind,
            key: intent.key.clone(),
            undo: intent.undo,
            persistence: intent.persistence,
            state: EffectState::Applied,
            boot: os.boot_id.current().unwrap(),
            observation: Some(observation),
            failures: 0,
            last_error: None,
            recorded_at: jiff::Timestamp::now(),
        };
        assert!(matches!(reclaim.probe(&effect).await, Probe::Present(_)));
        let verification = fence.verify(&spec, std::process::id()).await;
        let verdict = second();
        let other_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let other = FenceSpec {
            instance: InstanceId::from("o1-other"),
            epoch: Epoch(1),
            address: other_listener.local_addr().unwrap(),
        };
        let other_key = fence.plan(&other).key;
        fence.install(&other).await.unwrap();
        drop(listener);
        assert_eq!(reclaim.reclaim(&effect).await.unwrap(), Reclaimed::Removed);
        assert!(matches!(reclaim.probe(&effect).await, Probe::Absent));
        assert!(
            os.observer
                .observe(EffectKind::WinFenceFilter, &other_key)
                .await
                .unwrap()
                .is_some(),
            "reclaim of one port must not remove another fence"
        );
        drop(other_listener);
        assert_eq!(fence.remove(&other).await.unwrap(), Reclaimed::Removed);
        assert_wfp_container_absent();
        assert!(
            os.observer
                .enumerate(SystemClass::FirewallRules)
                .await
                .unwrap()
                .iter()
                .all(|r| r.key != intent.key)
        );
        assert_eq!(verdict, "refused");
        let verification = verification.unwrap();
        assert!(verification.passed(), "{verification:?}");
        println!(
            "WFP {addr}: SYSTEM connected, independent second account refused; persistent filters reclaimed: {verification:?}"
        );
    }
}

const SUBLAYER: u128 = 0x51e7d002_7bc3_43b9_a795_7b80c196382f;
const PROVIDER: u128 = 0x51e7d001_7bc3_43b9_a795_7b80c196382f;

/// Flags of our provider, our sublayer and every filter in our sublayer,
/// read with an independent BFE handle.
fn wfp_container() -> (u32, u32, Vec<u32>) {
    use ::windows::{
        Win32::{Foundation::HANDLE, NetworkManagement::WindowsFilteringPlatform::*},
        core::{GUID, PCWSTR},
    };
    unsafe {
        let mut engine = HANDLE::default();
        assert_eq!(
            FwpmEngineOpen0(PCWSTR::null(), 10, None, None, &mut engine),
            0
        );
        let mut provider = std::ptr::null_mut();
        assert_eq!(
            FwpmProviderGetByKey0(engine, &GUID::from_u128(PROVIDER), &mut provider),
            0
        );
        let provider_flags = (*provider).flags;
        FwpmFreeMemory0((&mut provider as *mut *mut FWPM_PROVIDER0).cast());
        let mut sublayer = std::ptr::null_mut();
        assert_eq!(
            FwpmSubLayerGetByKey0(engine, &GUID::from_u128(SUBLAYER), &mut sublayer),
            0
        );
        let sublayer_flags = (*sublayer).flags;
        FwpmFreeMemory0((&mut sublayer as *mut *mut FWPM_SUBLAYER0).cast());
        let mut filters = Vec::new();
        let mut handle = HANDLE::default();
        assert_eq!(FwpmFilterCreateEnumHandle0(engine, None, &mut handle), 0);
        loop {
            let mut entries = std::ptr::null_mut();
            let mut count = 0;
            assert_eq!(
                FwpmFilterEnum0(engine, handle, 128, &mut entries, &mut count),
                0
            );
            for i in 0..count as usize {
                let f = &**entries.add(i);
                if f.subLayerKey == GUID::from_u128(SUBLAYER) {
                    filters.push(f.flags.0);
                }
            }
            FwpmFreeMemory0((&mut entries as *mut *mut *mut FWPM_FILTER0).cast());
            if count == 0 {
                break;
            }
        }
        FwpmFilterDestroyEnumHandle0(engine, handle);
        FwpmEngineClose0(engine);
        (provider_flags, sublayer_flags, filters)
    }
}

/// A restricted primary copy of this token: BUILTIN\Administrators
/// deny-only, Medium integrity, owner and default DACL the user's. Built
/// here independently of the product's probe; the caller closes it.
fn restricted_token(user: &str) -> ::windows::Win32::Foundation::HANDLE {
    use ::windows::{
        Win32::{
            Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree},
            Security::{
                Authorization::{
                    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
                    SDDL_REVISION_1,
                },
                CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, GetSecurityDescriptorDacl,
                PSECURITY_DESCRIPTOR, PSID, SID_AND_ATTRIBUTES, SetTokenInformation,
                TOKEN_ALL_ACCESS, TOKEN_DEFAULT_DACL, TOKEN_MANDATORY_LABEL, TOKEN_OWNER,
                TokenDefaultDacl, TokenIntegrityLevel, TokenOwner,
            },
            System::{
                SystemServices::SE_GROUP_INTEGRITY,
                Threading::{GetCurrentProcess, OpenProcessToken},
            },
        },
        core::HSTRING,
    };
    let sid = |text: &str| {
        let mut sid = PSID::default();
        unsafe { ConvertStringSidToSidW(&HSTRING::from(text), &mut sid).unwrap() };
        sid
    };
    unsafe {
        let mut own = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut own).unwrap();
        let admins = sid("S-1-5-32-544");
        let disable = [SID_AND_ATTRIBUTES {
            Sid: admins,
            Attributes: 0,
        }];
        let mut token = HANDLE::default();
        CreateRestrictedToken(
            own,
            DISABLE_MAX_PRIVILEGE,
            Some(&disable),
            None,
            None,
            &mut token,
        )
        .unwrap();
        let medium = sid("S-1-16-8192");
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: medium,
                Attributes: SE_GROUP_INTEGRITY as u32,
            },
        };
        SetTokenInformation(
            token,
            TokenIntegrityLevel,
            (&raw const label).cast(),
            size_of_val(&label) as u32,
        )
        .unwrap();
        let user_sid = sid(user);
        let owner = TOKEN_OWNER { Owner: user_sid };
        SetTokenInformation(
            token,
            TokenOwner,
            (&raw const owner).cast(),
            size_of_val(&owner) as u32,
        )
        .unwrap();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(format!("D:(A;;GA;;;{user})(A;;GA;;;SY)")),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .unwrap();
        let mut present = false.into();
        let mut defaulted = false.into();
        let mut dacl = std::ptr::null_mut();
        GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted).unwrap();
        let default = TOKEN_DEFAULT_DACL { DefaultDacl: dacl };
        SetTokenInformation(
            token,
            TokenDefaultDacl,
            (&raw const default).cast(),
            size_of_val(&default) as u32,
        )
        .unwrap();
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        for s in [admins, medium, user_sid] {
            let _ = LocalFree(Some(HLOCAL(s.0)));
        }
        let _ = CloseHandle(own);
        token
    }
}

/// On a thread impersonating the restricted copy: open the filter engine
/// and add a block filter for `address`'s port in `sublayer` (in a dynamic
/// session, so nothing outlives the attempt). Returns the first non-zero
/// status, or 0 if the filter was added.
fn restricted_wfp_add(address: std::net::SocketAddr, sublayer: u128) -> u32 {
    let user = ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value");
    std::thread::spawn(move || {
        use ::windows::{
            Win32::{
                Foundation::{CloseHandle, HANDLE},
                NetworkManagement::WindowsFilteringPlatform::*,
                Security::{
                    DuplicateTokenEx, RevertToSelf, SecurityImpersonation, TOKEN_ALL_ACCESS,
                    TokenImpersonation,
                },
                System::Threading::SetThreadToken,
            },
            core::{GUID, PCWSTR, PWSTR},
        };
        unsafe {
            let primary = restricted_token(&user);
            let mut token = HANDLE::default();
            DuplicateTokenEx(
                primary,
                TOKEN_ALL_ACCESS,
                None,
                SecurityImpersonation,
                TokenImpersonation,
                &mut token,
            )
            .unwrap();
            let _ = CloseHandle(primary);
            SetThreadToken(None, Some(token)).unwrap();
            let session = FWPM_SESSION0 {
                flags: FWPM_SESSION_FLAG_DYNAMIC,
                ..Default::default()
            };
            let mut engine = HANDLE::default();
            let mut status = FwpmEngineOpen0(PCWSTR::null(), 10, None, Some(&session), &mut engine);
            if status == 0 {
                let mut conditions = [FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_UINT16,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            uint16: address.port(),
                        },
                    },
                }];
                let mut name: Vec<u16> = "etd-test-restricted-add"
                    .encode_utf16()
                    .chain([0])
                    .collect();
                let filter = FWPM_FILTER0 {
                    displayData: FWPM_DISPLAY_DATA0 {
                        name: PWSTR(name.as_mut_ptr()),
                        ..Default::default()
                    },
                    subLayerKey: GUID::from_u128(sublayer),
                    layerKey: if address.is_ipv6() {
                        FWPM_LAYER_ALE_AUTH_CONNECT_V6
                    } else {
                        FWPM_LAYER_ALE_AUTH_CONNECT_V4
                    },
                    weight: FWP_VALUE0 {
                        r#type: FWP_UINT8,
                        Anonymous: FWP_VALUE0_0 { uint8: 15 },
                    },
                    numFilterConditions: conditions.len() as u32,
                    filterCondition: conditions.as_mut_ptr(),
                    action: FWPM_ACTION0 {
                        r#type: FWP_ACTION_BLOCK,
                        ..Default::default()
                    },
                    ..Default::default()
                };
                status = FwpmFilterAdd0(engine, &filter, None, None);
                FwpmEngineClose0(engine);
            }
            RevertToSelf().unwrap();
            let _ = CloseHandle(token);
            status
        }
    })
    .join()
    .unwrap()
}

/// A connection attempt from a child process started with
/// [`restricted_token`]. Returns "connected", "refused" or what went wrong.
fn restricted_connect(address: std::net::SocketAddr) -> String {
    use ::windows::{
        Win32::{
            Foundation::CloseHandle,
            System::Threading::{
                CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
                GetExitCodeProcess, PROCESS_INFORMATION, STARTUPINFOW, WaitForSingleObject,
            },
        },
        core::{HSTRING, PCWSTR, PWSTR},
    };
    let user = ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value");
    let token = restricted_token(&user);
    unsafe {
        let family = if address.is_ipv6() {
            "InterNetworkV6"
        } else {
            "InterNetwork"
        };
        let code = format!(
            "$i=[Security.Principal.WindowsIdentity]::GetCurrent(); if ($i.User.Value -ne '{user}' -or ([Security.Principal.WindowsPrincipal]$i).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{ exit 3 }}; $s=[Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::{family},[Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Tcp); try {{ $s.Connect([ipaddress]'{}',{}); exit 0 }} catch {{ $e=$_.Exception; while ($e -and $e -isnot [Net.Sockets.SocketException]) {{ $e=$e.InnerException }}; if ($e) {{ exit ([int]$e.NativeErrorCode) }}; exit 2 }} finally {{ $s.Dispose() }}",
            address.ip(),
            address.port()
        );
        let encoded = {
            let bytes: Vec<u8> = code.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for chunk in bytes.chunks(3) {
                let n = (u32::from(chunk[0]) << 16)
                    | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                    | u32::from(*chunk.get(2).unwrap_or(&0));
                for i in 0..4 {
                    if i <= chunk.len() {
                        out.push(alphabet[((n >> (18 - 6 * i)) & 63) as usize] as char);
                    } else {
                        out.push('=');
                    }
                }
            }
            out
        };
        let exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        let mut command: Vec<u16> =
            format!("\"{exe}\" -NoProfile -NonInteractive -EncodedCommand {encoded}")
                .encode_utf16()
                .chain([0])
                .collect();
        let environment: Vec<u16> = [r"SystemRoot=C:\Windows", r"windir=C:\Windows"]
            .iter()
            .flat_map(|v| v.encode_utf16().chain([0]))
            .chain([0])
            .collect();
        let startup = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut process = PROCESS_INFORMATION::default();
        let created = CreateProcessAsUserW(
            Some(token),
            &HSTRING::from(exe),
            Some(PWSTR(command.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            Some(environment.as_ptr().cast()),
            PCWSTR::null(),
            &startup,
            &mut process,
        );
        let _ = CloseHandle(token);
        if let Err(e) = created {
            return format!("CreateProcessAsUserW failed: {e}");
        }
        WaitForSingleObject(process.hProcess, 30_000);
        let mut code = 0;
        GetExitCodeProcess(process.hProcess, &mut code).unwrap();
        let _ = CloseHandle(process.hThread);
        let _ = CloseHandle(process.hProcess);
        match code {
            0 => "connected".into(),
            10013 => "refused".into(),
            other => format!("exit {other:#x}"),
        }
    }
}

/// The session tree's protected profile directory, as the composition root
/// makes it: SYSTEM and Administrators only, the whole DACL replaced (an
/// elevated creator's default DACL can add an explicit entry for the user).
fn protected_profile(path: &std::path::Path) {
    use ::windows::{
        Win32::{
            Foundation::{HLOCAL, LocalFree},
            Security::{
                Authorization::{
                    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
                    SE_FILE_OBJECT, SetNamedSecurityInfoW,
                },
                DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
                PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            },
        },
        core::HSTRING,
    };
    std::fs::create_dir(path).unwrap();
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
        .unwrap();
        let mut present = false.into();
        let mut defaulted = false.into();
        let mut dacl = std::ptr::null_mut();
        GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted).unwrap();
        SetNamedSecurityInfoW(
            &HSTRING::from(path.as_os_str()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
        .ok()
        .unwrap();
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }
}

/// A permit-everyone filter for one loopback port inside our sublayer, at
/// a higher weight than the fence's block: the fence's four filters stay
/// complete, but anyone can connect. Added in a dynamic engine session, so
/// it is gone when this value drops.
struct Breaker(::windows::Win32::Foundation::HANDLE);
impl Breaker {
    fn add(address: std::net::SocketAddr) -> Self {
        use ::windows::{
            Win32::{Foundation::HANDLE, NetworkManagement::WindowsFilteringPlatform::*},
            core::{GUID, PCWSTR, PWSTR},
        };
        unsafe {
            let session = FWPM_SESSION0 {
                flags: FWPM_SESSION_FLAG_DYNAMIC,
                ..Default::default()
            };
            let mut engine = HANDLE::default();
            assert_eq!(
                FwpmEngineOpen0(PCWSTR::null(), 10, None, Some(&session), &mut engine),
                0
            );
            let mut addr6 = FWP_BYTE_ARRAY16 {
                byteArray16: std::net::Ipv6Addr::LOCALHOST.octets(),
            };
            let remote = if address.is_ipv6() {
                FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_BYTE_ARRAY16_TYPE,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            byteArray16: &mut addr6,
                        },
                    },
                }
            } else {
                FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_UINT32,
                        Anonymous: FWP_CONDITION_VALUE0_0 { uint32: 0x7f000001 },
                    },
                }
            };
            let mut conditions = [
                remote,
                FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_UINT16,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            uint16: address.port(),
                        },
                    },
                },
            ];
            let mut name: Vec<u16> = "etd-test-fence-breaker".encode_utf16().chain([0]).collect();
            let filter = FWPM_FILTER0 {
                displayData: FWPM_DISPLAY_DATA0 {
                    name: PWSTR(name.as_mut_ptr()),
                    ..Default::default()
                },
                subLayerKey: GUID::from_u128(SUBLAYER),
                layerKey: if address.is_ipv6() {
                    FWPM_LAYER_ALE_AUTH_CONNECT_V6
                } else {
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4
                },
                weight: FWP_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_VALUE0_0 { uint8: 15 },
                },
                numFilterConditions: conditions.len() as u32,
                filterCondition: conditions.as_mut_ptr(),
                action: FWPM_ACTION0 {
                    r#type: FWP_ACTION_PERMIT,
                    ..Default::default()
                },
                ..Default::default()
            };
            assert_eq!(FwpmFilterAdd0(engine, &filter, None, None), 0);
            Self(engine)
        }
    }
}
impl Drop for Breaker {
    fn drop(&mut self) {
        unsafe {
            ::windows::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineClose0(self.0);
        }
    }
}

#[tokio::test]
#[ignore = "requires an elevated administrator that is not SYSTEM on a disposable Windows CI runner"]
async fn session_fence() {
    assert_eq!(std::env::var("CI").as_deref(), Ok("true"));
    assert_ne!(
        ps("[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),
        "S-1-5-18",
        "the session fence needs a host that is not SYSTEM"
    );
    let dir = tempfile::tempdir().unwrap();
    // The protected profile directory the composition root creates next
    // to the state directory.
    protected_profile(&dir.path().join("profile"));
    std::fs::create_dir(dir.path().join("state")).unwrap();
    let os = adapters(&OsConfig {
        state_dir: dir.path().join("state"),
        run_dir: dir.path().join("run"),
        core_store_dir: dir.path().join("core"),
    })
    .unwrap();
    let fence = os.fence.unwrap();
    let reclaim = os
        .reclaimers
        .iter()
        .find(|r| r.kind() == EffectKind::WinFenceFilter)
        .unwrap();
    for loopback in ["127.0.0.1:0", "[::1]:0"] {
        let listener = tokio::net::TcpListener::bind(loopback).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let spec = FenceSpec {
            instance: InstanceId::from("es2-session-fence"),
            epoch: Epoch(1),
            address: addr,
        };
        let intent = fence.plan(&spec);
        assert_eq!(intent.persistence, Persistence::UntilReboot);
        // Without the fence the restricted copy connects: its refusal below
        // comes from the fence, not from the identity or the environment.
        assert_eq!(restricted_connect(addr), "connected");
        let observation = fence.install(&spec).await.unwrap();
        assert!(matches!(
            observation.credential,
            Some(Credential::ExclusiveContainer { .. })
        ));
        assert_eq!(
            observation.detail.as_deref(),
            Some("4 non-persistent WFP filters")
        );
        // FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_SUBLAYER_FLAG_PERSISTENT and
        // FWPM_FILTER_FLAG_PERSISTENT are all 0x1.
        let (provider, sublayer, filters) = wfp_container();
        assert_eq!(provider & 1, 0, "provider is persistent");
        assert_eq!(sublayer & 1, 0, "sublayer is persistent");
        assert_eq!(filters.len(), 4, "{filters:?}");
        assert!(filters.iter().all(|f| f & 1 == 0), "{filters:?}");

        // The product probe runs on a host thread impersonating the
        // restricted Medium copy: its refusal is this verification passing.
        let verification = fence.verify(&spec, std::process::id()).await.unwrap();
        assert!(verification.passed(), "{verification:?}");
        // Independently, while the listener is up: refused for a child with
        // the restricted copy, admitted for this elevated process (the
        // unimpersonated positive control).
        assert_eq!(restricted_connect(addr), "refused");
        tokio::net::TcpStream::connect(addr).await.unwrap();

        // A broken fence (complete, but anyone gets through) is never
        // verified: the impersonated probe connects. There is no probe child
        // a same-user process could end with a forged exit code.
        let breaker = Breaker::add(addr);
        assert_eq!(restricted_connect(addr), "connected", "the breaker works");
        let broken = fence.verify(&spec, std::process::id()).await;
        assert!(
            matches!(&broken, Ok(v) if !v.passed() && v.unprivileged == DirectionResult::Connected),
            "{broken:?}"
        );
        drop(breaker);
        assert_eq!(restricted_connect(addr), "refused");

        // The restricted identity cannot add a filter of its own (one that
        // blocks itself would forge a refusal), in our sublayer or the
        // universal one; this elevated process could (the breaker above).
        for sublayer in [SUBLAYER, 0] {
            let status = restricted_wfp_add(addr, sublayer);
            assert!(
                [5, 0x8007_0005].contains(&status),
                "restricted FwpmFilterAdd0 in {sublayer:#x}: {status:#x}"
            );
        }

        let effect = Effect {
            id: EffectId("session-fence".into()),
            scope: intent.scope,
            kind: intent.kind,
            key: intent.key.clone(),
            undo: intent.undo,
            persistence: intent.persistence,
            state: EffectState::Applied,
            boot: os.boot_id.current().unwrap(),
            observation: Some(observation),
            failures: 0,
            last_error: None,
            recorded_at: jiff::Timestamp::now(),
        };
        assert!(matches!(reclaim.probe(&effect).await, Probe::Present(_)));
        drop(listener);
        assert_eq!(reclaim.reclaim(&effect).await.unwrap(), Reclaimed::Removed);
        assert!(matches!(reclaim.probe(&effect).await, Probe::Absent));
        assert_wfp_container_absent();
        println!(
            "session WFP {addr}: elevated host connected, restricted Medium copy refused; non-persistent filters reclaimed: {verification:?}"
        );
    }
}
