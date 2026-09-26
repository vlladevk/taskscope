//! Подпись файла (WinVerifyTrust — встроенная подпись, а если её нет, каталог Windows,
//! как у системных файлов) и SHA-256 для ссылки на VirusTotal. Проверка без сети:
//! отзыв сертификатов не запрашиваем, только кэш — иначе проверка висела бы на таймаутах.

use std::collections::HashMap;
use std::ffi::c_void;
use std::io::Read;
use std::mem::size_of;
use std::os::windows::io::AsRawHandle;
use std::ptr;
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

use serde::Serialize;
use windows_sys::core::GUID;
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash, BCryptHashData, CertGetNameStringW, BCRYPT_SHA256_ALG_HANDLE, CERT_NAME_SIMPLE_DISPLAY_TYPE,
};
use windows_sys::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_FILE_INFO,
};

use crate::system::wide;

/// WINTRUST_ACTION_GENERIC_VERIFY_V2 = {00AAC56B-CD44-11D0-8CC2-00C04FC295EE}
const VERIFY_V2: GUID = GUID { data1: 0x00AA_C56B, data2: 0xCD44, data3: 0x11D0, data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE] };
const WTD_UI_NONE: u32 = 2;
const WTD_REVOKE_NONE: u32 = 0;
const WTD_CHOICE_FILE: u32 = 1;
const WTD_CHOICE_CATALOG: u32 = 2;
const WTD_STATEACTION_VERIFY: u32 = 1;
const WTD_STATEACTION_CLOSE: u32 = 2;
const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x1000;
const TRUST_E_NOSIGNATURE: i32 = 0x800B_0100_u32 as i32;
/// Формат файла без встроенной подписи (текст, картинка, архив): подписывать тут нечего.
const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B_0003_u32 as i32;

#[derive(Clone, Debug, Serialize)]
pub struct Signature {
    /// signed, unsigned, untrusted, expired, revoked, bad_digest, distrusted, error.
    pub status: &'static str,
    /// Кем подписан (имя из сертификата): «Microsoft Windows», «Google LLC».
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    /// Подпись из каталога Windows (у системных файлов нет встроенной подписи).
    pub catalog: bool,
    /// SHA-256 файла (для VirusTotal); None — файл не прочитать.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

fn status_of(code: i32) -> &'static str {
    match code as u32 {
        0 => "signed",
        0x800B_0100 => "unsigned",
        0x800B_0004 | 0x800B_0109 | 0x800B_010A => "untrusted",
        0x800B_0101 => "expired",
        0x800B_010C => "revoked",
        0x8009_6010 => "bad_digest",
        0x800B_0111 => "distrusted",
        // не программа и не в каталоге Windows — «не применимо», а не ошибка проверки
        0x800B_0003 => "not_applicable",
        _ => "error",
    }
}

/// Имя подписавшего из данных проверки (до WTD_STATEACTION_CLOSE).
unsafe fn signer_of(state: *mut c_void) -> Option<String> {
    let pd = WTHelperProvDataFromStateData(state as _);
    if pd.is_null() {
        return None;
    }
    let sg = WTHelperGetProvSignerFromChain(pd, 0, 0, 0);
    if sg.is_null() || (*sg).csCertChain == 0 || (*sg).pasCertChain.is_null() {
        return None;
    }
    let cert = (*(*sg).pasCertChain).pCert;
    if cert.is_null() {
        return None;
    }
    let mut buf = [0u16; 256];
    let n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, ptr::null(), buf.as_mut_ptr(), buf.len() as u32) as usize;
    (n > 1).then(|| String::from_utf16_lossy(&buf[..n - 1]))
}

/// Один вызов WinVerifyTrust: код результата и подписавший.
unsafe fn verify(choice: u32, info: *mut c_void) -> (i32, Option<String>) {
    let mut wd: WINTRUST_DATA = std::mem::zeroed();
    wd.cbStruct = size_of::<WINTRUST_DATA>() as u32;
    wd.dwUIChoice = WTD_UI_NONE as _;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE as _;
    wd.dwUnionChoice = choice as _;
    if choice == WTD_CHOICE_FILE {
        wd.Anonymous.pFile = info.cast();
    } else {
        wd.Anonymous.pCatalog = info.cast();
    }
    wd.dwStateAction = WTD_STATEACTION_VERIFY as _;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL as _;
    let mut action = VERIFY_V2;
    let code = WinVerifyTrust(ptr::null_mut(), &mut action, (&mut wd as *mut WINTRUST_DATA).cast());
    let signer = if code == 0 { signer_of(wd.hWVTStateData as _) } else { None };
    wd.dwStateAction = WTD_STATEACTION_CLOSE as _;
    WinVerifyTrust(ptr::null_mut(), &mut action, (&mut wd as *mut WINTRUST_DATA).cast());
    (code, signer)
}

/// Подпись через каталог: хеш файла ищется в каталогах Windows (так подписаны notepad.exe, svchost.exe…).
unsafe fn verify_catalog(path: &[u16], file: &std::fs::File) -> Option<(i32, Option<String>)> {
    for alg in ["SHA256", "SHA1"] {
        let mut admin: isize = 0;
        if CryptCATAdminAcquireContext2(&mut admin as *mut isize as _, ptr::null(), wide(alg).as_ptr(), ptr::null(), 0) == 0 {
            continue;
        }
        let mut hash = [0u8; 64];
        let mut cb = hash.len() as u32;
        let h = file.as_raw_handle();
        let mut found = None;
        if CryptCATAdminCalcHashFromFileHandle2(admin as _, h as _, &mut cb, hash.as_mut_ptr(), 0) != 0 {
            let cat = CryptCATAdminEnumCatalogFromHash(admin as _, hash.as_ptr(), cb, 0, ptr::null_mut());
            if cat as isize != 0 {
                let mut ci: CATALOG_INFO = std::mem::zeroed();
                ci.cbStruct = size_of::<CATALOG_INFO>() as u32;
                if CryptCATCatalogInfoFromContext(cat, &mut ci, 0) != 0 {
                    let tag: String = hash[..cb as usize].iter().map(|b| format!("{b:02X}")).collect();
                    let wtag = wide(&tag);
                    let mut info: WINTRUST_CATALOG_INFO = std::mem::zeroed();
                    info.cbStruct = size_of::<WINTRUST_CATALOG_INFO>() as u32;
                    info.pcwszCatalogFilePath = ci.wszCatalogFile.as_ptr();
                    info.pcwszMemberTag = wtag.as_ptr();
                    info.pcwszMemberFilePath = path.as_ptr();
                    info.hMemberFile = h as _;
                    info.pbCalculatedFileHash = hash.as_mut_ptr();
                    info.cbCalculatedFileHash = cb;
                    info.hCatAdmin = admin as _;
                    found = Some(verify(WTD_CHOICE_CATALOG, (&mut info as *mut WINTRUST_CATALOG_INFO).cast()));
                }
                CryptCATAdminReleaseCatalogContext(admin as _, cat, 0);
            }
        }
        CryptCATAdminReleaseContext(admin as _, 0);
        if found.is_some() {
            return found;
        }
    }
    None
}

/// SHA-256 файла потоком (файлы бывают в сотни мегабайт).
fn sha256(file: &mut std::fs::File) -> Option<String> {
    unsafe {
        let mut h = ptr::null_mut();
        if BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &mut h, ptr::null_mut(), 0, ptr::null(), 0, 0) < 0 {
            return None;
        }
        let mut buf = vec![0u8; 1 << 20];
        let mut ok = true;
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if BCryptHashData(h, buf.as_ptr(), n as u32, 0) < 0 {
                        ok = false;
                        break;
                    }
                }
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        let mut out = [0u8; 32];
        ok = ok && BCryptFinishHash(h, out.as_mut_ptr(), 32, 0) >= 0;
        BCryptDestroyHash(h);
        ok.then(|| out.iter().map(|b| format!("{b:02x}")).collect())
    }
}

type Key = (String, Option<SystemTime>, u64);

/// Подпись и SHA-256 файла. Результат кэшируется по пути, времени изменения и размеру.
pub fn check(path: &str) -> std::io::Result<Signature> {
    // сетевой путь: обращение к \\сервер\… отдало бы серверу NTLM-учётку (путь может прийти от агента)
    if crate::locks::is_remote(std::path::Path::new(path)) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "сетевые пути не проверяются — только локальные файлы"));
    }
    static CACHE: OnceLock<Mutex<HashMap<Key, Signature>>> = OnceLock::new();
    let meta = std::fs::metadata(path)?;
    let key = (path.to_lowercase(), meta.modified().ok(), meta.len());
    let cache = CACHE.get_or_init(Default::default);
    if let Some(s) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
        return Ok(s.clone());
    }
    let mut file = std::fs::File::open(path)?;
    let wpath = wide(path);
    let (code, signer, catalog) = unsafe {
        let mut fi: WINTRUST_FILE_INFO = std::mem::zeroed();
        fi.cbStruct = size_of::<WINTRUST_FILE_INFO>() as u32;
        fi.pcwszFilePath = wpath.as_ptr();
        let (code, signer) = verify(WTD_CHOICE_FILE, (&mut fi as *mut WINTRUST_FILE_INFO).cast());
        // файлы без встроенной подписи (и не программы: .inf, .ps1 без подписи) бывают в каталоге
        if code == TRUST_E_NOSIGNATURE || code == TRUST_E_SUBJECT_FORM_UNKNOWN {
            match verify_catalog(&wpath, &file) {
                Some((c, s)) => (c, s, true),
                None if code == TRUST_E_NOSIGNATURE => (code, None, false),
                None => (TRUST_E_SUBJECT_FORM_UNKNOWN, None, false),
            }
        } else {
            (code, signer, false)
        }
    };
    // больше 1 ГБ не хешируем: долго, а VirusTotal такие файлы всё равно не принимает
    let hash = if meta.len() <= 1 << 30 { sha256(&mut file) } else { None };
    let sig = Signature { status: status_of(code), signer, catalog, sha256: hash };
    let mut c = cache.lock().unwrap_or_else(|e| e.into_inner());
    if c.len() > 2000 {
        c.clear();
    }
    c.insert(key, sig.clone());
    Ok(sig)
}

