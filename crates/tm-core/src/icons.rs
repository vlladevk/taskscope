//! App icons: the icon is taken from the .exe and handed to the interface as a PNG (data URL).
//! Cached by file path — identical exes share one icon.

use std::collections::HashMap;
use std::sync::Mutex;

use windows_sys::Win32::Graphics::Gdi::{
    DeleteObject, GetDC, GetDIBits, ReleaseDC, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS,
};
use windows_sys::Win32::UI::Shell::ExtractIconExW;
use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, HICON, ICONINFO};

#[derive(Default)]
pub struct IconCache {
    map: Mutex<HashMap<String, Option<String>>>,
}

impl IconCache {
    /// A 32×32 PNG icon as a data URL; `None` — the file has no icon or there is no access.
    pub fn get(&self, path: &str) -> Option<String> {
        let key = path.to_lowercase();
        if let Some(v) = self.map.lock().unwrap().get(&key) {
            return v.clone();
        }
        let v = extract(path).map(|(w, h, rgba)| format!("data:image/png;base64,{}", base64(&png(w, h, &rgba))));
        let mut m = self.map.lock().unwrap();
        if m.len() > 2000 {
            m.clear();
        }
        m.insert(key, v.clone());
        v
    }
}

fn extract(path: &str) -> Option<(u32, u32, Vec<u8>)> {
    let wpath: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut large: HICON = std::ptr::null_mut();
    let n = unsafe { ExtractIconExW(wpath.as_ptr(), 0, &mut large, std::ptr::null_mut(), 1) };
    if n == 0 || large.is_null() {
        return None;
    }
    let r = icon_rgba(large);
    unsafe { DestroyIcon(large) };
    r
}

fn icon_rgba(icon: HICON) -> Option<(u32, u32, Vec<u8>)> {
    let mut ii: ICONINFO = unsafe { std::mem::zeroed() };
    if unsafe { GetIconInfo(icon, &mut ii) } == 0 {
        return None;
    }
    let dc = unsafe { GetDC(std::ptr::null_mut()) };
    let read = |bmp, w: i32, h: i32| -> Option<Vec<u8>> {
        let mut bi: BITMAPINFO = unsafe { std::mem::zeroed() };
        bi.bmiHeader = BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: w,
            biHeight: -h, // top-down
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            ..unsafe { std::mem::zeroed() }
        };
        let mut buf = vec![0u8; (w * h * 4) as usize];
        let got = unsafe { GetDIBits(dc, bmp, 0, h as u32, buf.as_mut_ptr().cast(), &mut bi, DIB_RGB_COLORS) };
        (got != 0).then_some(buf)
    };
    const S: i32 = 32;
    let out = (|| {
        if ii.hbmColor.is_null() {
            return None; // monochrome icons are not supported
        }
        let mut px = read(ii.hbmColor, S, S)?;
        // BGRA → RGBA; old icons have zero alpha — the transparency comes from the mask
        let no_alpha = px.chunks(4).all(|c| c[3] == 0);
        let mask = if no_alpha { read(ii.hbmMask, S, S) } else { None };
        for (i, c) in px.chunks_mut(4).enumerate() {
            c.swap(0, 2);
            if no_alpha {
                let transparent = mask.as_ref().map_or(false, |m| m[i * 4] != 0);
                c[3] = if transparent { 0 } else { 255 };
            }
        }
        Some((S as u32, S as u32, px))
    })();
    unsafe {
        ReleaseDC(std::ptr::null_mut(), dc);
        if !ii.hbmColor.is_null() {
            DeleteObject(ii.hbmColor);
        }
        if !ii.hbmMask.is_null() {
            DeleteObject(ii.hbmMask);
        }
    }
    out
}

// ───────────── minimal PNG: uncompressed deflate, good enough for 32×32 icons ─────────────

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
        }
    }
    !c
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + x as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

pub fn png(w: u32, h: u32, rgba: &[u8]) -> Vec<u8> {
    let mut raw = Vec::with_capacity((w * 4 + 1) as usize * h as usize);
    for row in rgba.chunks((w * 4) as usize) {
        raw.push(0); // filter None
        raw.extend_from_slice(row);
    }
    let mut z = vec![0x78, 0x01];
    let mut chunks = raw.chunks(65535).peekable();
    while let Some(c) = chunks.next() {
        z.push(if chunks.peek().is_none() { 1 } else { 0 });
        z.extend_from_slice(&(c.len() as u16).to_le_bytes());
        z.extend_from_slice(&(!(c.len() as u16)).to_le_bytes());
        z.extend_from_slice(c);
    }
    z.extend_from_slice(&adler32(&raw).to_be_bytes());

    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut chunk = |kind: &[u8], data: &[u8]| {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        let mut body = kind.to_vec();
        body.extend_from_slice(data);
        out.extend_from_slice(&body);
        out.extend_from_slice(&crc32(&body).to_be_bytes());
    };
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8 bits, RGBA
    chunk(b"IHDR", &ihdr);
    chunk(b"IDAT", &z);
    chunk(b"IEND", &[]);
    out
}

pub fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    s
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_and_crc() {
        assert_eq!(super::base64(b"Man"), "TWFu");
        assert_eq!(super::base64(b"Ma"), "TWE=");
        assert_eq!(super::crc32(b"IEND"), 0xAE42_6082);
    }
}
