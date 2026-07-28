//! Filename-extension -> MIME type. A small static table; anything unknown is
//! served as `application/octet-stream`.

pub(crate) fn mime_for(path: &str) -> &'static str {
    let ext = match path.rfind('.') {
        Some(i) => &path[i + 1..],
        None => return "application/octet-stream",
    };
    match ext.to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_extensions_map_correctly() {
        assert_eq!(mime_for("/a/b/index.html"), "text/html; charset=utf-8");
        assert_eq!(mime_for("/x.htm"), "text/html; charset=utf-8");
        assert_eq!(mime_for("/style.css"), "text/css; charset=utf-8");
        assert_eq!(mime_for("/app.js"), "text/javascript; charset=utf-8");
        assert_eq!(mime_for("/app.mjs"), "text/javascript; charset=utf-8");
        assert_eq!(mime_for("/data.json"), "application/json; charset=utf-8");
        assert_eq!(mime_for("/m.wasm"), "application/wasm");
        assert_eq!(mime_for("/i.svg"), "image/svg+xml");
        assert_eq!(mime_for("/f.woff2"), "font/woff2");
        assert_eq!(mime_for("/v.mp4"), "video/mp4");
    }

    #[test]
    fn extension_matching_is_case_insensitive() {
        assert_eq!(mime_for("/INDEX.HTML"), "text/html; charset=utf-8");
        assert_eq!(mime_for("/Photo.JPG"), "image/jpeg");
        assert_eq!(mime_for("/A.Png"), "image/png");
    }

    #[test]
    fn unknown_or_missing_extension_is_octet_stream() {
        assert_eq!(mime_for("/binary.xyz"), "application/octet-stream");
        assert_eq!(mime_for("/no-extension"), "application/octet-stream");
        assert_eq!(mime_for("/"), "application/octet-stream");
    }

    #[test]
    fn only_the_last_dot_segment_is_the_extension() {
        assert_eq!(mime_for("/archive.tar.gz"), "application/octet-stream");
        assert_eq!(mime_for("/app.min.js"), "text/javascript; charset=utf-8");
        // A dot in a parent directory does not become the extension.
        assert_eq!(mime_for("/v1.2/app"), "application/octet-stream");
    }
}
