//! Markdown rendering with a security-first sanitisation strategy (spec §10.3,
//! §11 output safety).
//!
//! Strategy (in lieu of a heavyweight HTML sanitiser):
//!   * Raw HTML passthrough is **disabled** — `pulldown-cmark` HTML/inline-HTML
//!     events are dropped entirely, so no untrusted markup ever reaches the DOM.
//!   * Link schemes are allow-listed to `http`, `https`, `mailto`; anything else
//!     (notably `javascript:`, `data:`) is stripped to a neutral `#`.
//!   * Image references are allowed for `http`/`https` only and rendered with
//!     `referrerpolicy="no-referrer"` and `loading="lazy"`.
//!
//! The output is HTML-escaped by `pulldown-cmark`'s writer for all text, so the
//! result is safe to inject as `innerHTML` on the client.

use pulldown_cmark::{html, BrokenLink, CowStr, Event, Options, Parser, Tag};

const ALLOWED_LINK_SCHEMES: [&str; 3] = ["http://", "https://", "mailto:"];
const ALLOWED_IMG_SCHEMES: [&str; 2] = ["http://", "https://"];

/// Maximum accepted Markdown source length (§11 length limits).
pub const MAX_MARKDOWN_LEN: usize = 50_000;

fn scheme_allowed(url: &str, allowed: &[&str]) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    // Relative/anchor links are permitted (no scheme, not protocol-relative).
    if !lower.contains(':') && !lower.starts_with("//") {
        return true;
    }
    allowed.iter().any(|s| lower.starts_with(s))
}

/// Render trusted-as-text Markdown into sanitised HTML.
pub fn render(md: &str) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_TASKLISTS);

    // Broken-link callback keeps reference links from emitting raw text.
    let mut callback = |_: BrokenLink| -> Option<(CowStr, CowStr)> { None };
    let parser = Parser::new_with_broken_link_callback(md, options, Some(&mut callback));

    let sanitised = parser.filter_map(|event| match event {
        // Drop all raw HTML — passthrough disabled.
        Event::Html(_) | Event::InlineHtml(_) => None,

        Event::Start(Tag::Link {
            link_type,
            dest_url,
            title,
            id,
        }) => {
            let dest = if scheme_allowed(&dest_url, &ALLOWED_LINK_SCHEMES) {
                dest_url
            } else {
                CowStr::Borrowed("#")
            };
            Some(Event::Start(Tag::Link {
                link_type,
                dest_url: dest,
                title,
                id,
            }))
        }

        Event::Start(Tag::Image {
            link_type,
            dest_url,
            title,
            id,
        }) => {
            let dest = if scheme_allowed(&dest_url, &ALLOWED_IMG_SCHEMES) {
                dest_url
            } else {
                CowStr::Borrowed("")
            };
            Some(Event::Start(Tag::Image {
                link_type,
                dest_url: dest,
                title,
                id,
            }))
        }

        other => Some(other),
    });

    let mut out = String::new();
    html::push_html(&mut out, sanitised);

    // Harden images: enforce no-referrer + lazy loading on every emitted <img>.
    out.replace(
        "<img ",
        "<img referrerpolicy=\"no-referrer\" loading=\"lazy\" ",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_markdown_renders() {
        let html = render("# Title\n\nsome **bold** text");
        assert!(html.contains("<h1>Title</h1>"));
        assert!(html.contains("<strong>bold</strong>"));
    }

    #[test]
    fn raw_html_is_dropped() {
        let html = render("hello <script>alert(1)</script> world");
        assert!(!html.contains("<script"));
        assert!(html.contains("hello"));
        assert!(html.contains("world"));
    }

    #[test]
    fn inline_html_is_dropped() {
        let html = render("a <b onclick=\"x\">b</b> c");
        assert!(!html.contains("onclick"));
        assert!(!html.contains("<b "));
    }

    #[test]
    fn javascript_link_scheme_is_stripped() {
        let html = render("[click](javascript:alert(1))");
        assert!(!html.to_lowercase().contains("javascript:"));
        assert!(html.contains("href=\"#\""));
    }

    #[test]
    fn data_link_scheme_is_stripped() {
        let html = render("[x](data:text/html,<script>alert(1)</script>)");
        assert!(!html.to_lowercase().contains("data:"));
    }

    #[test]
    fn safe_link_schemes_preserved() {
        assert!(render("[a](https://example.com)").contains("href=\"https://example.com\""));
        assert!(render("[m](mailto:a@b.com)").contains("href=\"mailto:a@b.com\""));
    }

    #[test]
    fn external_image_allowed_with_hardening() {
        let html = render("![alt](https://example.com/x.png)");
        assert!(html.contains("src=\"https://example.com/x.png\""));
        assert!(html.contains("referrerpolicy=\"no-referrer\""));
        assert!(html.contains("loading=\"lazy\""));
    }

    #[test]
    fn javascript_image_scheme_stripped() {
        let html = render("![x](javascript:alert(1))");
        assert!(!html.to_lowercase().contains("javascript:"));
    }
}
