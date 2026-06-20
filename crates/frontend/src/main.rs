//! OKR Tracker SPA (spec §10). Leptos CSR. Client-side-rendered, served as
//! static immutable assets; all data comes from the JSON API. Markdown preview
//! reuses the very same `okr_core::markdown` renderer the server uses, so what
//! you preview is exactly what is stored and shown.

mod api;
mod auth;

use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::{json, Value};

fn main() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(App);
}

#[derive(Clone)]
struct Me {
    name: String,
    is_admin: bool,
}

#[component]
fn App() -> impl IntoView {
    let me = RwSignal::new(None::<Me>);
    let loading = RwSignal::new(true);

    let load_me = move || {
        spawn_local(async move {
            match api::get("/me").await {
                Ok(v) => me.set(Some(Me {
                    name: v["name"].as_str().unwrap_or("?").to_string(),
                    is_admin: v["isAdmin"].as_bool().unwrap_or(false),
                })),
                Err(_) => me.set(None),
            }
            loading.set(false);
        });
    };
    load_me();

    view! {
        <main>
            <Show
                when=move || !loading.get()
                fallback=|| view! { <p class="center muted">"Loading…"</p> }
            >
                {move || match me.get() {
                    Some(user) => view! { <Dashboard user=user on_logout=move || load_me() /> }.into_any(),
                    None => view! { <Login on_authed=move || load_me() /> }.into_any(),
                }}
            </Show>
        </main>
    }
}

#[component]
fn Login(on_authed: impl Fn() + 'static + Copy + Send + Sync) -> impl IntoView {
    let status = RwSignal::new(String::new());
    let code = RwSignal::new(String::new());
    let secret = RwSignal::new(String::new());

    let run =
        move |fut: std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>>>>| {
            status.set("Working…".into());
            spawn_local(async move {
                match fut.await {
                    Ok(()) => on_authed(),
                    Err(e) => status.set(e),
                }
            });
        };

    let do_login = move |_| run(Box::pin(auth::login()));
    let do_register = move |_| {
        let c = code.get();
        run(Box::pin(async move { auth::register_with_code(&c).await }));
    };
    let do_bootstrap = move |_| {
        let s = secret.get();
        run(Box::pin(async move { auth::bootstrap(&s).await }));
    };

    view! {
        <div class="card login">
            <h1>"OKR Tracker"</h1>
            <p class="muted">"Sign in with your passkey."</p>
            <Show
                when=auth::passkeys_supported
                fallback=|| view! { <p class="status">"This browser does not support passkeys."</p> }
            >
                <button class="primary" on:click=do_login>"Sign in with a passkey"</button>
            </Show>

            <details>
                <summary>"I have a registration code"</summary>
                <input
                    placeholder="XXXX-XXXX-XXXX-…"
                    on:input=move |e| code.set(event_target_value(&e))
                    prop:value=move || code.get()
                />
                <button on:click=do_register>"Register passkey"</button>
            </details>

            <details>
                <summary>"First-time setup"</summary>
                <p class="muted">"Bootstrap the first administrator with the setup secret."</p>
                <input
                    r#type="password"
                    placeholder="SETUP_SECRET"
                    on:input=move |e| secret.set(event_target_value(&e))
                    prop:value=move || secret.get()
                />
                <button on:click=do_bootstrap>"Create first admin"</button>
            </details>

            <p class="status">{move || status.get()}</p>
        </div>
    }
}

#[component]
fn Dashboard(user: Me, on_logout: impl Fn() + 'static + Copy + Send + Sync) -> impl IntoView {
    let groups = RwSignal::new(Vec::<Value>::new());
    let okrs = RwSignal::new(Vec::<Value>::new());
    let status = RwSignal::new(String::new());
    let is_admin = user.is_admin;

    let reload = move || {
        spawn_local(async move {
            if let Ok(v) = api::get("/groups").await {
                groups.set(v.as_array().cloned().unwrap_or_default());
            }
            if let Ok(v) = api::get("/okrs").await {
                okrs.set(v.as_array().cloned().unwrap_or_default());
            }
        });
    };
    reload();

    // Admin: create group.
    let new_group = RwSignal::new(String::new());
    let create_group = move |_| {
        let name = new_group.get();
        if name.trim().is_empty() {
            return;
        }
        spawn_local(async move {
            match api::post("/groups", json!({ "name": name, "descriptionMd": "" })).await {
                Ok(_) => {
                    new_group.set(String::new());
                    reload();
                }
                Err((s, _)) => status.set(format!("Could not create group (HTTP {s})")),
            }
        });
    };

    let logout = move |_| {
        spawn_local(async move {
            let _ = api::post("/auth/logout", Value::Null).await;
            on_logout();
        });
    };

    view! {
        <header class="topbar">
            <strong>"OKR Tracker"</strong>
            <span class="spacer"></span>
            <span class="muted">{user.name.clone()}</span>
            {is_admin.then(|| view! { <span class="badge">"admin"</span> })}
            <button class="link" on:click=logout>"Sign out"</button>
        </header>

        <section class="content">
            <Show when=move || is_admin>
                <div class="card">
                    <h3>"New group"</h3>
                    <div class="row">
                        <input
                            placeholder="Group name"
                            on:input=move |e| new_group.set(event_target_value(&e))
                            prop:value=move || new_group.get()
                        />
                        <button class="primary" on:click=create_group>"Add group"</button>
                    </div>
                </div>
            </Show>

            <p class="status">{move || status.get()}</p>

            <For
                each=move || groups.get()
                key=|g| g["id"].as_str().unwrap_or("").to_string()
                children=move |g| {
                    let gid = g["id"].as_str().unwrap_or("").to_string();
                    let group_okrs = move || {
                        okrs.get()
                            .into_iter()
                            .filter(|o| o["groupId"].as_str() == Some(gid.as_str()))
                            .collect::<Vec<_>>()
                    };
                    view! {
                        <div class="card group">
                            <div class="group-head">
                                <h2>{g["name"].as_str().unwrap_or("").to_string()}</h2>
                                <code class="ref">{g["humanRef"].as_str().unwrap_or("").to_string()}</code>
                            </div>
                            <For
                                each=group_okrs
                                key=|o| o["id"].as_str().unwrap_or("").to_string()
                                children=move |o| view! { <OkrCard okr=o is_admin=is_admin /> }
                            />
                        </div>
                    }
                }
            />
        </section>
    }
}

#[component]
fn OkrCard(okr: Value, is_admin: bool) -> impl IntoView {
    let id = okr["id"].as_str().unwrap_or("").to_string();
    let done = RwSignal::new(okr["done"].as_bool().unwrap_or(false));
    let objective_html = okr["objectiveHtml"].as_str().unwrap_or("").to_string();
    let human_ref = okr["humanRef"].as_str().unwrap_or("").to_string();
    let _ = is_admin;

    let id_for_done = id.clone();
    let toggle_done = move |_| {
        let next = !done.get();
        let path = format!("/okrs/{}/done", id_for_done);
        spawn_local(async move {
            if api::call("PUT", &path, Some(json!({ "done": next })))
                .await
                .is_ok()
            {
                done.set(next);
            }
        });
    };

    let editor_open = RwSignal::new(false);

    view! {
        <div class="okr">
            <div class="okr-head">
                <code class="ref">{human_ref}</code>
                <label class="done">
                    <input type="checkbox" prop:checked=move || done.get() on:change=toggle_done />
                    "Done"
                </label>
            </div>
            <div class="md" inner_html=objective_html></div>
            <button class="link" on:click=move |_| editor_open.update(|v| *v = !*v)>
                {move || if editor_open.get() { "Close update" } else { "Post update" }}
            </button>
            <Show when=move || editor_open.get()>
                <UpdateEditor okr_id=id.clone() />
            </Show>
        </div>
    }
}

/// Full(ish)-screen Markdown editor with live preview (spec §10.3). Preview is
/// rendered with the same sanitising renderer the server uses.
#[component]
fn UpdateEditor(okr_id: String) -> impl IntoView {
    let body = RwSignal::new(String::new());
    let status = RwSignal::new(String::new());
    let preview = move || okr_core::markdown::render(&body.get());

    let submit = move |_| {
        let text = body.get();
        let path = format!("/okrs/{}/updates", okr_id);
        spawn_local(async move {
            match api::post(&path, json!({ "bodyMd": text })).await {
                Ok(_) => status.set("Posted.".into()),
                Err((s, _)) => status.set(format!("Failed (HTTP {s})")),
            }
        });
    };

    view! {
        <div class="editor">
            <div class="editor-split">
                <textarea
                    placeholder="Progress update (Markdown)…"
                    on:input=move |e| body.set(event_target_value(&e))
                    prop:value=move || body.get()
                ></textarea>
                <div class="md preview" inner_html=preview></div>
            </div>
            <div class="row">
                <button class="primary" on:click=submit>"Post update"</button>
                <span class="status">{move || status.get()}</span>
            </div>
        </div>
    }
}
