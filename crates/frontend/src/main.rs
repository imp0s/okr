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
    id: String,
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
                    id: v["id"].as_str().unwrap_or("").to_string(),
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
    let users = RwSignal::new(Vec::<Value>::new());
    let is_admin = user.is_admin;
    // Copy-able owned id for use inside nested per-item closures.
    let me_id = StoredValue::new(user.id.clone());
    // Which page is shown: "okrs" (default) or "team" (admin only).
    let page = RwSignal::new("okrs");

    let reload = move || {
        spawn_local(async move {
            if let Ok(v) = api::get("/groups").await {
                groups.set(v.as_array().cloned().unwrap_or_default());
            }
            if let Ok(v) = api::get("/okrs").await {
                okrs.set(v.as_array().cloned().unwrap_or_default());
            }
            if is_admin {
                if let Ok(v) = api::get("/users").await {
                    users.set(v.as_array().cloned().unwrap_or_default());
                }
            }
        });
    };
    reload();

    let logout = move |_| {
        spawn_local(async move {
            let _ = api::post("/auth/logout", Value::Null).await;
            on_logout();
        });
    };

    view! {
        <header class="topbar">
            <strong>"OKR Tracker"</strong>
            {is_admin.then(|| view! {
                <nav class="nav">
                    <button class="link" class:active=move || page.get() == "okrs"
                        on:click=move |_| page.set("okrs")>"OKRs"</button>
                    <button class="link" class:active=move || page.get() == "team"
                        on:click=move |_| page.set("team")>"Team"</button>
                </nav>
            })}
            <span class="spacer"></span>
            <span class="muted">{user.name.clone()}</span>
            {is_admin.then(|| view! { <span class="badge">"admin"</span> })}
            <button class="link" on:click=logout>"Sign out"</button>
        </header>

        <section class="content">
            <Show when=move || is_admin && page.get() == "team">
                <Team users=users reload=reload />
            </Show>

            <Show when=move || page.get() == "okrs">
                <Show
                    when=move || !groups.get().is_empty()
                    fallback=|| view! { <p class="muted center">"No groups yet."</p> }
                >
                    <For
                        each=move || groups.get()
                        key=|g| g["id"].as_str().unwrap_or("").to_string()
                        children=move |g| view! {
                            <GroupCard
                                group=g is_admin=is_admin me_id=me_id.get_value()
                                okrs=okrs users=users reload=reload
                            />
                        }
                    />
                </Show>
                <Show when=move || is_admin>
                    <NewGroup reload=reload />
                </Show>
            </Show>
        </section>
    }
}

/// One group card: its OKRs, an admin "+ Add OKR" affordance, and an admin
/// delete control (with inline confirm, since it cascades the group's OKRs).
#[component]
fn GroupCard(
    group: Value,
    is_admin: bool,
    me_id: String,
    okrs: RwSignal<Vec<Value>>,
    users: RwSignal<Vec<Value>>,
    reload: impl Fn() + 'static + Copy + Send + Sync,
) -> impl IntoView {
    let gid = StoredValue::new(group["id"].as_str().unwrap_or("").to_string());
    let me_id = StoredValue::new(me_id);
    let name = group["name"].as_str().unwrap_or("").to_string();
    let human_ref = group["humanRef"].as_str().unwrap_or("").to_string();
    let confirming = RwSignal::new(false);

    let group_okrs = move || {
        let g = gid.get_value();
        okrs.get()
            .into_iter()
            .filter(|o| o["groupId"].as_str() == Some(g.as_str()))
            .collect::<Vec<_>>()
    };

    let do_delete = move |_| {
        let path = format!("/groups/{}", gid.get_value());
        spawn_local(async move {
            if api::call("DELETE", &path, None).await.is_ok() {
                reload();
            }
        });
    };

    view! {
        <div class="card group">
            <div class="group-head">
                <h2>{name}</h2>
                <code class="ref">{human_ref}</code>
                <span class="spacer"></span>
                <Show when=move || is_admin>
                    {move || if confirming.get() {
                        view! {
                            <span class="confirm">
                                <span class="muted">"Delete group and all its OKRs?"</span>
                                <button class="danger" on:click=do_delete>"Confirm"</button>
                                <button class="link" on:click=move |_| confirming.set(false)>"Cancel"</button>
                            </span>
                        }.into_any()
                    } else {
                        view! {
                            <button class="link danger" on:click=move |_| confirming.set(true)>"Delete"</button>
                        }.into_any()
                    }}
                </Show>
            </div>
            <For
                each=group_okrs
                key=|o| o["id"].as_str().unwrap_or("").to_string()
                children=move |o| view! {
                    <OkrCard okr=o is_admin=is_admin me_id=me_id.get_value() users=users reload=reload />
                }
            />
            <Show when=move || is_admin>
                <AddOkr group_id=gid.get_value() reload=reload />
            </Show>
        </div>
    }
}

/// Subtle inline "+ New group" affordance (group creation is infrequent).
#[component]
fn NewGroup(reload: impl Fn() + 'static + Copy + Send + Sync) -> impl IntoView {
    let open = RwSignal::new(false);
    let name = RwSignal::new(String::new());
    let status = RwSignal::new(String::new());

    let create = move |_| {
        let n = name.get();
        if n.trim().is_empty() {
            return;
        }
        spawn_local(async move {
            match api::post("/groups", json!({ "name": n, "descriptionMd": "" })).await {
                Ok(_) => {
                    name.set(String::new());
                    open.set(false);
                    status.set(String::new());
                    reload();
                }
                Err((s, _)) => status.set(format!("Could not create group (HTTP {s})")),
            }
        });
    };

    view! {
        <div class="newgroup">
            {move || if open.get() {
                view! {
                    <div class="row">
                        <input
                            placeholder="Group name"
                            on:input=move |e| name.set(event_target_value(&e))
                            prop:value=move || name.get()
                        />
                        <button class="primary" on:click=create>"Create"</button>
                        <button class="link" on:click=move |_| open.set(false)>"Cancel"</button>
                    </div>
                }.into_any()
            } else {
                view! {
                    <button class="link subtle" on:click=move |_| open.set(true)>"＋ New group"</button>
                }.into_any()
            }}
            <span class="status">{move || status.get()}</span>
        </div>
    }
}

/// Admin team management (spec §6.3): create users and surface the single-use
/// registration code to hand over out-of-band (never emailed).
#[component]
fn Team(
    users: RwSignal<Vec<Value>>,
    reload: impl Fn() + 'static + Copy + Send + Sync,
) -> impl IntoView {
    let new_name = RwSignal::new(String::new());
    let new_admin = RwSignal::new(false);
    let status = RwSignal::new(String::new());
    // Last issued code to display prominently: (name, code).
    let issued = RwSignal::new(None::<(String, String)>);

    let add_user = move |_| {
        let name = new_name.get();
        if name.trim().is_empty() {
            return;
        }
        let is_admin = new_admin.get();
        status.set("Creating…".into());
        spawn_local(async move {
            match api::post("/users", json!({ "name": name, "isAdmin": is_admin })).await {
                Ok(v) => {
                    let uname = v["user"]["name"].as_str().unwrap_or(&name).to_string();
                    let code = v["code"].as_str().unwrap_or("").to_string();
                    issued.set(Some((uname, code)));
                    new_name.set(String::new());
                    new_admin.set(false);
                    status.set(String::new());
                    reload();
                }
                Err((s, _)) => status.set(format!("Could not create user (HTTP {s})")),
            }
        });
    };

    let reissue = move |id: String| {
        spawn_local(async move {
            if let Ok(v) = api::post(&format!("/users/{id}/code"), Value::Null).await {
                let code = v["code"].as_str().unwrap_or("").to_string();
                issued.set(Some(("(re-issued)".into(), code)));
            }
        });
    };

    view! {
        <div class="card">
            <h3>"Team"</h3>
            <div class="row">
                <input
                    placeholder="New teammate's name"
                    on:input=move |e| new_name.set(event_target_value(&e))
                    prop:value=move || new_name.get()
                />
                <label class="done">
                    <input type="checkbox"
                        prop:checked=move || new_admin.get()
                        on:change=move |e| new_admin.set(event_target_checked(&e)) />
                    "admin"
                </label>
                <button class="primary" on:click=add_user>"Add teammate"</button>
            </div>
            <p class="status">{move || status.get()}</p>

            <Show when=move || issued.get().is_some()>
                {move || {
                    let (n, c) = issued.get().unwrap_or_default();
                    view! {
                        <div class="codebox">
                            <div class="muted">"Share this single-use registration code with " {n} " — it expires in 24h:"</div>
                            <code class="bigcode">{c}</code>
                            <div class="muted">"They open the app, choose \"I have a registration code\", paste it, and register a passkey."</div>
                        </div>
                    }
                }}
            </Show>

            <ul class="userlist">
                <For
                    each=move || users.get()
                    key=|u| u["id"].as_str().unwrap_or("").to_string()
                    children=move |u| {
                        let id = u["id"].as_str().unwrap_or("").to_string();
                        let name = u["name"].as_str().unwrap_or("").to_string();
                        let short = u["shortName"].as_str().unwrap_or("").to_string();
                        let admin = u["isAdmin"].as_bool().unwrap_or(false);
                        view! {
                            <li>
                                <span>{name} " " <code class="ref">{short}</code></span>
                                {admin.then(|| view! { <span class="badge">"admin"</span> })}
                                <span class="spacer"></span>
                                <button class="link" on:click=move |_| reissue(id.clone())>"New code"</button>
                            </li>
                        }
                    }
                />
            </ul>
        </div>
    }
}

/// Admin: create an OKR within a group (spec §7).
#[component]
fn AddOkr(group_id: String, reload: impl Fn() + 'static + Copy + Send + Sync) -> impl IntoView {
    let open = RwSignal::new(false);
    let objective = RwSignal::new(String::new());
    let key_results = RwSignal::new(String::new());
    let status = RwSignal::new(String::new());
    let group_id = StoredValue::new(group_id);

    let submit = move |_| {
        let gid = group_id.get_value();
        let obj = objective.get();
        let kr = key_results.get();
        if obj.trim().is_empty() {
            status.set("Objective is required.".into());
            return;
        }
        spawn_local(async move {
            let body = json!({ "groupId": gid, "objectiveMd": obj, "keyResultsMd": kr });
            match api::post("/okrs", body).await {
                Ok(_) => {
                    objective.set(String::new());
                    key_results.set(String::new());
                    open.set(false);
                    status.set(String::new());
                    reload();
                }
                Err((s, _)) => status.set(format!("Could not create OKR (HTTP {s})")),
            }
        });
    };

    view! {
        <div class="addokr">
            <button class="link" on:click=move |_| open.update(|v| *v = !*v)>
                {move || if open.get() { "Cancel" } else { "+ Add OKR" }}
            </button>
            <Show when=move || open.get()>
                <div class="editor">
                    <input
                        placeholder="Objective (what we want to achieve)"
                        on:input=move |e| objective.set(event_target_value(&e))
                        prop:value=move || objective.get()
                    />
                    <textarea
                        placeholder="Key results (Markdown — one per line)…"
                        on:input=move |e| key_results.set(event_target_value(&e))
                        prop:value=move || key_results.get()
                    ></textarea>
                    <div class="row">
                        <button class="primary" on:click=submit>"Create OKR"</button>
                        <span class="status">{move || status.get()}</span>
                    </div>
                </div>
            </Show>
        </div>
    }
}

#[component]
fn OkrCard(
    okr: Value,
    is_admin: bool,
    me_id: String,
    users: RwSignal<Vec<Value>>,
    reload: impl Fn() + 'static + Copy + Send + Sync,
) -> impl IntoView {
    let id = StoredValue::new(okr["id"].as_str().unwrap_or("").to_string());
    let done = RwSignal::new(okr["done"].as_bool().unwrap_or(false));
    let objective_html = okr["objectiveHtml"].as_str().unwrap_or("").to_string();
    let key_results_html = okr["keyResultsHtml"].as_str().unwrap_or("").to_string();
    let has_krs = !key_results_html.trim().is_empty();
    let human_ref = okr["humanRef"].as_str().unwrap_or("").to_string();
    let assignees: Vec<String> = okr["assignees"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let assignees_sig = RwSignal::new(assignees.clone());
    // Only assignees may toggle done / post updates (server enforces this too).
    let can_contribute = assignees.contains(&me_id);

    let toggle_done = move |_| {
        let next = !done.get();
        let path = format!("/okrs/{}/done", id.get_value());
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
    let assign_open = RwSignal::new(false);

    // Names of current assignees, resolved from the user list.
    let assignee_names = move || {
        let ids = assignees_sig.get();
        let all = users.get();
        let names: Vec<String> = ids
            .iter()
            .map(|uid| {
                all.iter()
                    .find(|u| u["id"].as_str() == Some(uid.as_str()))
                    .and_then(|u| u["shortName"].as_str())
                    .unwrap_or("?")
                    .to_string()
            })
            .collect();
        if names.is_empty() {
            "unassigned".to_string()
        } else {
            names.join(", ")
        }
    };

    let toggle_assignee = move |uid: String| {
        let path = format!("/okrs/{}/assignees", id.get_value());
        let mut current = assignees_sig.get();
        if let Some(pos) = current.iter().position(|x| x == &uid) {
            current.remove(pos);
        } else {
            current.push(uid);
        }
        let to_send = current.clone();
        spawn_local(async move {
            if api::call("PUT", &path, Some(json!({ "assignees": to_send })))
                .await
                .is_ok()
            {
                assignees_sig.set(current);
                reload();
            }
        });
    };

    view! {
        <div class="okr">
            <div class="okr-head">
                <code class="ref">{human_ref}</code>
                <span class="muted assignees">"👤 " {assignee_names}</span>
                <span class="spacer"></span>
                <Show when=move || can_contribute>
                    <label class="done">
                        <input type="checkbox" prop:checked=move || done.get() on:change=toggle_done />
                        "Done"
                    </label>
                </Show>
            </div>
            <div class="md" inner_html=objective_html></div>
            <Show when=move || has_krs>
                <div class="md krs" inner_html=key_results_html.clone()></div>
            </Show>

            <div class="row">
                <Show when=move || can_contribute>
                    <button class="link" on:click=move |_| editor_open.update(|v| *v = !*v)>
                        {move || if editor_open.get() { "Close update" } else { "Post update" }}
                    </button>
                </Show>
                <Show when=move || is_admin>
                    <button class="link" on:click=move |_| assign_open.update(|v| *v = !*v)>
                        {move || if assign_open.get() { "Done assigning" } else { "Assign" }}
                    </button>
                </Show>
            </div>

            <Show when=move || is_admin && assign_open.get()>
                <div class="assign">
                    <For
                        each=move || users.get()
                        key=|u| u["id"].as_str().unwrap_or("").to_string()
                        children=move |u| {
                            let uid = u["id"].as_str().unwrap_or("").to_string();
                            let uid_chk = uid.clone();
                            let label = format!(
                                "{} ({})",
                                u["name"].as_str().unwrap_or(""),
                                u["shortName"].as_str().unwrap_or("")
                            );
                            view! {
                                <label class="done">
                                    <input type="checkbox"
                                        prop:checked=move || assignees_sig.get().contains(&uid_chk)
                                        on:change=move |_| toggle_assignee(uid.clone()) />
                                    {label}
                                </label>
                            }
                        }
                    />
                </div>
            </Show>

            <Show when=move || editor_open.get()>
                <UpdateEditor okr_id=id.get_value() />
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
