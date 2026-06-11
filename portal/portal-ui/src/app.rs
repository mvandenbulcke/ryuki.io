use crate::shell::{self, Shell};
use crate::views::login::LoginView;
use leptos::prelude::*;
use leptos_meta::{provide_meta_context, Link, MetaTags, Stylesheet, Title};

pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <script>
                    "(function(){var t=localStorage.getItem('ryuki-theme');if(t==='dark'||t==='light'){document.documentElement.setAttribute('data-theme',t)}})()"
                </script>
                <AutoReload options=options.clone()/>
                <HydrationScripts options/>
                <MetaTags/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    let authenticated = shell::is_authenticated();

    view! {
        <Stylesheet id="ryuki-portal-css" href="/pkg/ryuki-portal-ui.css"/>
        <Link
            rel="icon"
            href="data:image/svg+xml,%3Csvg%20xmlns=%27http://www.w3.org/2000/svg%27%20viewBox=%270%200%2032%2032%27%3E%3Cdefs%3E%3ClinearGradient%20id=%27a%27%20x1=%270%27%20y1=%270%27%20x2=%271%27%20y2=%271%27%3E%3Cstop%20offset=%270%27%20stop-color=%27%235FA8EC%27/%3E%3Cstop%20offset=%271%27%20stop-color=%27%232E62C0%27/%3E%3C/linearGradient%3E%3ClinearGradient%20id=%27b%27%20x1=%270%27%20y1=%270%27%20x2=%270%27%20y2=%271%27%3E%3Cstop%20offset=%270%27%20stop-color=%27%2316315e%27/%3E%3Cstop%20offset=%271%27%20stop-color=%27%230f2347%27/%3E%3C/linearGradient%3E%3C/defs%3E%3Cpath%20d=%27M16%202%2028.12%209v14L16%2030%203.88%2023V9z%27%20fill=%27url(%23a)%27%20stroke=%27url(%23a)%27%20stroke-width=%273%27%20stroke-linejoin=%27round%27/%3E%3Cpath%20d=%27M5.5%2016C10%2010.4%2022%2010.4%2026.5%2016%2022%2021.6%2010%2021.6%205.5%2016z%27%20fill=%27%23fff%27/%3E%3Cpath%20d=%27M16%2011.9c1.5%201.8%201.5%206.4%200%208.2-1.5-1.8-1.5-6.4%200-8.2z%27%20fill=%27url(%23b)%27/%3E%3C/svg%3E"
        />
        <Title text="Ryuki Infrastructure Platform"/>
        {move || if authenticated { view! { <Shell/> }.into_any() } else { view! { <LoginView/> }.into_any() }}
    }
}
