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
            href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mM8c+YMfwAJ0AOi77DmxQAAAABJRU5ErkJggg=="
        />
        <Title text="Ryuki Infrastructure Platform"/>
        {move || if authenticated { view! { <Shell/> }.into_any() } else { view! { <LoginView/> }.into_any() }}
    }
}
