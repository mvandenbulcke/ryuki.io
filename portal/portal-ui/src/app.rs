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
            href="data:image/svg+xml,%3Csvg%20xmlns%3D'http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg'%20viewBox%3D'0%200%2064%2064'%3E%3Cpath%20d%3D'M%2035.5%2015.3%20A%2020%2020%200%201%200%2050.0%2026.2'%20fill%3D'none'%20stroke%3D'%238B0000'%20stroke-width%3D'8'%20stroke-linecap%3D'round'%2F%3E%3Cpath%20d%3D'M%2046.5%2024.5%20L%2043%2018.5%20L%2044.5%2014%20L%2040%209%20L%2046%2010.5%20L%2050.5%204.5%20L%2051.5%2011.5%20L%2057%2013%20L%2053.5%2017.5%20L%2053.8%2022.5%20Z'%20fill%3D'%238B0000'%2F%3E%3Ccircle%20cx%3D'32'%20cy%3D'35'%20r%3D'6'%20fill%3D'%23d4a017'%2F%3E%3C%2Fsvg%3E"
        />
        <Title text="Ryuki Infrastructure Platform"/>
        {move || if authenticated { view! { <Shell/> }.into_any() } else { view! { <LoginView/> }.into_any() }}
    }
}
