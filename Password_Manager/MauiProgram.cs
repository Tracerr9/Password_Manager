using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Logging;
using Password_Manager.Services;
using Password_Manager.Services.Crypto;
using Password_Manager.Services.Data;
using Password_Manager.Services.Session;

namespace Password_Manager
{
    public static class MauiProgram
    {
        public static MauiApp CreateMauiApp()
        {
            var builder = MauiApp.CreateBuilder();
            builder
                .UseMauiApp<App>()
                .ConfigureFonts(fonts =>
                {
                    fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
                });

            builder.Services.AddSingleton<CryptoService>();
            builder.Services.AddSingleton<VaultRepository>();
            builder.Services.AddSingleton<SessionService>();
            builder.Services.AddSingleton<VaultService>();
            builder.Services.AddSingleton<SecureClipboardService>();

            builder.Services.AddAuthorizationCore();
            builder.Services.AddSingleton<VaultAuthStateProvider>();
            builder.Services.AddSingleton<AuthenticationStateProvider>(sp =>
                sp.GetRequiredService<VaultAuthStateProvider>());

            builder.Services.AddMauiBlazorWebView();

#if DEBUG
    		builder.Services.AddBlazorWebViewDeveloperTools();
    		builder.Logging.AddDebug();
#endif
#if WINDOWS && !DEBUG
        Microsoft.AspNetCore.Components.WebView.Maui.BlazorWebViewHandler.BlazorWebViewMapper.AppendToMapping(
            "HardenWebView2",
            (handler, _) =>
            {
                if (handler.PlatformView is Microsoft.UI.Xaml.Controls.WebView2 webView)
                {
                    if (webView.CoreWebView2 is not null)
                    {
                        ApplyWebView2SecuritySettings(webView.CoreWebView2);
                    }
                    else
                    {
                        webView.CoreWebView2Initialized += (sender, _) =>
                        {
                            if (sender.CoreWebView2 is not null)
                            {
                                ApplyWebView2SecuritySettings(sender.CoreWebView2);
                            }
                        };
                    }
                }
            });
#endif

            return builder.Build();
        }
    }

#if WINDOWS && !DEBUG
    private static void ApplyWebView2SecuritySettings(Microsoft.Web.WebView2.Core.CoreWebView2 coreWebView)
    {
        var settings = coreWebView.Settings;
        settings.AreDevToolsEnabled = false;              // Mematikan Inspect Element & DevTools
        settings.AreDefaultContextMenusEnabled = false;   // Mematikan menu klik kanan browser
        settings.AreBrowserAcceleratorKeysEnabled = false;// Memblokir F12, Ctrl+Shift+I, Ctrl+U, Ctrl+P, F5
        settings.IsStatusBarEnabled = false;              // Menyembunyikan preview URL di pojok bawah
    }
#endif
}
