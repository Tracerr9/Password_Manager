using Microsoft.Extensions.Logging;
using Password_Manager.Services.Crypto;
using Password_Manager.Services.Data;
using Password_Manager.Services.Session;
using static Password_Manager.Services.Session.SessionService;

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

            builder.Services.AddMauiBlazorWebView();

#if DEBUG
    		builder.Services.AddBlazorWebViewDeveloperTools();
    		builder.Logging.AddDebug();
#endif

            return builder.Build();
        }
    }
}
