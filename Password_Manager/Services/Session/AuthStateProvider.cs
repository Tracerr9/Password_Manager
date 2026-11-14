using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;
using static Password_Manager.Services.Session.SessionService;

namespace Password_Manager.Services.Session
{
    public sealed class VaultAuthStateProvider : AuthenticationStateProvider, IDisposable
    {
        private readonly VaultSessionService _session;

        public VaultAuthStateProvider(VaultSessionService session)
        {
            _session = session;
            _session.SessionStateChanged += OnSessionStateChanged;
        }

        public override Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            return Task.FromResult(BuildAuthState(_session.IsUnlocked));
        }

        private void OnSessionStateChanged(bool isUnlocked)
        {
            NotifyAuthenticationStateChanged(Task.FromResult(BuildAuthState(isUnlocked)));
        }

        private static AuthenticationState BuildAuthState(bool isUnlocked)
        {
            if (!isUnlocked)
            {
                // Pengguna anonim -> ditolak oleh [Authorize]
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            }

            var identity = new ClaimsIdentity(
                claims: [new Claim(ClaimTypes.Name, "VaultOwner")],
                authenticationType: "LocalVaultSession"
            );

            return new AuthenticationState(new ClaimsPrincipal(identity));
        }

        public void Dispose()
        {
            _session.SessionStateChanged -= OnSessionStateChanged;
        }
    }
}
