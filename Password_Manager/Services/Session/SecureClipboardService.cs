using System.Security.Cryptography;
using System.Text;
using MauiClipboard = Microsoft.Maui.ApplicationModel.DataTransfer.Clipboard;

#if WINDOWS
using WinClipboard = Windows.ApplicationModel.DataTransfer.Clipboard;
using WinClipboardOptions = Windows.ApplicationModel.DataTransfer.ClipboardContentOptions;
using WinDataPackage = Windows.ApplicationModel.DataTransfer.DataPackage;
using WinDataPackageView = Windows.ApplicationModel.DataTransfer.DataPackageView;
using WinStandardDataFormats = Windows.ApplicationModel.DataTransfer.StandardDataFormats;
#endif

namespace Password_Manager.Services.Session
{
    public sealed class SecureClipboardService : IDisposable
    {
        private readonly SessionService _session;
        private CancellationTokenSource? _clearCts;
        private byte[]? _lastSensitiveHash;

        public SecureClipboardService(SessionService session)
        {
            _session = session;
            _session.SessionStateChanged += OnSessionStateChanged;
        }

        /// <summary>
        /// Menyalin teks biasa (seperti username/URL) ke clipboard standar.
        /// </summary>
        public Task CopyStandardAsync(string text)
        {
            return MainThread.InvokeOnMainThreadAsync(() => MauiClipboard.Default.SetTextAsync(text));
        }

        /// <summary>
        /// Menyalin data sensitif (password) tanpa masuk ke Windows Clipboard History (Win + V)
        /// dan menghapusnya otomatis setelah durasi tertentu.
        /// </summary>
        public async Task CopySensitiveAsync(string secret, TimeSpan? clearAfter = null, Action? onCleared = null)
        {
            TimeSpan timeout = clearAfter ?? TimeSpan.FromSeconds(15);

            CancelPendingClear();
            _lastSensitiveHash = SHA256.HashData(Encoding.UTF8.GetBytes(secret));

#if WINDOWS
        await MainThread.InvokeOnMainThreadAsync(() =>
        {
            var dataPackage = new WinDataPackage();
            dataPackage.SetText(secret);

            var options = new WinClipboardOptions
            {
                IsAllowedInHistory = false, // Jangan catat ke Win + V
                IsRoamable = false          // Jangan sinkronkan ke Cloud Clipboard
            };

            WinClipboard.SetContentWithOptions(dataPackage, options);
        });
#else
            await MainThread.InvokeOnMainThreadAsync(() => MauiClipboard.Default.SetTextAsync(secret));
#endif

            _clearCts = new CancellationTokenSource();
            CancellationToken token = _clearCts.Token;

            _ = Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(timeout, token);
                    await ClearIfUnchangedAsync();
                    onCleared?.Invoke();
                }
                catch (OperationCanceledException)
                {
                    // Timer dibatalkan karena user menyalin item baru atau vault sudah dikunci
                }
            }, token);
        }

        public async Task ClearIfUnchangedAsync()
        {
            byte[]? expectedHash = _lastSensitiveHash;
            if (expectedHash is null)
                return;

            await MainThread.InvokeOnMainThreadAsync(async () =>
            {
                try
                {
                    string? currentText = await GetCurrentClipboardTextAsync();
                    if (string.IsNullOrEmpty(currentText))
                        return;

                    byte[] currentHash = SHA256.HashData(Encoding.UTF8.GetBytes(currentText));
                    if (CryptographicOperations.FixedTimeEquals(expectedHash, currentHash))
                    {
                        ClearSystemClipboard();
                    }
                }
                catch
                {
                    // Abaikan COMException sementara jika aplikasi lain sedang mengunci handle clipboard
                }
                finally
                {
                    _lastSensitiveHash = null;
                }
            });
        }

        private static async Task<string?> GetCurrentClipboardTextAsync()
        {
#if WINDOWS
        WinDataPackageView content = WinClipboard.GetContent();
        if (content.Contains(WinStandardDataFormats.Text))
        {
            return await content.GetTextAsync();
        }
        return null;
#else
            return await MauiClipboard.Default.GetTextAsync();
#endif
        }

        private static void ClearSystemClipboard()
        {
#if WINDOWS
        WinClipboard.Clear();
#else
            MauiClipboard.Default.SetTextAsync(string.Empty);
#endif
        }

        private void OnSessionStateChanged(bool isUnlocked)
        {
            if (!isUnlocked)
            {
                CancelPendingClear();
                _ = ClearIfUnchangedAsync();
            }
        }

        private void CancelPendingClear()
        {
            _clearCts?.Cancel();
            _clearCts?.Dispose();
            _clearCts = null;
        }

        public void Dispose()
        {
            CancelPendingClear();
            _session.SessionStateChanged -= OnSessionStateChanged;
            _lastSensitiveHash = null;
        }
    }
}
