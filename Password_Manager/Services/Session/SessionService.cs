using System.Security.Cryptography;
#if WINDOWS
using Microsoft.Win32;
#endif

namespace Password_Manager.Services.Session
{
    public sealed class SessionService
    {
        public sealed class VaultSessionService : IDisposable
        {
            private const int ExpectedDekSize = 32; // 256-bit

            private readonly object _syncLock = new();
            private readonly System.Threading.Timer _idleTimer;
            private TimeSpan _idleTimeout;
            private byte[]? _dek;
            private bool _disposed;

            /// <summary>
            /// Dipicu setiap kali status sesi berubah: true = Unlocked, false = Locked.
            /// </summary>
            public event Action<bool>? SessionStateChanged;

            public VaultSessionService(TimeSpan? defaultIdleTimeout = null)
            {
                _idleTimeout = defaultIdleTimeout ?? TimeSpan.FromMinutes(5);
                _idleTimer = new System.Threading.Timer(
                    callback: _ => Lock(),
                    state: null,
                    dueTime: Timeout.InfiniteTimeSpan,
                    period: Timeout.InfiniteTimeSpan
                );

#if WINDOWS
                SystemEvents.SessionSwitch += OnWindowsSessionSwitch;
#endif
            }

            public bool IsUnlocked
            {
                get
                {
                    lock (_syncLock)
                    {
                        return !_disposed && _dek is not null;
                    }
                }
            }

            public TimeSpan IdleTimeout
            {
                get
                {
                    lock (_syncLock)
                    {
                        return _idleTimeout;
                    }
                }
                set
                {
                    if (value <= TimeSpan.Zero)
                        throw new ArgumentOutOfRangeException(nameof(value), "Timeout harus lebih besar dari nol.");

                    lock (_syncLock)
                    {
                        ObjectDisposedException.ThrowIf(_disposed, this);
                        _idleTimeout = value;
                        if (_dek is not null)
                        {
                            ResetIdleTimerInternal();
                        }
                    }
                }
            }

            /// <summary>
            /// Menyimpan DEK ke RAM, langsung membersihkan buffer sumber milik pemanggil,
            /// dan memulai hitung mundur auto-lock.
            /// </summary>
            public void Unlock(byte[] dek)
            {
                ArgumentNullException.ThrowIfNull(dek);
                if (dek.Length != ExpectedDekSize)
                    throw new ArgumentException($"DEK harus berukuran {ExpectedDekSize} byte.", nameof(dek));

                lock (_syncLock)
                {
                    ObjectDisposedException.ThrowIf(_disposed, this);

                    if (_dek is not null)
                    {
                        CryptographicOperations.ZeroMemory(_dek);
                    }

                    _dek = new byte[ExpectedDekSize];
                    Buffer.BlockCopy(dek, 0, _dek, 0, ExpectedDekSize);

                    // Hapus jejak array DEK di sisi pemanggil segera setelah disalin
                    CryptographicOperations.ZeroMemory(dek);

                    ResetIdleTimerInternal();
                }

                // Panggil event di luar lock untuk mencegah deadlock dengan subscriber UI
                SessionStateChanged?.Invoke(true);
            }

            /// <summary>
            /// Menjalankan operasi kriptografi menggunakan DEK secara thread-safe.
            /// Menjamin DEK tidak di-ZeroMemory oleh timer saat operasi sedang berjalan.
            /// </summary>
            public T UseDek<T>(Func<byte[], T> cryptoOperation)
            {
                ArgumentNullException.ThrowIfNull(cryptoOperation);

                lock (_syncLock)
                {
                    ObjectDisposedException.ThrowIf(_disposed, this);

                    if (_dek is null)
                        throw new UnauthorizedAccessException("Vault dalam keadaan terkunci.");

                    ResetIdleTimerInternal();
                    return cryptoOperation(_dek);
                }
            }

            /// <summary>
            /// Memperpanjang waktu sesi aktif saat pengguna berinteraksi dengan UI.
            /// </summary>
            public void NotifyUserActivity()
            {
                lock (_syncLock)
                {
                    if (!_disposed && _dek is not null)
                    {
                        ResetIdleTimerInternal();
                    }
                }
            }

            /// <summary>
            /// Mengunci vault seketika dan menimpa DEK di RAM dengan nol (0x00).
            /// </summary>
            public void Lock()
            {
                bool wasUnlocked = false;

                lock (_syncLock)
                {
                    StopIdleTimerInternal();

                    if (_dek is not null)
                    {
                        CryptographicOperations.ZeroMemory(_dek);
                        _dek = null;
                        wasUnlocked = true;
                    }
                }

                if (wasUnlocked)
                {
                    SessionStateChanged?.Invoke(false);
                }
            }

            private void ResetIdleTimerInternal()
            {
                _idleTimer.Change(_idleTimeout, Timeout.InfiniteTimeSpan);
            }

            private void StopIdleTimerInternal()
            {
                _idleTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            }

#if WINDOWS
            private void OnWindowsSessionSwitch(object sender, SessionSwitchEventArgs e)
            {
                if (e.Reason is SessionSwitchReason.SessionLock
                             or SessionSwitchReason.SessionLogoff
                             or SessionSwitchReason.ConsoleDisconnect)
                {
                    Lock();
                }
            }
#endif

            public void Dispose()
            {
                lock (_syncLock)
                {
                    if (_disposed)
                        return;

                    _disposed = true;
                    StopIdleTimerInternal();

                    if (_dek is not null)
                    {
                        CryptographicOperations.ZeroMemory(_dek);
                        _dek = null;
                    }
                }

#if WINDOWS
                // Wajib unsubscribe static event agar tidak terjadi memory leak
                SystemEvents.SessionSwitch -= OnWindowsSessionSwitch;
#endif
                _idleTimer.Dispose();
            }
        }
    }
}
