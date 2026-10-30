import React, { useState, useEffect, useRef } from 'react';
import {
  ShieldCheckIcon,
  ShieldExclamationIcon,
  ArrowUpTrayIcon,
  CpuChipIcon,
  AdjustmentsHorizontalIcon,
  ArrowPathIcon,
  ChartBarIcon,
  MagnifyingGlassIcon,
  TrashIcon,
  ExclamationTriangleIcon,
  Square3Stack3DIcon,
  LockClosedIcon,
  ArrowRightOnRectangleIcon,
  XMarkIcon,
  ArrowRightIcon,
  DocumentMagnifyingGlassIcon,
  DevicePhoneMobileIcon,
  ComputerDesktopIcon,
  BoltIcon,
  CheckCircleIcon,
  KeyIcon,
  UserPlusIcon
} from '@heroicons/react/24/outline';
import VektorLogo from './components/VektorLogo';

const API_BASE = 'http://127.0.0.1:8000';

export default function App() {
  // Navigation & User State
  const [currentView, setCurrentView] = useState('landing'); // 'landing' | 'dashboard'
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [user, setUser] = useState(() => {
    const saved = localStorage.getItem('sentinel_user');
    return saved ? JSON.parse(saved) : null;
  });

  // Authentication State
  const [authMode, setAuthMode] = useState('login'); // 'login' | 'signup' | 'forgot'
  const [authEmail, setAuthEmail] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [authConfirmPassword, setAuthConfirmPassword] = useState('');
  const [authError, setAuthError] = useState(null);
  const [authSuccess, setAuthSuccess] = useState(null);
  const [authLoading, setAuthLoading] = useState(false);

  // Platform Mode: 'windows' | 'android' | 'visual'
  const [platformMode, setPlatformMode] = useState('windows');

  // Telemetry & Benchmarks
  const [health, setHealth] = useState({
    status: 'checking',
    windows_stadyn_model: false,
    android_kronodroid_model: false
  });
  const [stats, setStats] = useState({
    total_scans: 0,
    malware_detected: 0,
    benign_detected: 0,
    threat_rate_percent: 0,
    average_confidence: 0,
  });
  const [testSamples, setTestSamples] = useState([]);
  const [history, setHistory] = useState([]);

  // Scanner State
  const [selectedFile, setSelectedFile] = useState(null);
  const [threshold, setThreshold] = useState(0.5);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState(null);
  const [dragActive, setDragActive] = useState(false);

  // History Filter
  const [historyFilter, setHistoryFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');

  const fileInputRef = useRef(null);

  // Password validation helper
  const getPasswordCriteria = (pwd) => ({
    minLength: pwd.length >= 8,
    hasLower: /[a-z]/.test(pwd),
    hasUpper: /[A-Z]/.test(pwd),
    hasNumber: /[0-9]/.test(pwd),
    hasSpecial: /[!@#$%^&*(),.?":{}|<>_~-]/.test(pwd),
  });

  const isPasswordCompliant = (pwd) => {
    const c = getPasswordCriteria(pwd);
    return c.minLength && c.hasLower && c.hasUpper && c.hasNumber && c.hasSpecial;
  };

  // Fetch telemetry
  const fetchHealthAndStats = async () => {
    try {
      const [hRes, sRes, histRes, samplesRes] = await Promise.all([
        fetch(`${API_BASE}/api/health`).catch(() => null),
        fetch(`${API_BASE}/api/stats`).catch(() => null),
        fetch(`${API_BASE}/api/history`).catch(() => null),
        fetch(`${API_BASE}/api/test-samples`).catch(() => null),
      ]);

      if (hRes && hRes.ok) setHealth(await hRes.json());
      else setHealth({ status: 'offline', windows_stadyn_model: false, android_kronodroid_model: false });

      if (sRes && sRes.ok) setStats(await sRes.json());
      if (histRes && histRes.ok) setHistory(await histRes.json());
      if (samplesRes && samplesRes.ok) setTestSamples(await samplesRes.json());
    } catch {
      setHealth({ status: 'offline', windows_stadyn_model: false, android_kronodroid_model: false });
    }
  };

  useEffect(() => {
    fetchHealthAndStats();
    const interval = setInterval(fetchHealthAndStats, 10000);
    return () => clearInterval(interval);
  }, []);

  // Reset auth form state when opening/switching modal
  const openAuthWithMode = (mode) => {
    setAuthMode(mode);
    setAuthError(null);
    setAuthSuccess(null);
    setAuthPassword('');
    setAuthConfirmPassword('');
    setAuthModalOpen(true);
  };

  // Sign In Handler
  const handleLogin = async (e) => {
    if (e) e.preventDefault();
    setAuthError(null);
    setAuthSuccess(null);

    const email = authEmail.trim();
    if (!email || !authPassword) {
      setAuthError('Please enter both email and password.');
      return;
    }

    setAuthLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: authPassword }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Authentication failed. Please verify credentials.');
      }

      const authenticatedUser = {
        email: data.user.email,
        name: data.user.email.split('@')[0],
        role: 'Verified Researcher',
      };

      setUser(authenticatedUser);
      localStorage.setItem('sentinel_user', JSON.stringify(authenticatedUser));
      setAuthModalOpen(false);
      setCurrentView('dashboard');
      setAuthPassword('');
    } catch (err) {
      setAuthError(err.message || 'Unable to connect to the authentication service.');
    } finally {
      setAuthLoading(false);
    }
  };

  // Sign Up Handler
  const handleRegister = async (e) => {
    if (e) e.preventDefault();
    setAuthError(null);
    setAuthSuccess(null);

    const email = authEmail.trim();
    if (!email) {
      setAuthError('Please provide a valid email address.');
      return;
    }

    if (!isPasswordCompliant(authPassword)) {
      setAuthError('Password does not fulfill all security requirements.');
      return;
    }

    if (authPassword !== authConfirmPassword) {
      setAuthError('Passwords do not match. Please retype and confirm.');
      return;
    }

    setAuthLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: authPassword }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Registration could not be completed.');
      }

      const authenticatedUser = {
        email: data.user.email,
        name: data.user.email.split('@')[0],
        role: 'Verified Researcher',
      };

      setUser(authenticatedUser);
      localStorage.setItem('sentinel_user', JSON.stringify(authenticatedUser));
      setAuthModalOpen(false);
      setCurrentView('dashboard');
      setAuthPassword('');
      setAuthConfirmPassword('');
    } catch (err) {
      setAuthError(err.message || 'Registration error occurred.');
    } finally {
      setAuthLoading(false);
    }
  };

  // Forgot Password Handler
  const handleForgotPassword = async (e) => {
    if (e) e.preventDefault();
    setAuthError(null);
    setAuthSuccess(null);

    const email = authEmail.trim();
    if (!email) {
      setAuthError('Please enter the email registered to your account.');
      return;
    }

    if (!isPasswordCompliant(authPassword)) {
      setAuthError('New password does not fulfill all security requirements.');
      return;
    }

    if (authPassword !== authConfirmPassword) {
      setAuthError('Passwords do not match. Please retype and confirm.');
      return;
    }

    setAuthLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, new_password: authPassword }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Could not reset password.');
      }

      setAuthSuccess('Password has been successfully updated. You can now sign in.');
      setTimeout(() => {
        setAuthMode('login');
        setAuthSuccess(null);
        setAuthPassword('');
        setAuthConfirmPassword('');
      }, 1400);
    } catch (err) {
      setAuthError(err.message || 'Password reset error occurred.');
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLogout = () => {
    setUser(null);
    localStorage.removeItem('sentinel_user');
    setCurrentView('landing');
  };

  // Drag & Drop
  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') setDragActive(true);
    else if (e.type === 'dragleave') setDragActive(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const validateAndSetFile = (file) => {
    setScanError(null);
    setScanResult(null);

    const ext = '.' + file.name.split('.').pop().toLowerCase();
    const allowed = ['.exe', '.dll', '.bin', '.sys', '.apk', '.png', '.jpg', '.jpeg', '.bmp', '.webp'];

    if (!allowed.includes(ext)) {
      setScanError(`Unsupported format '${ext}'. Supported formats: ${allowed.join(', ')}`);
      return;
    }

    if (ext === '.apk') {
      setPlatformMode('android');
    } else if (['.exe', '.dll', '.sys', '.bin'].includes(ext)) {
      setPlatformMode('windows');
    } else if (['.png', '.jpg', '.jpeg', '.bmp', '.webp'].includes(ext)) {
      setPlatformMode('visual');
    }

    if (file.size > 50 * 1024 * 1024) {
      setScanError(`File exceeds the 50MB limit (${(file.size / (1024 * 1024)).toFixed(2)} MB).`);
      return;
    }

    setSelectedFile(file);
  };

  // Scan uploaded file
  const handleScan = async () => {
    if (!selectedFile) return;
    setScanning(true);
    setScanError(null);
    setScanResult(null);

    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('platform', platformMode === 'visual' ? 'windows' : platformMode);
    formData.append('threshold', threshold.toString());

    try {
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: 'POST',
        body: formData,
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({ detail: 'Scan failed' }));
        throw new Error(errData.detail || 'Scan processing error');
      }

      const result = await res.json();
      setScanResult(result);
      fetchHealthAndStats();
    } catch (err) {
      setScanError(err.message || 'Unable to connect to the backend server.');
    } finally {
      setScanning(false);
    }
  };

  // 1-Click Evaluation of Test Samples
  const handleRunTestSample = async (sampleId) => {
    setScanning(true);
    setScanError(null);
    setScanResult(null);

    try {
      const res = await fetch(`${API_BASE}/api/scan/test-sample/${sampleId}?threshold=${threshold}`, {
        method: 'POST',
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({ detail: 'Sample evaluation failed' }));
        throw new Error(errData.detail || 'Sample processing error');
      }

      const result = await res.json();
      setScanResult(result);
      fetchHealthAndStats();
    } catch (err) {
      setScanError(err.message || 'Unable to process sample.');
    } finally {
      setScanning(false);
    }
  };

  const handleClearHistory = async () => {
    if (!window.confirm('Delete all records from the scan history?')) return;
    try {
      await fetch(`${API_BASE}/api/history`, { method: 'DELETE' });
      fetchHealthAndStats();
    } catch (err) {
      console.error(err);
    }
  };

  const filteredHistory = history.filter((item) => {
    if (historyFilter === 'malware' && item.prediction !== 'Malware') return false;
    if (historyFilter === 'benign' && item.prediction !== 'Benign') return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        item.filename.toLowerCase().includes(q) ||
        (item.sha256 && item.sha256.toLowerCase().includes(q)) ||
        (item.platform && item.platform.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const pwdCriteria = getPasswordCriteria(authPassword);
  const passwordsMatch = authPassword && authPassword === authConfirmPassword;

  return (
    <div className="min-h-screen text-[#FFFFFF] flex flex-col bg-[#090909]">
      {/* ──────────────── FLOATING SLEEK CLAYMORPHIC NAVBAR ──────────────── */}
      <header className="sticky top-3.5 z-40 w-full flex justify-center px-3 sm:px-6">
        <div className="w-[95%] max-w-7xl border border-[#FF2E2E] rounded-full bg-[#141010] shadow-[0_12px_30px_#000000,inset_1px_1px_1.5px_rgba(255,255,255,0.12),inset_-2px_-2px_4px_rgba(0,0,0,0.7)] px-5 sm:px-7 h-14 sm:h-16 flex items-center justify-between transition-all">
          {/* Brand */}
          <div
            onClick={() => setCurrentView('landing')}
            className="flex items-center gap-2.5 cursor-pointer select-none"
          >
            <VektorLogo className="w-8 h-8" />
            <div className="flex items-center gap-1.5">
              <span className="text-lg font-bold tracking-tight text-white">
                Vektor
              </span>
              <span className="w-1.5 h-1.5 rounded-full bg-[#FF2E2E]" />
            </div>
          </div>

          {/* Navigation Links */}
          {currentView === 'landing' ? (
            <nav className="hidden md:flex items-center gap-7 text-xs sm:text-sm font-medium text-[#B8B1AA]">
              <a href="#overview" className="hover:text-white transition-colors">Overview</a>
              <a href="#benchmarks" className="hover:text-white transition-colors">Benchmarks</a>
              <a href="#architecture" className="hover:text-white transition-colors">Architecture</a>
              <a href="#workflow" className="hover:text-white transition-colors">Process</a>
            </nav>
          ) : (
            <div className="flex items-center gap-2">
              <span className="clay-pill px-3 py-1 text-xs font-mono text-[#B8B1AA]">
                Dashboard Mode
              </span>
            </div>
          )}

          {/* Right Controls */}
          <div className="flex items-center gap-3">
            {user ? (
              <div className="flex items-center gap-2.5">
                {currentView === 'landing' ? (
                  <button
                    onClick={() => setCurrentView('dashboard')}
                    className="clay-btn-primary text-xs py-1.5 px-3.5"
                  >
                    <span>Dashboard</span>
                    <ArrowRightIcon className="w-3.5 h-3.5" />
                  </button>
                ) : (
                  <button
                    onClick={() => setCurrentView('landing')}
                    className="clay-btn-secondary text-xs py-1.5 px-3.5"
                  >
                    <span>Home</span>
                  </button>
                )}

                <button
                  onClick={handleLogout}
                  className="p-1.5 rounded-xl text-[#B8B1AA] hover:text-white clay-btn-secondary"
                  title="Sign Out"
                >
                  <ArrowRightOnRectangleIcon className="w-4 h-4" />
                </button>
              </div>
            ) : (
              <div className="flex items-center gap-2.5">
                <button
                  onClick={() => openAuthWithMode('login')}
                  className="clay-btn-secondary text-xs py-1.5 px-3.5"
                >
                  <LockClosedIcon className="w-3.5 h-3.5 text-[#FF2E2E]" />
                  <span>Sign In</span>
                </button>
                <button
                  onClick={() => openAuthWithMode('signup')}
                  className="clay-btn-primary text-xs py-1.5 px-3.5"
                >
                  <UserPlusIcon className="w-3.5 h-3.5" />
                  <span>Sign Up</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* ──────────────── VIEW 1: LANDING PAGE ──────────────── */}
      {currentView === 'landing' && (
        <div className="flex-1 space-y-28 pb-28">
          {/* Hero Section */}
          <section id="overview" className="relative isolate max-w-7xl mx-auto px-6 lg:px-10 pt-24 sm:pt-28 pb-14 text-center overflow-hidden rounded-3xl">
            {/* ──────────────── HERO BACKGROUND: TRANSPARENT SHIELD & 3D CYBER MESH ──────────────── */}
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-0 overflow-hidden select-none">
              {/* Cyber Perspective Grid */}
              <div className="absolute inset-0 cyber-grid [mask-image:radial-gradient(ellipse_75%_65%_at_50%_45%,#000_70%,transparent_100%)] opacity-35" />

              {/* Deep Red Volumetric Radial Glows */}
              <div className="absolute w-[600px] sm:w-[850px] h-[600px] sm:h-[850px] bg-[#8B1111]/35 rounded-full blur-[140px] pointer-events-none" />
              <div className="absolute w-[350px] sm:w-[520px] h-[350px] sm:h-[520px] bg-[#FF2E2E]/25 rounded-full blur-[90px] pointer-events-none" />

              {/* Concentric Radar Scan Circles Behind the Text */}
              <div className="absolute w-[460px] sm:w-[660px] lg:w-[780px] aspect-square rounded-full border border-[#FF2E2E]/30 animate-spin-slow pointer-events-none flex items-center justify-center">
                <div className="absolute top-0 w-3 h-3 rounded-full bg-[#FF2E2E] shadow-[0_0_12px_#FF2E2E]" />
                <div className="absolute bottom-0 w-3 h-3 rounded-full bg-[#8B1111]" />
                <div className="absolute left-0 w-3 h-3 rounded-full bg-[#8B1111]" />
                <div className="absolute right-0 w-3 h-3 rounded-full bg-[#FF2E2E] shadow-[0_0_12px_#FF2E2E]" />
              </div>
              <div className="absolute w-[340px] sm:w-[500px] lg:w-[600px] aspect-square rounded-full border border-dashed border-[#8B1111]/50 animate-spin-reverse pointer-events-none" />

              {/* High-Res Transparent Vektor Shield Emblem (Background Cleanly Removed) */}
              <img
                src="/hero-bg.png"
                alt="Vektor Shield Emblem"
                className="w-[360px] sm:w-[520px] lg:w-[640px] aspect-square object-contain opacity-45 sm:opacity-50 filter drop-shadow-[0_0_70px_rgba(255,46,46,0.75)] select-none transition-all duration-700"
              />

              {/* Ambient Edge Vignette */}
              <div className="absolute inset-0 bg-gradient-to-b from-[#090909]/40 via-transparent to-[#090909]" />
            </div>

            {/* ──────────────── HERO FOREGROUND CONTENT (z-10 on top of background) ──────────────── */}
            <div className="relative z-10 space-y-8">
              {/* Pill Tag with Logo */}
              <div className="inline-flex items-center gap-2.5 px-4 py-1.5 rounded-full clay-inset border border-[#8B1111]/60 shadow-[0_4px_16px_rgba(0,0,0,0.8)] backdrop-blur-md">
                <img src="/logo.png" alt="Vektor" className="w-5 h-5 object-contain" />
                <span className="text-xs font-mono font-medium tracking-wider text-[#FF2E2E] uppercase">
                  Cross-Platform Threat Defense
                </span>
              </div>

              <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-white max-w-4xl mx-auto leading-[1.16] drop-shadow-[0_6px_24px_rgba(0,0,0,0.95)]">
                Vektor Threat Intelligence <br className="hidden sm:block" />
                Cross-Platform Defense
              </h1>

              {/* Enhanced High-Contrast Subtitle Plate */}
              <div className="max-w-3xl mx-auto px-6 py-4 rounded-2xl bg-[#141010]/80 backdrop-blur-md border border-[#8B1111]/50 shadow-[0_8px_32px_rgba(0,0,0,0.9)]">
                <p className="text-base sm:text-lg text-white font-normal leading-relaxed drop-shadow-[0_2px_8px_rgba(0,0,0,0.8)]">
                  A deep learning detection system that classifies malicious files across Windows executables and Android application packages using spatial convolutional filters and long short-term memory recurrent networks.
                </p>
              </div>

              <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-1">
                <button
                  onClick={() => {
                    if (user) setCurrentView('dashboard');
                    else openAuthWithMode('login');
                  }}
                  className="clay-btn-primary text-sm py-3 px-8 w-full sm:w-auto justify-center shadow-[0_6px_20px_rgba(255,46,46,0.35)]"
                >
                  <span>{user ? 'Open Scanner' : 'Get Started'}</span>
                  <ArrowRightIcon className="w-4 h-4" />
                </button>

                <a href="#benchmarks" className="clay-btn-secondary text-sm py-3 px-8 w-full sm:w-auto justify-center shadow-[0_4px_16px_rgba(0,0,0,0.8)]">
                  <ChartBarIcon className="w-4 h-4 text-[#FF2E2E]" />
                  <span>View Results</span>
                </a>
              </div>

              {/* 4 Wide Metric Tiles */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 pt-6">
                <div className="clay-card p-6 text-left space-y-2 backdrop-blur-md">
                  <span className="text-xs font-mono text-[#B8B1AA] uppercase block">Windows ROC-AUC</span>
                  <span className="text-3xl font-bold font-mono text-[#FF2E2E] block">99.54%</span>
                  <span className="text-xs text-[#B8B1AA]/80 block">UCI staDyn &bull; 244 Features</span>
                </div>
                <div className="clay-card p-6 text-left space-y-2 backdrop-blur-md">
                  <span className="text-xs font-mono text-[#B8B1AA] uppercase block">Windows Accuracy</span>
                  <span className="text-3xl font-bold font-mono text-white block">97.97%</span>
                  <span className="text-xs text-[#B8B1AA]/80 block">F1: 98.87% &bull; Recall: 98.00%</span>
                </div>
                <div className="clay-card p-6 text-left space-y-2 backdrop-blur-md">
                  <span className="text-xs font-mono text-[#B8B1AA] uppercase block">Android ROC-AUC</span>
                  <span className="text-3xl font-bold font-mono text-[#FF2E2E] block">95.31%</span>
                  <span className="text-xs text-[#B8B1AA]/80 block">KronoDroid &bull; 487 Features</span>
                </div>
                <div className="clay-card p-6 text-left space-y-2 backdrop-blur-md">
                  <span className="text-xs font-mono text-[#B8B1AA] uppercase block">Android Accuracy</span>
                  <span className="text-3xl font-bold font-mono text-white block">91.14%</span>
                  <span className="text-xs text-[#B8B1AA]/80 block">F1: 91.42% &bull; Recall: 90.38%</span>
                </div>
              </div>
            </div>
          </section>

          {/* Benchmarks Section */}
          <section id="benchmarks" className="max-w-7xl mx-auto px-6 lg:px-10 space-y-8">
            <div className="space-y-2">
              <span className="text-xs font-mono uppercase tracking-wider text-[#FF2E2E] font-semibold block">
                Experimental Results
              </span>
              <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
                Held-Out Benchmark Validation
              </h2>
              <p className="text-sm text-[#B8B1AA] max-w-2xl">
                Evaluated separately on held-out test splits. CNN layers extract structural patterns while LSTM layers capture sequence dependencies.
              </p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              {/* Windows Benchmark Card */}
              <div className="clay-card p-8 space-y-6">
                <div className="flex items-center justify-between pb-4 border-b border-[#8B1111]/30">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-[#191414] border border-[#8B1111]/40 text-[#FF2E2E] flex items-center justify-center shadow-[3px_3px_8px_#040404]">
                      <ComputerDesktopIcon className="w-5 h-5" />
                    </div>
                    <div>
                      <h3 className="text-base font-semibold text-white">Windows PE Platform</h3>
                      <span className="text-xs font-mono text-[#B8B1AA]">UCI staDyn Dataset (6,248 Samples)</span>
                    </div>
                  </div>
                  <span className="clay-pill text-xs font-mono px-3 py-1 text-[#FF2E2E]">
                    244 Features
                  </span>
                </div>

                <div className="grid grid-cols-3 gap-4 text-center">
                  <div className="clay-inset p-4">
                    <span className="text-xs text-[#B8B1AA] block">Accuracy</span>
                    <span className="text-xl font-bold font-mono text-white mt-1 block">97.97%</span>
                  </div>
                  <div className="clay-inset p-4">
                    <span className="text-xs text-[#B8B1AA] block">F1-Score</span>
                    <span className="text-xl font-bold font-mono text-[#FF2E2E] mt-1 block">98.87%</span>
                  </div>
                  <div className="clay-inset p-4">
                    <span className="text-xs text-[#B8B1AA] block">ROC-AUC</span>
                    <span className="text-xl font-bold font-mono text-[#FF2E2E] mt-1 block">99.54%</span>
                  </div>
                </div>

                <div className="space-y-2 text-xs font-mono text-[#B8B1AA]">
                  <div className="flex justify-between py-1.5 border-b border-[#1f1616]">
                    <span>Model Structure</span>
                    <span className="text-white">Conv1D(32, 5) + MaxPool1D(2) + LSTM(32, 0.3)</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-[#1f1616]">
                    <span>Trainable Parameters</span>
                    <span className="text-[#FF2E2E]">9,601 Weights</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-[#1f1616]">
                    <span>Precision / Recall</span>
                    <span className="text-white">99.76% Precision / 98.00% Recall</span>
                  </div>
                  <div className="flex justify-between py-1.5">
                    <span>Held-Out Test Results</span>
                    <span className="text-emerald-400">831 TP / 88 TN (938 Samples)</span>
                  </div>
                </div>
              </div>

              {/* Android Benchmark Card */}
              <div className="clay-card p-8 space-y-6">
                <div className="flex items-center justify-between pb-4 border-b border-[#8B1111]/30">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-[#191414] border border-[#8B1111]/40 text-[#FF2E2E] flex items-center justify-center shadow-[3px_3px_8px_#040404]">
                      <DevicePhoneMobileIcon className="w-5 h-5" />
                    </div>
                    <div>
                      <h3 className="text-base font-semibold text-white">Android APK Platform</h3>
                      <span className="text-xs font-mono text-[#B8B1AA]">KronoDroid Dataset (142,112 Samples)</span>
                    </div>
                  </div>
                  <span className="clay-pill text-xs font-mono px-3 py-1 text-[#FF2E2E]">
                    487 Features
                  </span>
                </div>

                <div className="grid grid-cols-3 gap-4 text-center">
                  <div className="clay-inset p-4">
                    <span className="text-xs text-[#B8B1AA] block">Accuracy</span>
                    <span className="text-xl font-bold font-mono text-white mt-1 block">91.14%</span>
                  </div>
                  <div className="clay-inset p-4">
                    <span className="text-xs text-[#B8B1AA] block">F1-Score</span>
                    <span className="text-xl font-bold font-mono text-[#FF2E2E] mt-1 block">91.42%</span>
                  </div>
                  <div className="clay-inset p-4">
                    <span className="text-xs text-[#B8B1AA] block">ROC-AUC</span>
                    <span className="text-xl font-bold font-mono text-[#FF2E2E] mt-1 block">95.31%</span>
                  </div>
                </div>

                <div className="space-y-2 text-xs font-mono text-[#B8B1AA]">
                  <div className="flex justify-between py-1.5 border-b border-[#1f1616]">
                    <span>Model Structure</span>
                    <span className="text-white">Conv1D(32, 5) + MaxPool1D(2) + LSTM(32, 0.3)</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-[#1f1616]">
                    <span>Trainable Parameters</span>
                    <span className="text-[#FF2E2E]">9,601 Weights</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-[#1f1616]">
                    <span>Precision / Recall</span>
                    <span className="text-white">92.48% Precision / 90.38% Recall</span>
                  </div>
                  <div className="flex justify-between py-1.5">
                    <span>Held-Out Test Results</span>
                    <span className="text-emerald-400">14,221 TP / 13,271 TN (30,163 Samples)</span>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* Architecture Capabilities */}
          <section id="architecture" className="max-w-7xl mx-auto px-6 lg:px-10 space-y-8">
            <div className="space-y-2">
              <span className="text-xs font-mono uppercase tracking-wider text-[#FF2E2E] font-semibold block">
                Core Capabilities
              </span>
              <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
                Built for Multi-Platform Detection
              </h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="clay-card p-7 space-y-4">
                <div className="w-10 h-10 rounded-xl bg-[#191414] border border-[#8B1111]/40 text-[#FF2E2E] flex items-center justify-center shadow-[3px_3px_8px_#040404]">
                  <DocumentMagnifyingGlassIcon className="w-5 h-5" />
                </div>
                <h3 className="text-base font-semibold text-white">Static and Dynamic Features</h3>
                <p className="text-sm text-[#B8B1AA] leading-relaxed">
                  Extracts structural headers and Cuckoo API counts for Windows, plus manifest permissions and runtime system calls for Android packages.
                </p>
              </div>

              <div className="clay-card p-7 space-y-4">
                <div className="w-10 h-10 rounded-xl bg-[#191414] border border-[#8B1111]/40 text-[#FF2E2E] flex items-center justify-center shadow-[3px_3px_8px_#040404]">
                  <CpuChipIcon className="w-5 h-5" />
                </div>
                <h3 className="text-base font-semibold text-white">Hybrid Neural Network</h3>
                <p className="text-sm text-[#B8B1AA] leading-relaxed">
                  Convolutional layers identify local feature interactions, while an LSTM layer models sequential order across execution traces.
                </p>
              </div>

              <div className="clay-card p-7 space-y-4">
                <div className="w-10 h-10 rounded-xl bg-[#191414] border border-[#8B1111]/40 text-[#FF2E2E] flex items-center justify-center shadow-[3px_3px_8px_#040404]">
                  <Square3Stack3DIcon className="w-5 h-5" />
                </div>
                <h3 className="text-base font-semibold text-white">Safe In-Memory Analysis</h3>
                <p className="text-sm text-[#B8B1AA] leading-relaxed">
                  Files are parsed safely in memory without running executable code, preventing any risk of infection or sandbox evasion.
                </p>
              </div>
            </div>
          </section>

          {/* Workflow */}
          <section id="workflow" className="max-w-7xl mx-auto px-6 lg:px-10 space-y-8">
            <div className="space-y-2">
              <span className="text-xs font-mono uppercase tracking-wider text-[#FF2E2E] font-semibold block">
                Detection Process
              </span>
              <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
                How It Works
              </h2>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="clay-card p-6 space-y-2">
                <span className="text-xs font-mono text-[#FF2E2E] font-bold block">01 / PARSING</span>
                <h4 className="text-sm font-semibold text-white">Feature Extraction</h4>
                <p className="text-xs text-[#B8B1AA] leading-relaxed">
                  Reads PE structural tables for Windows or manifest entries and DEX calls for Android packages.
                </p>
              </div>

              <div className="clay-card p-6 space-y-2">
                <span className="text-xs font-mono text-[#FF2E2E] font-bold block">02 / CONVOLUTION</span>
                <h4 className="text-sm font-semibold text-white">Pattern Extraction</h4>
                <p className="text-xs text-[#B8B1AA] leading-relaxed">
                  Conv1D filters identify recurring feature combinations and structural signatures.
                </p>
              </div>

              <div className="clay-card p-6 space-y-2">
                <span className="text-xs font-mono text-[#FF2E2E] font-bold block">03 / RECURRENT MEMORY</span>
                <h4 className="text-sm font-semibold text-white">Sequence Analysis</h4>
                <p className="text-xs text-[#B8B1AA] leading-relaxed">
                  LSTM unit tracks sequential relationships between calls and permissions over long ranges.
                </p>
              </div>

              <div className="clay-card p-6 space-y-2">
                <span className="text-xs font-mono text-[#FF2E2E] font-bold block">04 / OUTPUT</span>
                <h4 className="text-sm font-semibold text-white">Classification</h4>
                <p className="text-xs text-[#B8B1AA] leading-relaxed">
                  Sigmoid layer produces a probability score evaluated against the configured threshold.
                </p>
              </div>
            </div>
          </section>

          {/* Bottom Action Card */}
          <section className="max-w-7xl mx-auto px-6 lg:px-10">
            <div className="clay-card p-10 flex flex-col md:flex-row items-center justify-between gap-6">
              <div className="space-y-1">
                <h3 className="text-xl font-bold text-white">Ready to test a sample?</h3>
                <p className="text-sm text-[#B8B1AA]">
                  Open the scanner to evaluate Windows executables, Android packages, or pre-validated test samples.
                </p>
              </div>
              <button
                onClick={() => {
                  if (user) setCurrentView('dashboard');
                  else openAuthWithMode('login');
                }}
                className="clay-btn-primary py-3 px-6 text-xs whitespace-nowrap"
              >
                <LockClosedIcon className="w-4 h-4" />
                <span>{user ? 'Open Scanner' : 'Sign In to Scanner'}</span>
              </button>
            </div>
          </section>
        </div>
      )}

      {/* ──────────────── VIEW 2: SCANNER DASHBOARD ──────────────── */}
      {currentView === 'dashboard' && (
        <main className="max-w-7xl mx-auto w-full px-6 lg:px-10 pt-10 pb-16 space-y-8 flex-1">
          {/* Top Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#8B1111]/30">
            <div>
              <div className="flex items-center gap-3">
                <VektorLogo className="w-8 h-8" />
                <h1 className="text-2xl font-bold text-white tracking-tight">
                  Vektor Scanner
                </h1>
                <span className="clay-pill text-xs font-mono px-3 py-1 text-[#FF2E2E]">
                  Detection Console
                </span>
              </div>
              <p className="text-xs text-[#B8B1AA] mt-1">
                Logged in as <span className="text-white font-medium">{user?.email}</span>
              </p>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={() => setCurrentView('landing')}
                className="clay-btn-secondary text-xs py-2 px-4"
              >
                <span>Home Page</span>
              </button>
            </div>
          </div>

          {/* Platform Switcher */}
          <div className="clay-card p-2 flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <button
                onClick={() => {
                  setPlatformMode('windows');
                  setSelectedFile(null);
                  setScanResult(null);
                }}
                className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-medium transition-all ${
                  platformMode === 'windows'
                    ? 'bg-[#1e1515] text-[#FF2E2E] border border-[#8B1111]/60 font-semibold shadow-[inset_1px_1px_1px_rgba(255,255,255,0.1)]'
                    : 'text-[#B8B1AA] hover:text-white'
                }`}
              >
                <ComputerDesktopIcon className="w-4 h-4" />
                <span>Windows (UCI staDyn &bull; 244 Features)</span>
              </button>

              <button
                onClick={() => {
                  setPlatformMode('android');
                  setSelectedFile(null);
                  setScanResult(null);
                }}
                className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-medium transition-all ${
                  platformMode === 'android'
                    ? 'bg-[#1e1515] text-[#FF2E2E] border border-[#8B1111]/60 font-semibold shadow-[inset_1px_1px_1px_rgba(255,255,255,0.1)]'
                    : 'text-[#B8B1AA] hover:text-white'
                }`}
              >
                <DevicePhoneMobileIcon className="w-4 h-4" />
                <span>Android (KronoDroid &bull; 487 Features)</span>
              </button>

              <button
                onClick={() => {
                  setPlatformMode('visual');
                  setSelectedFile(null);
                  setScanResult(null);
                }}
                className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-medium transition-all ${
                  platformMode === 'visual'
                    ? 'bg-[#1e1515] text-[#FF2E2E] border border-[#8B1111]/60 font-semibold shadow-[inset_1px_1px_1px_rgba(255,255,255,0.1)]'
                    : 'text-[#B8B1AA] hover:text-white'
                }`}
              >
                <Square3Stack3DIcon className="w-4 h-4" />
                <span>Visual Byte Matrix (Grad-CAM)</span>
              </button>
            </div>

            <div className="text-xs font-mono text-[#B8B1AA] px-3 py-1">
              {platformMode === 'windows' && 'Model: windows_stadyn_model.keras (9,601 Weights)'}
              {platformMode === 'android' && 'Model: android_kronodroid_model.keras (9,601 Weights)'}
              {platformMode === 'visual' && 'Model: best_model.keras (687,845 Weights)'}
            </div>
          </div>

          {/* Quick Test Samples */}
          <div className="clay-card p-6 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
              <div className="flex items-center gap-2">
                <BoltIcon className="w-4 h-4 text-[#FF2E2E]" />
                <h3 className="text-xs font-semibold uppercase tracking-wider text-white">
                  Quick Test Samples (Pre-Validated Benchmarks)
                </h3>
              </div>
              <span className="text-xs font-mono text-[#B8B1AA]">
                Run immediate inference without uploading a file
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {testSamples.map((sample) => (
                <button
                  key={sample.id}
                  onClick={() => handleRunTestSample(sample.id)}
                  disabled={scanning}
                  className="flex flex-col items-start p-4 clay-inset hover:border-[#FF2E2E]/50 text-left transition-all group disabled:opacity-50"
                >
                  <div className="flex items-center justify-between w-full mb-1.5">
                    <span
                      className={`text-xs font-mono px-2 py-0.5 rounded font-semibold ${
                        sample.expected === 'Malware'
                          ? 'bg-[#8B1111]/40 text-[#FF2E2E] border border-[#8B1111]/60'
                          : 'bg-emerald-950/40 text-emerald-400 border border-emerald-800/40'
                      }`}
                    >
                      {sample.expected}
                    </span>
                    <span className="text-xs font-mono text-[#B8B1AA] uppercase">
                      {sample.platform}
                    </span>
                  </div>
                  <span className="text-xs font-semibold text-white group-hover:text-[#FF2E2E] truncate w-full mt-1">
                    {sample.name}
                  </span>
                  <span className="text-xs text-[#B8B1AA] mt-1 line-clamp-2">
                    {sample.description}
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* Main Scanner Section (7 cols Upload + 5 cols Stats) */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Left: Upload and Controls (7 cols) */}
            <div className="clay-card p-8 lg:col-span-7 flex flex-col justify-between space-y-6">
              <div>
                <div className="flex items-center justify-between pb-4 border-b border-[#8B1111]/30">
                  <h2 className="text-sm font-semibold text-white">
                    {platformMode === 'windows' && 'Windows Binary Upload (.exe / .dll / .sys)'}
                    {platformMode === 'android' && 'Android Application Package (.apk)'}
                    {platformMode === 'visual' && 'PE Byte Image (.png / .jpg)'}
                  </h2>
                  <span className="text-xs font-mono text-[#B8B1AA]">
                    {platformMode === 'windows' && '244-Feature Representation'}
                    {platformMode === 'android' && '487-Feature Representation'}
                    {platformMode === 'visual' && '32x32 Matrix'}
                  </span>
                </div>

                {/* Stretched Dropzone */}
                <div className="mt-6">
                  <div
                    onDragEnter={handleDrag}
                    onDragLeave={handleDrag}
                    onDragOver={handleDrag}
                    onDrop={handleDrop}
                    onClick={() => fileInputRef.current?.click()}
                    className={`clay-inset p-12 text-center cursor-pointer transition-all ${
                      dragActive
                        ? 'border-[#FF2E2E] bg-[#1a1212]'
                        : 'hover:border-[#8B1111]/60'
                    }`}
                  >
                    <input
                      ref={fileInputRef}
                      type="file"
                      onChange={handleFileChange}
                      className="hidden"
                      accept={
                        platformMode === 'windows'
                          ? '.exe,.dll,.bin,.sys'
                          : platformMode === 'android'
                          ? '.apk'
                          : '.png,.jpg,.jpeg,.bmp,.webp'
                      }
                    />
                    <div className="w-12 h-12 rounded-xl bg-[#191414] border border-[#8B1111]/40 text-[#FF2E2E] flex items-center justify-center mx-auto mb-3 shadow-[3px_3px_8px_#040404]">
                      <ArrowUpTrayIcon className="w-6 h-6" />
                    </div>
                    <p className="text-sm font-medium text-white">
                      {selectedFile ? selectedFile.name : `Select or drop a ${platformMode} sample`}
                    </p>
                    <p className="text-xs text-[#B8B1AA] mt-1.5 font-mono">
                      {selectedFile
                        ? `${(selectedFile.size / 1024).toFixed(1)} KB &bull; Ready`
                        : platformMode === 'windows'
                        ? 'Accepts .exe, .dll, .sys, .bin files (up to 50MB)'
                        : platformMode === 'android'
                        ? 'Accepts Android .apk packages (up to 50MB)'
                        : 'Accepts 32x32 byte visual images (.png, .jpg)'}
                    </p>
                  </div>
                </div>

                {/* Threshold Slider */}
                <div className="mt-6 pt-5 border-t border-[#8B1111]/30 space-y-3">
                  <div className="flex justify-between items-center">
                    <div className="flex items-center gap-2">
                      <AdjustmentsHorizontalIcon className="w-4 h-4 text-[#FF2E2E]" />
                      <span className="text-xs font-medium text-white">Classification Threshold</span>
                    </div>
                    <span className="clay-pill font-mono text-xs px-2.5 py-0.5 text-[#FF2E2E]">
                      {threshold.toFixed(2)}
                    </span>
                  </div>

                  <input
                    type="range"
                    min="0.10"
                    max="0.90"
                    step="0.05"
                    value={threshold}
                    onChange={(e) => setThreshold(parseFloat(e.target.value))}
                    className="w-full my-2"
                  />

                  <div className="flex justify-between text-xs text-[#B8B1AA] font-mono">
                    <span>0.10 (High Sensitivity)</span>
                    <span>0.50 (Balanced)</span>
                    <span>0.90 (High Precision)</span>
                  </div>
                </div>

                {/* Error Banner */}
                {scanError && (
                  <div className="mt-5 p-3.5 rounded-xl bg-[#8B1111]/25 border border-[#FF2E2E]/40 text-xs text-rose-300 flex items-start gap-2.5">
                    <ExclamationTriangleIcon className="w-4 h-4 text-[#FF2E2E] shrink-0 mt-0.5" />
                    <span>{scanError}</span>
                  </div>
                )}
              </div>

              <button
                onClick={handleScan}
                disabled={!selectedFile || scanning}
                className="clay-btn-primary w-full justify-center py-3 text-sm mt-4"
              >
                {scanning ? (
                  <>
                    <ArrowPathIcon className="w-4 h-4 animate-spin" />
                    <span>Analyzing File...</span>
                  </>
                ) : (
                  <>
                    <ShieldCheckIcon className="w-4 h-4" />
                    <span>Scan File</span>
                  </>
                )}
              </button>
            </div>

            {/* Right: Overview Statistics (5 cols) */}
            <div className="clay-card p-8 lg:col-span-5 flex flex-col justify-between space-y-6">
              <div>
                <div className="flex items-center gap-2 pb-4 border-b border-[#8B1111]/30">
                  <ChartBarIcon className="w-5 h-5 text-[#FF2E2E]" />
                  <h3 className="text-sm font-semibold text-white">System Statistics</h3>
                </div>

                <div className="grid grid-cols-2 gap-3.5 mt-5">
                  <div className="clay-inset p-4">
                    <span className="text-xs text-[#B8B1AA] uppercase font-mono block">Total Scans</span>
                    <span className="text-2xl font-bold font-mono text-white mt-1 block">{stats.total_scans}</span>
                  </div>
                  <div className="clay-inset p-4">
                    <span className="text-xs text-[#B8B1AA] uppercase font-mono block">Threats Found</span>
                    <span className="text-2xl font-bold font-mono text-[#FF2E2E] mt-1 block">{stats.malware_detected}</span>
                  </div>
                  <div className="clay-inset p-4">
                    <span className="text-xs text-[#B8B1AA] uppercase font-mono block">Clean Files</span>
                    <span className="text-2xl font-bold font-mono text-emerald-400 mt-1 block">{stats.benign_detected}</span>
                  </div>
                  <div className="clay-inset p-4">
                    <span className="text-xs text-[#B8B1AA] uppercase font-mono block">Avg Confidence</span>
                    <span className="text-2xl font-bold font-mono text-white mt-1 block">{stats.average_confidence}%</span>
                  </div>
                </div>
              </div>

              <div className="clay-inset p-4 text-xs font-mono space-y-2 text-[#B8B1AA]">
                <div className="flex justify-between">
                  <span>Database</span>
                  <span className="text-white">SQLite (scans.db)</span>
                </div>
                <div className="flex justify-between">
                  <span>Windows Weights</span>
                  <span className="text-[#FF2E2E]">Conv1D-LSTM (9,601)</span>
                </div>
                <div className="flex justify-between">
                  <span>Android Weights</span>
                  <span className="text-[#FF2E2E]">Conv1D-LSTM (9,601)</span>
                </div>
                <div className="flex justify-between">
                  <span>Status</span>
                  <span className="text-emerald-400">Ready</span>
                </div>
              </div>
            </div>
          </div>

          {/* Result Card (When Scan Completed) */}
          {scanResult && (
            <div className="clay-card p-8 border-[#FF2E2E]/40 space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6 pb-6 border-b border-[#8B1111]/30">
                <div className="flex items-center gap-4">
                  <div
                    className={`w-12 h-12 rounded-xl flex items-center justify-center border shadow-[3px_3px_8px_#040404] ${
                      scanResult.is_malware
                        ? 'bg-[#8B1111]/40 border-[#FF2E2E]/50 text-[#FF2E2E]'
                        : 'bg-emerald-950/40 border-emerald-800 text-emerald-400'
                    }`}
                  >
                    {scanResult.is_malware ? (
                      <ShieldExclamationIcon className="w-6 h-6" />
                    ) : (
                      <ShieldCheckIcon className="w-6 h-6" />
                    )}
                  </div>
                  <div>
                    <span className="text-xs uppercase font-mono text-[#B8B1AA] block">
                      Verdict &bull; {scanResult.platform || 'Cross-Platform'}
                    </span>
                    <h3
                      className={`text-2xl font-bold tracking-tight uppercase ${
                        scanResult.is_malware ? 'text-[#FF2E2E]' : 'text-emerald-400'
                      }`}
                    >
                      {scanResult.prediction === 'Malware' ? 'Malware Detected' : 'Clean File'}
                    </h3>
                  </div>
                </div>

                <div className="flex items-center gap-8 font-mono text-sm">
                  <div>
                    <span className="text-[#B8B1AA] block text-xs">Confidence</span>
                    <span className="text-2xl font-bold text-white">{scanResult.confidence}%</span>
                  </div>
                  <div>
                    <span className="text-[#B8B1AA] block text-xs">Raw Score</span>
                    <span className="text-2xl font-bold text-[#B8B1AA]">{scanResult.raw_score}</span>
                  </div>
                  <div>
                    <span className="text-[#B8B1AA] block text-xs">Scan Time</span>
                    <span className="text-2xl font-bold text-[#FF2E2E]">
                      {scanResult.execution_time_ms ? scanResult.execution_time_ms.toFixed(1) : 40} ms
                    </span>
                  </div>
                </div>
              </div>

              {/* Sample Details */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3.5 text-xs font-mono">
                <div className="clay-inset p-3.5">
                  <span className="text-[#B8B1AA] block mb-1">Target Filename</span>
                  <span className="text-white truncate block">{scanResult.filename}</span>
                </div>
                <div className="clay-inset p-3.5">
                  <span className="text-[#B8B1AA] block mb-1">Feature Count</span>
                  <span className="text-[#FF2E2E] block">
                    {scanResult.input_features_count ? `${scanResult.input_features_count} Tabular Features` : '32x32 Matrix'}
                  </span>
                </div>
                <div className="clay-inset p-3.5">
                  <span className="text-[#B8B1AA] block mb-1">Architecture</span>
                  <span className="text-white truncate block">
                    {scanResult.model_architecture || 'Conv1D + LSTM'}
                  </span>
                </div>
              </div>

              <div className="clay-inset p-3.5 text-xs font-mono">
                <span className="text-[#B8B1AA] block text-xs mb-1">SHA-256 Checksum</span>
                <span className="text-[#FF2E2E] break-all select-all">{scanResult.sha256}</span>
              </div>

              {/* Grad-CAM Heatmap if visual mode */}
              {scanResult.gradcam_base64 && (
                <div className="pt-4 border-t border-[#8B1111]/30 space-y-3">
                  <div className="flex justify-between items-center text-xs">
                    <span className="font-semibold text-white flex items-center gap-2">
                      <Square3Stack3DIcon className="w-4 h-4 text-[#FF2E2E]" />
                      Grad-CAM Visual Heatmap
                    </span>
                    <span className="text-xs font-mono text-[#B8B1AA]">32x32 Byte Matrix</span>
                  </div>
                  <div className="clay-inset p-4 flex justify-center">
                    <img
                      src={`data:image/png;base64,${scanResult.gradcam_base64}`}
                      alt="Grad-CAM Saliency Heatmap"
                      className="max-w-full h-auto rounded-xl"
                    />
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Scan History Table */}
          <div className="clay-card p-8 space-y-6">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 pb-4 border-b border-[#8B1111]/30">
              <div>
                <h3 className="text-sm font-semibold text-white">Scan History</h3>
                <p className="text-xs text-[#B8B1AA] mt-0.5">Records stored in SQLite (scans.db)</p>
              </div>

              <div className="flex items-center gap-3 w-full sm:w-auto">
                <div className="flex items-center gap-1.5 p-1 clay-inset">
                  <button
                    onClick={() => setHistoryFilter('all')}
                    className={`px-3 py-1 rounded-lg text-xs transition-colors ${
                      historyFilter === 'all'
                        ? 'bg-[#1e1515] text-white font-medium border border-[#8B1111]/50'
                        : 'text-[#B8B1AA] hover:text-white'
                    }`}
                  >
                    All ({history.length})
                  </button>
                  <button
                    onClick={() => setHistoryFilter('malware')}
                    className={`px-3 py-1 rounded-lg text-xs transition-colors ${
                      historyFilter === 'malware'
                        ? 'bg-[#8B1111]/50 text-[#FF2E2E] font-medium border border-[#FF2E2E]/40'
                        : 'text-[#B8B1AA] hover:text-white'
                    }`}
                  >
                    Threats ({stats.malware_detected})
                  </button>
                  <button
                    onClick={() => setHistoryFilter('benign')}
                    className={`px-3 py-1 rounded-lg text-xs transition-colors ${
                      historyFilter === 'benign'
                        ? 'bg-emerald-950/50 text-emerald-300 font-medium border border-emerald-800/40'
                        : 'text-[#B8B1AA] hover:text-white'
                    }`}
                  >
                    Clean ({stats.benign_detected})
                  </button>
                </div>

                <div className="relative flex-1 sm:w-56">
                  <MagnifyingGlassIcon className="w-4 h-4 absolute left-3 top-2.5 text-[#B8B1AA]" />
                  <input
                    type="text"
                    placeholder="Search history..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full pl-9 pr-3 py-1.5 clay-inset text-xs text-white placeholder-[#B8B1AA]/60 focus:outline-none focus:border-[#FF2E2E]/60"
                  />
                </div>

                <button
                  onClick={handleClearHistory}
                  disabled={history.length === 0}
                  className="clay-btn-secondary py-1.5 px-3 text-xs text-[#FF2E2E]"
                  title="Clear history"
                >
                  <TrashIcon className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* History Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="text-[#B8B1AA] border-b border-[#8B1111]/30">
                    <th className="py-3 px-4">ID</th>
                    <th className="py-3 px-4">Platform</th>
                    <th className="py-3 px-4">Filename</th>
                    <th className="py-3 px-4">Result</th>
                    <th className="py-3 px-4">Confidence</th>
                    <th className="py-3 px-4">Score</th>
                    <th className="py-3 px-4">Threshold</th>
                    <th className="py-3 px-4">Date / Time</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#8B1111]/20">
                  {filteredHistory.length > 0 ? (
                    filteredHistory.map((item) => (
                      <tr key={item.id} className="hover:bg-[#161212] transition-colors">
                        <td className="py-3 px-4 text-[#B8B1AA]">#{item.id}</td>
                        <td className="py-3 px-4 text-[#B8B1AA]">
                          <span className="clay-pill px-2 py-0.5 text-xs text-[#FF2E2E]">
                            {item.platform || 'Windows'}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-white truncate max-w-xs" title={item.filename}>
                          {item.filename}
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-xs font-semibold border ${
                              item.prediction === 'Malware'
                                ? 'bg-[#8B1111]/40 text-[#FF2E2E] border-[#FF2E2E]/40'
                                : 'bg-emerald-950/40 text-emerald-400 border-emerald-800/40'
                            }`}
                          >
                            {item.prediction}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-[#B8B1AA]">{item.confidence}%</td>
                        <td className="py-3 px-4 text-[#B8B1AA]">{item.raw_score}</td>
                        <td className="py-3 px-4 text-[#B8B1AA]">{item.threshold}</td>
                        <td className="py-3 px-4 text-[#B8B1AA]/80">{item.timestamp}</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={8} className="py-8 text-center text-[#B8B1AA]">
                        No records match the current filter.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </main>
      )}

      {/* ──────────────── AUTHENTICATION MODAL (REAL LOGIN / SIGN UP / FORGOT PASSWORD) ──────────────── */}
      {authModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80">
          <div className="clay-card w-full max-w-md p-8 space-y-6 relative rounded-2xl border-[#8B1111]/50 bg-[#141111] max-h-[90vh] overflow-y-auto">
            {/* Close Button */}
            <button
              onClick={() => setAuthModalOpen(false)}
              className="absolute top-6 right-6 text-[#B8B1AA] hover:text-white"
            >
              <XMarkIcon className="w-5 h-5" />
            </button>

            {/* Header Icon & Title */}
            <div className="flex items-center gap-3">
              <VektorLogo className="w-11 h-11" />
              <div>
                <h3 className="text-base font-semibold text-white">
                  {authMode === 'login' && 'Sign In to Vektor'}
                  {authMode === 'signup' && 'Create Vektor Account'}
                  {authMode === 'forgot' && 'Reset Vektor Password'}
                </h3>
                <p className="text-xs text-[#B8B1AA]">
                  {authMode === 'login' && 'Enter your verified account credentials'}
                  {authMode === 'signup' && 'Register a new malware analyst account'}
                  {authMode === 'forgot' && 'Update the password for your account'}
                </p>
              </div>
            </div>

            {/* Mode Switcher Tabs */}
            {authMode !== 'forgot' && (
              <div className="flex rounded-xl clay-inset p-1">
                <button
                  type="button"
                  onClick={() => openAuthWithMode('login')}
                  className={`flex-1 py-1.5 text-xs font-medium rounded-lg transition-all ${
                    authMode === 'login'
                      ? 'bg-[#1e1515] text-[#FF2E2E] border border-[#8B1111]/60 font-semibold'
                      : 'text-[#B8B1AA] hover:text-white'
                  }`}
                >
                  Sign In
                </button>
                <button
                  type="button"
                  onClick={() => openAuthWithMode('signup')}
                  className={`flex-1 py-1.5 text-xs font-medium rounded-lg transition-all ${
                    authMode === 'signup'
                      ? 'bg-[#1e1515] text-[#FF2E2E] border border-[#8B1111]/60 font-semibold'
                      : 'text-[#B8B1AA] hover:text-white'
                  }`}
                >
                  Create Account
                </button>
              </div>
            )}

            {/* Alerts */}
            {authError && (
              <div className="p-3 rounded-xl bg-[#8B1111]/25 border border-[#FF2E2E]/40 text-xs text-rose-300 flex items-start gap-2">
                <ExclamationTriangleIcon className="w-4 h-4 text-[#FF2E2E] shrink-0 mt-0.5" />
                <span>{authError}</span>
              </div>
            )}
            {authSuccess && (
              <div className="p-3 rounded-xl bg-emerald-950/40 border border-emerald-800/40 text-xs text-emerald-300 flex items-start gap-2">
                <CheckCircleIcon className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <span>{authSuccess}</span>
              </div>
            )}

            {/* Form */}
            <form
              onSubmit={
                authMode === 'login'
                  ? handleLogin
                  : authMode === 'signup'
                  ? handleRegister
                  : handleForgotPassword
              }
              className="space-y-4 pt-1"
            >
              {/* Email Address */}
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-[#B8B1AA]">Email Address</label>
                <input
                  type="email"
                  required
                  placeholder="analyst@security.local"
                  value={authEmail}
                  onChange={(e) => setAuthEmail(e.target.value)}
                  className="w-full px-3.5 py-2.5 clay-inset text-xs text-white placeholder-[#B8B1AA]/50 focus:outline-none focus:border-[#FF2E2E]/60"
                />
              </div>

              {/* Password */}
              <div className="space-y-1.5">
                <div className="flex justify-between items-center">
                  <label className="text-xs font-medium text-[#B8B1AA]">
                    {authMode === 'forgot' ? 'New Password' : 'Password'}
                  </label>
                  {authMode === 'login' && (
                    <button
                      type="button"
                      onClick={() => openAuthWithMode('forgot')}
                      className="text-xs text-[#FF2E2E] hover:underline"
                    >
                      Forgot password?
                    </button>
                  )}
                </div>
                <input
                  type="password"
                  required
                  placeholder="••••••••••••"
                  value={authPassword}
                  onChange={(e) => setAuthPassword(e.target.value)}
                  className="w-full px-3.5 py-2.5 clay-inset text-xs text-white placeholder-[#B8B1AA]/50 focus:outline-none focus:border-[#FF2E2E]/60"
                />
              </div>

              {/* Confirm Password (For Sign Up & Forgot Password) */}
              {(authMode === 'signup' || authMode === 'forgot') && (
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-[#B8B1AA]">Confirm Password</label>
                  <input
                    type="password"
                    required
                    placeholder="••••••••••••"
                    value={authConfirmPassword}
                    onChange={(e) => setAuthConfirmPassword(e.target.value)}
                    className="w-full px-3.5 py-2.5 clay-inset text-xs text-white placeholder-[#B8B1AA]/50 focus:outline-none focus:border-[#FF2E2E]/60"
                  />
                </div>
              )}

              {/* Password Criteria Checklist (For Sign Up & Forgot Password) */}
              {(authMode === 'signup' || authMode === 'forgot') && (
                <div className="clay-inset p-3.5 space-y-2 text-xs">
                  <span className="font-medium text-white block text-xs">Password Requirements:</span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 font-mono text-xs">
                    <div className={`flex items-center gap-1.5 ${pwdCriteria.minLength ? 'text-emerald-400' : 'text-[#B8B1AA]'}`}>
                      <span className="w-1.5 h-1.5 rounded-full bg-current" />
                      <span>Min 8 characters</span>
                    </div>
                    <div className={`flex items-center gap-1.5 ${pwdCriteria.hasLower ? 'text-emerald-400' : 'text-[#B8B1AA]'}`}>
                      <span className="w-1.5 h-1.5 rounded-full bg-current" />
                      <span>One lowercase (a-z)</span>
                    </div>
                    <div className={`flex items-center gap-1.5 ${pwdCriteria.hasUpper ? 'text-emerald-400' : 'text-[#B8B1AA]'}`}>
                      <span className="w-1.5 h-1.5 rounded-full bg-current" />
                      <span>One uppercase (A-Z)</span>
                    </div>
                    <div className={`flex items-center gap-1.5 ${pwdCriteria.hasNumber ? 'text-emerald-400' : 'text-[#B8B1AA]'}`}>
                      <span className="w-1.5 h-1.5 rounded-full bg-current" />
                      <span>One number (0-9)</span>
                    </div>
                    <div className={`flex items-center gap-1.5 ${pwdCriteria.hasSpecial ? 'text-emerald-400' : 'text-[#B8B1AA]'}`}>
                      <span className="w-1.5 h-1.5 rounded-full bg-current" />
                      <span>One symbol (!@#$%^&*)</span>
                    </div>
                    <div className={`flex items-center gap-1.5 ${passwordsMatch ? 'text-emerald-400' : 'text-[#B8B1AA]'}`}>
                      <span className="w-1.5 h-1.5 rounded-full bg-current" />
                      <span>Passwords match</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Submit Button */}
              <button
                type="submit"
                disabled={
                  authLoading ||
                  ((authMode === 'signup' || authMode === 'forgot') &&
                    (!isPasswordCompliant(authPassword) || !passwordsMatch))
                }
                className="clay-btn-primary w-full justify-center py-2.5 text-xs mt-3"
              >
                {authLoading ? (
                  <>
                    <ArrowPathIcon className="w-4 h-4 animate-spin" />
                    <span>Processing...</span>
                  </>
                ) : (
                  <span>
                    {authMode === 'login' && 'Sign In'}
                    {authMode === 'signup' && 'Create Account'}
                    {authMode === 'forgot' && 'Reset Password'}
                  </span>
                )}
              </button>

              {/* Bottom Mode Switch Links */}
              <div className="pt-2 text-center text-xs text-[#B8B1AA]">
                {authMode === 'login' ? (
                  <span>
                    Don't have an account?{' '}
                    <button
                      type="button"
                      onClick={() => openAuthWithMode('signup')}
                      className="text-[#FF2E2E] hover:underline font-medium"
                    >
                      Sign Up
                    </button>
                  </span>
                ) : (
                  <span>
                    Already have an account?{' '}
                    <button
                      type="button"
                      onClick={() => openAuthWithMode('login')}
                      className="text-[#FF2E2E] hover:underline font-medium"
                    >
                      Sign In
                    </button>
                  </span>
                )}
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Clean Footer */}
      <footer className="border-t border-[#8B1111]/30 bg-[#0c0909] py-8 px-6 text-center text-xs text-[#B8B1AA] font-mono mt-auto flex flex-col sm:flex-row items-center justify-center gap-3">
        <VektorLogo className="w-6 h-6" />
        <span>Vektor &bull; Cross-Platform Malware Detection System &bull; Windows (UCI staDyn) &amp; Android (KronoDroid)</span>
      </footer>
    </div>
  );
}
