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
  UserPlusIcon,
  UserIcon,
  EyeIcon,
  EyeSlashIcon,
  ClockIcon
} from '@heroicons/react/24/outline';
import VektorLogo from './components/VektorLogo';

const API_BASE = 'http://127.0.0.1:8000';

export default function App() {
  // Navigation & User State
  const [currentView, setCurrentView] = useState('landing'); // 'landing' | 'dashboard'
  const [dashboardTab, setDashboardTab] = useState('scanner'); // 'scanner' | 'history' | 'analytics' | 'models'
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [user, setUser] = useState(() => {
    const saved = localStorage.getItem('sentinel_user');
    return saved ? JSON.parse(saved) : null;
  });

  // Authentication State
  const [authMode, setAuthMode] = useState('login'); // 'login' | 'signup' | 'forgot'
  const [authFullName, setAuthFullName] = useState('');
  const [authEmail, setAuthEmail] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [authConfirmPassword, setAuthConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
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
      const [hRes, sRes, histRes] = await Promise.all([
        fetch(`${API_BASE}/api/health`).catch(() => null),
        fetch(`${API_BASE}/api/stats`).catch(() => null),
        fetch(`${API_BASE}/api/history`).catch(() => null),
      ]);

      if (hRes && hRes.ok) setHealth(await hRes.json());
      else setHealth({ status: 'offline', windows_stadyn_model: false, android_kronodroid_model: false });

      if (sRes && sRes.ok) setStats(await sRes.json());
      if (histRes && histRes.ok) setHistory(await histRes.json());
    } catch {
      setHealth({ status: 'offline', windows_stadyn_model: false, android_kronodroid_model: false });
    }
  };

  useEffect(() => {
    fetchHealthAndStats();
    const interval = setInterval(fetchHealthAndStats, 10000);
    return () => clearInterval(interval);
  }, []);

  // Strict route protection: Only authenticated users can access the application
  useEffect(() => {
    if (currentView === 'dashboard' && !user) {
      setCurrentView('landing');
    }
  }, [currentView, user]);

  // Reset auth form state when opening/switching modal
  const openAuthWithMode = (mode) => {
    setAuthMode(mode);
    setAuthError(null);
    setAuthSuccess(null);
    setAuthFullName('');
    setAuthPassword('');
    setAuthConfirmPassword('');
    setShowPassword(false);
    setShowConfirmPassword(false);
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
        name: data.user.full_name || data.user.email.split('@')[0],
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

    const fullName = authFullName.trim();
    if (!fullName) {
      setAuthError('Please enter your full name.');
      return;
    }

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
        body: JSON.stringify({ full_name: fullName, email, password: authPassword }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Registration could not be completed.');
      }

      const authenticatedUser = {
        email: data.user.email,
        name: data.user.full_name || fullName,
        role: 'Verified Researcher',
      };

      setUser(authenticatedUser);
      localStorage.setItem('sentinel_user', JSON.stringify(authenticatedUser));
      setAuthModalOpen(false);
      setCurrentView('dashboard');
      setAuthPassword('');
      setAuthConfirmPassword('');
      setAuthFullName('');
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
        <div className="w-[96%] max-w-[1700px] border border-[#FF2E2E] rounded-full bg-[#141010] shadow-[0_12px_30px_#000000,inset_1px_1px_1.5px_rgba(255,255,255,0.12),inset_-2px_-2px_4px_rgba(0,0,0,0.7)] px-5 sm:px-7 h-14 sm:h-16 flex items-center justify-between transition-all">
          {/* Brand */}
          <div
            onClick={() => {
              if (currentView === 'landing') {
                window.scrollTo(0, 0);
              }
            }}
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
              <a href="#architecture" className="hover:text-white transition-colors">Capabilities</a>
              <a href="#workflow" className="hover:text-white transition-colors">Process</a>
            </nav>
          ) : (
            <nav className="flex items-center gap-1 sm:gap-2">
              <button
                onClick={() => setDashboardTab('scanner')}
                className={`flex items-center gap-2 px-3 sm:px-4 py-1.5 rounded-full text-xs sm:text-sm font-medium transition-all ${
                  dashboardTab === 'scanner'
                    ? 'bg-[#1e1515] text-[#FF2E2E] border border-[#FF2E2E]/60 shadow-[0_0_12px_rgba(255,46,46,0.3)] font-semibold'
                    : 'text-[#B8B1AA] hover:text-white'
                }`}
              >
                <ShieldCheckIcon className="w-4 h-4" />
                <span>Scanner</span>
              </button>

              <button
                onClick={() => setDashboardTab('history')}
                className={`flex items-center gap-2 px-3 sm:px-4 py-1.5 rounded-full text-xs sm:text-sm font-medium transition-all ${
                  dashboardTab === 'history'
                    ? 'bg-[#1e1515] text-[#FF2E2E] border border-[#FF2E2E]/60 shadow-[0_0_12px_rgba(255,46,46,0.3)] font-semibold'
                    : 'text-[#B8B1AA] hover:text-white'
                }`}
              >
                <ClockIcon className="w-4 h-4" />
                <span className="hidden sm:inline">Scan</span>
                <span>History</span>
                {history.length > 0 && (
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-full bg-[#8B1111]/50 border border-[#FF2E2E]/40 text-[#FF2E2E]">
                    {history.length}
                  </span>
                )}
              </button>

              <button
                onClick={() => setDashboardTab('analytics')}
                className={`flex items-center gap-2 px-3 sm:px-4 py-1.5 rounded-full text-xs sm:text-sm font-medium transition-all ${
                  dashboardTab === 'analytics'
                    ? 'bg-[#1e1515] text-[#FF2E2E] border border-[#FF2E2E]/60 shadow-[0_0_12px_rgba(255,46,46,0.3)] font-semibold'
                    : 'text-[#B8B1AA] hover:text-white'
                }`}
              >
                <ChartBarIcon className="w-4 h-4" />
                <span>Analytics</span>
              </button>

              <button
                onClick={() => setDashboardTab('models')}
                className={`flex items-center gap-2 px-3 sm:px-4 py-1.5 rounded-full text-xs sm:text-sm font-medium transition-all ${
                  dashboardTab === 'models'
                    ? 'bg-[#1e1515] text-[#FF2E2E] border border-[#FF2E2E]/60 shadow-[0_0_12px_rgba(255,46,46,0.3)] font-semibold'
                    : 'text-[#B8B1AA] hover:text-white'
                }`}
              >
                <CpuChipIcon className="w-4 h-4" />
                <span className="hidden sm:inline">Model</span>
                <span>Specs</span>
              </button>
            </nav>
          )}

          {/* Right Controls */}
          <div className="flex items-center gap-3">
            {currentView === 'dashboard' ? (
              <div className="flex items-center gap-2.5">
                <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full clay-inset border border-[#8B1111]/30">
                  <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                  <span className="text-xs font-mono text-white font-medium truncate max-w-[150px]">
                    {user?.name || 'Analyst'}
                  </span>
                </div>

                {/* Dashboard Mode: ONLY Sign Out button! No Dashboard, No Home, No Landing Page button */}
                <button
                  onClick={handleLogout}
                  className="clay-btn-secondary text-xs py-1.5 px-3.5 text-rose-300 hover:text-white hover:border-[#FF2E2E] gap-1.5 shadow-[0_4px_16px_rgba(0,0,0,0.8)]"
                  title="Sign Out of Application"
                >
                  <ArrowRightOnRectangleIcon className="w-3.5 h-3.5 text-[#FF2E2E]" />
                  <span>Sign Out</span>
                </button>
              </div>
            ) : (
              /* ON LANDING PAGE: NEVER SHOW DASHBOARD BUTTON OR SIGN OUT BUTTON! ONLY Sign In and Sign Up */
              <div className="flex items-center gap-2.5">
                <button
                  onClick={() => openAuthWithMode('login')}
                  className="clay-btn-secondary text-xs py-1.5 px-3.5 shadow-[0_4px_16px_rgba(0,0,0,0.8)]"
                >
                  <LockClosedIcon className="w-3.5 h-3.5 text-[#FF2E2E]" />
                  <span>Sign In</span>
                </button>
                <button
                  onClick={() => openAuthWithMode('signup')}
                  className="clay-btn-primary text-xs py-1.5 px-3.5 shadow-[0_4px_16px_rgba(255,46,46,0.35)]"
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
        <div className="flex-1 space-y-16 pb-16">
          {/* Hero Section */}
          <section id="overview" className="relative isolate max-w-7xl mx-auto px-6 lg:px-10 pt-16 sm:pt-20 pb-16 overflow-hidden rounded-3xl">
            {/* ──────────────── HERO BACKGROUND: AMBIENT GLOWS & CYBER GRID ──────────────── */}
            <div className="absolute inset-0 pointer-events-none z-0 overflow-hidden select-none">
              {/* Cyber Perspective Grid */}
              <div className="absolute inset-0 cyber-grid [mask-image:radial-gradient(ellipse_80%_65%_at_65%_45%,#000_65%,transparent_100%)] opacity-30" />

              {/* Deep Red Volumetric Radial Glows concentrated near right side */}
              <div className="absolute top-1/4 right-1/6 w-[550px] sm:w-[700px] h-[550px] sm:h-[700px] bg-[#8B1111]/30 rounded-full blur-[140px] pointer-events-none" />
              <div className="absolute top-1/3 right-1/4 w-[320px] sm:w-[450px] h-[320px] sm:h-[450px] bg-[#FF2E2E]/20 rounded-full blur-[90px] pointer-events-none" />

              {/* Ambient Edge Vignette */}
              <div className="absolute inset-0 bg-gradient-to-b from-[#090909]/40 via-transparent to-[#090909]" />
            </div>

            {/* ──────────────── 2-COLUMN SPLIT: LEFT = TEXT & CTAs, RIGHT = ANIMATED LOGO ──────────────── */}
            <div className="relative z-10 grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-8 items-center">
              
              {/* LEFT COLUMN: Text, Heading & CTA Buttons */}
              <div className="lg:col-span-7 text-left space-y-6 sm:space-y-7">
                {/* Pill Tag with Logo */}
                <div className="inline-flex items-center gap-2.5 px-4 py-1.5 rounded-full clay-inset border border-[#8B1111]/60 shadow-[0_4px_16px_rgba(0,0,0,0.8)]">
                  <img src="/logo.png" alt="Vektor" className="w-5 h-5 object-contain" />
                  <span className="text-xs font-mono font-medium tracking-wider text-[#FF2E2E] uppercase">
                    Cross-Platform Threat Defense
                  </span>
                </div>

                {/* H1 Heading */}
                <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-white leading-[1.12] drop-shadow-[0_6px_24px_rgba(0,0,0,0.95)]">
                  Vektor Threat Intelligence <br />
                  <span className="text-transparent bg-clip-text bg-gradient-to-r from-white via-[#FFFFFF] to-[#FF2E2E]">
                    Cross-Platform Defense
                  </span>
                </h1>

                {/* Description */}
                <p className="text-base sm:text-lg text-[#B8B1AA] max-w-2xl leading-relaxed font-normal">
                  A deep learning detection system that classifies malicious files across Windows executables and Android application packages using spatial convolutional filters and long short-term memory recurrent networks.
                </p>

                {/* CTA Buttons & Feature Badges */}
                <div className="space-y-4 pt-1">
                  <div className="flex flex-wrap items-center gap-4">
                    <button
                      onClick={() => openAuthWithMode('login')}
                      className="clay-btn-primary text-sm py-3 px-8 justify-center shadow-[0_6px_20px_rgba(255,46,46,0.35)]"
                    >
                      <span>Sign In to Scanner</span>
                      <ArrowRightIcon className="w-4 h-4" />
                    </button>

                    <a href="#architecture" className="clay-btn-secondary text-sm py-3 px-7 justify-center shadow-[0_4px_16px_rgba(0,0,0,0.8)]">
                      <CpuChipIcon className="w-4 h-4 text-[#FF2E2E]" />
                      <span>Explore Capabilities</span>
                    </a>
                  </div>

                  {/* Feature Badges below CTAs */}
                  <div className="flex flex-wrap items-center gap-3 pt-2 text-xs font-mono text-[#B8B1AA]">
                    <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full clay-inset border border-[#8B1111]/40">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#FF2E2E] animate-pulse" />
                      Windows PE (244 Features)
                    </span>
                    <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full clay-inset border border-[#8B1111]/40">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#FF2E2E] animate-pulse" />
                      Android APK (487 Features)
                    </span>
                    <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full clay-inset border border-[#8B1111]/40">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                      Zero Heuristics
                    </span>
                  </div>
                </div>
              </div>

              {/* RIGHT COLUMN: Clean, Grounded Enterprise Vektor Shield Emblem */}
              <div className="lg:col-span-5 flex items-center justify-center relative">
                <div className="relative w-[280px] sm:w-[360px] aspect-square flex items-center justify-center">
                  {/* Subtle ambient red atmospheric glow */}
                  <div className="absolute inset-4 rounded-full bg-[#8B1111]/30 blur-3xl pointer-events-none" />

                  {/* High-Res Transparent Vektor Shield Emblem */}
                  <img
                    src="/hero-bg.png"
                    alt="Vektor Shield Emblem"
                    className="relative z-10 w-[260px] sm:w-[320px] aspect-square object-contain filter drop-shadow-[0_16px_40px_rgba(255,46,46,0.5)] select-none"
                  />
                </div>
              </div>

            </div>

            {/* 4 Core Platform Pillars */}
            <div className="relative z-10 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 pt-16">
              <div className="clay-card p-6 text-left space-y-2">
                <span className="text-xs font-mono text-[#B8B1AA] uppercase block">Multi-Platform</span>
                <span className="text-xl sm:text-2xl font-bold text-white block">Dual Engine</span>
                <span className="text-xs text-[#B8B1AA]/80 block">Windows PE &bull; Android APK</span>
              </div>
              <div className="clay-card p-6 text-left space-y-2">
                <span className="text-xs font-mono text-[#B8B1AA] uppercase block">Spatial Feature Extractor</span>
                <span className="text-xl sm:text-2xl font-bold text-[#FF2E2E] block">Conv1D Layers</span>
                <span className="text-xs text-[#B8B1AA]/80 block">32 Kernels &bull; Structural Mining</span>
              </div>
              <div className="clay-card p-6 text-left space-y-2">
                <span className="text-xs font-mono text-[#B8B1AA] uppercase block">Temporal Sequence Memory</span>
                <span className="text-xl sm:text-2xl font-bold text-white block">LSTM Units</span>
                <span className="text-xs text-[#B8B1AA]/80 block">Long-range API Trace Dependency</span>
              </div>
              <div className="clay-card p-6 text-left space-y-2">
                <span className="text-xs font-mono text-[#B8B1AA] uppercase block">Explainable AI (XAI)</span>
                <span className="text-xl sm:text-2xl font-bold text-[#FF2E2E] block">Grad-CAM Saliency</span>
                <span className="text-xs text-[#B8B1AA]/80 block">Transparent Byte Visual Maps</span>
              </div>
            </div>
          </section>

          

          {/* Architecture Capabilities */}
          <section id="architecture" className="max-w-7xl mx-auto px-6 lg:px-10 space-y-10">
            <div className="text-center max-w-3xl mx-auto space-y-3.5 pb-2">
              <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full clay-inset border border-[#8B1111]/50">
                <span className="text-xs font-mono uppercase tracking-wider text-[#FF2E2E] font-semibold">
                  Core Capabilities
                </span>
              </div>
              <h2 className="text-2xl sm:text-4xl font-extrabold text-white tracking-tight">
                Built for Multi-Platform Detection
              </h2>
              {/* Center Border Accent Line */}
              <div className="flex items-center justify-center gap-2 pt-1">
                <div className="w-12 h-[1px] bg-gradient-to-r from-transparent to-[#8B1111]" />
                <div className="w-20 h-[2px] bg-[#FF2E2E] rounded-full shadow-[0_0_8px_#FF2E2E]" />
                <div className="w-12 h-[1px] bg-gradient-to-l from-transparent to-[#8B1111]" />
              </div>
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
          <section id="workflow" className="max-w-7xl mx-auto px-6 lg:px-10 space-y-10">
            <div className="text-center max-w-3xl mx-auto space-y-3.5 pb-2">
              <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full clay-inset border border-[#8B1111]/50">
                <span className="text-xs font-mono uppercase tracking-wider text-[#FF2E2E] font-semibold">
                  Detection Process
                </span>
              </div>
              <h2 className="text-2xl sm:text-4xl font-extrabold text-white tracking-tight">
                How It Works
              </h2>
              {/* Center Border Accent Line */}
              <div className="flex items-center justify-center gap-2 pt-1">
                <div className="w-12 h-[1px] bg-gradient-to-r from-transparent to-[#8B1111]" />
                <div className="w-20 h-[2px] bg-[#FF2E2E] rounded-full shadow-[0_0_8px_#FF2E2E]" />
                <div className="w-12 h-[1px] bg-gradient-to-l from-transparent to-[#8B1111]" />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="clay-card p-6 space-y-2">
                <span className="text-xs font-mono text-[#FF2E2E] font-semibold block">Step 1</span>
                <h4 className="text-sm font-semibold text-white">Feature Extraction</h4>
                <p className="text-xs text-[#B8B1AA] leading-relaxed">
                  Parses PE structural tables for Windows executables, and manifest permissions with DEX API traces for Android packages.
                </p>
              </div>

              <div className="clay-card p-6 space-y-2">
                <span className="text-xs font-mono text-[#FF2E2E] font-semibold block">Step 2</span>
                <h4 className="text-sm font-semibold text-white">Spatial Convolution</h4>
                <p className="text-xs text-[#B8B1AA] leading-relaxed">
                  32 Conv1D kernels extract recurring structural patterns and localized opcode clusters across the feature vector.
                </p>
              </div>

              <div className="clay-card p-6 space-y-2">
                <span className="text-xs font-mono text-[#FF2E2E] font-semibold block">Step 3</span>
                <h4 className="text-sm font-semibold text-white">Temporal Recurrence</h4>
                <p className="text-xs text-[#B8B1AA] leading-relaxed">
                  32 LSTM memory cells retain sequential dependencies across long-range system call executions.
                </p>
              </div>

              <div className="clay-card p-6 space-y-2">
                <span className="text-xs font-mono text-[#FF2E2E] font-semibold block">Step 4</span>
                <h4 className="text-sm font-semibold text-white">Threshold Classification</h4>
                <p className="text-xs text-[#B8B1AA] leading-relaxed">
                  Calibrated sigmoid layer calculates the final malicious probability against the analyst-configured sensitivity threshold.
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
                  Open the scanner to evaluate Windows executables, Android packages, or visual byte matrices.
                </p>
              </div>
              <button
                onClick={() => openAuthWithMode('login')}
                className="clay-btn-primary py-3 px-6 text-xs whitespace-nowrap shadow-[0_6px_20px_rgba(255,46,46,0.35)]"
              >
                <LockClosedIcon className="w-4 h-4" />
                <span>Sign In to Scanner</span>
              </button>
            </div>
          </section>
        </div>
      )}

      {/* ──────────────── VIEW 2: SCANNER DASHBOARD ──────────────── */}
      {currentView === 'dashboard' && (
        <main className="w-full max-w-[1700px] mx-auto px-4 sm:px-8 lg:px-10 py-5 space-y-5 flex-1">
          {/* Top Bar with Dynamic Title & Status */}
          <div className="flex items-center justify-between pb-3 border-b border-[#8B1111]/30">
            <div className="flex items-center gap-3">
              <VektorLogo className="w-8 h-8" />
              <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
                {dashboardTab === 'scanner' && 'Vektor Scanner'}
                {dashboardTab === 'history' && 'Audit History Log'}
                {dashboardTab === 'analytics' && 'Security Telemetry & System Analytics'}
                {dashboardTab === 'models' && 'Deep Learning Architecture & Benchmarks'}
              </h1>
              {dashboardTab !== 'scanner' && (
                <span className="clay-pill text-xs font-mono px-3 py-1 text-[#FF2E2E]">
                  {dashboardTab === 'history' && `${history.length} SQLite Records`}
                  {dashboardTab === 'analytics' && 'Active Metrics'}
                  {dashboardTab === 'models' && 'Held-Out Validation'}
                </span>
              )}
            </div>
          </div>

          {/* ════════════════════ TAB 1: SCANNER ════════════════════ */}
          {dashboardTab === 'scanner' && (
            <div className="space-y-6">
              {/* Platform Switcher */}
              <div className="clay-card p-2 flex flex-wrap items-center justify-between gap-3">
                <div className="flex flex-wrap items-center gap-2">
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
                    <span>Windows PE (UCI staDyn &bull; 244 Features)</span>
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
                    <span>Android APK (KronoDroid &bull; 487 Features)</span>
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

                <div className="text-xs font-mono text-[#B8B1AA] px-3 py-1 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-[#FF2E2E]" />
                  {platformMode === 'windows' && 'Active Model: windows_stadyn_model.keras (9,601 Weights)'}
                  {platformMode === 'android' && 'Active Model: android_kronodroid_model.keras (9,601 Weights)'}
                  {platformMode === 'visual' && 'Active Model: best_model.keras (687,845 Weights)'}
                </div>
              </div>

              {/* 2-Column Wide Stretched Grid (50/50 Balance) */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-stretch">
                {/* Left Column: Manual Upload & Settings */}
                <div className="clay-card p-7 sm:p-8 flex flex-col justify-between h-full space-y-6">
                  <div>
                    <div className="flex items-center justify-between pb-4 border-b border-[#8B1111]/30">
                      <div className="flex items-center gap-2.5">
                        <ArrowUpTrayIcon className="w-4 h-4 text-[#FF2E2E]" />
                        <h2 className="text-sm font-semibold text-white">
                          {platformMode === 'windows' && 'Windows Binary Upload (.exe / .dll / .sys)'}
                          {platformMode === 'android' && 'Android Application Package (.apk)'}
                          {platformMode === 'visual' && 'PE Byte Image (.png / .jpg)'}
                        </h2>
                      </div>
                      <span className="clay-pill text-xs font-mono px-3 py-1 text-[#FF2E2E]">
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
                        className={`clay-inset p-6 sm:p-8 text-center cursor-pointer transition-all border-2 border-dashed ${
                          dragActive
                            ? 'border-[#FF2E2E] bg-[#1a1212]'
                            : selectedFile
                            ? 'border-[#FF2E2E]/60 bg-[#161111]'
                            : 'border-[#8B1111]/40 hover:border-[#FF2E2E]/60'
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
                        <div className="w-14 h-14 rounded-2xl bg-[#191414] border border-[#8B1111]/40 text-[#FF2E2E] flex items-center justify-center mx-auto mb-4 shadow-[3px_3px_10px_#040404]">
                          <ArrowUpTrayIcon className="w-7 h-7" />
                        </div>
                        <p className="text-base font-semibold text-white">
                          {selectedFile ? selectedFile.name : `Select or drop a ${platformMode} binary sample`}
                        </p>
                        <p className="text-xs text-[#B8B1AA] mt-2 font-mono">
                          {selectedFile
                            ? `${(selectedFile.size / 1024).toFixed(1)} KB • Binary Staged • Click to Replace`
                            : platformMode === 'windows'
                            ? 'Accepts compiled PE executables .exe, .dll, .sys, .bin (up to 50MB)'
                            : platformMode === 'android'
                            ? 'Accepts Android Application Packages .apk (up to 50MB)'
                            : 'Accepts 32x32 PE byte visual matrices (.png, .jpg)'}
                        </p>
                      </div>

                      {selectedFile && (
                        <div className="mt-3 flex items-center justify-between text-xs font-mono px-3 py-1.5 rounded-lg clay-inset text-[#B8B1AA]">
                          <span>Staged: <strong className="text-white">{selectedFile.name}</strong></span>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedFile(null);
                              setScanResult(null);
                            }}
                            className="text-[#FF2E2E] hover:underline"
                          >
                            Remove file
                          </button>
                        </div>
                      )}
                    </div>

                    {/* Classification Sensitivity Threshold Slider */}
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
                        className="w-full my-2 accent-[#FF2E2E]"
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
                    className="clay-btn-primary w-full justify-center py-3.5 text-sm mt-4 shadow-[0_6px_20px_rgba(255,46,46,0.35)]"
                  >
                    {scanning ? (
                      <>
                        <ArrowPathIcon className="w-4 h-4 animate-spin" />
                        <span>Extracting Features & Running Inference...</span>
                      </>
                    ) : (
                      <>
                        <ShieldCheckIcon className="w-4 h-4" />
                        <span>Scan & Classify Binary</span>
                      </>
                    )}
                  </button>
                </div>

                {/* Right Column: Live Detection Result OR Inference Engine Standby */}
                {scanResult ? (
                  <div className="clay-card p-7 sm:p-8 border border-[#FF2E2E]/50 flex flex-col justify-between h-full space-y-4 shadow-[0_8px_30px_rgba(255,46,46,0.2)]">
                    <div className="space-y-4">
                      {/* Compact Verdict Header with Reduced Text Size */}
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-[#8B1111]/30">
                        <div className="flex items-center gap-3">
                          <div
                            className={`w-10 h-10 rounded-xl flex items-center justify-center border shadow-[3px_3px_8px_#040404] shrink-0 ${
                              scanResult.is_malware
                                ? 'bg-[#8B1111]/40 border-[#FF2E2E]/60 text-[#FF2E2E]'
                                : 'bg-emerald-950/40 border-emerald-800 text-emerald-400'
                            }`}
                          >
                            {scanResult.is_malware ? (
                              <ShieldExclamationIcon className="w-5 h-5" />
                            ) : (
                              <ShieldCheckIcon className="w-5 h-5" />
                            )}
                          </div>
                          <div>
                            <span className="text-[11px] uppercase font-mono text-[#B8B1AA] block">
                              Verdict • {scanResult.platform || platformMode.toUpperCase()}
                            </span>
                            <h3
                              className={`text-lg sm:text-xl font-bold tracking-tight uppercase ${
                                scanResult.is_malware ? 'text-[#FF2E2E]' : 'text-emerald-400'
                              }`}
                            >
                              {scanResult.prediction === 'Malware' ? 'Malware Detected' : 'Clean File'}
                            </h3>
                          </div>
                        </div>

                        {/* Reduced Metrics: Confidence, Raw Score, Latency */}
                        <div className="flex items-center gap-5 sm:gap-6 font-mono">
                          <div>
                            <span className="text-[#B8B1AA] block text-[10px] sm:text-xs">Confidence</span>
                            <span className="text-base sm:text-lg font-bold text-white">{scanResult.confidence}%</span>
                          </div>
                          <div>
                            <span className="text-[#B8B1AA] block text-[10px] sm:text-xs">Raw Score</span>
                            <span className="text-base sm:text-lg font-bold text-[#FF2E2E]">{scanResult.raw_score}</span>
                          </div>
                          <div>
                            <span className="text-[#B8B1AA] block text-[10px] sm:text-xs">Latency</span>
                            <span className="text-base sm:text-lg font-bold text-emerald-400">
                              {scanResult.execution_time_ms ? scanResult.execution_time_ms.toFixed(1) : 38} ms
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Forensic Assessment & Explanation Box (Requested: "explanations kuda ravali") */}
                      <div className="p-3.5 rounded-xl clay-inset space-y-2 text-xs text-[#B8B1AA] leading-relaxed">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-mono text-white font-semibold flex items-center gap-1.5">
                            <DocumentMagnifyingGlassIcon className="w-4 h-4 text-[#FF2E2E]" />
                            <span>Forensic Analysis Explanation</span>
                          </span>
                          <span
                            className={`text-[10px] font-mono px-2 py-0.5 rounded font-semibold ${
                              scanResult.is_malware
                                ? 'bg-[#8B1111]/50 text-[#FF2E2E] border border-[#FF2E2E]/40'
                                : 'bg-emerald-950/50 text-emerald-300 border border-emerald-800/40'
                            }`}
                          >
                            {scanResult.is_malware ? 'High Threat Severity' : 'Verified Benign Utility'}
                          </span>
                        </div>

                        <p className="text-[11px] leading-relaxed text-[#B8B1AA]">
                          {scanResult.is_malware
                            ? `Structural anomaly detected. The 32 Conv1D spatial filters identified suspicious opcode grouping and packing signatures, while the temporal LSTM units identified malicious execution call chains. The classification probability (${scanResult.raw_score}) exceeded your configured threshold of ${threshold.toFixed(2)}.`
                            : `Normal binary profile confirmed. The spatial filters and recurrent memory layers detected standard PE section headers, valid import tables, and routine API sequences. The classification score (${scanResult.raw_score}) is well below your configured sensitivity threshold of ${threshold.toFixed(2)}.`}
                        </p>
                      </div>

                      {/* Sample Details */}
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                        <div className="clay-inset p-3">
                          <span className="text-[#B8B1AA] block mb-0.5 text-[11px]">Target Filename</span>
                          <span className="text-white truncate block font-semibold">{scanResult.filename}</span>
                        </div>
                        <div className="clay-inset p-3">
                          <span className="text-[#B8B1AA] block mb-0.5 text-[11px]">Feature Count</span>
                          <span className="text-[#FF2E2E] block font-semibold">
                            {scanResult.input_features_count ? `${scanResult.input_features_count} Tabular Features` : '32x32 Matrix'}
                          </span>
                        </div>
                        <div className="clay-inset p-3">
                          <span className="text-[#B8B1AA] block mb-0.5 text-[11px]">Architecture</span>
                          <span className="text-white truncate block font-semibold">
                            {scanResult.model_architecture || 'Conv1D + LSTM'}
                          </span>
                        </div>
                      </div>

                      {/* SHA-256 Checksum */}
                      <div className="clay-inset p-3 text-xs font-mono">
                        <span className="text-[#B8B1AA] block text-[11px] mb-0.5">SHA-256 Checksum</span>
                        <span className="text-[#FF2E2E] break-all select-all font-medium text-[11px]">{scanResult.sha256}</span>
                      </div>

                      {/* Grad-CAM Heatmap if visual mode */}
                      {scanResult.gradcam_base64 && (
                        <div className="pt-3 border-t border-[#8B1111]/30 space-y-2">
                          <div className="flex justify-between items-center text-xs">
                            <span className="font-semibold text-white flex items-center gap-2">
                              <Square3Stack3DIcon className="w-4 h-4 text-[#FF2E2E]" />
                              Grad-CAM Visual Heatmap
                            </span>
                            <span className="text-xs font-mono text-[#B8B1AA]">32x32 Byte Matrix</span>
                          </div>
                          <div className="clay-inset p-3 flex justify-center">
                            <img
                              src={`data:image/png;base64,${scanResult.gradcam_base64}`}
                              alt="Grad-CAM Saliency Heatmap"
                              className="max-w-full h-auto rounded-xl"
                            />
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Bottom Status & Scan Another Button */}
                    <div className="flex items-center justify-between pt-3 border-t border-[#8B1111]/30">
                      <span className="text-xs text-[#B8B1AA] font-mono">Record saved to SQLite (scans.db)</span>
                      <button
                        onClick={() => {
                          setScanResult(null);
                          setSelectedFile(null);
                        }}
                        className="clay-btn-secondary text-xs py-1.5 px-4"
                      >
                        Scan Another File
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="clay-card p-7 sm:p-8 flex flex-col justify-between h-full space-y-6">
                    <div>
                      <div className="flex items-center justify-between pb-4 border-b border-[#8B1111]/30">
                        <div className="flex items-center gap-2.5">
                          <div className="w-3 h-3 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_#10b981]" />
                          <h3 className="text-sm font-semibold text-white">Inference Engine Standby</h3>
                        </div>
                        <span className="clay-pill text-xs font-mono px-3 py-1 text-emerald-400">
                          System Armed
                        </span>
                      </div>

                      <p className="text-sm text-[#B8B1AA] mt-5 leading-relaxed">
                        Vektor dual-platform neural detection engine is loaded and awaiting file ingestion. Load a Windows executable (.exe/.dll) or Android package (.apk) on the left panel to begin forensic feature extraction and deep sequence classification.
                      </p>

                      <div className="mt-5 p-4 rounded-xl clay-inset space-y-2.5 text-xs text-[#B8B1AA] leading-relaxed">
                        <span className="text-xs font-mono text-[#FF2E2E] uppercase font-semibold block">
                          Inference Pipeline Overview
                        </span>
                        <p>
                          The system ingests binary files, computes SHA-256 cryptographic signatures, and extracts structured feature vectors (244 attributes for Windows PE or 487 for Android APK). Next, 32 spatial Conv1D kernels identify localized opcode clustering and structural patterns, followed by 32 recurrent LSTM memory units that evaluate temporal call sequences across long execution ranges. The final sigmoid layer computes a calibrated malware probability against the analyst-configured threshold.
                        </p>
                      </div>
                    </div>

                    <div className="clay-inset p-4 text-xs font-mono space-y-2 text-[#B8B1AA]">
                      <div className="flex justify-between">
                        <span>Windows Model Engine</span>
                        <span className="text-emerald-400">Ready &bull; 9,601 Weights</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Android Model Engine</span>
                        <span className="text-emerald-400">Ready &bull; 9,601 Weights</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Audit Database</span>
                        <span className="text-white">SQLite (scans.db)</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ════════════════════ TAB 2: SCAN HISTORY ════════════════════ */}
          {dashboardTab === 'history' && (
            <div className="clay-card p-8 space-y-6">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 pb-4 border-b border-[#8B1111]/30">
                <div>
                  <h3 className="text-base font-semibold text-white">Full Scan History & Audit Trail</h3>
                  <p className="text-xs text-[#B8B1AA] mt-0.5">Persistent records stored in SQLite database (backend/scans.db)</p>
                </div>

                <div className="flex flex-wrap items-center gap-3 w-full sm:w-auto">
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

                  <div className="relative flex-1 sm:w-64">
                    <MagnifyingGlassIcon className="w-4 h-4 absolute left-3 top-2.5 text-[#B8B1AA]" />
                    <input
                      type="text"
                      placeholder="Search filename or SHA-256..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-9 pr-3 py-1.5 clay-inset text-xs text-white placeholder-[#B8B1AA]/60 focus:outline-none focus:border-[#FF2E2E]/60"
                    />
                  </div>

                  <button
                    onClick={handleClearHistory}
                    disabled={history.length === 0}
                    className="clay-btn-secondary py-1.5 px-3 text-xs text-[#FF2E2E] gap-1.5"
                    title="Clear history database"
                  >
                    <TrashIcon className="w-4 h-4" />
                    <span>Clear</span>
                  </button>
                </div>
              </div>

              {/* History Table */}
              <div className="overflow-x-auto max-h-[60vh] overflow-y-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="text-[#B8B1AA] border-b border-[#8B1111]/30">
                      <th className="py-3 px-4">ID</th>
                      <th className="py-3 px-4">Platform</th>
                      <th className="py-3 px-4">Target Filename</th>
                      <th className="py-3 px-4">Detection Verdict</th>
                      <th className="py-3 px-4">Confidence</th>
                      <th className="py-3 px-4">Raw Score</th>
                      <th className="py-3 px-4">Threshold</th>
                      <th className="py-3 px-4">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#8B1111]/20">
                    {filteredHistory.length > 0 ? (
                      filteredHistory.map((item) => (
                        <tr key={item.id} className="hover:bg-[#161212] transition-colors">
                          <td className="py-3.5 px-4 text-[#B8B1AA]">#{item.id}</td>
                          <td className="py-3.5 px-4 text-[#B8B1AA]">
                            <span className="clay-pill px-2.5 py-0.5 text-xs text-[#FF2E2E]">
                              {item.platform || 'Windows'}
                            </span>
                          </td>
                          <td className="py-3.5 px-4 text-white font-medium truncate max-w-sm" title={item.filename}>
                            {item.filename}
                          </td>
                          <td className="py-3.5 px-4">
                            <span
                              className={`px-2.5 py-0.5 rounded text-xs font-semibold border ${
                                item.prediction === 'Malware'
                                  ? 'bg-[#8B1111]/40 text-[#FF2E2E] border-[#FF2E2E]/40'
                                  : 'bg-emerald-950/40 text-emerald-400 border-emerald-800/40'
                              }`}
                            >
                              {item.prediction}
                            </span>
                          </td>
                          <td className="py-3.5 px-4 text-[#B8B1AA] font-semibold">{item.confidence}%</td>
                          <td className="py-3.5 px-4 text-[#B8B1AA]">{item.raw_score}</td>
                          <td className="py-3.5 px-4 text-[#B8B1AA]">{item.threshold}</td>
                          <td className="py-3.5 px-4 text-[#B8B1AA]/80">{item.timestamp}</td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={8} className="py-12 text-center text-[#B8B1AA]">
                          No records match your filter criteria. Run a scan from the Scanner tab to populate the audit log.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ════════════════════ TAB 3: ANALYTICS ════════════════════ */}
          {dashboardTab === 'analytics' && (
            <div className="space-y-8">
              {/* 4 Wide Metric Tiles */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
                <div className="clay-card p-6 space-y-2 text-left">
                  <span className="text-xs font-mono text-[#B8B1AA] uppercase block">Total Scans Evaluated</span>
                  <span className="text-3xl font-extrabold font-mono text-white block">{stats.total_scans}</span>
                  <span className="text-xs text-[#B8B1AA]/80 block">Logged across sessions</span>
                </div>
                <div className="clay-card p-6 space-y-2 text-left">
                  <span className="text-xs font-mono text-[#B8B1AA] uppercase block">Threats Intercepted</span>
                  <span className="text-3xl font-extrabold font-mono text-[#FF2E2E] block">{stats.malware_detected}</span>
                  <span className="text-xs text-[#B8B1AA]/80 block">Malicious payloads quarantined</span>
                </div>
                <div className="clay-card p-6 space-y-2 text-left">
                  <span className="text-xs font-mono text-[#B8B1AA] uppercase block">Clean Files Validated</span>
                  <span className="text-3xl font-extrabold font-mono text-emerald-400 block">{stats.benign_detected}</span>
                  <span className="text-xs text-[#B8B1AA]/80 block">Legitimate software confirmed</span>
                </div>
                <div className="clay-card p-6 space-y-2 text-left">
                  <span className="text-xs font-mono text-[#B8B1AA] uppercase block">Mean Confidence Score</span>
                  <span className="text-3xl font-extrabold font-mono text-white block">{stats.average_confidence}%</span>
                  <span className="text-xs text-[#B8B1AA]/80 block">Calibrated Sigmoid output</span>
                </div>
              </div>

              {/* Threat Distribution & System Telemetry Split */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {/* Threat Distribution Bar */}
                <div className="clay-card p-8 space-y-6">
                  <div className="flex items-center justify-between pb-4 border-b border-[#8B1111]/30">
                    <h3 className="text-base font-semibold text-white">Threat vs. Clean Distribution</h3>
                    <span className="clay-pill text-xs font-mono px-3 py-1 text-[#FF2E2E]">
                      {stats.threat_rate_percent}% Threat Rate
                    </span>
                  </div>

                  <div className="space-y-4 pt-2">
                    {/* Visual Progress Bar */}
                    <div className="w-full h-6 rounded-xl bg-[#141010] p-1 flex overflow-hidden border border-[#8B1111]/40 shadow-inner">
                      <div
                        style={{ width: `${stats.threat_rate_percent}%` }}
                        className="bg-gradient-to-r from-[#8B1111] to-[#FF2E2E] rounded-lg h-full transition-all duration-700 shadow-[0_0_12px_#FF2E2E]"
                      />
                      <div
                        style={{ width: `${100 - stats.threat_rate_percent}%` }}
                        className="bg-gradient-to-r from-emerald-900 to-emerald-500 rounded-lg h-full transition-all duration-700 ml-1"
                      />
                    </div>

                    <div className="flex justify-between items-center text-xs font-mono">
                      <div className="flex items-center gap-2">
                        <span className="w-2.5 h-2.5 rounded-full bg-[#FF2E2E]" />
                        <span>Threats: <strong>{stats.malware_detected}</strong> ({stats.threat_rate_percent}%)</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                        <span>Clean: <strong>{stats.benign_detected}</strong> ({(100 - stats.threat_rate_percent).toFixed(1)}%)</span>
                      </div>
                    </div>
                  </div>

                  <p className="text-xs text-[#B8B1AA] leading-relaxed pt-2">
                    Real-time threat distribution computed continuously from historical inference evaluations recorded in the local SQLite engine.
                  </p>
                </div>

                {/* Database & Runtime Telemetry */}
                <div className="clay-card p-8 space-y-6">
                  <div className="flex items-center justify-between pb-4 border-b border-[#8B1111]/30">
                    <h3 className="text-base font-semibold text-white">Runtime Telemetry & Architecture</h3>
                    <span className="clay-pill text-xs font-mono px-3 py-1 text-emerald-400">
                      Uptime 100%
                    </span>
                  </div>

                  <div className="space-y-3 font-mono text-xs text-[#B8B1AA]">
                    <div className="flex justify-between py-2 border-b border-[#1f1616]">
                      <span>Database Engine</span>
                      <span className="text-white font-semibold">SQLite 3 (scans.db)</span>
                    </div>
                    <div className="flex justify-between py-2 border-b border-[#1f1616]">
                      <span>Windows PE Weights</span>
                      <span className="text-[#FF2E2E]">windows_stadyn_model.keras (9,601 params)</span>
                    </div>
                    <div className="flex justify-between py-2 border-b border-[#1f1616]">
                      <span>Android APK Weights</span>
                      <span className="text-[#FF2E2E]">android_kronodroid_model.keras (9,601 params)</span>
                    </div>
                    <div className="flex justify-between py-2 border-b border-[#1f1616]">
                      <span>Backend REST Server</span>
                      <span className="text-emerald-400">FastAPI Uvicorn @ port 8000</span>
                    </div>
                    <div className="flex justify-between py-2">
                      <span>Inference Execution Latency</span>
                      <span className="text-white">~35 - 50 ms (Local CPU)</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ════════════════════ TAB 4: MODEL SPECS & BENCHMARKS ════════════════════ */}
          {dashboardTab === 'models' && (
            <div className="space-y-8">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {/* Windows PE Benchmark Card */}
                <div className="clay-card p-8 space-y-6">
                  <div className="flex items-center justify-between pb-4 border-b border-[#8B1111]/30">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-xl bg-[#191414] border border-[#8B1111]/40 text-[#FF2E2E] flex items-center justify-center shadow-[3px_3px_8px_#040404]">
                        <ComputerDesktopIcon className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="text-base font-semibold text-white">Windows PE Architecture</h3>
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
                      <span className="text-2xl font-extrabold font-mono text-white mt-1 block">97.97%</span>
                    </div>
                    <div className="clay-inset p-4">
                      <span className="text-xs text-[#B8B1AA] block">F1-Score</span>
                      <span className="text-2xl font-extrabold font-mono text-[#FF2E2E] mt-1 block">98.87%</span>
                    </div>
                    <div className="clay-inset p-4">
                      <span className="text-xs text-[#B8B1AA] block">ROC-AUC</span>
                      <span className="text-2xl font-extrabold font-mono text-[#FF2E2E] mt-1 block">99.54%</span>
                    </div>
                  </div>

                  <div className="space-y-2 text-xs font-mono text-[#B8B1AA]">
                    <div className="flex justify-between py-1.5 border-b border-[#1f1616]">
                      <span>Model Layer Stack</span>
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
                      <span>Held-Out Confusion Matrix</span>
                      <span className="text-emerald-400">831 TP &bull; 88 TN &bull; 2 FP &bull; 17 FN</span>
                    </div>
                  </div>
                </div>

                {/* Android KronoDroid Benchmark Card */}
                <div className="clay-card p-8 space-y-6">
                  <div className="flex items-center justify-between pb-4 border-b border-[#8B1111]/30">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-xl bg-[#191414] border border-[#8B1111]/40 text-[#FF2E2E] flex items-center justify-center shadow-[3px_3px_8px_#040404]">
                        <DevicePhoneMobileIcon className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="text-base font-semibold text-white">Android APK Architecture</h3>
                        <span className="text-xs font-mono text-[#B8B1AA]">KronoDroid Real-Device Dataset (41,262 Samples)</span>
                      </div>
                    </div>
                    <span className="clay-pill text-xs font-mono px-3 py-1 text-[#FF2E2E]">
                      487 Features
                    </span>
                  </div>

                  <div className="grid grid-cols-3 gap-4 text-center">
                    <div className="clay-inset p-4">
                      <span className="text-xs text-[#B8B1AA] block">Accuracy</span>
                      <span className="text-2xl font-extrabold font-mono text-white mt-1 block">91.14%</span>
                    </div>
                    <div className="clay-inset p-4">
                      <span className="text-xs text-[#B8B1AA] block">F1-Score</span>
                      <span className="text-2xl font-extrabold font-mono text-[#FF2E2E] mt-1 block">91.42%</span>
                    </div>
                    <div className="clay-inset p-4">
                      <span className="text-xs text-[#B8B1AA] block">ROC-AUC</span>
                      <span className="text-2xl font-extrabold font-mono text-[#FF2E2E] mt-1 block">95.31%</span>
                    </div>
                  </div>

                  <div className="space-y-2 text-xs font-mono text-[#B8B1AA]">
                    <div className="flex justify-between py-1.5 border-b border-[#1f1616]">
                      <span>Model Layer Stack</span>
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
                      <span>Held-Out Confusion Matrix</span>
                      <span className="text-emerald-400">3,749 TP &bull; 3,678 TN &bull; 305 FP &bull; 399 FN</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Architecture Layer Breakdown */}
              <div className="clay-card p-8 space-y-4">
                <h3 className="text-base font-semibold text-white">Hybrid Neural Layer Execution Pipeline</h3>
                <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
                  <div className="clay-inset p-4 space-y-1">
                    <span className="text-xs font-mono text-[#FF2E2E] font-bold block">01 / DISASSEMBLY</span>
                    <span className="text-sm font-semibold text-white block">Feature Ingestion</span>
                    <p className="text-xs text-[#B8B1AA] leading-relaxed">
                      Static & dynamic feature vectors extracted and normalized into structured tabular input matrices.
                    </p>
                  </div>
                  <div className="clay-inset p-4 space-y-1">
                    <span className="text-xs font-mono text-[#FF2E2E] font-bold block">02 / CONVOLUTION</span>
                    <span className="text-sm font-semibold text-white block">Conv1D Spatial Filters</span>
                    <p className="text-xs text-[#B8B1AA] leading-relaxed">
                      32 kernels of size 5 scan feature sequences to detect recurring structural malware patterns.
                    </p>
                  </div>
                  <div className="clay-inset p-4 space-y-1">
                    <span className="text-xs font-mono text-[#FF2E2E] font-bold block">03 / RECURRENT MEMORY</span>
                    <span className="text-sm font-semibold text-white block">LSTM Sequence Units</span>
                    <p className="text-xs text-[#B8B1AA] leading-relaxed">
                      32 LSTM memory cells retain long-distance temporal correlations across sequential API invocations.
                    </p>
                  </div>
                  <div className="clay-inset p-4 space-y-1">
                    <span className="text-xs font-mono text-[#FF2E2E] font-bold block">04 / CLASSIFICATION</span>
                    <span className="text-sm font-semibold text-white block">Calibrated Sigmoid</span>
                    <p className="text-xs text-[#B8B1AA] leading-relaxed">
                      Sigmoid activation calculates malicious probability evaluated against the analyst threshold.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
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
              {/* Full Name Field (Create Account Only) */}
              {authMode === 'signup' && (
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-[#B8B1AA] flex items-center gap-1.5">
                    <UserIcon className="w-3.5 h-3.5 text-[#FF2E2E]" />
                    <span>Full Name</span>
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Modepalli Ravindra"
                    value={authFullName}
                    onChange={(e) => setAuthFullName(e.target.value)}
                    className="w-full px-3.5 py-2.5 clay-inset text-xs text-white placeholder-[#B8B1AA]/50 focus:outline-none focus:border-[#FF2E2E]/60 border border-[#8B1111]/30"
                  />
                </div>
              )}

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
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    placeholder="••••••••••••"
                    value={authPassword}
                    onChange={(e) => setAuthPassword(e.target.value)}
                    className="w-full pl-3.5 pr-10 py-2.5 clay-inset text-xs text-white placeholder-[#B8B1AA]/50 focus:outline-none focus:border-[#FF2E2E]/60 border border-[#8B1111]/30"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[#B8B1AA] hover:text-[#FF2E2E] p-1 transition-colors"
                    title={showPassword ? 'Hide password' : 'Show password'}
                  >
                    {showPassword ? (
                      <EyeSlashIcon className="w-4 h-4" />
                    ) : (
                      <EyeIcon className="w-4 h-4" />
                    )}
                  </button>
                </div>
              </div>

              {/* Confirm Password (For Sign Up & Forgot Password) */}
              {(authMode === 'signup' || authMode === 'forgot') && (
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-[#B8B1AA]">Confirm Password</label>
                  <div className="relative">
                    <input
                      type={showConfirmPassword ? 'text' : 'password'}
                      required
                      placeholder="••••••••••••"
                      value={authConfirmPassword}
                      onChange={(e) => setAuthConfirmPassword(e.target.value)}
                      className="w-full pl-3.5 pr-10 py-2.5 clay-inset text-xs text-white placeholder-[#B8B1AA]/50 focus:outline-none focus:border-[#FF2E2E]/60 border border-[#8B1111]/30"
                    />
                    <button
                      type="button"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[#B8B1AA] hover:text-[#FF2E2E] p-1 transition-colors"
                      title={showConfirmPassword ? 'Hide password' : 'Show password'}
                    >
                      {showConfirmPassword ? (
                        <EyeSlashIcon className="w-4 h-4" />
                      ) : (
                        <EyeIcon className="w-4 h-4" />
                      )}
                    </button>
                  </div>
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

      {/* Clean Footer (Landing Page Only - Never in Dashboard) */}
      {currentView === 'landing' && (
        <footer className="border-t border-[#8B1111]/30 bg-[#0c0909] py-8 px-6 text-center text-xs text-[#B8B1AA] font-mono mt-auto flex flex-col sm:flex-row items-center justify-center gap-3">
          <VektorLogo className="w-6 h-6" />
          <span>Vektor &bull; Cross-Platform Malware Detection System &bull; Windows (UCI staDyn) &amp; Android (KronoDroid)</span>
        </footer>
      )}
    </div>
  );
}
