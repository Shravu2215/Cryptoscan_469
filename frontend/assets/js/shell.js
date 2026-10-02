/**
 * CryptoScan Global Shell
 * Injects the global sidebar and topbar into authenticated pages,
 * handles responsive sidebar toggling, and initializes user data.
 */

class AppShell {
  constructor() {
    this.init();
  }

  init() {
    // Theme Preference Initialization
    const savedTheme = localStorage.getItem('cs_theme') || 'light';
    if (savedTheme === 'dark') {
      document.documentElement.classList.add('dark', 'dark-mode');
      document.documentElement.classList.remove('light-mode');
    } else {
      document.documentElement.classList.add('light-mode');
      document.documentElement.classList.remove('dark', 'dark-mode');
      localStorage.setItem('cs_theme', 'light');
    }

    // Determine current page to set active nav item
    const path = window.location.pathname;
    const page = path.split('/').pop() || 'dashboard.html';
    
    // Inject CSS
    if (!document.querySelector('link[href*="global.css"]')) {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = 'assets/css/global.css';
      document.head.prepend(link);
    }
    if (!document.querySelector('link[href*="visuals.css"]')) {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = 'assets/css/visuals.css';
      document.head.appendChild(link);
    }

    // Inject Visuals JS
    if (!document.querySelector('script[src*="visuals.js"]')) {
      const script = document.createElement('script');
      script.src = 'assets/js/visuals.js';
      document.body.appendChild(script);
    }

    this.renderSidebar(page);
    this.renderTopbar(page);
    this.bindEvents();
    this.loadUserData();
  }

  renderSidebar(currentPage) {
    const sidebar = document.getElementById('app-sidebar') || document.querySelector('.app-sidebar') || document.querySelector('.sb') || document.querySelector('.sidebar');
    if (!sidebar) return;

    const pageName = currentPage.split('/').pop() || 'dashboard.html';

    const navItems = [
      { group: 'OVERVIEW', items: [
        { name: 'Dashboard', url: 'dashboard.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/>' }
      ]},
      { group: 'ANALYSIS', items: [
        { name: 'Repositories', url: 'repositories.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>' },
        { name: 'Scan', url: 'scan.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4"/>' },
        { name: 'Findings', url: 'findings.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>' },
        { name: 'CBOM', url: 'cbom.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>' }
      ]},
      { group: 'SECURITY', items: [
        { name: 'Risk Analysis', url: 'risk-analysis.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>' },
        { name: 'Migration Plan', url: 'migration-plan.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"/>' },
        { name: 'Verification', url: 'verification.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>' }
      ]},
      { group: 'SYSTEM', items: [
        { name: 'Profile', url: 'profile.html', icon: '<path stroke-linecap="round" stroke-linejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>' }
      ]}
    ];

    let navHtml = '';
    navItems.forEach(group => {
      navHtml += `<div class="sb-nav-group"><div class="sb-nav-group-title">${group.group}</div>`;
      group.items.forEach(item => {
        const isActive = (pageName === item.url || (pageName === '' && item.url === 'dashboard.html')) ? 'active' : '';
        navHtml += `
          <a href="${item.url}" class="sb-nav-item nav-item ${isActive}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">${item.icon}</svg>
            <span class="sb-label">${item.name}</span>
          </a>
        `;
      });
      navHtml += `</div>`;
    });

    sidebar.innerHTML = `
      <div class="sb-header">
        <a href="dashboard.html" class="sb-brand" style="display:flex; align-items:center; gap:10px; text-decoration:none; width:100%;">
          <img src="assets/images/cryptoscan-logo.png" alt="CryptoScan Logo" class="sb-brand-logo" style="height:32px; width:auto; max-height:32px; border-radius:6px; object-fit:contain; filter:drop-shadow(0 0 6px rgba(139,92,246,0.3)); flex-shrink:0;">
          <div style="display:flex; flex-direction:column; justify-content:center;">
            <span class="sb-brand-name" style="font-size:15px; font-weight:800; letter-spacing:1.2px; background:linear-gradient(135deg, #c084fc, #60a5fa); -webkit-background-clip:text; -webkit-text-fill-color:transparent; line-height:1.2;">CryptoScan</span>
            <span style="font-size:8.5px; font-weight:600; color:var(--text-muted); letter-spacing:0.8px; text-transform:uppercase; line-height:1.2; margin-top:1px;">Quantum Security</span>
          </div>
        </a>
      </div>
      <nav class="sb-content">
        ${navHtml}
      </nav>
      <div class="sb-footer">
        <div class="sb-system-status">
          <div class="indicator"></div>
          <span class="status-text">System Operational</span>
        </div>
        <div class="sb-user">
          <div class="sb-user-avatar" id="sb-user-avatar">S</div>
          <div class="sb-user-info">
            <div class="sb-user-name" id="sb-user-name">Shravani Dinesh Joshi</div>
            <div class="sb-user-role">Security Analyst</div>
          </div>
        </div>
      </div>
    `;
  }

  renderTopbar(currentPage) {
    const topbar = document.getElementById('app-topbar') || document.querySelector('.app-topbar') || document.querySelector('.topbar');
    if (!topbar) return;

    // Get page title for breadcrumb
    const titles = {
      'dashboard.html': 'Dashboard',
      'repositories.html': 'Repositories',
      'scan.html': 'Scan Repository',
      'findings.html': 'Findings',
      'cbom.html': 'CBOM',
      'risk-migration.html': 'Risk & Migration',
      'risk-analysis.html': 'Risk Analysis',
      'migration-plan.html': 'Migration Plan',
      'verification.html': 'Verification',
      'profile.html': 'Profile'
    };
    const title = titles[currentPage] || 'Overview';

    topbar.className = 'app-topbar';
    topbar.id = 'app-topbar';
    topbar.innerHTML = `
      <div class="tb-left">
        <button class="mobile-menu-trigger" id="mobile-menu-btn">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="24" height="24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M4 6h16M4 12h16M4 18h16"/>
          </svg>
        </button>
        <div class="tb-breadcrumbs" style="display:flex; align-items:center; gap:8px;">
          <img src="assets/images/cryptoscan-logo.png" alt="CryptoScan" style="height:22px; width:auto; border-radius:4px;">
          <span style="font-weight:700; color:var(--text-h);">CryptoScan</span>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7"/></svg>
          <span class="current" style="color:#c084fc; font-weight:600;">${title}</span>
        </div>
      </div>
      <div class="tb-right" style="display:flex; align-items:center; gap:12px;">
        <button class="search-trigger">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
          <span>Search</span>
          <kbd>⌘ K</kbd>
        </button>
        <button class="icon-btn" id="theme-toggle-btn" title="Toggle Light/Dark Theme" style="display:inline-flex; align-items:center; justify-content:center; cursor:pointer;">
          <svg class="theme-icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:18px;height:18px;display:none;"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
          <svg class="theme-icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:18px;height:18px;"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>
        </button>
        <button class="icon-btn" id="compact-toggle-btn" title="Toggle Fit-to-Screen Compact View" style="display:inline-flex; align-items:center; justify-content:center; cursor:pointer;">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:18px;height:18px;"><path stroke-linecap="round" stroke-linejoin="round" d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4"/></svg>
        </button>
        <button class="icon-btn" title="Notifications">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>
        </button>
        <div style="position: relative;">
          <button class="icon-btn" id="tb-user-btn" title="Log Out">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 14l9-5-9-5-9 5 9 5z"/><path stroke-linecap="round" stroke-linejoin="round" d="M12 14l6.16-3.422a12.083 12.083 0 01.665 6.479A11.952 11.952 0 0012 20.055a11.952 11.952 0 00-6.824-2.998 12.078 12.078 0 01.665-6.479L12 14z"/><path stroke-linecap="round" stroke-linejoin="round" d="M12 14l9-5-9-5-9 5 9 5zm0 0l6.16-3.422a12.083 12.083 0 01.665 6.479A11.952 11.952 0 0012 20.055a11.952 11.952 0 00-6.824-2.998 12.078 12.078 0 01.665-6.479L12 14zm-4 6v-7.5l4-2.222"/></svg>
          </button>
        </div>
      </div>
    `;
  }

  bindEvents() {
    // Compact View State Check
    if (localStorage.getItem('cs_compact') === 'true') {
      document.documentElement.classList.add('compact-mode');
    }

    // Theme toggle
    const themeBtn = document.getElementById('theme-toggle-btn');
    if (themeBtn) {
      themeBtn.addEventListener('click', () => {
        const isLight = document.documentElement.classList.contains('light-mode');
        if (isLight) {
          document.documentElement.classList.remove('light-mode');
          document.documentElement.classList.add('dark', 'dark-mode');
          localStorage.setItem('cs_theme', 'dark');
        } else {
          document.documentElement.classList.remove('dark', 'dark-mode');
          document.documentElement.classList.add('light-mode');
          localStorage.setItem('cs_theme', 'light');
        }
        this.updateThemeIcons();
      });
    }
    this.updateThemeIcons();

    // Compact View Toggle
    const compactBtn = document.getElementById('compact-toggle-btn');
    if (compactBtn) {
      const updateCompactBtnStyle = () => {
        const isCompact = document.documentElement.classList.contains('compact-mode');
        compactBtn.style.color = isCompact ? '#c084fc' : '';
        compactBtn.style.borderColor = isCompact ? '#8b5cf6' : '';
        compactBtn.style.background = isCompact ? 'rgba(139, 92, 246, 0.2)' : '';
      };
      updateCompactBtnStyle();

      compactBtn.addEventListener('click', () => {
        const isCompact = document.documentElement.classList.toggle('compact-mode');
        localStorage.setItem('cs_compact', isCompact ? 'true' : 'false');
        updateCompactBtnStyle();
      });
    }

    // Mobile Sidebar Toggle
    const mobileBtn = document.getElementById('mobile-menu-btn');
    if (mobileBtn) {
      mobileBtn.addEventListener('click', () => {
        document.body.classList.toggle('sidebar-open');
      });
    }

    // Topbar user menu toggle (logout)
    const userBtn = document.getElementById('tb-user-btn');
    if (userBtn) {
      userBtn.addEventListener('click', () => {
        if (confirm('Are you sure you want to log out?')) {
          if (window.Auth && window.Auth.logout) {
            window.Auth.logout();
          } else {
            localStorage.removeItem('cs_token');
            localStorage.removeItem('cs_user');
            window.location.href = 'login.html';
          }
        }
      });
    }
  }

  updateThemeIcons() {
    const isDark = document.documentElement.classList.contains('dark') || document.documentElement.classList.contains('dark-mode');
    const sunIcons = document.querySelectorAll('.theme-icon-sun');
    const moonIcons = document.querySelectorAll('.theme-icon-moon');
    sunIcons.forEach(icon => icon.style.display = isDark ? 'block' : 'none');
    moonIcons.forEach(icon => icon.style.display = isDark ? 'none' : 'block');
  }

  loadUserData() {
    try {
      const u = JSON.parse(localStorage.getItem('cs_user'));
      if (u) {
        const name = u.name || (u.email ? u.email.split('@')[0] : 'User');
        const initial = name.charAt(0).toUpperCase();
        
        const avatarEl = document.getElementById('sb-user-avatar');
        const nameEl = document.getElementById('sb-user-name');
        
        if (avatarEl) avatarEl.textContent = initial;
        if (nameEl) nameEl.textContent = name;
      }
    } catch (e) {
      console.warn('Failed to load user data for shell', e);
    }
  }
}

// Initialize shell on DOM load
document.addEventListener('DOMContentLoaded', () => {
  new AppShell();
});
