const STORAGE_KEY = 'codebull-theme';
const THEME_ATTR = 'data-theme';
const DARK = 'dark';
const LIGHT = 'light';

function getSystemTheme() {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? DARK : LIGHT;
}

function getSavedTheme() {
    return localStorage.getItem(STORAGE_KEY);
}

function setTheme(theme) {
    document.documentElement.setAttribute(THEME_ATTR, theme);
    localStorage.setItem(STORAGE_KEY, theme);
    updateToggleButton(theme);
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute(THEME_ATTR);
    const newTheme = currentTheme === DARK ? LIGHT : DARK;
    setTheme(newTheme);
}

function updateToggleButton(theme) {
    const btn = document.getElementById('theme-toggle');
    if (btn) {
        // Simple text/icon change. You can use icons (SVG) if preferred.
        // For now, let's use text or simple emoji for simplicity.
        // Moon for Dark, Sun for Light.
        // If current is dark, show Sun (to switch to light).
        // If current is light, show Moon (to switch to dark).
        btn.textContent = theme === DARK ? '☀️' : '🌙';
        btn.setAttribute('aria-label', `Switch to ${theme === DARK ? 'Light' : 'Dark'} mode`);
    }
}

// Initialize
(function initTheme() {
    const savedTheme = getSavedTheme();
    const systemTheme = getSystemTheme();
    const theme = savedTheme || systemTheme;
    setTheme(theme);
})();

// Wait for DOM to load button
document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('theme-toggle');
    if (btn) {
        btn.addEventListener('click', toggleTheme);
        // Ensure button state matches current theme
        const currentTheme = document.documentElement.getAttribute(THEME_ATTR);
        updateToggleButton(currentTheme);
    }
});
