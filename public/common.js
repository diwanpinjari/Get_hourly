function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
}
function jsArg(value) {
    return escapeHtml(JSON.stringify(String(value ?? '')));
}
function parseCsv(text) {
    const rows = [];
    let row = [], field = '', quoted = false;
    for (let i = 0; i < text.length; i++) {
        const ch = text[i];
        if (ch === '"') {
            if (quoted && text[i + 1] === '"') { field += '"'; i++; }
            else quoted = !quoted;
        } else if (!quoted && (ch === ',' || ch === '\n')) {
            row.push(field.trim()); field = '';
            if (ch === '\n') { if (row.some(Boolean)) rows.push(row); row = []; }
        } else if (ch !== '\r' || quoted) field += ch;
    }
    if (quoted) throw new Error('CSV contains an unclosed quote.');
    row.push(field.trim());
    if (row.some(Boolean)) rows.push(row);
    return rows;
}
function csvCell(value) {
    let text = String(value ?? '');
    if (/^[=+@-]/.test(text)) text = "'" + text;
    return '"' + text.replace(/"/g, '""') + '"';
}
function attendanceDate() {
    const parts = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Kolkata', year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(new Date());
    const value = type => parts.find(p => p.type === type).value;
    return `${value('year')}-${value('month')}-${value('day')}`;
}
const originalFetch = window.fetch.bind(window);
window.fetch = async function(input, options) {
    const response = await originalFetch(input, options);
    if (response.status === 401 && !String(input).includes('login') && !String(input).includes('/doe/')) {
        sessionStorage.removeItem('adminSession');
        document.getElementById('adminLoginModal')?.classList.remove('hidden');
        if (document.getElementById('loginScreen')) {
            document.getElementById('loginScreen').classList.remove('hidden');
            document.getElementById('dashboardScreen').classList.add('hidden');
        }
        throw new Error('Session expired. Please log in again.');
    }
    return response;
};
window.addEventListener('unhandledrejection', event => {
    event.preventDefault();
    alert(event.reason?.message || 'Request failed. Please retry.');
});
async function logoutAdmin() {
    await fetch('/api/logout', { method: 'POST' });
    sessionStorage.removeItem('adminSession');
    window.location.reload();
}
