// Portal script: copy and show/hide buttons for revealed credentials, sortable and resizable tables.
// Progressive enhancement: without JavaScript passwords stay visible, buttons stay hidden and tables keep their order.
// Loaded from the same origin (CSP script-src 'self').
(function () {
    'use strict';
    function flash(button, label) {
        var original = button.getAttribute('data-label') || button.textContent;
        button.setAttribute('data-label', original);
        button.textContent = label;
        button.classList.add('done');
        window.setTimeout(function () { button.textContent = original; button.classList.remove('done'); }, 1800);
    }
    function legacyCopy(value) {
        var area = document.createElement('textarea');
        area.value = value;
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        var ok = false;
        try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
        document.body.removeChild(area);
        return ok;
    }
    // ---- Sortable, resizable tables (table.sortable; th[data-sort] = text|number; td[data-sort-value] overrides) ----
    function store(key, value) { try { if (value === undefined) return JSON.parse(window.localStorage.getItem(key) || 'null'); window.localStorage.setItem(key, JSON.stringify(value)); } catch (e) { return null; } return null; }
    function cellValue(row, index, type) {
        var cell = row.cells[index];
        if (!cell) return '';
        var raw = cell.hasAttribute('data-sort-value') ? cell.getAttribute('data-sort-value') : cell.textContent.trim();
        if (type === 'number') { var n = parseFloat(raw); return isNaN(n) ? -Infinity : n; }
        return raw.toLowerCase();
    }
    function sortTable(table, index, direction) {
        var header = table.tHead.rows[0].cells[index];
        var type = header.getAttribute('data-sort') || 'text';
        var body = table.tBodies[0];
        var rows = Array.prototype.slice.call(body.rows);
        rows.sort(function (a, b) {
            var x = cellValue(a, index, type), y = cellValue(b, index, type);
            if (x === y) return 0;
            if (x === '' || x === -Infinity) return 1;   // empty values always last
            if (y === '' || y === -Infinity) return -1;
            return (x < y ? -1 : 1) * direction;
        });
        rows.forEach(function (row) { body.appendChild(row); });
        Array.prototype.forEach.call(table.tHead.rows[0].cells, function (th, i) {
            th.classList.remove('sorted-asc', 'sorted-desc');
            if (th.hasAttribute('data-sort')) th.setAttribute('aria-sort', i === index ? (direction > 0 ? 'ascending' : 'descending') : 'none');
        });
        header.classList.add(direction > 0 ? 'sorted-asc' : 'sorted-desc');
    }
    function initTable(table) {
        var key = 'slaps-table-' + (table.getAttribute('data-table-key') || 'table');
        var saved = store(key) || {};
        var headers = table.tHead.rows[0].cells;
        Array.prototype.forEach.call(headers, function (th, index) {
            if (!th.hasAttribute('data-sort')) return;
            th.tabIndex = 0;
            th.setAttribute('aria-sort', 'none');
            th.title = 'Sort by ' + th.textContent.trim();
            var activate = function () {
                var direction = th.classList.contains('sorted-asc') ? -1 : 1;
                sortTable(table, index, direction);
                saved.sort = index; saved.direction = direction; store(key, saved);
            };
            th.addEventListener('click', function (event) { if (!event.target.classList.contains('col-resizer')) activate(); });
            th.addEventListener('keydown', function (event) { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); activate(); } });
            var grip = document.createElement('span');
            grip.className = 'col-resizer';
            grip.setAttribute('aria-hidden', 'true');
            th.appendChild(grip);
            grip.addEventListener('mousedown', function (event) {
                event.preventDefault();
                // Freeze all current widths once, then resize only this column.
                if (!table.classList.contains('resized')) {
                    Array.prototype.forEach.call(headers, function (h) { h.style.width = h.getBoundingClientRect().width + 'px'; });
                    table.classList.add('resized');
                }
                var startX = event.clientX, startWidth = th.getBoundingClientRect().width;
                var move = function (e) { th.style.width = Math.max(60, startWidth + e.clientX - startX) + 'px'; };
                var up = function () {
                    document.removeEventListener('mousemove', move); document.removeEventListener('mouseup', up);
                    saved.widths = Array.prototype.map.call(headers, function (h) { return h.style.width; }); store(key, saved);
                };
                document.addEventListener('mousemove', move); document.addEventListener('mouseup', up);
            });
            grip.addEventListener('dblclick', function () { saved.widths = null; store(key, saved); Array.prototype.forEach.call(headers, function (h) { h.style.width = ''; }); table.classList.remove('resized'); });
        });
        if (saved.widths && saved.widths.length === headers.length) {
            Array.prototype.forEach.call(headers, function (h, i) { if (saved.widths[i]) h.style.width = saved.widths[i]; });
            table.classList.add('resized');
        }
        if (typeof saved.sort === 'number' && headers[saved.sort] && headers[saved.sort].hasAttribute('data-sort')) sortTable(table, saved.sort, saved.direction || 1);
    }

    function init() {
        Array.prototype.forEach.call(document.querySelectorAll('[data-secret]'), function (element) { element.classList.add('masked'); });
        Array.prototype.forEach.call(document.querySelectorAll('button[data-copy], button[data-toggle]'), function (button) { button.hidden = false; });
        Array.prototype.forEach.call(document.querySelectorAll('table.sortable'), function (table) { if (table.tHead && table.tBodies.length) initTable(table); });
    }
    document.addEventListener('click', function (event) {
        var button = event.target.closest ? event.target.closest('button[data-copy], button[data-toggle]') : null;
        if (!button) return;
        event.preventDefault();
        if (button.hasAttribute('data-toggle')) {
            var secret = document.getElementById(button.getAttribute('data-toggle'));
            if (!secret) return;
            var masked = secret.classList.toggle('masked');
            button.textContent = masked ? 'Show' : 'Hide';
            button.setAttribute('aria-pressed', masked ? 'false' : 'true');
            return;
        }
        var source = document.getElementById(button.getAttribute('data-copy'));
        var value = source ? source.textContent : '';
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(value).then(function () { flash(button, 'Copied'); }, function () { flash(button, legacyCopy(value) ? 'Copied' : 'Copy failed'); });
        } else {
            flash(button, legacyCopy(value) ? 'Copied' : 'Copy failed');
        }
    });
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
