(function(){
  try {
    var scripts = Array.prototype.slice.call(document.getElementsByTagName('script'));
    var scriptEl = document.currentScript || scripts.find(function(s){ return s.src && (s.src.indexOf('/install.js') !== -1 || s.src.indexOf('/api/nexabot') !== -1); });
    var botId = scriptEl && scriptEl.getAttribute ? scriptEl.getAttribute('data-bot-id') : '';
    var apiKey = scriptEl && scriptEl.getAttribute ? scriptEl.getAttribute('data-api-key') : '';
    var scriptUrl = scriptEl && scriptEl.src ? new URL(scriptEl.src) : null;
    var apiBase = scriptUrl ? scriptUrl.origin : '';
    if (!apiKey || !apiBase) return;

    var state = { open: false, config: null, panel: null, button: null, messages: null, input: null, send: null };
    var fallback = {
      title: 'NexaBot',
      subtitle: 'AI support assistant',
      primaryColor: '#22d3c8',
      buttonLabel: 'Chat',
      position: 'bottom-right',
      logoUrl: ''
    };

    function esc(value) {
      return String(value || '').replace(/[&<>"']/g, function(ch) {
        return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch];
      });
    }

    function getPosition(pos, panel) {
      var base = { position: 'fixed', zIndex: 2147483647 };
      var corner = pos || 'bottom-right';
      if (corner.indexOf('top') === 0) base.top = panel ? '82px' : '18px';
      else base.bottom = panel ? '82px' : '18px';
      if (corner.indexOf('left') > -1) base.left = '18px';
      else base.right = '18px';
      return base;
    }

    function appendMessage(role, text) {
      if (!state.messages) return;
      var row = document.createElement('div');
      row.style.cssText = 'display:flex;margin:10px 0;' + (role === 'user' ? 'justify-content:flex-end;' : 'justify-content:flex-start;');
      var bubble = document.createElement('div');
      bubble.textContent = text;
      bubble.style.cssText = 'max-width:82%;padding:10px 12px;border-radius:14px;font:14px/1.4 Inter,system-ui,-apple-system,sans-serif;white-space:pre-wrap;' + (role === 'user' ? 'background:' + state.config.primaryColor + ';color:#fff;border-bottom-right-radius:4px;' : 'background:#f2f7f7;color:#0f1f1e;border:1px solid #dcebea;border-bottom-left-radius:4px;');
      row.appendChild(bubble);
      state.messages.appendChild(row);
      state.messages.scrollTop = state.messages.scrollHeight;
    }

    function setTyping(on) {
      var existing = state.panel && state.panel.querySelector('[data-nexabot-typing]');
      if (existing) existing.remove();
      if (!on || !state.messages) return;
      var row = document.createElement('div');
      row.setAttribute('data-nexabot-typing', 'true');
      row.style.cssText = 'margin:10px 0;color:#667b79;font:13px Inter,system-ui,sans-serif;';
      row.textContent = 'NexaBot is replying...';
      state.messages.appendChild(row);
      state.messages.scrollTop = state.messages.scrollHeight;
    }

    function sendMessage() {
      var text = state.input && state.input.value ? state.input.value.trim() : '';
      if (!text) return;
      state.input.value = '';
      appendMessage('user', text);
      setTyping(true);
      fetch(apiBase + '/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ botId: botId, apiKey: apiKey, message: text })
      }).then(function(r){ return r.json(); }).then(function(j){
        setTyping(false);
        appendMessage('bot', j && j.reply ? j.reply : 'I am checking that for you. Please try again in a moment.');
      }).catch(function(){
        setTyping(false);
        appendMessage('bot', 'I am checking that for you. Please try again in a moment.');
      });
    }

    function buildPanel() {
      if (state.panel) return;
      var panel = document.createElement('div');
      Object.assign(panel.style, getPosition(state.config.position, true), {
        width: '340px',
        maxWidth: 'calc(100vw - 36px)',
        height: '460px',
        maxHeight: 'calc(100vh - 110px)',
        background: '#fff',
        border: '1px solid #dcebea',
        borderRadius: '16px',
        boxShadow: '0 18px 45px rgba(15,31,30,.18)',
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column'
      });
      var logo = state.config.logoUrl ? '<img src="' + esc(state.config.logoUrl) + '" alt="" style="width:34px;height:34px;border-radius:10px;object-fit:cover">' : '<div style="width:34px;height:34px;border-radius:10px;background:' + esc(state.config.primaryColor) + ';display:grid;place-items:center;color:#fff;font-weight:700">N</div>';
      panel.innerHTML =
        '<div style="display:flex;align-items:center;gap:10px;padding:14px;border-bottom:1px solid #e6eeee">' +
          logo +
          '<div style="min-width:0"><div style="font:700 14px Inter,system-ui,sans-serif;color:#0f1f1e">' + esc(state.config.title) + '</div><div style="font:12px Inter,system-ui,sans-serif;color:#667b79;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + esc(state.config.subtitle) + '</div></div>' +
        '</div>' +
        '<div id="nexabot-msgs" style="flex:1;overflow:auto;padding:12px;background:#fbfefe"></div>' +
        '<div style="display:flex;gap:8px;padding:10px;border-top:1px solid #e6eeee;background:#fff">' +
          '<input id="nexabot-input" style="flex:1;min-width:0;padding:10px 12px;border-radius:10px;border:1px solid #d7e5e4;outline:none;font:14px Inter,system-ui,sans-serif" placeholder="Type a message...">' +
          '<button id="nexabot-send" style="padding:10px 12px;background:' + esc(state.config.primaryColor) + ';color:#fff;border:0;border-radius:10px;font:700 13px Inter,system-ui,sans-serif;cursor:pointer">Send</button>' +
        '</div>';
      document.body.appendChild(panel);
      state.panel = panel;
      state.messages = panel.querySelector('#nexabot-msgs');
      state.input = panel.querySelector('#nexabot-input');
      state.send = panel.querySelector('#nexabot-send');
      state.send.addEventListener('click', sendMessage);
      state.input.addEventListener('keydown', function(e){ if (e.key === 'Enter') sendMessage(); });
      appendMessage('bot', 'Hi. How can I help?');
    }

    function togglePanel() {
      state.open = !state.open;
      if (state.open) buildPanel();
      if (state.panel) state.panel.style.display = state.open ? 'flex' : 'none';
    }

    function initButton() {
      var cfg = state.config;
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = cfg.buttonLabel || 'Chat';
      Object.assign(btn.style, getPosition(cfg.position, false), {
        minWidth: '58px',
        height: '48px',
        borderRadius: '14px',
        background: cfg.primaryColor,
        color: '#fff',
        border: '0',
        padding: '0 16px',
        cursor: 'pointer',
        boxShadow: '0 12px 28px rgba(15,31,30,.18)',
        font: '700 14px Inter,system-ui,-apple-system,sans-serif'
      });
      btn.addEventListener('click', togglePanel);
      document.body.appendChild(btn);
      state.button = btn;
    }

    fetch(apiBase + '/api/widget-config-public?key=' + encodeURIComponent(apiKey), {
      headers: { 'X-NexaBot-Origin': location.origin }
    }).then(function(r){
      if (!r.ok) throw new Error('inactive');
      return r.json();
    }).then(function(j){
      state.config = Object.assign({}, fallback, (j && j.widget) || {});
      botId = botId || (j && j.botId) || '';
      initButton();
    }).catch(function(){ return; });
  } catch (e) {}
})();
