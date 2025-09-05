(function(){
  try {
    var scriptEl = document.currentScript || Array.from(document.getElementsByTagName('script')).find(function(s){return s.src && s.src.indexOf('/install.js')!==-1});
    var botId = scriptEl && scriptEl.getAttribute ? scriptEl.getAttribute('data-bot-id') : null;
    var token = scriptEl && scriptEl.getAttribute ? scriptEl.getAttribute('data-widget-token') : null;
    if(!botId) return;
    var btn = document.createElement('button'); btn.innerText = 'Chat';
    Object.assign(btn.style,{position:'fixed',right:'16px',bottom:'16px',borderRadius:'999px',background:'#6366f1',color:'#fff',border:'none',padding:'12px 16px',cursor:'pointer',zIndex:999999});
    document.body.appendChild(btn);
    var open=false, ui=null;
    function fetchConfig(cb){
      try{
        var hostBase = (location.protocol+'//'+location.host);
        var fnUrl = hostBase + '/.netlify/functions/widget-config?botId='+encodeURIComponent(botId)+'&token='+encodeURIComponent(token);
        var apiUrl = hostBase + '/api/widget-config?botId='+encodeURIComponent(botId)+'&token='+encodeURIComponent(token);
        // Try functions endpoint first, fallback to /api
        fetch(fnUrl).then(function(r){ if(!r.ok){
          fetch(apiUrl).then(function(r2){ if(!r2.ok){cb(null);return;} r2.json().then(function(j){cb(j);}).catch(function(){cb(null);}); }).catch(function(){cb(null);});
          return;
        } r.json().then(function(j){cb(j);}).catch(function(){cb(null);}); }).catch(function(){
          fetch(apiUrl).then(function(r2){ if(!r2.ok){cb(null);return;} r2.json().then(function(j){cb(j);}).catch(function(){cb(null);}); }).catch(function(){cb(null);});
        });
      }catch(e){cb(null);}    }
    btn.addEventListener('click',function(){
      if(open){ if(ui){document.body.removeChild(ui); ui=null;} open=false; return; }
      open=true;
      fetchConfig(function(cfg){
        ui=document.createElement('div');
        Object.assign(ui.style,{position:'fixed',right:'16px',bottom:'76px',width:'320px',maxHeight:'60vh',background:'#fff',borderRadius:'12px',boxShadow:'0 8px 24px rgba(0,0,0,0.12)',overflow:'hidden',zIndex:999999});
        var headerColor = (cfg && cfg.settings && cfg.settings.settings && cfg.settings.settings.chatHeaderColor) || '#8b5cf6';
        var buttonColor = (cfg && cfg.settings && cfg.settings.settings && cfg.settings.settings.buttonColor) || '#6366f1';
        var headerTitle = (cfg && cfg.settings && cfg.settings.settings && cfg.settings.settings.headerTitle) || 'Ask NexaBot';
        ui.innerHTML = '<div style="padding:12px;background:'+headerColor+';color:#fff;font-weight:600">'+headerTitle+'</div><div style="padding:12px;height:260px;overflow:auto"><div id="nexabot-msgs"></div></div><div style="display:flex;padding:8px;border-top:1px solid #eee"><input id="nexabot-input" style="flex:1;padding:8px;border-radius:8px;border:1px solid #e5e7eb" placeholder="Type a message..."/><button id="nexabot-send" style="margin-left:8px;padding:8px 12px;background:'+buttonColor+';color:#fff;border-radius:8px;border:none">Send</button></div>';
        document.body.appendChild(ui);
        var msgs = ui.querySelector('#nexabot-msgs');
        var input = ui.querySelector('#nexabot-input');
        var send = ui.querySelector('#nexabot-send');
        send.addEventListener('click',function(){
          var v = (input.value||'').trim(); if(!v) return;
          var d = document.createElement('div'); d.textContent = 'You: '+v; msgs.appendChild(d);
          input.value = '';
          fetch((location.protocol+'//'+location.host) + '/api/chat', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ botId: botId, message: v }) }).then(function(r){ return r.json(); }).then(function(j){ var rep = j.reply || "I'm still learning, our team will reply soon."; var nd = document.createElement('div'); nd.textContent = 'Bot: '+rep; msgs.appendChild(nd); msgs.scrollTop = msgs.scrollHeight; }).catch(function(){ var nd = document.createElement('div'); nd.textContent = 'Bot: (error)'; msgs.appendChild(nd); });
        });
      });
    });
  } catch (e) { /* fail silently */ }
})();
