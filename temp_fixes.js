let authToken = null;

async function authenticate(password) {
  const r = await fetch('/api/auth', {
    method: 'POST',
    headers: { 'Content-Type':'application/json' },
    body: JSON.stringify({ password })
  });
  if (!r.ok) throw new Error('Invalid password');
  const { token } = await r.json();
  authToken = token;
  return true;
}

// override callAI to use JWT and parse {response: "..."}
window.callAI = async function(speaker, prompt) {
  const endpoint = speaker === 'claude' ? '/api/claude'
                  : speaker === 'gemini' ? '/api/gemini'
                  : '/api/openai';
  const r = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type':'application/json',
      'Authorization': `Bearer ${authToken}`
    },
    body: JSON.stringify({ prompt })
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `API failed: ${r.status}`);
  return data.response;
};

// wrap existing start to request password then proceed
(function() {
  const origStart = window.startShow || (async ()=>{});
  window.startShow = async function() {
    const topicEl = document.getElementById('topic');
    const topic = topicEl ? topicEl.value.trim() : '';
    if (!topic) { alert('Please enter a discussion topic!'); return; }

    const pwd = prompt('Enter password:');
    if (!pwd) return;
    try { await authenticate(pwd); }
    catch { alert('Invalid password'); return; }

    return origStart(); // continues existing flow
  };
})();
