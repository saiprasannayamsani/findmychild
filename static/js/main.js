function showTab(tabId, btn) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
  const el = document.getElementById(tabId);
  if (el) el.classList.add('active');
  if (btn) btn.classList.add('active');
}
function setMsg(text) {
  const input = document.getElementById('chat-input');
  if (input) { input.value = text; input.focus(); }
}
window.addEventListener('load', () => {
  const chat = document.getElementById('chat-messages');
  if (chat) chat.scrollTop = chat.scrollHeight;
  document.querySelectorAll('.flash').forEach(a => {
    setTimeout(() => { a.style.transition='opacity 0.6s'; a.style.opacity='0'; setTimeout(()=>a.remove(),600); }, 6000);
  });
});
