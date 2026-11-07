const form = document.getElementById("chatForm");
const input = document.getElementById("chatInput");
const messages = document.getElementById("chatMessages");
let conversationId = messages?.dataset.conversationId || null;
const LABELS = {
  PERIGO: "⛔ Alto risco de golpe",
  CUIDADO: "⚠️ Risco moderado",
  SEGURO: "✅ Sem sinais de golpe",
  INFO: "💡 Orientação"
};

function addMessage(role, text, verdict = null) {
  const wrapper = document.createElement("div");
  wrapper.className = `message ${role}`;
  const avatar = document.createElement("div");
  avatar.className = "message-avatar";
  avatar.textContent = role === "user" ? "Você" : "CG";
  const bubble = document.createElement("div");
  bubble.className = "message-bubble";
  if (role === "assistant" && verdict && LABELS[verdict]) {
    const badge = document.createElement("div");
    badge.className = "verdict v-" + verdict;
    badge.textContent = LABELS[verdict];
    bubble.appendChild(badge);
  }
  const body = document.createElement("div");
  body.className = "answer-text";
  body.textContent = String(text).replace(/\*\*/g, "");
  bubble.appendChild(body);
  wrapper.append(avatar, bubble);
  messages.querySelector(".chat-welcome")?.remove();
  messages.appendChild(wrapper);
  messages.scrollTop = messages.scrollHeight;
  return wrapper;
}
document.querySelectorAll(".prompt-chip").forEach(button => {
  button.addEventListener("click", () => {
    input.value = button.textContent.trim();
    input.focus();
  });
});
input?.addEventListener("keydown", event => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    form.requestSubmit();
  }
});
if (messages) messages.scrollTop = messages.scrollHeight;
form?.addEventListener("submit", async event => {
  event.preventDefault();
  const message = input.value.trim();
  if (!message) return;
  addMessage("user", message);
  input.value = "";
  input.disabled = true;
  const submit = form.querySelector("button[type=submit]");
  submit.disabled = true;
  const typing = addMessage("assistant", "Analisando…");
  try {
    const response = await fetch("/api/chat", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({message, conversation_id: conversationId})
    });
    const data = await response.json();
    typing.remove();
    if (!response.ok) throw new Error(data.error || "Não foi possível enviar sua mensagem.");
    conversationId = data.conversation_id;
    addMessage("assistant", data.answer, data.risk);
    if (window.location.pathname === "/chat" && !window.location.search) {
      history.replaceState({}, "", data.redirect);
    }
  } catch (error) {
    typing.remove?.();
    addMessage("assistant", error.message || "Ocorreu um erro. Tente novamente.");
  } finally {
    input.disabled = false;
    submit.disabled = false;
    input.focus();
  }
});

// NOVA-CONVERSA: se já estamos em /chat sem conversa aberta, o link recarrega uma conversa vazia.
document.querySelectorAll("[data-new-chat]").forEach(link => {
  link.addEventListener("click", event => {
    const target = new URL(link.href, window.location.href);
    if (target.pathname === window.location.pathname && target.search === window.location.search) {
      event.preventDefault();
      window.location.reload();
    }
  });
});
