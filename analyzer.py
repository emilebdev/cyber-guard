"""Motor de análise do CyberGuard.

Reúne as regras de detecção de golpes, a conferência de links, as respostas prontas e a conversa
com o usuário. Não depende do Flask nem do banco de dados, o que permite testá-lo isoladamente.
"""
import os
import re
import unicodedata
from urllib.parse import urlparse

VERDICT_LABELS = {
    "PERIGO": "⛔ Alto risco de golpe",
    "CUIDADO": "⚠️ Risco moderado",
    "SEGURO": "✅ Sem sinais de golpe",
    "INFO": "💡 Orientação",
}
SEVERITY = {"SEGURO": 0, "INFO": 1, "CUIDADO": 2, "PERIGO": 3}
# Conversas antigas guardavam o risco como texto livre; aqui elas são convertidas.
LEGACY_RISK = {
    "Alto": "PERIGO",
    "Moderado": "CUIDADO",
    "Baixo indício identificado": "CUIDADO",
    "Verificação de endereço": "INFO",
    "Verificações recomendadas": "INFO",
}


def verdict_code(value):
    """Converte o valor salvo no banco no código do selo (PERIGO, CUIDADO, SEGURO ou INFO)."""
    if not value:
        return ""
    if value in VERDICT_LABELS:
        return value
    return LEGACY_RISK.get(value, "INFO")




def worst(*verdicts):
    """Retorna o veredito mais grave entre os informados, ignorando valores vazios."""
    valid = [v for v in verdicts if v in SEVERITY]
    return max(valid, key=lambda v: SEVERITY[v]) if valid else None


RED_FLAGS = [
    (r"urgente|imediat|ultima chance|hoje mesmo|bloquead|suspens|cancelad|expira|prazo",
     "pede pressa ou ameaça bloquear algo"),
    (r"senha|codigo|token|cvv|cpf|cartao|dados bancarios",
     "menciona senha, código ou dados pessoais"),
    (r"pix|transferenc|deposit|boleto|taxa|pagamento",
     "fala em pagamento ou transferência"),
    (r"bit\.ly|tinyurl|cutt\.ly|goo\.gl|t\.co/|https?://\S+\.(xyz|top|click|site|icu)\b",
     "traz link encurtado ou de endereço estranho"),
    (r"ganhou|premio|sorteio|heranca|brinde|gratis",
     "promete prêmio ou dinheiro fácil"),
    (r"mudei de numero|novo numero|sou seu (filho|filha|neto|neta)|perdi (meu )?celular",
     "alguém diz ser parente com “número novo”"),
    (r"anydesk|teamviewer|acesso remoto|instal\w+ (o )?(app|aplicativo)",
     "pede acesso remoto ou instalação de aplicativo"),
    (r"clique aqui|clique no link|regularize|atualize seus dados|confirme seus dados",
     "pede para clicar em link e confirmar dados"),
]
# Pedir senha ou código é o sinal mais grave: sozinho já indica alto risco.
CRITICAL_PATTERN = (
    r"(pedindo|pedem|pede|peca|solicitando|solicita|informe|informar|envie|enviar|passe|passar|"
    r"mande|mandar|digite|digitar|compartilhe|compartilhar)\W+(\w+\W+){0,4}(codigo|senha|token)"
)

STEPS = [
    "Não clique em links nem responda a mensagem.",
    "Não envie dinheiro, senhas ou códigos.",
    "Fale com a empresa pelo telefone ou aplicativo oficial que você já conhece.",
    "Peça ajuda a uma pessoa de confiança antes de agir.",
]
DISCLAIMER = (
    "Esta análise é educativa e automática. Ela não confirma se links, telefones ou remetentes "
    "são verdadeiros. Na dúvida, não prossiga e procure o canal oficial."
)


def assess_message(text):
    """Análise heurística: retorna (veredito ou None, lista de sinais encontrados)."""
    normalized = normalize_text(text)
    reasons = [label for pattern, label in RED_FLAGS if re.search(pattern, normalized)]
    critical = re.search(CRITICAL_PATTERN, normalized) is not None
    if critical and "menciona senha, código ou dados pessoais" not in reasons:
        reasons.append("menciona senha, código ou dados pessoais")
    if critical or len(reasons) >= 2:
        return "PERIGO", reasons
    if len(reasons) == 1:
        return "CUIDADO", reasons
    return None, reasons


def compose(intro, reasons=None, steps=None, disclaimer=None):
    parts = [intro]
    if reasons:
        parts.append("Sinais encontrados:\n" + "\n".join(f"- {r}" for r in reasons))
    if steps:
        parts.append("O que fazer:\n" + "\n".join(f"- {s}" for s in steps))
    parts.append(disclaimer or DISCLAIMER)
    return "\n\n".join(parts)


def local_answer(verdict, reasons):
    if verdict == "PERIGO":
        intro = ("Isso tem várias características de golpe." if len(reasons) >= 2
                 else "Pedir senha ou código é o sinal mais comum de golpe.")
        return compose(intro, reasons, STEPS)
    if verdict == "CUIDADO":
        return compose(
            "Há um sinal de alerta nesta mensagem. Pode ser golpe, então confirme antes de agir.",
            reasons, STEPS[:3])
    return compose(
        "Não encontrei sinais claros de golpe, mas isso não garante que seja seguro.",
        None,
        ["Não clique em links recebidos sem conferir quem enviou.",
         "Não informe dados pessoais.",
         "Confirme pelo site ou telefone oficial.",
         "Se puder, conte mais detalhes: quem enviou, o que pede e como chegou."])


def normalize_text(value):
    """Remove acentos e padroniza o texto para reconhecer perguntas equivalentes."""
    import unicodedata
    value = unicodedata.normalize("NFKD", value.lower())
    return "".join(char for char in value if not unicodedata.combining(char))


def answer_store_reliability_question(user_text):
    """Resposta direta para dúvidas sobre a confiabilidade de lojas virtuais."""
    normalized = normalize_text(user_text)
    store_terms = ("loja virtual", "loja online", "loja on-line", "site de compras",
                   "comprar pela internet", "loja confiavel")
    trust_terms = ("confiavel", "confiabilidade", "segura", "seguro", "golpe",
                   "fraude", "posso comprar", "como saber", "como verificar")
    if not (any(term in normalized for term in store_terms) or
            ("loja" in normalized and any(term in normalized for term in trust_terms))):
        return None
    return (
        "Para saber se uma loja virtual é confiável, faça estas verificações:\n\n"
        "1. Confira o endereço do site. Veja se o nome está escrito corretamente e desconfie de endereços estranhos.\n"
        "2. Procure o CNPJ e os dados da empresa. Confira se as informações correspondem à loja.\n"
        "3. Pesquise a reputação fora do próprio site, por exemplo no Reclame Aqui e no consumidor.gov.br.\n"
        "4. Desconfie de preços muito abaixo dos praticados por outras lojas.\n"
        "5. Tenha cuidado se o pagamento for apenas por Pix ou transferência para pessoa física.\n"
        "6. Confira os canais de atendimento e as regras de troca e devolução.\n\n"
        "Antes de comprar: nunca informe senhas ou códigos recebidos por SMS ou aplicativo. Se estiver em dúvida, não pague.\n\n"
        "Se quiser, envie o endereço do site ou uma mensagem recebida da loja. Posso ajudar a procurar sinais de alerta, "
        "mas esta análise não garante que a loja seja legítima."
    )


KNOWN_SITES = {
    "magazine luiza": (("magazineluiza.com.br", "magalu.com.br", "magalu.com"), "Magazine Luiza"),
    "magazineluiza": (("magazineluiza.com.br", "magalu.com.br", "magalu.com"), "Magazine Luiza"),
    "magalu": (("magazineluiza.com.br", "magalu.com.br", "magalu.com"), "Magalu"),
    "amazon": (("amazon.com.br", "amazon.com"), "Amazon"),
    "globo": (("globo.com", "globoplay.globo.com"), "Globo"),
    "centauro": (("centauro.com.br",), "Centauro"),
    "mercado livre": (("mercadolivre.com.br", "mercadolivre.com", "mercadolibre.com"), "Mercado Livre"),
    "mercadolivre": (("mercadolivre.com.br", "mercadolivre.com", "mercadolibre.com"), "Mercado Livre"),
    "americanas": (("americanas.com.br", "americanas.com"), "Americanas"),
    "casas bahia": (("casasbahia.com.br", "casasbahia.com"), "Casas Bahia"),
    "netshoes": (("netshoes.com.br",), "Netshoes"),
    "shein": (("shein.com", "shein.com.br"), "Shein"),
    "aliexpress": (("aliexpress.com", "aliexpress.us"), "AliExpress"),
    "shopee": (("shopee.com.br", "shopee.com"), "Shopee"),
    "nubank": (("nubank.com.br", "nu.com.br"), "Nubank"),
    "itau": (("itau.com.br", "itau.com"), "Itaú"),
    "bradesco": (("bradesco.com.br", "bradesco"), "Bradesco"),
    "banco do brasil": (("bb.com.br",), "Banco do Brasil"),
    "caixa": (("caixa.gov.br",), "Caixa"),
    "gov.br": (("gov.br",), "Governo Federal"),
}
SHORTENERS = ("bit.ly", "tinyurl.com", "cutt.ly", "goo.gl", "t.co", "is.gd", "rebrand.ly")


def analyze_known_link(user_text):
    """Compara domínios citados com domínios oficiais conhecidos; não consulta reputação em tempo real."""
    urls = re.findall(
        r"(?i)(?<![@\w.-])(?:(?:https?://|www\.)[^\s<>\"']+|(?:[a-z0-9-]+\.)+(?:com\.br|gov\.br|org\.br|com|net|org|br|app|xyz|top|click|site|online|icu|shop|store|info|me|co|io|link|ly|gl)\b(?:/[^\s<>\"']*)?)",
        user_text)
    if not urls:
        return None
    normalized = normalize_text(user_text)
    flags_verdict, flag_reasons = assess_message(user_text)
    lines, verdicts = [], []
    for raw in urls[:5]:
        raw = raw.rstrip(".,;:!?)")
        candidate = raw if raw.lower().startswith(("http://", "https://")) else "https://" + raw
        host = (urlparse(candidate).hostname or "").lower().strip(".")
        if not host:
            continue
        compact_host = host.replace("-", "").replace(".", "")
        in_host = [(o, b) for o, b in KNOWN_SITES.values()
                   if re.sub(r"\W", "", normalize_text(b)) in compact_host]
        in_host += [(o, b) for k, (o, b) in KNOWN_SITES.items()
                    if len(k) > 4 and k.replace(" ", "") in compact_host and (o, b) not in in_host]
        mentioned = [(o, b) for k, (o, b) in KNOWN_SITES.items() if k in normalized]
        if in_host or mentioned:
            officials, brand = (in_host or mentioned)[0]
            official = officials[0]
            if any(host == o or host.endswith("." + o) for o in officials):
                verdicts.append("SEGURO")
                lines.append(
                    f"O endereço {host} corresponde ao domínio conhecido da {brand}. "
                    "É um bom sinal, mas isso não confirma que a página específica seja segura.")
            elif in_host:
                verdicts.append("PERIGO")
                lines.append(
                    f"Atenção: {host} imita o nome da {brand}, mas o domínio oficial é {official}. "
                    "Isso é típico de site falso. Não faça login nem pagamento por esse link.")
            else:
                verdicts.append("CUIDADO")
                lines.append(
                    f"Você citou a {brand}, mas o endereço {host} não é o domínio oficial ({official}). "
                    "Acesse digitando o endereço oficial no navegador.")
        elif host in SHORTENERS:
            verdicts.append("CUIDADO")
            lines.append(f"{host} é um encurtador: ele esconde o destino real do link. Evite clicar.")
        else:
            verdicts.append("CUIDADO")
            lines.append(
                f"Não reconheci {host} entre os endereços oficiais que conheço. "
                "Isso não prova que seja falso. Pesquise a empresa e acesse digitando o endereço oficial.")
    if not lines:
        return None
    verdict = worst(*verdicts, flags_verdict)
    reasons = flag_reasons if flags_verdict else None
    steps = STEPS[:3] if verdict in ("PERIGO", "CUIDADO") else ["Mesmo assim, digite o endereço oficial por conta própria."]
    answer = compose(
        "\n\n".join(lines), reasons, steps,
        "Esta conferência compara o nome do domínio com uma pequena lista de sites conhecidos. "
        "Não verifica o conteúdo da página, certificados nem a reputação do endereço em tempo real.")
    return answer, verdict


FAQ = [
    (("phishing",),
     "Phishing é quando golpistas se passam por bancos, lojas ou órgãos públicos para fazer você clicar em um link falso ou entregar dados.",
     ["Desconfie de urgência, como “sua conta será bloqueada”.", "Não clique em links recebidos; abra o aplicativo oficial por conta própria.", "Banco não pede senha completa nem código por mensagem."]),
    (("whatsapp", "clonad"),
     "Golpistas tentam clonar o WhatsApp pedindo o código de 6 dígitos que chega por SMS.",
     ["Nunca informe esse código a ninguém.", "Ative a confirmação em duas etapas em Configurações > Conta.", "Se clonaram seu número, avise seus contatos por outro meio."]),
    (("senha forte", "criar senha", "senhas"),
     "Frases longas que só você entende são mais seguras do que senhas curtas.",
     ["Use uma senha diferente em cada serviço importante.", "Ative a verificação em duas etapas.", "Nunca compartilhe códigos recebidos por SMS."]),
    (("pix",),
     "Golpistas pedem Pix com histórias de urgência: parente em apuros, prêmio ou taxa para liberar dinheiro.",
     ["Confirme ligando para a pessoa no número que você já conhecia.", "Nenhum prêmio legítimo exige pagamento antecipado.", "Se caiu no golpe, ligue para o banco e peça o bloqueio pelo aplicativo."]),
    (("ligaram", "ligacao", "central", "telefone"),
     "Golpistas ligam dizendo ser do banco e pedem para “confirmar” dados ou instalar um aplicativo.",
     ["Desligue e ligue você mesmo para o número do cartão.", "Banco não manda ninguém buscar cartão em casa.", "Nunca instale aplicativos a pedido de desconhecidos."]),
    (("wifi", "wi-fi", "rede publica"),
     "Wi-Fi público de praça, shopping ou aeroporto não é um lugar seguro para acessar o banco.",
     ["Use os dados do celular para operações financeiras.", "Evite digitar senhas em redes abertas."]),
    (("virus", "antivirus", "malware"),
     "O principal cuidado é não clicar em links estranhos nem abrir anexos inesperados.",
     ["Baixe aplicativos apenas das lojas oficiais.", "Mantenha o sistema atualizado.", "Um antivírus confiável ajuda como proteção extra."]),
]
QUESTION_STARTS = ("o que", "como", "por que", "porque", "qual", "quais", "onde", "quando", "posso", "devo")


def answer_faq(user_text):
    normalized = normalize_text(user_text)
    if not ("?" in user_text or normalized.strip().startswith(QUESTION_STARTS)):
        return None
    for keys, intro, steps in FAQ:
        if any(k in normalized for k in keys):
            return compose(intro, None, steps, "Quer que eu analise uma mensagem ou link específico? É só colar aqui.")
    return None


AI_INSTRUCTIONS = (
    "Você é o CyberGuard, assistente EXCLUSIVO de segurança digital para pessoas idosas, no Brasil. "
    "Responda em português simples, com frases curtas, tom acolhedor e respeitoso. "
    "Responda sempre de acordo com o que a pessoa realmente perguntou, usando o histórico da conversa. "
    "Se a pessoa agradecer, cumprimentar ou se despedir, responda de forma natural e breve. "
    "Se o assunto NÃO for segurança digital (golpes, mensagens, links, senhas, Pix, contas, aplicativos, "
    "compras online, privacidade), diga com educação que seu objetivo é apenas cibersegurança e convide a "
    "pessoa a perguntar algo dessa área; não responda ao outro assunto. "
    "Para análises, a PRIMEIRA linha deve ser exatamente [VEREDITO: PERIGO], [VEREDITO: CUIDADO], "
    "[VEREDITO: SEGURO] ou [VEREDITO: INFO]; depois explique em até 3 frases e liste no máximo 4 passos "
    "começando com “- ”. Nunca peça senhas, códigos, dados bancários ou documentos. Não afirme que um "
    "link é seguro sem verificação técnica; explique incertezas e oriente a procurar os canais oficiais."
)

TOPIC_PATTERN = re.compile(
    r"\b(senha|golp|link|mensagem|mensagens|banco|bancari|pix|whats|zap|celular|internet|site|e-?mail|"
    r"virus|antiviru|hacker|hack|phishing|fraud|cartao|minha conta|sua conta|conta bancaria|codigo|wi-?fi|"
    r"rede social|redes sociais|aplicativ|apps?\b|dados|privacidade|segur|protec|protej|ligacao|ligaram|"
    r"ligou|telefon|compra|loja|boleto|cpf|clon|perfil|facebook|instagram|tiktok|suspeit|confiav|confio|"
    r"confiar|perigo|ameac|invad|vazamento|cyber|ciber|online|anexo|sms|token|pagamento|transfer|deposit|"
    r"extors|falso|fake|anuncio|premio|sorteio|heranca|inss|gov\.br|correios|encomenda|emprestimo|"
    r"consignado|clique|cliquei|clicar|baixei|instalei|instalar|navegador|login|autentic|criptograf|"
    r"backup|firewall|computador|notebook|smartphone|roubo|roubar|engan|desbloque|spam|malware|"
    r"ransomware|criminos|policia|delegacia|boletim|procon|taxa|urgente|bloquead)"
)
# Quem já entregou dados ou dinheiro precisa de passos urgentes; quem só clicou, de calma e verificação.
INCIDENT_HIGH = re.compile(
    r"(passei|informei|enviei|mandei|forneci|digitei|dei)\W+(\w+\W+){0,3}(codigo|senha|dados|cpf|cartao|token)|"
    r"(fiz|mandei|enviei|transferi|paguei)\W+(\w+\W+){0,3}(pix|dinheiro|boleto|transferencia|deposito)|"
    r"perdi\W+(\w+\W+){0,2}dinheiro|roubaram|invadiram|clonaram|cai no golpe|fui (enganad|vitima)|me enganaram"
)
INCIDENT_LOW = re.compile(r"\b(cliquei|abri|baixei|instalei|acessei)\b")
FOLLOW_CUES = re.compile(
    r"\b(e se|e agora|e depois|entao|isso|esse|essa|esses|essas|aquele|aquela|mesmo|tambem|outro|outra|"
    r"antes|depois|ja|nele|nela|dele|dela|nisso|disso|ainda|mas)\b"
)

INCIDENT_HIGH_STEPS = [
    "Ligue agora para o seu banco, pelo número oficial do cartão ou do aplicativo, e conte o que aconteceu.",
    "Se enviou Pix, peça o bloqueio e a contestação do valor (MED) o quanto antes.",
    "Troque as senhas das contas envolvidas, de preferência usando outro aparelho.",
    "Registre um boletim de ocorrência (pode ser online) e guarde as mensagens como prova.",
    "Avise familiares e contatos, caso alguém possa receber mensagens em seu nome.",
]
INCIDENT_LOW_STEPS = [
    "Feche a página ou o aplicativo e não digite nenhum dado nele.",
    "Se baixou ou instalou algo, desinstale e rode um antivírus confiável.",
    "Se digitou senha ou código em algum lugar, troque a senha por outro aparelho.",
    "Fique atento a movimentações estranhas no banco nos próximos dias.",
]
CLARIFY_REPLY = (
    "Posso ajudar com isso! Para analisar com segurança, preciso de mais detalhes. Cole aqui o texto da "
    "mensagem ou o endereço do site, ou me conte o que aconteceu: quem entrou em contato, como e o que foi pedido."
)
FOLLOWUP_REPLY = "Entendi a sua pergunta. Para orientar com segurança, conte um pouco mais: o que aconteceu, quem entrou em contato e o que foi pedido."
FOLLOWUP_STEPS = ["Não clique em links nem responda.", "Não passe códigos, senhas ou dados.", "Confirme pelos canais oficiais."]
OFF_TOPIC_REPLIES = [
    "Desculpe, mas esse assunto foge do meu objetivo. Eu sou o CyberGuard e só posso ajudar com segurança "
    "digital: golpes, mensagens e links suspeitos, senhas, Pix, WhatsApp, compras online e proteção de dados. "
    "Se tiver alguma dúvida nessa área, pode perguntar!",
    "Esse não é um assunto em que eu possa ajudar: meu foco é exclusivamente segurança digital. Posso analisar "
    "uma mensagem ou link suspeito, explicar como evitar golpes ou orientar sobre senhas e Pix. O que você "
    "gostaria de verificar?",
]
# (nome, padrão, máximo de palavras, respostas). A resposta é escolhida de forma estável pelo tamanho do histórico.
SMALLTALK = [
    ("farewell", re.compile(r"^\W*(tchau|ate (logo|mais|breve|amanha)|adeus|falou|flw)\b"), 8, [
        "Até logo! Cuide-se e, na dúvida, confirme sempre pelos canais oficiais.",
        "Tchau! Se aparecer qualquer mensagem ou ligação suspeita, volte aqui antes de agir."]),
    ("thanks", re.compile(
        r"^\W*(entendi|entendido|compreendi|obrigad[oa]|obrigadissim[oa]|brigad[oa]|valeu|muito obrigad[oa]|ok|"
        r"okay|certo|certinho|beleza|blz|perfeito|show|legal|otimo|ajudou|era so isso|so isso|tudo certo|"
        r"combinado|anotado|fechado|bom saber|muito bom|ficou claro|ta bom|esta bem|tudo bem entao)\b"), 10, [
        "De nada! Fico feliz em ajudar. Sempre que receber uma mensagem, um link ou uma ligação estranha, mostre aqui antes de agir.",
        "Por nada! Lembre-se: na dúvida, não clique, não pague e não passe códigos. Se aparecer algo suspeito, estou por aqui.",
        "Disponha! Se surgir qualquer outra dúvida sobre segurança digital, é só escrever."]),
    ("confused", re.compile(
        r"(nao entendi|nao compreendi|nao ficou claro|explica (melhor|de novo)|explique (melhor|de novo)|"
        r"pode repetir|nao sei o que fazer)"), 12, [
        "Sem problema, vou explicar de outro jeito: na dúvida, não clique em nada, não passe códigos e não faça "
        "pagamentos. Procure o banco ou a empresa pelo telefone oficial. Se quiser, diga qual ponto ficou confuso "
        "ou cole a mensagem de novo."]),
    ("about", re.compile(
        r"(quem e (voce|vc)|o que (voce|vc) (faz|pode|sabe)|como (voce|vc) (funciona|pode)|pode me ajudar|"
        r"voce pode ajudar|para que serve|me ajuda|preciso de ajuda)"), 12, [
        "Eu sou o CyberGuard, um assistente de segurança digital. Posso analisar mensagens, links e ligações "
        "suspeitas, explicar golpes como o do Pix e do WhatsApp clonado, e orientar sobre senhas e compras online. "
        "É só colar aqui o que você recebeu ou contar o que aconteceu."]),
    ("greeting", re.compile(r"^\W*(oi|ola|opa|oie|e ai|bom dia|boa tarde|boa noite|tudo bem|como vai)\b"), 6, [
        "Olá! Eu sou o CyberGuard. Cole aqui a mensagem, o link ou a situação que deixou você em dúvida, e eu "
        "ajudo a verificar se pode ser golpe."]),
    ("yesno", re.compile(r"^\W*(sim|nao|talvez|pode ser|acho que sim|acho que nao)\W*$"), 4, [
        "Entendi. Pode me contar um pouco mais? Se for sobre uma mensagem, link ou ligação suspeita, cole aqui o "
        "texto que você recebeu e eu analiso."]),
]


def pick(options, history):
    """Escolhe uma resposta de forma estável, variando conforme o tamanho da conversa."""
    return options[len(history) % len(options)]


def _history_messages(history):
    return [{"role": m["role"], "content": m["content"]} for m in history[-8:]]


def generate_answer(user_text, history=None):
    """Gera a resposta do assistente.

    history: lista de dicts {"role", "content", "risk"} com as mensagens anteriores da conversa.
    Retorna (texto, veredito). O veredito é None em respostas de conversa, sem selo de risco.
    """
    history = list(history or [])
    normalized = normalize_text(user_text)
    words = normalized.split()

    # 1) Links: conferência objetiva, funciona sem chave de API.
    link = analyze_known_link(user_text)
    if link:
        return link
    # 2) Quem já clicou, informou dados ou pagou precisa de orientação imediata.
    if INCIDENT_HIGH.search(normalized):
        return compose("Calma, e aja rápido: quanto antes, maiores as chances de reduzir o prejuízo.",
                       None, INCIDENT_HIGH_STEPS, "Se quiser, explico cada passo com calma."), "PERIGO"
    if INCIDENT_LOW.search(normalized):
        return compose("Você clicou, mas isso nem sempre significa que algo foi roubado. Vamos com calma.",
                       None, INCIDENT_LOW_STEPS,
                       "Se você digitou senha, código ou dados, me conte: aí o risco é maior."), "CUIDADO"

    verdict, reasons = assess_message(user_text)
    topical = bool(TOPIC_PATTERN.search(normalized)) or verdict == "PERIGO" or len(reasons) >= 2

    # 3) Conversa social (agradecer, cumprimentar, despedir), apenas quando não há tema de segurança.
    if not topical:
        for name, pattern, max_words, replies in SMALLTALK:
            if len(words) <= max_words and pattern.search(normalized):
                if name == "thanks" and "?" in user_text:
                    continue
                return pick(replies, history), None

    # 4) Perguntas de continuação dependem do contexto da conversa.
    last_assistant = next((m for m in reversed(history) if m["role"] == "assistant"), None)
    followup = bool(last_assistant and last_assistant.get("risk") and len(words) <= 15
                    and FOLLOW_CUES.search(normalized))

    # 5) Assunto fora do objetivo do sistema.
    if not topical and not followup:
        return pick(OFF_TOPIC_REPLIES, history), None

    # 6) Perguntas frequentes com respostas prontas.
    if verdict != "PERIGO":
        faq = answer_faq(user_text)
        if faq:
            return faq, "INFO"
    store_answer = answer_store_reliability_question(user_text)
    if store_answer:
        return store_answer, "INFO"

    # 7) Integração opcional com OpenAI. O sistema permanece funcional sem a chave.
    api_key = os.getenv("OPENAI_API_KEY")
    if api_key:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            hint = "; ".join(reasons) if reasons else "nenhum"
            messages = _history_messages(history) + [{
                "role": "user",
                "content": f"Sinais detectados automaticamente: {hint}\n\nMensagem da pessoa:\n{user_text}"}]
            response = client.responses.create(
                model=os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
                instructions=AI_INSTRUCTIONS,
                input=messages,
            )
            raw = response.output_text.strip().replace("**", "")
            match = re.match(r"^\s*\[?VEREDITO:\s*(PERIGO|CUIDADO|SEGURO|INFO)\]?\s*", raw, re.I)
            ai_verdict = match.group(1).upper() if match else "INFO"
            body = raw[match.end():].strip() if match else raw
            if body:
                # A IA nunca deve rebaixar um alerta grave detectado pelas regras locais.
                return body, worst(ai_verdict, verdict)
        except Exception:
            pass

    # 8) Plano B local.
    if followup and verdict is None:
        return compose(FOLLOWUP_REPLY, None, FOLLOWUP_STEPS, "Pode me contar mais detalhes quando quiser."), None
    if verdict is None and len(words) < 12:
        return CLARIFY_REPLY, None
    return local_answer(verdict, reasons), verdict or "CUIDADO"
