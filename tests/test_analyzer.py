"""Testes do motor de análise do CyberGuard (não exigem Flask nem banco de dados)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.pop("OPENAI_API_KEY", None)  # os testes validam o funcionamento sem IA externa

from analyzer import generate_answer, verdict_code  # noqa: E402


def ask(text, history=None):
    return generate_answer(text, history or [])


# ---------- conversa natural ----------
@pytest.mark.parametrize("text", ["Entendi, obrigada", "obrigado!", "valeu", "ok, entendi", "Certo, muito bom"])
def test_agradecimento_recebe_resposta_cordial_sem_selo(text):
    answer, verdict = ask(text)
    assert verdict is None
    assert "foge do meu objetivo" not in answer
    assert answer.startswith(("De nada", "Por nada", "Disponha"))


@pytest.mark.parametrize("text", ["Bom dia", "Oi", "boa tarde, tudo bem?"])
def test_saudacao(text):
    answer, verdict = ask(text)
    assert verdict is None and answer.startswith("Olá")


def test_despedida():
    answer, verdict = ask("Tchau, até logo")
    assert verdict is None and ("Até logo" in answer or "Tchau" in answer)


def test_respostas_variam_ao_longo_da_conversa():
    first, _ = ask("obrigada", [])
    history = [{"role": "user", "content": "x", "risk": None}, {"role": "assistant", "content": first, "risk": None}]
    second, _ = ask("obrigada", history)
    assert first != second


# ---------- escopo: somente segurança digital ----------
@pytest.mark.parametrize("text", [
    "Qual a capital da França?",
    "Me conte uma piada",
    "Quem ganhou o jogo ontem?",
    "Como fazer um bolo de chocolate?",
    "Qual é a receita de feijoada?",
])
def test_assunto_fora_do_tema_explica_o_objetivo(text):
    answer, verdict = ask(text)
    assert verdict is None
    assert "segurança digital" in answer
    assert "Sinais encontrados" not in answer


# ---------- análise de mensagens ----------
def test_pedido_de_codigo_e_alto_risco():
    answer, verdict = ask("Estão pedindo um código que chegou no meu celular. O que faço?")
    assert verdict == "PERIGO"
    assert "O que fazer" in answer


def test_varios_sinais_de_golpe():
    answer, verdict = ask("Sua conta será bloqueada hoje mesmo. Clique aqui e informe sua senha")
    assert verdict == "PERIGO"


def test_um_sinal_gera_cuidado():
    _, verdict = ask("Recebi uma mensagem falando em pagamento de uma taxa")
    assert verdict in ("CUIDADO", "PERIGO")


# ---------- links ----------
@pytest.mark.parametrize("text", [
    "https://www.magazineluiza.com.br/oferta",
    "Esse link é seguro? www.magalu.com.br/produto",
    "magalu.com.br/produto é confiável?",
    "magazineluiza.com.br",
])
def test_dominios_oficiais_da_magalu(text):
    answer, verdict = ask(text)
    assert verdict == "SEGURO"
    assert "domínio conhecido" in answer


def test_site_que_imita_marca_e_alto_risco():
    _, verdict = ask("https://magazineluiza-promo.xyz/ganhe")
    assert verdict == "PERIGO"


def test_encurtador_gera_cuidado():
    _, verdict = ask("me mandaram bit.ly/abc123")
    assert verdict in ("CUIDADO", "PERIGO")


def test_email_nao_e_tratado_como_link():
    answer, _ = ask("fale com joao@gmail.com")
    assert "encurtador" not in answer and "domínio" not in answer


def test_resposta_nunca_tem_barra_n_literal():
    for text in ["https://bit.ly/x clique aqui", "www.magazineluiza.com.br", "me ligaram pedindo pix urgente"]:
        answer, _ = ask(text)
        assert "\\n" not in answer


# ---------- quem já caiu no golpe ----------
def test_ja_passou_codigo_recebe_passos_urgentes():
    answer, verdict = ask("Eu já passei o código para o golpista")
    assert verdict == "PERIGO" and "banco" in answer


def test_apenas_clicou_recebe_orientacao_calma():
    answer, verdict = ask("e se eu já cliquei no link?")
    assert verdict == "CUIDADO" and "antivírus" in answer


# ---------- perguntas gerais e continuação ----------
def test_pergunta_geral_usa_resposta_pronta():
    answer, verdict = ask("O que é phishing?")
    assert verdict == "INFO" and "Phishing" in answer


def test_pergunta_de_continuacao_usa_o_contexto():
    history = [{"role": "user", "content": "Me ligaram pedindo Pix", "risk": None},
               {"role": "assistant", "content": "Isso tem características de golpe.", "risk": "PERIGO"}]
    answer, verdict = ask("e agora, o que eu faço?", history)
    assert verdict is None and "conte um pouco mais" in answer


def test_pedido_vago_de_ajuda_pede_detalhes():
    answer, verdict = ask("Esse site é confiável?")
    assert verdict is None and "Cole aqui" in answer


# ---------- compatibilidade ----------
def test_selos_de_conversas_antigas():
    assert verdict_code("Alto") == "PERIGO"
    assert verdict_code("Moderado") == "CUIDADO"
    assert verdict_code("PERIGO") == "PERIGO"
    assert verdict_code(None) == ""
