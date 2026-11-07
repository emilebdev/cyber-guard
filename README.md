# CyberGuard — Assistente de Segurança Digital

Projeto demonstrativo de extensão: plataforma educativa para orientar usuários na identificação de possíveis golpes digitais.

## Funcionalidades
- Cadastro e login com senhas armazenadas usando hash.
- Conta demonstrativa criada automaticamente.
- Painel inicial responsivo.
- Chat com análise preliminar de risco.
- Histórico persistente de conversas por usuário.
- Central de conhecimento pesquisável.
- Tema claro/escuro com preferência salva no navegador.
- Botão **A+** que aumenta a letra em três tamanhos (preferência salva no navegador).
- Selo de veredito em cada resposta: Alto risco, Risco moderado, Sem sinais de golpe ou Orientação.
- Conversa natural: responde a agradecimentos, saudações e despedidas, entende perguntas de continuação usando o histórico da conversa e orienta quem já clicou, informou dados ou fez um Pix.
- Escopo restrito: assuntos que não sejam segurança digital recebem uma resposta educada explicando o objetivo do sistema.
- Respostas prontas para dúvidas comuns (phishing, Pix, WhatsApp clonado, senhas, Wi-Fi público, ligações falsas e vírus).
- Conferência de links: reconhece endereços com ou sem `www.`/`https://`, aceita todos os domínios oficiais de cada marca e alerta sobre sites que imitam marcas conhecidas e sobre encurtadores.
- Exclusão de conversas pelo histórico, com confirmação.
- SQLite por padrão e configuração opcional para MySQL.
- Integração opcional com API OpenAI; sem chave, utiliza mecanismo heurístico local.

## Requisitos
- Python 3.10 ou superior.
- Navegador atualizado.
- Internet apenas para Google Fonts e, se habilitada, API de IA.

## Instalação no Windows (modo rápido)

1. Extraia o ZIP.
2. Dê dois cliques em `iniciar_windows.bat`. Ele cria o ambiente virtual, instala as dependências, cria `.env` se necessário e inicia o servidor.
3. Acesse http://127.0.0.1:5000.

## Instalação manual no Windows (VS Code)

1. Extraia o ZIP e abra a pasta `CyberGuard` no VS Code.
2. Abra o terminal na pasta do projeto.
3. Crie o ambiente virtual:

   ```powershell
   python -m venv venv
   ```

4. Ative:

   ```powershell
   .\venv\Scripts\Activate.ps1
   ```

   Se o PowerShell bloquear a execução, use o terminal CMD e execute:

   ```cmd
   venv\Scripts\activate.bat
   ```

5. Instale as dependências:

   ```bash
   pip install -r requirements.txt
   ```

6. Copie `.env.example` para `.env`. No Windows, pode usar:

   ```powershell
   Copy-Item .env.example .env
   ```

7. Edite `SECRET_KEY` no `.env` e mantenha `FLASK_DEBUG=1` somente no desenvolvimento.
8. Inicie:

   ```bash
   python app.py
   ```

9. Acesse http://127.0.0.1:5000

O banco SQLite `cyberguard.db` e os conteúdos iniciais são criados automaticamente.

## Acesso demonstrativo
- E-mail: `teste@cyberguard.local`
- Senha: `Teste@123`

Altere ou remova essa conta antes de disponibilizar o sistema publicamente.

## Habilitar IA generativa (opcional)
1. Configure uma chave válida em `OPENAI_API_KEY` no `.env`.
2. Opcionalmente ajuste `OPENAI_MODEL`.
3. Reinicie o servidor.

Sem a chave, o chat usa regras locais demonstrativas. A análise local é baseada em palavras e padrões simples, não consulta reputação real de URLs, telefones, domínios ou remetentes.

## Usar MySQL (opcional)
1. Crie um banco, por exemplo `cyberguard`.
2. Instale as dependências de `requirements.txt`.
3. No `.env`, configure:

   ```env
   DATABASE_URL=mysql+pymysql://USUARIO:SENHA@localhost/cyberguard
   ```

4. Reinicie a aplicação.

## Estrutura
```text
CyberGuard/
├── app.py                  # Rotas, modelos e banco de dados (Flask)
├── analyzer.py             # Motor de análise e conversa (Python puro, testável)
├── requirements.txt
├── requirements-dev.txt    # Dependências de desenvolvimento (pytest)
├── pytest.ini
├── .env.example
├── .github/workflows/tests.yml   # Testes automáticos no GitHub
├── tests/
│   └── test_analyzer.py
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── chat.html
│   ├── history.html
│   ├── knowledge.html
│   └── article.html
└── static/
    ├── css/style.css
    └── js/
        ├── app.js
        └── chat.js
```

## Testes
O motor de análise (`analyzer.py`) tem testes automatizados que não exigem banco de dados nem internet.
```bash
pip install -r requirements-dev.txt
python -m pytest
```
Os testes cobrem conversa natural, escopo do assunto, análise de mensagens, conferência de links e orientação a quem já caiu em golpe.

## Limitações e cuidados
- A avaliação sem IA é apenas uma triagem educativa por palavras-chave. Não deve ser apresentada como detector infalível.
- Mesmo com IA, o sistema não confirma sozinho a segurança de um link ou identidade.
- Não inserir dados pessoais, senhas, códigos bancários ou informações sensíveis em demonstrações.
- Antes de produção: usar HTTPS, chave secreta forte, proteção CSRF, limitação de tentativas de login, política de privacidade, revisão de segurança, backups e configuração de servidor apropriada.
- A conta demonstrativa é pública por definição e não deve conter dados reais.
