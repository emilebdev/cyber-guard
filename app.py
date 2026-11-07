import os
from datetime import datetime
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_

from analyzer import VERDICT_LABELS, generate_answer, verdict_code

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "troque-esta-chave-em-producao")
database_url = os.getenv("DATABASE_URL", "sqlite:///cyberguard.db")
if database_url.startswith("mysql://"):
    database_url = database_url.replace("mysql://", "mysql+pymysql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(160), default="Nova análise")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    messages = db.relationship("Message", backref="conversation", lazy=True,
                               cascade="all, delete-orphan", order_by="Message.created_at")


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey("conversation.id"), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    content = db.Column(db.Text, nullable=False)
    risk = db.Column(db.String(30))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Knowledge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(180), nullable=False)
    category = db.Column(db.String(80), nullable=False)
    summary = db.Column(db.Text, nullable=False)
    content = db.Column(db.Text, nullable=False)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def current_user():
    return db.session.get(User, session.get("user_id"))


def seed_data():
    demo_email = "teste@cyberguard.local"
    demo = User.query.filter_by(email=demo_email).first()
    if not demo:
        demo = User(name="Usuário Demonstrativo", email=demo_email,
                    password_hash=generate_password_hash("Teste@123"))
        db.session.add(demo)

    articles = [
        ("Como identificar phishing", "Golpes por mensagem",
         "Phishing tenta enganar você para revelar dados ou clicar em links.",
         "Desconfie de mensagens inesperadas que pedem senhas, códigos ou dados bancários. Observe erros, remetentes estranhos, urgência e links diferentes do endereço oficial. Não clique. Abra o aplicativo ou digite o endereço oficial por conta própria."),
        ("Golpe do falso suporte", "Golpes telefônicos",
         "Criminosos fingem ser funcionários de bancos, lojas ou empresas de tecnologia.",
         "Nunca informe senhas, códigos de autenticação ou tokens a alguém que ligou para você. Encerre a ligação e procure o canal oficial impresso no cartão ou no site verdadeiro."),
        ("Proteja suas senhas", "Proteção de contas",
         "Senhas fortes e únicas dificultam invasões.",
         "Use uma senha diferente para cada serviço, prefira frases longas e ative a autenticação em dois fatores. Um gerenciador de senhas pode ajudar. Nunca compartilhe códigos recebidos por SMS ou aplicativo."),
        ("Compras pela internet", "Compras seguras",
         "Ofertas muito abaixo do preço e pressão para pagar rápido podem indicar fraude.",
         "Pesquise a reputação da loja, confira o endereço do site, desconfie de pagamentos para pessoas físicas e prefira meios de pagamento com proteção. Não confie apenas em comentários publicados na própria loja."),
        ("Golpe do Pix", "Fraudes financeiras",
         "Golpistas usam urgência, comprovantes falsos e histórias emocionais para obter transferências.",
         "Confira o nome do destinatário e os dados no aplicativo do banco antes de confirmar. Comprovante enviado por outra pessoa não significa que o dinheiro caiu. Em caso de suspeita, fale com seu banco pelos canais oficiais.")
    ]
    for title, category, summary, content in articles:
        if not Knowledge.query.filter_by(title=title).first():
            db.session.add(Knowledge(title=title, category=category, summary=summary, content=content))
    db.session.commit()


app.jinja_env.filters["vcode"] = verdict_code
app.jinja_env.globals["VERDICT_LABELS"] = VERDICT_LABELS


@app.context_processor
def inject_sidebar_conversations():
    if "user_id" not in session:
        return {}
    recent = (Conversation.query.filter_by(user_id=session["user_id"])
              .order_by(Conversation.created_at.desc()).limit(12).all())
    return {"sidebar_conversations": recent}


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session["user_id"] = user.id
            session["user_name"] = user.name
            flash("Acesso realizado com sucesso.", "success")
            return redirect(url_for("dashboard"))
        flash("E-mail ou senha incorretos. Confira os dados e tente novamente.", "error")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or not email or len(password) < 8:
            flash("Preencha todos os campos. A senha deve ter pelo menos 8 caracteres.", "error")
        elif User.query.filter_by(email=email).first():
            flash("Este e-mail já está cadastrado.", "error")
        else:
            user = User(name=name, email=email,
                        password_hash=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            session["user_id"] = user.id
            session["user_name"] = user.name
            return redirect(url_for("dashboard"))
    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    conversations = Conversation.query.filter_by(user_id=user.id).order_by(Conversation.created_at.desc()).limit(6).all()
    articles = Knowledge.query.limit(3).all()
    return render_template("dashboard.html", user=user, conversations=conversations, articles=articles)


@app.route("/chat")
@login_required
def chat():
    conversations = Conversation.query.filter_by(user_id=session["user_id"]).order_by(Conversation.created_at.desc()).all()
    conversation_id = request.args.get("id", type=int)
    active = None
    if conversation_id:
        active = Conversation.query.filter_by(id=conversation_id, user_id=session["user_id"]).first_or_404()
    return render_template("chat.html", conversations=conversations, active=active)


@app.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    data = request.get_json(silent=True) or {}
    text = (data.get("message") or "").strip()
    conversation_id = data.get("conversation_id")
    if not text:
        return jsonify({"error": "Digite uma mensagem para continuar."}), 400
    if len(text) > 5000:
        return jsonify({"error": "A mensagem deve ter no máximo 5.000 caracteres."}), 400

    conversation = None
    if conversation_id:
        conversation = Conversation.query.filter_by(
            id=conversation_id, user_id=session["user_id"]).first()
    if not conversation:
        title = text[:55] + ("..." if len(text) > 55 else "")
        conversation = Conversation(user_id=session["user_id"], title=title or "Nova análise")
        db.session.add(conversation)
        db.session.flush()

    history = [{"role": m.role, "content": m.content, "risk": m.risk}
               for m in conversation.messages[-8:]]
    db.session.add(Message(conversation_id=conversation.id, role="user", content=text))
    answer, risk = generate_answer(text, history)
    db.session.add(Message(conversation_id=conversation.id, role="assistant", content=answer, risk=risk))
    db.session.commit()
    return jsonify({
        "conversation_id": conversation.id,
        "answer": answer,
        "risk": risk,
        "redirect": url_for("chat", id=conversation.id)
    })


@app.route("/history")
@login_required
def history():
    conversations = Conversation.query.filter_by(user_id=session["user_id"]).order_by(Conversation.created_at.desc()).all()
    return render_template("history.html", conversations=conversations)


@app.route("/conversation/<int:conversation_id>/delete", methods=["POST"])
@login_required
def delete_conversation(conversation_id):
    conversation = Conversation.query.filter_by(id=conversation_id, user_id=session["user_id"]).first_or_404()
    db.session.delete(conversation)
    db.session.commit()
    flash("Conversa excluída.", "success")
    return redirect(url_for("history"))


@app.route("/knowledge")
@login_required
def knowledge():
    query = request.args.get("q", "").strip()
    articles_query = Knowledge.query
    if query:
        articles_query = articles_query.filter(or_(
            Knowledge.title.ilike(f"%{query}%"),
            Knowledge.category.ilike(f"%{query}%"),
            Knowledge.summary.ilike(f"%{query}%")
        ))
    articles = articles_query.order_by(Knowledge.category, Knowledge.title).all()
    return render_template("knowledge.html", articles=articles, query=query)


@app.route("/article/<int:article_id>")
@login_required
def article(article_id):
    item = db.get_or_404(Knowledge, article_id)
    return render_template("article.html", article=item)


with app.app_context():
    db.create_all()
    seed_data()


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "1") == "1")
