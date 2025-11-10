from datetime import UTC, datetime
from functools import wraps
import logging
import os

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from sqlalchemy import inspect, text
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "chat.db")

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)


app = Flask(__name__)
app.secret_key = "dev-secret-key"
app.config.update(
    SQLALCHEMY_DATABASE_URI=f"sqlite:///{DB_PATH}",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")


def utcnow() -> datetime:
    return datetime.now(UTC)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def verify_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    username = db.Column(db.String(80), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


def init_db() -> None:
    with app.app_context():
        db.create_all()
        migrate_message_table()
        app.config["DB_READY"] = True


@app.before_request
def ensure_database_ready():
    if not app.config.get("DB_READY"):
        db.create_all()
        migrate_message_table()
        app.config["DB_READY"] = True
        logging.info("Database tables ensured.")


def migrate_message_table() -> None:
    inspector = inspect(db.engine)
    if "message" not in inspector.get_table_names():
        return
    columns = [col["name"] for col in inspector.get_columns("message")]
    if "room" not in columns:
        return
    with db.engine.begin() as conn:
        conn.execute(text("ALTER TABLE message RENAME TO message_old"))
        conn.execute(
            text(
                """
                CREATE TABLE message (
                    id INTEGER PRIMARY KEY,
                    content TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    username VARCHAR(80) NOT NULL,
                    user_id INTEGER NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES user (id)
                )
                """
            )
        )
        conn.execute(
            text(
                """
                INSERT INTO message (id, content, timestamp, username, user_id)
                SELECT id, content, timestamp, username, user_id
                FROM message_old
                """
            )
        )
        conn.execute(text("DROP TABLE message_old"))
    logging.info("Migrated message table to remove unused room column.")


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped_view


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("chat"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            return render_template(
                "register.html", error="Username dan password wajib diisi."
            )

        if User.query.filter_by(username=username).first():
            return render_template("register.html", error="Username sudah digunakan.")

        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        logging.info("User registered: %s", username)

        session["user_id"] = user.id
        session["username"] = user.username
        return redirect(url_for("chat"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if not user or not user.verify_password(password):
            return render_template("login.html", error="Kredensial tidak valid.")

        session["user_id"] = user.id
        session["username"] = user.username
        logging.info("User logged in: %s", username)
        return redirect(url_for("chat"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    username = session.get("username")
    session.clear()
    if username:
        logging.info("User logged out: %s", username)
    else:
        logging.info("User logged out.")
    return redirect(url_for("login"))


@app.route("/chat")
@login_required
def chat():
    return render_template("chat.html", username=session.get("username"))


@app.get("/messages")
@login_required
def fetch_messages():
    messages = Message.query.order_by(Message.timestamp.asc()).limit(100).all()
    payload = [
        {
            "id": msg.id,
            "username": msg.username,
            "content": msg.content,
            "timestamp": msg.timestamp.isoformat(),
        }
        for msg in messages
    ]
    logging.info("Messages requested (global chat).")
    return jsonify(payload)


@socketio.on("connect")
def handle_connect():
    username = session.get("username")
    if not username:
        logging.warning("Unauthorized socket connection attempt.")
        return False
    logging.info("%s connected to chat", username)
    emit(
        "system",
        {
            "message": f"{username} bergabung ke chat.",
            "timestamp": utcnow().isoformat(),
        },
        broadcast=True,
    )


@socketio.on("disconnect")
def handle_disconnect():
    username = session.get("username")
    if not username:
        return
    logging.info("%s disconnected from chat", username)
    emit(
        "system",
        {
            "message": f"{username} meninggalkan chat.",
            "timestamp": utcnow().isoformat(),
        },
        broadcast=True,
    )


@socketio.on("send_message")
def handle_send_message(data):
    content = data.get("message", "").strip()
    username = session.get("username")
    user_id = session.get("user_id")

    if not content or not username or not user_id:
        return

    message = Message(content=content, username=username, user_id=user_id)
    db.session.add(message)
    db.session.commit()
    logging.info("%s sent message", username)

    emit(
        "new_message",
        {
            "username": username,
            "content": content,
            "timestamp": message.timestamp.isoformat(),
        },
        broadcast=True,
    )


if __name__ == "__main__":
    init_db()
    logging.info("Starting Flask-SocketIO server on port 1234")
    socketio.run(app, host="0.0.0.0", port=1234)
