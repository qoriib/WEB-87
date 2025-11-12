from datetime import datetime
from functools import wraps
import base64
import hashlib
import logging
import os
from zoneinfo import ZoneInfo

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
from flask_socketio import SocketIO, emit, join_room
from sqlalchemy import and_, inspect, or_, text
from werkzeug.security import check_password_hash, generate_password_hash
from cryptography.fernet import Fernet, InvalidToken


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)
DB_PATH = os.path.join(INSTANCE_DIR, "chat.db")

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)


app = Flask(__name__)
app.secret_key = "dev-secret-key"
app.config.update(
    SQLALCHEMY_DATABASE_URI=f"sqlite:///{DB_PATH}",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)
app.config["FERNET_KEY"] = os.environ.get("FERNET_KEY")

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

WIB = ZoneInfo("Asia/Jakarta")


def now_wib() -> datetime:
    return datetime.now(WIB)


def _get_fernet_key() -> bytes:
    key = app.config.get("FERNET_KEY")
    if key:
        return key.encode()
    derived = hashlib.sha256(app.secret_key.encode()).digest()
    encoded = base64.urlsafe_b64encode(derived)
    app.config["FERNET_KEY"] = encoded.decode()
    return encoded


def _cipher() -> Fernet:
    return Fernet(_get_fernet_key())


def encrypt_message(value: str) -> str:
    return _cipher().encrypt(value.encode()).decode()


def decrypt_message(value: str) -> str:
    try:
        return _cipher().decrypt(value.encode()).decode()
    except InvalidToken:
        logging.warning("Failed to decrypt message; returning raw content.")
        return value


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def verify_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), default=now_wib, nullable=False)

    sender = db.relationship("User", foreign_keys=[sender_id], backref="sent_messages")
    receiver = db.relationship(
        "User", foreign_keys=[receiver_id], backref="received_messages"
    )


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
    desired = {"id", "sender_id", "receiver_id", "content", "timestamp"}
    if set(columns) == desired:
        return
    with db.engine.begin() as conn:
        conn.execute(text("ALTER TABLE message RENAME TO message_old"))
        conn.execute(
            text(
                """
                CREATE TABLE message (
                    id INTEGER PRIMARY KEY,
                    sender_id INTEGER NOT NULL REFERENCES user (id),
                    receiver_id INTEGER NOT NULL REFERENCES user (id),
                    content TEXT NOT NULL,
                    timestamp DATETIME NOT NULL
                )
                """
            )
        )
        conn.execute(text("DROP TABLE message_old"))
    logging.info("Message table schema reset for private chat support.")


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
    return render_template(
        "chat.html", username=session.get("username"), user_id=session.get("user_id")
    )


@app.get("/users")
@login_required
def list_users():
    me_id = session.get("user_id")
    users = (
        User.query.filter(User.id != me_id)
        .order_by(User.username.asc())
        .with_entities(User.id, User.username)
        .all()
    )
    return jsonify([{"id": uid, "username": uname} for uid, uname in users])


@app.get("/messages/<int:other_user_id>")
@login_required
def fetch_private_messages(other_user_id: int):
    me_id = session.get("user_id")
    if other_user_id == me_id:
        return jsonify([])

    other_user = User.query.get(other_user_id)
    if not other_user:
        return jsonify([]), 404

    messages = (
        Message.query.filter(
            or_(
                and_(
                    Message.sender_id == me_id, Message.receiver_id == other_user_id
                ),
                and_(
                    Message.sender_id == other_user_id, Message.receiver_id == me_id
                ),
            )
        )
        .order_by(Message.timestamp.asc())
        .limit(200)
        .all()
    )

    payload = [
        {
            "id": msg.id,
            "sender_id": msg.sender_id,
            "receiver_id": msg.receiver_id,
            "sender": msg.sender.username,
            "receiver": msg.receiver.username,
            "content": decrypt_message(msg.content),
            "timestamp": msg.timestamp.isoformat(),
        }
        for msg in messages
    ]
    return jsonify(payload)


@socketio.on("connect")
def handle_connect():
    username = session.get("username")
    user_id = session.get("user_id")
    if not username or not user_id:
        logging.warning("Unauthorized socket connection attempt.")
        return False
    join_room(f"user:{user_id}")
    logging.info("%s connected to chat", username)
    emit(
        "system",
        {"message": "Terhubung ke server chat.", "timestamp": now_wib().isoformat()},
        to=f"user:{user_id}",
    )


@socketio.on("disconnect")
def handle_disconnect():
    username = session.get("username")
    if username:
        logging.info("%s disconnected from chat", username)


@socketio.on("send_message")
def handle_send_message(data):
    content = data.get("message", "").strip()
    target_id = data.get("to")
    username = session.get("username")
    user_id = session.get("user_id")

    if not content or not username or not user_id or not target_id:
        return

    if user_id == target_id:
        return

    target_user = User.query.get(target_id)
    if not target_user:
        return

    encrypted_content = encrypt_message(content)
    message = Message(
        sender_id=user_id, receiver_id=target_id, content=encrypted_content
    )
    db.session.add(message)
    db.session.commit()
    logging.info("%s sent message to %s", username, target_user.username)

    payload = {
        "id": message.id,
        "sender_id": user_id,
        "receiver_id": target_id,
        "sender": username,
        "receiver": target_user.username,
        "content": content,
        "timestamp": message.timestamp.isoformat(),
    }

    emit("new_message", payload, to=f"user:{user_id}")
    emit("new_message", payload, to=f"user:{target_id}")


if __name__ == "__main__":
    init_db()
    logging.info("Starting Flask-SocketIO server on port 1234")
    socketio.run(app, host="0.0.0.0", port=1234)
