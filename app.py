import os
import sqlite3
import hashlib
import base64
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image
from cryptography.fernet import Fernet, InvalidToken

app = Flask(__name__)
app.secret_key = "change-this-secret-key"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "outputs")
DB_PATH = os.path.join(BASE_DIR, "users.db")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

MAGIC = b"STEG"
ALLOWED_EXTENSIONS = {"png", "bmp"}  # Use lossless images only


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first.")
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def get_current_user():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()
    return user


def make_fernet_key(password_hash):
    """
    Requirement: use the password hash as encryption key.
    Fernet needs a 32-byte url-safe base64 key, so we derive it from the stored password hash.
    """
    digest = hashlib.sha256(password_hash.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def text_to_bits(data: bytes):
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits):
    output = bytearray()
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i + 8]
        value = 0
        for bit in byte_bits:
            value = (value << 1) | bit
        output.append(value)
    return bytes(output)


def encode_image(image_path, encrypted_text: bytes, output_path):
    image = Image.open(image_path).convert("RGB")
    pixels = image.load()
    width, height = image.size

    payload = MAGIC + len(encrypted_text).to_bytes(4, "big") + encrypted_text
    bits = text_to_bits(payload)
    capacity = width * height * 3

    if len(bits) > capacity:
        raise ValueError("Message is too large for this image. Use a bigger PNG/BMP image.")

    bit_index = 0
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            channels = [r, g, b]
            for c in range(3):
                if bit_index < len(bits):
                    channels[c] = (channels[c] & 0b11111110) | bits[bit_index]
                    bit_index += 1
            pixels[x, y] = tuple(channels)
            if bit_index >= len(bits):
                image.save(output_path)
                return


def decode_image(image_path):
    image = Image.open(image_path).convert("RGB")
    pixels = image.load()
    width, height = image.size

    all_bits = []
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            all_bits.extend([r & 1, g & 1, b & 1])

    header_bits = all_bits[:64]  # MAGIC 4 bytes + LENGTH 4 bytes
    header = bits_to_bytes(header_bits)

    if len(header) < 8 or header[:4] != MAGIC:
        raise ValueError("No hidden data found, or this image was changed/corrupted.")

    data_length = int.from_bytes(header[4:8], "big")
    start = 64
    end = start + data_length * 8
    encrypted_bits = all_bits[start:end]

    if len(encrypted_bits) < data_length * 8:
        raise ValueError("Hidden data is incomplete or corrupted.")

    return bits_to_bytes(encrypted_bits)


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        try:
            conn = get_db()
            conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
            conn.commit()
            conn.close()
            flash("Account created. Please login.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists.")
            return redirect(url_for("register"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session.get("username"))


@app.route("/encode", methods=["POST"])
@login_required
def encode():
    image = request.files.get("image")
    secret_text = request.form.get("secret_text", "")

    if not image or image.filename == "" or not secret_text:
        flash("Please upload an image and enter secret text.")
        return redirect(url_for("dashboard"))

    if not allowed_file(image.filename):
        flash("Only PNG and BMP images are allowed because JPG compression destroys hidden bits.")
        return redirect(url_for("dashboard"))

    filename = secure_filename(image.filename)
    input_path = os.path.join(UPLOAD_FOLDER, filename)
    image.save(input_path)

    user = get_current_user()
    key = make_fernet_key(user["password_hash"])
    encrypted_text = Fernet(key).encrypt(secret_text.encode("utf-8"))

    output_filename = "encoded_" + os.path.splitext(filename)[0] + ".png"
    output_path = os.path.join(OUTPUT_FOLDER, output_filename)

    try:
        encode_image(input_path, encrypted_text, output_path)
        return render_template("result.html", filename=output_filename)
    except Exception as e:
        flash(str(e))
        return redirect(url_for("dashboard"))


@app.route("/decode", methods=["POST"])
@login_required
def decode():
    image = request.files.get("encoded_image")

    if not image or image.filename == "":
        flash("Please upload an encoded image.")
        return redirect(url_for("dashboard"))

    filename = secure_filename(image.filename)
    input_path = os.path.join(UPLOAD_FOLDER, "decode_" + filename)
    image.save(input_path)

    user = get_current_user()
    key = make_fernet_key(user["password_hash"])

    try:
        encrypted_text = decode_image(input_path)
        secret_text = Fernet(key).decrypt(encrypted_text).decode("utf-8")
        return render_template("decoded.html", secret_text=secret_text)
    except InvalidToken:
        flash("Data found, but it cannot be decrypted with this logged-in user's password hash.")
        return redirect(url_for("dashboard"))
    except Exception as e:
        flash(str(e))
        return redirect(url_for("dashboard"))


@app.route("/download/<filename>")
@login_required
def download(filename):
    return send_from_directory(OUTPUT_FOLDER, filename, as_attachment=True)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
