import os, json, hashlib, secrets, base64, shutil
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.utils import secure_filename

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:
    boto3 = None
    BotoCoreError = ClientError = Exception

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
META_DIR = DATA_DIR / "metadata"
NODES = [DATA_DIR / f"node_{i}" for i in range(1, 4)]
for folder in [META_DIR, *NODES]:
    folder.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-demo-secret")
CHUNK_SIZE = 1024 * 1024  # 1 MiB per chunk
S3_BUCKET = os.environ.get("AWS_S3_BUCKET", "").strip()
S3_PREFIX = os.environ.get("AWS_S3_PREFIX", "cloudshield").strip("/")
CLOUDFRONT_DOMAIN = os.environ.get("CLOUDFRONT_DOMAIN", "").strip().rstrip("/")


def s3_client():
    """Return an AWS S3 client when boto3 and a bucket are configured."""
    if not (boto3 and S3_BUCKET):
        return None
    return boto3.client("s3", region_name=os.environ.get("AWS_REGION") or None)


def cloud_key(file_id, chunk_name):
    return f"{S3_PREFIX}/{file_id}/{chunk_name}" if S3_PREFIX else f"{file_id}/{chunk_name}"


def upload_encrypted_chunk_to_s3(file_id, chunk_name, data):
    client = s3_client()
    if client:
        client.put_object(Bucket=S3_BUCKET, Key=cloud_key(file_id, chunk_name), Body=data,
                          ServerSideEncryption="AES256", ContentType="application/octet-stream")
        return True
    return False


def read_encrypted_chunk(file_id, chunk):
    local_path = NODES[int(chunk["node"]) - 1] / chunk["file"]
    if local_path.exists():
        return local_path.read_bytes()
    client = s3_client()
    if client:
        response = client.get_object(Bucket=S3_BUCKET, Key=cloud_key(file_id, chunk["file"]))
        return response["Body"].read()
    raise FileNotFoundError(f"Missing chunk {chunk['index']} on local storage and S3 is not configured")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive_key(passphrase: str, salt: bytes) -> bytes:
    # PBKDF2 key derivation; AES-256-GCM uses the resulting 32-byte key.
    import hashlib as _hashlib
    return _hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 300_000, dklen=32)


def metadata_files():
    items = []
    for p in sorted(META_DIR.glob("*.json")):
        try:
            m = json.loads(p.read_text(encoding="utf-8"))
            total_chunks = len(m.get("chunks", []))
            stored_bytes = sum((NODES[int(c["node"]) - 1] / c["file"]).stat().st_size
                               for c in m.get("chunks", [])
                               if (NODES[int(c["node"]) - 1] / c["file"]).exists())
            items.append({
                "id": m["id"], "name": m["name"], "size": m["size"],
                "checksum": m["checksum"], "chunks": total_chunks,
                "stored_bytes": stored_bytes, "created": m.get("created", ""),
            })
        except Exception:
            continue
    return items


@app.route("/")
def dashboard():
    files = metadata_files()
    node_stats = []
    for i, node in enumerate(NODES, 1):
        used = sum(p.stat().st_size for p in node.iterdir() if p.is_file())
        node_stats.append({"name": f"Storage Node {i}", "files": sum(1 for p in node.iterdir() if p.is_file()), "bytes": used})
    cloud_status = "Connected" if s3_client() else "Local demo (AWS not configured)"
    return render_template("index.html", files=files, node_stats=node_stats,
                           total_files=len(files), total_bytes=sum(f["size"] for f in files),
                           cloud_status=cloud_status, cloudfront_domain=CLOUDFRONT_DOMAIN)


@app.route("/upload", methods=["POST"])
def upload():
    uploaded = request.files.get("file")
    passphrase = request.form.get("passphrase", "")
    if not uploaded or not uploaded.filename:
        flash("Please choose a file first.", "error")
        return redirect(url_for("dashboard"))
    if len(passphrase) < 8:
        flash("Use an encryption passphrase of at least 8 characters.", "error")
        return redirect(url_for("dashboard"))

    original_name = secure_filename(uploaded.filename) or "uploaded_file"
    raw = uploaded.read()
    file_id = secrets.token_hex(8)
    salt = secrets.token_bytes(16)
    key = derive_key(passphrase, salt)
    aes = AESGCM(key)
    chunks = []
    # Round-robin placement across three local storage nodes simulates distributed storage.
    for idx, start in enumerate(range(0, len(raw) or 1, CHUNK_SIZE)):
        piece = raw[start:start + CHUNK_SIZE]
        nonce = secrets.token_bytes(12)
        encrypted = aes.encrypt(nonce, piece, f"{file_id}:{idx}".encode())
        node_num = (idx % len(NODES)) + 1
        chunk_name = f"{file_id}_{idx}.bin"
        target = NODES[node_num - 1] / chunk_name
        packed_chunk = nonce + encrypted
        target.write_bytes(packed_chunk)
        cloud_uploaded = False
        try:
            cloud_uploaded = upload_encrypted_chunk_to_s3(file_id, chunk_name, packed_chunk)
        except Exception as exc:
            # Keep local storage usable, but report that cloud upload did not complete.
            app.logger.exception("S3 upload failed for %s: %s", chunk_name, exc)
        chunks.append({"index": idx, "node": node_num, "file": chunk_name,
                       "plain_sha256": sha256(piece), "s3_key": cloud_key(file_id, chunk_name) if cloud_uploaded else None,
                       "s3_uploaded": cloud_uploaded})
    manifest = {
        "id": file_id, "name": original_name, "size": len(raw),
        "checksum": sha256(raw), "salt": base64.b64encode(salt).decode(),
        "chunks": chunks, "created": __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    (META_DIR / f"{file_id}.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    flash(f"File encrypted and stored successfully. File ID: {file_id}", "success")
    return redirect(url_for("dashboard"))


@app.route("/download/<file_id>", methods=["GET", "POST"])
def download(file_id):
    meta_path = META_DIR / f"{file_id}.json"
    if not meta_path.exists():
        flash("File not found.", "error")
        return redirect(url_for("dashboard"))
    manifest = json.loads(meta_path.read_text(encoding="utf-8"))
    if request.method == "GET":
        return render_template("decrypt.html", item=manifest)
    passphrase = request.form.get("passphrase", "")
    salt = base64.b64decode(manifest["salt"])
    key = derive_key(passphrase, salt)
    aes = AESGCM(key)
    pieces = []
    try:
        for chunk in sorted(manifest["chunks"], key=lambda c: c["index"]):
            packed = read_encrypted_chunk(file_id, chunk)
            nonce, ciphertext = packed[:12], packed[12:]
            plain = aes.decrypt(nonce, ciphertext, f"{file_id}:{chunk['index']}".encode())
            if sha256(plain) != chunk["plain_sha256"]:
                raise ValueError("Chunk integrity check failed.")
            pieces.append(plain)
        restored = b"".join(pieces)
        if sha256(restored) != manifest["checksum"]:
            raise ValueError("Final SHA-256 checksum mismatch.")
    except Exception:
        flash("Decryption failed: wrong passphrase, corrupted data, or missing chunk. Original file was not restored.", "error")
        return redirect(url_for("download", file_id=file_id))
    out_dir = DATA_DIR / "restored"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / f"{file_id}_{manifest['name']}"
    out_path.write_bytes(restored)
    return send_file(out_path, as_attachment=True, download_name=manifest["name"])


@app.route("/verify/<file_id>")
def verify(file_id):
    path = META_DIR / f"{file_id}.json"
    if not path.exists():
        flash("File not found.", "error")
        return redirect(url_for("dashboard"))
    m = json.loads(path.read_text(encoding="utf-8"))
    missing, corrupt = [], []
    for c in m["chunks"]:
        p = NODES[int(c["node"]) - 1] / c["file"]
        if not p.exists():
            missing.append(f"Chunk {c['index']} (Node {c['node']})")
        elif p.stat().st_size < 28:
            corrupt.append(f"Chunk {c['index']} (Node {c['node']})")
    if missing or corrupt:
        flash("Integrity check issue. Missing: " + (", ".join(missing) or "none") + "; suspicious: " + (", ".join(corrupt) or "none"), "error")
    else:
        flash(f"Storage check passed: all {len(m['chunks'])} encrypted chunk(s) are present. Full checksum is verified when decrypting.", "success")
    return redirect(url_for("dashboard"))


@app.route("/delete/<file_id>", methods=["POST"])
def delete_file(file_id):
    path = META_DIR / f"{file_id}.json"
    if path.exists():
        m = json.loads(path.read_text(encoding="utf-8"))
        for c in m.get("chunks", []):
            local = NODES[int(c["node"]) - 1] / c["file"]
            if local.exists():
                local.unlink()
            client = s3_client()
            if client and c.get("s3_uploaded"):
                try:
                    client.delete_object(Bucket=S3_BUCKET, Key=c.get("s3_key") or cloud_key(m["id"], c["file"]))
                except Exception:
                    app.logger.exception("Could not delete cloud object %s", c["file"])
        path.unlink()
        flash("File and its stored chunks deleted.", "success")
    return redirect(url_for("dashboard"))


@app.route("/health")
def health():
    return {"status": "ok", "storage_nodes": len(NODES), "encryption": "AES-256-GCM", "checksum": "SHA-256",
            "s3_configured": bool(s3_client()), "cloudfront_configured": bool(CLOUDFRONT_DOMAIN)}


if __name__ == "__main__":
    print("\\nSecure Cloud File Storage & Distributed Storage Management System")
    print("Open http://127.0.0.1:5000 in your browser")
    app.run(debug=False, host="127.0.0.1", port=5000)
