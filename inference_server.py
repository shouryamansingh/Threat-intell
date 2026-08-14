"""Inference service — the model half of a split deployment.

This process exists for one reason: `facebook/bart-large-cnn` and
`all-MiniLM-L6-v2` need ~4.5 GB of resident RAM, and that requirement is what
forces the whole application onto an expensive instance. Moving just these two
models here lets the dashboard, scheduler and database run on a small box (see
deploy/SPLIT-DEPLOYMENT.md).

It is deliberately the thinnest possible service:

  * It imports nothing from the application — not `config`, not `database`. It
    holds no credentials, no SQLite file, no email settings. If this box is
    compromised the attacker gets two public news-article summarisers.
  * It does no article cleaning and no sentence splitting. Those are regex and
    BeautifulSoup, they need no models, and they carry the report-quality tuning
    that belongs with the rest of the application. The caller sends already-clean
    text; only the tensor work happens here.

That split is why editing summarisation *logic* never means redeploying this
box, and why `requirements-inference.txt` is six lines.

Endpoints (all require `Authorization: Bearer <TI_INFERENCE_TOKEN>`):

    GET  /health   -> {"status", "models": {...}}    liveness + which models loaded
    POST /summarize {"text", "max_length", "min_length"} -> {"summary": str|null}
    POST /rank      {"query", "sentences", "top_k", "threshold"} -> {"sentences": [...]}

Run it under gunicorn with exactly ONE worker — see
deploy/threatintel-inference.service. Each worker loads its own copy of the
weights, so two workers means ~9 GB and an OOM kill.
"""

import hmac
import logging
import os

from flask import Flask, jsonify, request

LOG = logging.getLogger("inference")
logging.basicConfig(
    level=os.environ.get("TI_INFERENCE_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

# The one secret this box holds. There is no other authentication — anyone who
# can open a TCP connection and present this token can use the models.
TOKEN = os.environ.get("TI_INFERENCE_TOKEN", "").strip()
if not TOKEN:
    raise SystemExit(
        "TI_INFERENCE_TOKEN is not set. Refusing to start an unauthenticated "
        "inference service."
    )

# Cap on request body size. The caller truncates article text to 2000 chars, so
# anything approaching a megabyte is a mistake or an attempt to exhaust memory.
MAX_CONTENT_LENGTH = int(os.environ.get("TI_INFERENCE_MAX_BODY_BYTES", "1048576"))

# Bound the work a single call can ask for, independent of what the caller sends.
MAX_SENTENCES = int(os.environ.get("TI_INFERENCE_MAX_SENTENCES", "200"))
MAX_TEXT_CHARS = int(os.environ.get("TI_INFERENCE_MAX_TEXT_CHARS", "20000"))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


# ── Model loading ────────────────────────────────────────────────────────────
# Loaded eagerly at import, not lazily on first request. On a lazy load the
# first article of the weekly scrape pays a 30-60s model load inside its own
# request, which reads as a timeout to the caller and drops that article's
# summary. Eager loading moves that cost to service start, where systemd waits
# for it and `/health` reports honestly.
#
# HF_HOME must point somewhere writable — the systemd unit sets
# ProtectSystem=strict, and the default cache path lands in the read-only code
# directory. Getting this wrong is exactly the failure documented in
# .env.example: the download fails, the model never loads, and every summary
# silently falls back to non-AI text.

_summarizer = None
_ranker = None


def _load_models() -> None:
    global _summarizer, _ranker

    try:
        from transformers import pipeline

        LOG.info("loading facebook/bart-large-cnn ...")
        _summarizer = pipeline("summarization", model="facebook/bart-large-cnn")
        LOG.info("summarizer ready")
    except Exception:
        # Logged with a traceback and left as None. The service still starts and
        # /health reports summarizer: false, which is far easier to diagnose than
        # a container that crash-loops before it can tell you why.
        LOG.exception("failed to load summarization model — /summarize will 503")

    try:
        from sentence_transformers import SentenceTransformer

        LOG.info("loading all-MiniLM-L6-v2 ...")
        _ranker = SentenceTransformer("all-MiniLM-L6-v2")
        LOG.info("ranker ready")
    except Exception:
        LOG.exception("failed to load sentence model — /rank will 503")


_load_models()


# ── Auth ─────────────────────────────────────────────────────────────────────

def _authorized() -> bool:
    """Constant-time bearer-token check.

    compare_digest rather than `==` so the comparison does not leak the token
    prefix through response timing.
    """
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return False
    return hmac.compare_digest(header[7:].strip(), TOKEN)


@app.before_request
def _require_token():
    """Every route, /health included.

    An unauthenticated health endpoint would tell anyone who can reach the port
    whether the models are loaded, which is a free confirmation that this is
    worth attacking. The deploy checks in SPLIT-DEPLOYMENT.md send the token.
    """
    if not _authorized():
        LOG.warning("rejected unauthenticated %s %s", request.method, request.path)
        return jsonify({"error": "unauthorized"}), 401
    return None


# ── Routes ───────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    ready = _summarizer is not None and _ranker is not None
    return (
        jsonify(
            {
                "status": "ok" if ready else "degraded",
                "models": {
                    "summarizer": _summarizer is not None,
                    "ranker": _ranker is not None,
                },
            }
        ),
        200 if ready else 503,
    )


@app.post("/summarize")
def summarize():
    if _summarizer is None:
        return jsonify({"error": "summarization model not loaded"}), 503

    payload = request.get_json(silent=True) or {}
    text = (payload.get("text") or "").strip()
    if not text:
        return jsonify({"error": "text is required"}), 400

    text = text[:MAX_TEXT_CHARS]
    max_length = int(payload.get("max_length", 150))
    min_length = int(payload.get("min_length", 50))

    # BART fails outright if min_length exceeds max_length; clamp rather than
    # 500 on a caller's rounding.
    min_length = min(min_length, max(1, max_length - 1))

    try:
        result = _summarizer(
            text, max_length=max_length, min_length=min_length, do_sample=False
        )
    except Exception:
        LOG.exception("summarization failed")
        return jsonify({"error": "inference failed"}), 500

    if not result:
        return jsonify({"summary": None})
    return jsonify({"summary": result[0]["summary_text"]})


@app.post("/rank")
def rank():
    """Return the `top_k` sentences most semantically similar to `query`.

    Replaces the caller's in-process MiniLM + cosine_similarity. Note what does
    NOT cross the wire: no embeddings are returned or stored. The caller sends
    candidate sentences and gets back a subset of those same strings, so there
    is no vector store to run and nothing to persist.
    """
    if _ranker is None:
        return jsonify({"error": "sentence model not loaded"}), 503

    payload = request.get_json(silent=True) or {}
    query = (payload.get("query") or "").strip()
    sentences = payload.get("sentences") or []

    if not query:
        return jsonify({"error": "query is required"}), 400
    if not isinstance(sentences, list):
        return jsonify({"error": "sentences must be a list"}), 400

    sentences = [str(s) for s in sentences[:MAX_SENTENCES] if str(s).strip()]
    if not sentences:
        return jsonify({"sentences": []})

    top_k = max(1, int(payload.get("top_k", 3)))
    threshold = float(payload.get("threshold", 0.3))

    try:
        import numpy as np
        from sklearn.metrics.pairwise import cosine_similarity

        query_embedding = _ranker.encode([query])
        sentence_embeddings = _ranker.encode(sentences)
        similarities = cosine_similarity(query_embedding, sentence_embeddings)[0]

        top_indices = np.argsort(similarities)[-top_k:][::-1]
        ranked = [
            sentences[i] for i in top_indices if similarities[i] > threshold
        ]
    except Exception:
        LOG.exception("ranking failed")
        return jsonify({"error": "inference failed"}), 500

    return jsonify({"sentences": ranked})


if __name__ == "__main__":
    # Development only. Production runs gunicorn via the systemd unit — the
    # Werkzeug server has no request timeouts and no slow-client protection.
    app.run(
        host=os.environ.get("TI_INFERENCE_BIND_HOST", "127.0.0.1"),
        port=int(os.environ.get("TI_INFERENCE_PORT", "5002")),
    )
