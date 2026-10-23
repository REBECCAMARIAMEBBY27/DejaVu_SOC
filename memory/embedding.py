
from sentence_transformers import SentenceTransformer
from matching.fingerprint import build_fingerprint


MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

_model = None


def get_model():
    global _model

    if _model is None:
        _model = SentenceTransformer(MODEL_NAME)

    return _model


def fingerprint_to_text(fingerprint: dict) -> str:
    parts = []

    for event in fingerprint["events"]:
        parts.append(
            f"Event {event['seq']}: {event['event_type']}"
        )

        if event.get("technique"):
            parts.append(
                f"Technique: {event['technique']}"
            )

        if event.get("gap_seconds") is not None:
            parts.append(
                f"Time since previous event: "
                f"{event['gap_seconds']} seconds"
            )

    return " ; ".join(parts)


def embed_incident(incident: dict):
    fingerprint = build_fingerprint(incident)
    text = fingerprint_to_text(fingerprint)

    vector = get_model().encode(
        text,
        normalize_embeddings=True,
        convert_to_numpy=True,
    )

    return vector.astype("float32")
