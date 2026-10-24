
import json
from pathlib import Path

import faiss
import numpy as np

from memory.historical_store import load_incidents
from memory.embedding import embed_incident, MODEL_NAME


ROOT = Path(__file__).resolve().parents[1]
INDEX_FILE = ROOT / "data" / "historical.faiss"
MAPPING_FILE = ROOT / "data" / "faiss_mapping.json"
MODEL_FILE = ROOT / "data" / "embedding_model.json"


def build_index():
    incidents = load_incidents()

    if not incidents:
        raise ValueError("Cannot build an index without incidents")

    vectors = np.vstack([
        embed_incident(incident)
        for incident in incidents
    ]).astype("float32")

    dimension = vectors.shape[1]

    index = faiss.IndexFlatIP(dimension)
    index.add(vectors)

    faiss.write_index(index, str(INDEX_FILE))

    mapping = {
        str(vector_id): incident["incident_id"]
        for vector_id, incident in enumerate(incidents)
    }

    MAPPING_FILE.write_text(
        json.dumps(mapping, indent=2),
        encoding="utf-8",
    )

    MODEL_FILE.write_text(
        json.dumps({
            "model_name": MODEL_NAME,
            "normalized_embeddings": True,
        }, indent=2),
        encoding="utf-8",
    )

    return {
        "incident_count": len(incidents),
        "vector_dimension": dimension,
        "index_path": str(INDEX_FILE),
    }


def load_index():
    if not INDEX_FILE.exists():
        raise FileNotFoundError(
            "FAISS index not found. Run build_index() first."
        )

    index = faiss.read_index(str(INDEX_FILE))

    mapping = json.loads(
        MAPPING_FILE.read_text(encoding="utf-8")
    )

    model_config = json.loads(
        MODEL_FILE.read_text(encoding="utf-8")
    )

    if model_config["model_name"] != MODEL_NAME:
        raise ValueError(
            "Embedding model differs from the model used "
            "to build the index. Rebuild the index."
        )

    if index.ntotal != len(mapping):
        raise ValueError("FAISS index and ID mapping are inconsistent")

    return index, mapping


def search_similar_incidents(query_incident: dict, top_k: int = 3):
    index, mapping = load_index()

    query_vector = embed_incident(query_incident)
    query_vector = np.asarray(
        query_vector, dtype="float32"
    ).reshape(1, -1)

    if query_vector.shape[1] != index.d:
        raise ValueError("Query embedding dimension mismatch")

    k = min(max(top_k, 1), index.ntotal)

    scores, ids = index.search(query_vector, k)

    results = []

    for score, vector_id in zip(scores[0], ids[0]):
        if vector_id < 0:
            continue

        results.append({
            "incident_id": mapping[str(int(vector_id))],
            "vector_score": float(score),
        })

    return results
