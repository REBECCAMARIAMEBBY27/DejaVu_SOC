
from memory.historical_store import load_incidents
from memory.faiss_index import build_index, search_similar_incidents


def test_index_and_retrieval():
    build_index()

    incidents = load_incidents()
    query = incidents[0]

    results = search_similar_incidents(query, top_k=3)

    assert results
    assert len(results) <= 3
    assert results[0]["incident_id"] == query["incident_id"]

    for result in results:
        assert "incident_id" in result
        assert -1.0 <= result["vector_score"] <= 1.0
