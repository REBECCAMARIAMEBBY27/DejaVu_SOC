
from memory.faiss_index import search_similar_incidents

# Simulate a new incident that is not in the historical dataset.
new_incident = {
    "incident_id": "NEW-002",
    "events": [
        {
            "seq": 1,
            "event_type": "malware_detected",
            "technique": "T1204.002",
            "timestamp": "2026-10-23T11:00:00Z",
        },
        {
            "seq": 2,
            "event_type": "file_encryption",
            "technique": "T1486",
            "timestamp": "2026-10-23T11:05:00Z",
        },
    ],
}

results = search_similar_incidents(new_incident, top_k=3)

print("\nSimilar historical incidents:")
for result in results:
    print(
        f"Incident: {result['incident_id']} | "
        f"Vector similarity: {result['vector_score']:.4f}"
    )
