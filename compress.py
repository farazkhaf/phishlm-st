from typing import List
from sentence_transformers import SentenceTransformer
import numpy as np

model = SentenceTransformer("all-MiniLM-L6-v2")

def rag_retrieve(query: str,
                 source: List[str],
                 top_k: int = 5,
                 min_score: float = 0.7) -> List[str]:
    """
    Generic RAG retrieval 
    
    Args:
        query: user query string
        source: list of text snippets (already chunked if needed)
        top_k: number of relevant snippets to return
    
    Returns:
        List of top_k relevant snippets
    """
    if not source:
        return []
    
    source_embeddings = model.encode(source, convert_to_numpy=True, normalize_embeddings=True)
    
    query_embedding = model.encode([query], convert_to_numpy=True, normalize_embeddings=True)
    
    similarities = np.dot(source_embeddings, query_embedding.T).flatten()
    sorted_indices = similarities.argsort()[::-1]
    
    results = []
    for idx in sorted_indices:
        if similarities[idx] >= min_score:
            results.append(source[idx])
        if len(results) >= top_k:
            break
    return results





