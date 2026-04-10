import os

import chromadb
import chromadb.utils.embedding_functions as embedding_functions
from dotenv import load_dotenv


def test_retrieval():
    # 1. Load your .env file so os.environ can see OPENAI_API_KEY
    load_dotenv()

    # 2. Instantiate the Embedding Function class
    openai_ef = embedding_functions.OpenAIEmbeddingFunction(
        api_key=os.environ.get("OPENAI_API_KEY"), model_name="text-embedding-3-small"
    )

    client = chromadb.PersistentClient(path="./chroma_db")

    # 3. Pass the instantiated object, not the module
    collection = client.get_collection(
        name="supply_chain_vulnerabilities",
        embedding_function=openai_ef,
    )

    query_text = (
        "Are there any vulnerabilities related to malicious code or token rewards?"
    )

    print(f"Querying: '{query_text}'\n")

    results = collection.query(
        query_texts=[query_text],
        n_results=2,
    )

    for i in range(len(results["ids"][0])):
        print(f"--- Result {i + 1} ---")
        print(f"ID: {results['ids'][0][i]}")
        print(f"Distance Score: {results['distances'][0][i]}")
        print(f"Text Snippet: {results['documents'][0][i][:150]}...\n")


if __name__ == "__main__":
    test_retrieval()
