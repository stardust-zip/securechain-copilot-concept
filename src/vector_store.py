import os

import chromadb
import chromadb.utils.embedding_functions as embedding_functions
from dotenv import load_dotenv

from data_pipeline import extract_osv_vulnerabilities, generate_knowledge_chunks

# Load the .env file
load_dotenv()


def build_knowledge_base():
    # 1. Set up the OpenAI Embedding Function
    openai_ef = embedding_functions.OpenAIEmbeddingFunction(
        api_key=os.environ.get("OPENAI_API_KEY"), model_name="text-embedding-3-small"
    )

    client = chromadb.PersistentClient(path="./chroma_db")

    # 2. Pass the function when creating/getting the collection
    collection = client.get_or_create_collection(
        name="supply_chain_vulnerabilities",
        embedding_function=openai_ef,  # This forces Chroma to use OpenAI instead of the local CPU model
    )

    print("Extracting OSV vulnerabilities...")
    all_vulns = extract_osv_vulnerabilities("data/osv-npm")
    test_vulns = all_vulns[:1000]

    print(f"Generating chunks for {len(test_vulns)} vulnerabilities...")
    chunks = generate_knowledge_chunks(test_vulns)

    documents = [c["text"] for c in chunks]
    metadatas = [c["metadata"] for c in chunks]
    ids = [c["metadata"]["id"] for c in chunks]

    print(f"Embedding {len(documents)} chunks via OpenAI API...")

    # This will now automatically call OpenAI to get the vectors
    collection.upsert(documents=documents, metadatas=metadatas, ids=ids)

    print("✅ Vector store built successfully with OpenAI embeddings.")


if __name__ == "__main__":
    build_knowledge_base()
