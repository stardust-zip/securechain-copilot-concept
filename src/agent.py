import json
import os

import chromadb
import chromadb.utils.embedding_functions as embedding_functions
from dotenv import load_dotenv
from openai import OpenAI

# Load environment variables (API Key)
load_dotenv()

# Initialize the OpenAI Client for text generation
openai_client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))


def load_sbom() -> str:
    """Loads the Contextual Data (The Current State)."""
    try:
        with open("data/sbom.json", "r", encoding="utf-8") as f:
            # We dump it back to a formatted string so the LLM can read it
            return json.dumps(json.load(f), indent=2)
    except FileNotFoundError:
        return "No SBOM found."


def ask_copilot(user_query: str) -> str:
    """The core RAG pipeline: Retrieve -> Inject -> Generate."""
    print(f"🔍 Searching knowledge base for: '{user_query}'...")

    # 1. Setup ChromaDB (The Semantic Layer)
    chroma_client = chromadb.PersistentClient(path="./chroma_db")
    openai_ef = embedding_functions.OpenAIEmbeddingFunction(
        api_key=os.environ.get("OPENAI_API_KEY"), model_name="text-embedding-3-small"
    )
    collection = chroma_client.get_collection(
        name="supply_chain_vulnerabilities", embedding_function=openai_ef
    )

    # 2. Retrieve Knowledge Data
    results = collection.query(
        query_texts=[user_query],
        n_results=3,  # Get the top 3 most relevant vulnerabilities
    )

    # Flatten the retrieved chunks into a single readable string
    retrieved_context = "\n\n".join(results["documents"][0])

    # 3. Load Contextual Data
    sbom_data = load_sbom()

    # 4. Construct the Prompt
    system_prompt = """You are 'SecureChain Copilot', an expert Software Supply Chain Security Assistant.
    Your job is to answer the user's question using ONLY the provided Vulnerability Context and the user's current SBOM (Software Bill of Materials).

    Rules:
    1. Cross-reference the packages in the SBOM against the affected packages in the Vulnerability Context.
    2. If the SBOM contains packages mentioned in the Vulnerability Context, explain the risk.
    3. If the Vulnerability Context discusses packages that are NOT in the user's SBOM, explicitly state that based on the current SBOM, the user does not appear to be running the affected packages.
    4. If the question is completely unrelated to supply chain security or the provided context, say "I don't have enough data to answer that."

    Do not hallucinate vulnerabilities."""

    user_prompt = f"""
    --- CURRENT SBOM (Contextual Data) ---
    {sbom_data}

    --- KNOWN VULNERABILITIES (Knowledge Data) ---
    {retrieved_context}

    --- USER QUESTION ---
    {user_query}
    """

    print("🧠 Analyzing context and generating response...\n")
    print("--- FINAL PROMPT TO LLM ---")
    print(user_prompt)
    print("---------------------------")

    # 5. Inject and Generate
    response = openai_client.chat.completions.create(
        model="gpt-4o-mini",  # Fast, cheap, and perfect for structured reasoning
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.1,  # Low temperature so the AI prioritizes factual security data over creativity
    )

    return response.choices[0].message.content


if __name__ == "__main__":
    # Test Question 1: Cross-referencing Knowledge with Context
    question = "Based on our SBOM, are we running any packages affected by the malicious tea.xyz token reward campaign?"

    answer = ask_copilot(question)
    print("🤖 SecureChain Copilot:\n")
    print(answer)
