from groq import Groq
import streamlit as st
def groq_chat(
    prompt: str,
    model: str = "openai/gpt-oss-120b",
    temperature: float = 1.0,
    max_completion_tokens: int = 5000,
    top_p: float = 1.0,
    stream: bool = False,
    stop: str | None = None,
    key_path: str = "groq_api.txt"
) -> str:
    """
    Stateless function to send a single prompt to Groq and return its response.

    Args:
        prompt (str): The user input string.
        model (str): Model name (default: meta-llama/llama-4-maverick-17b-128e-instruct).
        temperature (float): Sampling temperature (default: 1.0).
        max_completion_tokens (int): Max tokens in response (default: 5000).
        top_p (float): Nucleus sampling parameter (default: 1.0).
        stream (bool): Whether to stream responses (default: False).
        stop (str | None): Optional stop sequence.
        key_path (str): Path to file containing API key.

    Returns:
        str: The model's response text.
    """
    

    # Initialize client
    client = Groq(api_key=st.secrets["GROQ_API_KEY"])

    # Send request
    completion = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=temperature,
        max_completion_tokens=max_completion_tokens,
        top_p=top_p,
        stream=stream,
        stop=stop
    )

    # Extract response
    return completion.choices[0].message.content


import re
import json

def extract_json(text: str) -> dict | None:
    """
    Extract the JSON object from an LLM response and return as a dict.
    - Returns a Python dict, or None if no valid JSON found.
    """
    # Look for fenced ```json blocks
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    fenced = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        try:
            return json.loads(fenced.group(1))
        except json.JSONDecodeError:
            return None
    
    braces = re.search(r"(\{.*\})", text, re.DOTALL)
    if braces:
        try:
            return json.loads(braces.group(1))
        except json.JSONDecodeError:
            return None
    
    return None