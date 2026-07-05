#!/usr/bin/env python3
"""AI Vulnerability Discovery — uses LLM to find novel attack vectors."""
import sys, json, subprocess, re

def ask_llm(prompt):
    """Ask qwen3:14b via ollama chat endpoint."""
    data = json.dumps({
        "model": "qwen3:14b",
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "options": {"num_predict": 1000, "temperature": 0.3}
    })
    r = subprocess.run(["curl", "-s", "http://127.0.0.1:11434/api/chat", "-d", data],
                      capture_output=True, text=True, timeout=60)
    try:
        d = json.loads(r.stdout)
        msg = d.get("message", {})
        # Qwen3 puts everything in thinking - use that
        thinking = msg.get("thinking", ""); content = msg.get("content", ""); return content if content else thinking
    except:
        return ""

def discover(target, crawl_data):
    """Ask AI to find novel vulnerabilities."""
    findings = []

    context = f"Target: {target}\n"
    if crawl_data.get("urls"):
        context += f"URLs: {', '.join(crawl_data['urls'][:10])}\n"
    if crawl_data.get("params"):
        context += f"Params: {json.dumps(dict(list(crawl_data['params'].items())[:5]))}\n"

    prompt = f"""You are an expert bug bounty hunter analyzing a target.

{context}

List 5 specific, actionable vulnerability tests that automated scanners miss.
For each, provide:
- The exact endpoint/parameter to test
- The specific payload or technique
- Why it might work

Focus on: business logic, race conditions, auth bypass, IDOR, privilege escalation."""

    print(f"  [AI] Discovering novel attack vectors...")
    response = ask_llm(prompt)

    # Parse response for actionable items
    lines = response.split("\n")
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Look for numbered items, bullet points, or key patterns
        if re.match(r'^\d+[\.\)]|^[-*]|^Test|^Check|^Try', line):
            findings.append({
                "type": "AI-Discovered Vector",
                "severity": "info",
                "url": target,
                "evidence": line[:200],
            })

    return findings[:10]

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    crawl_data = {"urls": [], "params": {}}
    if len(sys.argv) > 2:
        try:
            crawl_data = json.load(open(sys.argv[2]))
        except:
            pass

    results = discover(target, crawl_data)
    print(f"\n  [AI] {len(results)} novel attack vectors found:")
    for r in results:
        print(f"    → {r['evidence'][:100]}")
