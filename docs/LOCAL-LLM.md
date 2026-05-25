# Local LLM setup — Ollama, LM Studio, vLLM, Hugging Face

> Available in v11.3.1+. The reports module's AI features (executive
> summaries, plain-language CVE explainers, quick-win detection,
> stakeholder narratives) all support running entirely on local models.
> Nothing leaves your laptop. Air-gap friendly.

---

## What this is for

The SafeCadence reports module uses an LLM to generate three things:

1. The **executive summary** at the top of every report
2. **Plain-language explanations** of each CVE
3. **Quick-win ranking** — which findings give you the most risk reduction
   per minute of effort

By default this calls OpenAI (`OPENAI_API_KEY`) or Anthropic
(`ANTHROPIC_API_KEY`) — both of which mean your scan data is sent to a
vendor cloud. For customers under data-residency rules (defense
contractors, hospitals handling PHI, banks under examination), that's
not an option.

v11.3.1 makes the reports module **local-first-capable**. Three paths,
all stdlib-only, all opt-in:

| Path | What it is | Best for |
|---|---|---|
| **Ollama** (native) | A daemon that runs open-source LLMs (Llama, Mistral, Phi, etc.) locally | Anyone who wants the simplest setup — `brew install ollama && ollama pull llama3.1` |
| **OpenAI-compatible local endpoint** | Any local runner that exposes `/v1/chat/completions` (LM Studio, vLLM, text-generation-inference, llama.cpp server) | People already running a specific model — including Hugging Face models — via one of these tools |
| **Hugging Face Inference API** (paid) | Hugging Face's hosted endpoint, which speaks the OpenAI shape | When you want HF model variety without managing GPU yourself |

All three paths share the same code path inside SafeCadence — you set
two or three environment variables and the reports module routes
through them automatically. Local always wins over cloud when both are
configured (override with `SC_AI_PROVIDER=openai` if you want the cloud
path explicitly).

---

## Path 1 — Ollama (recommended for first-time setup)

### Install Ollama

```bash
# macOS
brew install ollama
# Linux
curl -fsSL https://ollama.com/install.sh | sh
```

### Pull a model

```bash
ollama pull llama3.1          # 4.7 GB — solid default
# or, for smaller hardware:
ollama pull llama3.1:8b       # same model, explicit tag
ollama pull mistral           # 4.1 GB — strong on technical/security text
ollama pull phi3              # 2.3 GB — runs on smaller machines
```

### Start the daemon

```bash
ollama serve   # default port 11434
```

### Point SafeCadence at it

```bash
export OLLAMA_HOST="http://127.0.0.1:11434"
export SAFECADENCE_LOCAL_LLM="llama3.1"   # optional — defaults to llama3.1

# Or, set both at once:
export SAFECADENCE_LOCAL_LLM="mistral"    # this alone activates Ollama
```

### Verify it works

```bash
python3 -c "
from safecadence.reports.ai_helpers import llm_status, _try_ai
print('Status:', llm_status())
print('Test:', _try_ai('Say hello in 5 words.'))
"
```

Expected output:

```text
Status: {'provider': 'ollama', 'model': 'llama3.1', 'endpoint': 'http://127.0.0.1:11434'}
Test: Hello, how can I assist?
```

That's it — every report you build from now on uses the local Llama
3.1 instead of OpenAI.

### Air-gap installation

Ollama can run fully offline. Pull the model on a machine with
internet, then copy `~/.ollama/models/` to the air-gapped box. Or use
`ollama create` with a `Modelfile` pointing at a local GGUF file.

---

## Path 2 — OpenAI-compatible local endpoint (LM Studio, vLLM, etc.)

This is the universal path: anything that speaks
`POST /v1/chat/completions` works as a SafeCadence backend. The reports
module just talks to the URL you give it.

### Common runners that speak this shape

| Runner | Default endpoint | How to start |
|---|---|---|
| **LM Studio** | `http://localhost:1234` | Click "Local Server" → "Start Server" in the GUI |
| **vLLM** | `http://localhost:8000` | `vllm serve <model>` |
| **text-generation-inference** (TGI) | `http://localhost:8080` | `docker run ghcr.io/huggingface/text-generation-inference --model-id <hf-repo>` |
| **llama.cpp server** | `http://localhost:8080` | `./server -m model.gguf` |
| **Hugging Face Inference API** | `https://api-inference.huggingface.co` | (paid HF subscription) |
| **Together.ai** | `https://api.together.xyz` | (hosted, paid) |
| **Groq** | `https://api.groq.com/openai` | (hosted, very fast inference) |
| **Fireworks** | `https://api.fireworks.ai/inference` | (hosted) |

### Point SafeCadence at the endpoint

```bash
export OPENAI_API_KEY="<any-string-or-real-key>"   # required even for local; runner ignores it
export SAFECADENCE_AI_BASE_URL="http://localhost:1234"
export SAFECADENCE_OPENAI_MODEL="meta-llama/Meta-Llama-3.1-8B-Instruct"   # whatever your runner exposes
```

### Verify

```bash
python3 -c "
from safecadence.reports.ai_helpers import llm_status, _try_ai
print('Status:', llm_status())
print('Test:', _try_ai('Say hello in 5 words.'))
"
```

Expected:

```text
Status: {'provider': 'openai', 'model': 'meta-llama/Meta-Llama-3.1-8B-Instruct', 'endpoint': 'http://localhost:1234'}
Test: Hi there, how are you?
```

The `endpoint` field in `llm_status()` makes it clear the request isn't
going to OpenAI's cloud — useful when sharing scan reports with
customers who ask where their data went.

---

## Path 3 — Hugging Face (first-class provider, v11.3.1+)

Hugging Face is a labeled provider in SafeCadence — no env-var
contortions, no pretending HF is OpenAI. Two flavors are supported.

### Flavor A — HF Serverless Inference (hosted, easiest)

For any chat-capable model on the
[HF Inference Catalog](https://huggingface.co/models?inference=warm):

```bash
export HF_TOKEN="hf_xxxxxxxxxxxxxxxxxxxxxxxxx"     # from huggingface.co/settings/tokens
export SAFECADENCE_HF_MODEL="meta-llama/Meta-Llama-3.1-8B-Instruct"   # any HF chat model
# done — every report's AI sections now run on HF
```

That's it. Verify:

```bash
python3 -c "
from safecadence.reports.ai_helpers import llm_status, _try_ai
print('Status:', llm_status())
print('Test:', _try_ai('Say hello in 5 words.'))
"
```

Expected:

```text
Status: {'provider': 'huggingface', 'model': 'meta-llama/Meta-Llama-3.1-8B-Instruct', 'endpoint': 'https://api-inference.huggingface.co/v1'}
Test: Hi there, how can I help?
```

### Flavor B — HF Inference Endpoints (paid, dedicated)

If you've stood up an HF Inference Endpoint (the paid product), point
SafeCadence at it the same way — just override the base URL:

```bash
export HF_TOKEN="hf_xxxxxxxxxxxxxxxxxxxxxxxxx"
export SAFECADENCE_HF_BASE_URL="https://your-endpoint.us-east-1.aws.endpoints.huggingface.cloud/v1"
export SAFECADENCE_HF_MODEL="your-deployed-model-name"
```

### Flavor C — Self-hosting an HF model (local, air-gappable)

If you'd rather host the model yourself rather than use HF's cloud,
pick any of these OpenAI-compatible runners and follow Path 2 above
(`SAFECADENCE_AI_BASE_URL` + `OPENAI_API_KEY` = any string):

- **LM Studio** — easiest for desktop, GUI-driven. Search the HF model
  catalog in-app, download, click "Local Server" → Start.
- **vLLM** — best for production GPU servers. `vllm serve meta-llama/Meta-Llama-3.1-8B-Instruct --host 0.0.0.0 --port 8000`.
- **text-generation-inference (TGI)** — HF's own production runtime, Docker-friendly:
  ```bash
  docker run -d --name tgi --gpus all -p 8080:80 -v $PWD/models:/data \
      ghcr.io/huggingface/text-generation-inference \
      --model-id /data/your-hf-model
  ```
- **llama.cpp server** — best for CPU-only or low-VRAM scenarios with
  GGUF-quantized HF models.

### When to use which flavor

| Constraint | Recommended flavor |
|---|---|
| Quick try, no infra | A — HF Serverless |
| Production load, multi-tenant | B — HF Inference Endpoints |
| Air-gapped customer (no outbound) | C — vLLM or TGI on the customer's network |
| Desktop demo / single user | C — LM Studio |
| Cost-sensitive, intermittent use | A — HF Serverless (pay per token) |

---

## Provider precedence

When multiple env vars are set, the reports module auto-detects in this
order:

1. **`SC_AI_PROVIDER`** — explicit override, must be one of `ollama`,
   `huggingface` (alias `hf`), `openai`, `anthropic`. Highest priority.
2. **`OLLAMA_HOST`** or **`SAFECADENCE_LOCAL_LLM`** → Ollama. Local-first
   wins by default because if you went to the trouble of installing
   Ollama, you probably want it used.
3. **`HF_TOKEN`** or **`HUGGINGFACE_API_TOKEN`** → Hugging Face.
4. **`OPENAI_API_KEY`** → OpenAI (or your `SAFECADENCE_AI_BASE_URL`).
5. **`ANTHROPIC_API_KEY`** → Anthropic.
6. None of the above → deterministic stub. Reports still generate; the
   AI sections use the rule-based fallback (which is genuinely useful
   on its own, not a placeholder).

If your primary provider fails at runtime (Ollama daemon down,
OpenAI returns 5xx), the module **falls through to the next available
provider** so the report still produces an AI summary. Better partial
than empty.

---

## Environment variable reference

| Variable | Effect | Example |
|---|---|---|
| `SC_AI_PROVIDER` | Force a specific provider (`ollama`, `huggingface` (or `hf`), `openai`, `anthropic`) | `SC_AI_PROVIDER=huggingface` |
| `OLLAMA_HOST` | Where Ollama is listening | `http://127.0.0.1:11434` |
| `SAFECADENCE_LOCAL_LLM` | Which Ollama model to use | `mistral` or `llama3.1:8b` |
| `HF_TOKEN` | Hugging Face API token (from huggingface.co/settings/tokens) | `hf_xxxxxxxxxxxxxxxxxxxxxxxxx` |
| `HUGGINGFACE_API_TOKEN` | Alias for `HF_TOKEN` (HF docs use both interchangeably) | (same) |
| `SAFECADENCE_HF_MODEL` | Which HF model to use (default `meta-llama/Meta-Llama-3.1-8B-Instruct`) | `mistralai/Mistral-7B-Instruct-v0.3` |
| `SAFECADENCE_HF_BASE_URL` | Custom HF endpoint (default `https://api-inference.huggingface.co/v1`) | `https://your-endpoint.aws.endpoints.huggingface.cloud/v1` |
| `OPENAI_API_KEY` | OpenAI API key (or any string when using a local OpenAI-compatible endpoint) | `sk-...` |
| `SAFECADENCE_AI_BASE_URL` | Custom base URL for OpenAI calls (unlocks LM Studio / vLLM / TGI) | `http://localhost:1234` |
| `SAFECADENCE_OPENAI_MODEL` | Override the OpenAI model name (default `gpt-4o-mini`) | `meta-llama/Meta-Llama-3.1-8B-Instruct` |
| `ANTHROPIC_API_KEY` | Anthropic API key | `sk-ant-...` |
| `SAFECADENCE_ANTHROPIC_MODEL` | Override the Anthropic model (default `claude-haiku-4-5-20251001`) | `claude-3-5-sonnet-20241022` |

---

## Troubleshooting

### "I set OLLAMA_HOST but the report still uses OpenAI"

Check `OPENAI_API_KEY` isn't also set in your shell. If it is, set
`SC_AI_PROVIDER=ollama` explicitly to override.

### "The AI summary is empty / falls back to the deterministic version"

Run the verify command from each path's setup section. If the Ollama
daemon is down or the URL is wrong, the call returns `None` and the
deterministic fallback kicks in — that's by design (better partial
than empty), but it means the local provider isn't actually being
used.

### "vLLM / TGI / LM Studio returns 4xx"

The model name in `SAFECADENCE_OPENAI_MODEL` must match exactly what
your local runner serves. Run the runner's `/v1/models` endpoint to
list available names:

```bash
curl http://localhost:1234/v1/models
```

### "Llama 3.1 is making up CVE numbers"

Smaller open-source models tend to hallucinate technical content. For
security/compliance writing specifically, prefer:

- Mistral 7B Instruct — generally less prone to invention in technical
  domains
- Llama 3.1 70B — much more accurate but needs more GPU
- Phi-3 Medium — surprisingly good for its size
- Or fall back to a cloud model (OpenAI/Anthropic) for the report
  generation specifically while keeping the SafeCadence scan/analysis
  entirely local

You can also set `SC_AI_DISABLED=1` to skip the LLM step entirely and
rely only on the deterministic fallback (which never hallucinates
because it doesn't generate text — it just picks templated phrases
keyed by the actual scan data).

---

## What's NOT supported

- **Streaming responses.** The reports module makes blocking calls and
  reads the full response. Streaming would require structural changes
  to the report pipeline.
- **Tool/function calling.** SafeCadence prompts the model with
  structured KPI data inline; it doesn't use OpenAI's tool/function
  calling spec.
- **Multi-turn conversations.** Each LLM call is single-shot. No chat
  history is preserved across calls.
- **Direct Hugging Face Transformers Python API.** No
  `transformers.AutoModelForCausalLM.from_pretrained(...)` integration.
  This is intentional — we want the model to be a separate process
  (or remote service), not loaded into SafeCadence's address space.
  Use one of the runners in Path 2 instead.

---

*Questions? File an issue at*
*https://github.com/famousleads/safecadence-network-risk/issues*
