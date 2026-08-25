# Switching storopt to Hugging Face — follow these steps

storopt now talks to **Hugging Face** instead of Gemini. The same code path
also drives any endpoint you host yourself, because they all speak the
OpenAI-compatible chat protocol — swapping between them is one URL, not a
rewrite.

Two ways to run, both already supported:

| Mode | `base_url` | Token | Use it when |
|---|---|---|---|
| **Hosted router** (start here) | `https://router.huggingface.co/v1` | your `hf_…` token | you want it working in 5 minutes |
| **Self-hosted** | your own URL ending in `/v1` | whatever your server wants, often none | HF Inference Endpoint, TGI, vLLM, llama.cpp, Ollama, LM Studio |

Everything below takes ~10 minutes. Steps 1–4 are the whole job.

---

## Step 1 — Get a Hugging Face token

1. Sign in at <https://huggingface.co>.
2. Go to **Settings → Access Tokens** (<https://huggingface.co/settings/tokens>).
3. **Create new token** → token type **Read**… but tick the permission
   **"Make calls to Inference Providers"**. A plain Read token without that
   box will come back `403`.
4. Copy it. It looks like `hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`. You only see it
   once.

---

## Step 2 — Put the token in the app

You asked for the key hardcoded for now, so there is a slot waiting for it.

Open `python/storopt_ai/config.py` and paste it into the constant near the top:

```python
BUILTIN_API_KEY = "hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

That is the only edit you need. Every user of your build now gets working AI
advice with no setup.

> **Read this once, then move on.** A token in the source is readable by
> anyone who installs the package — `python/storopt_ai/` installs to
> `/usr/share/storopt/` as plain `.py` files. Treat it as public. Use a token
> that only has Inference Providers access, and rotate it if it gets abused.
> `docs/secrets-and-api-keys.md` covers the real fix when you get to it.

The other two ways still work and take priority over the constant, which is
what you want for your own dev machine:

```bash
export HF_TOKEN=hf_xxxxxxxxxxxx        # 1. environment — wins over everything
storopt-ai --set-key                   # 2. ~/.config/storopt/config.json (0600)
```

Precedence: **environment → config file → `BUILTIN_API_KEY`**.

---

## Step 3 — Pick a model and confirm it answers

The default is `Qwen/Qwen2.5-7B-Instruct`. Check what your token can reach and
verify the whole path end to end:

```bash
storopt-ai --show-key      # provider, endpoint, model, masked token
storopt-ai --list-models   # every model id this endpoint accepts
storopt-ai --check         # actually calls the model and prints its reply
```

`--check` is the one that matters. A green `result: reachable…` means the
token, the URL and the model id are all correct.

To use a different model:

```bash
storopt-ai --set-model "meta-llama/Llama-3.1-8B-Instruct"
# or, just for one run:
storopt-ai --model "Qwen/Qwen2.5-72B-Instruct" --check
```

Model ids are Hub repo ids. You can also pin the serving provider by
appending it — `deepseek-ai/DeepSeek-V3-0324:novita`.

**Which model:** this task is "read a few KB of JSON, follow safety rules,
emit JSON". That needs instruction-following, not world knowledge. 7–8B is the
usable floor; 30B+ is noticeably better at the risk-tiering rules ("photos are
never `low` risk"). Try `Qwen/Qwen2.5-7B-Instruct` first, and if the advice
feels dumb, move up before you blame the prompt.

---

## Step 4 — Run it

```bash
# terminal
storopt scan ~/Downloads --json | storopt-ai
storopt advise ~/Downloads

# GUI — nothing to configure, it shells out to the same helper
storopt-gui
```

If the model is unreachable for any reason, you get the built-in rule-based
advice instead of an error. That fallback is unchanged and always available
with `--offline`.

---

## Step 5 — Rebuild and install (only if you edited the C side)

The Python bridge is copied in, not compiled, so a token change needs no
build. Rebuild only when you touched `src/`:

```bash
./scripts/build.sh          # or: cmake --build build -j$(nproc)
./scripts/make-deb.sh       # package
```

Sanity check before packaging:

```bash
./build/test_core                      # 39 checks, 0 failures
PYTHONPATH=python python3 -m storopt_ai --check
```

---

## Moving to a self-hosted model later

Nothing in the code changes. Point it at your own endpoint:

```bash
# HF Inference Endpoint (you host, HF runs the GPU)
storopt-ai --set-base-url "https://<id>.<region>.aws.endpoints.huggingface.cloud/v1"
storopt-ai --set-model "tgi"           # TGI answers to whatever it was deployed as

# Ollama on your own machine — no token needed
storopt-ai --set-base-url "http://127.0.0.1:11434/v1"
storopt-ai --set-model "qwen2.5:7b-instruct"

# vLLM / llama.cpp / LM Studio — same shape
storopt-ai --set-base-url "http://your-server:8000/v1"
```

Then `storopt-ai --check` again. When the base URL is *not* the hosted router,
a missing token is not treated as an error — self-hosted servers usually have
no auth.

Two things to get right:

- The base URL **must end in `/v1`** and must not already include
  `/chat/completions`. A `404` here is almost always this.
- Ollama's default context window is small and truncation is silent — the
  front of the prompt, where the safety rules live, is what gets dropped. Set
  `num_ctx` to 8192 on the model before trusting its answers.

---

## What actually changed in the code

| File | Change |
|---|---|
| `python/storopt_ai/hf.py` | **New.** OpenAI-compatible client. Stdlib only, no `requests`, no `huggingface_hub` — the `.deb` still installs on stock Debian. |
| `python/storopt_ai/config.py` | `BUILTIN_API_KEY`, provider / base_url / model settings, HF env vars. |
| `python/storopt_ai/advisor.py` | `advise()` dispatches to HF or Gemini; **new `sanitise()`** validates model output. |
| `python/storopt_ai/__main__.py` | `--provider`, `--base-url`, `--set-model`, `--set-base-url`, `--list-models`; `--check` prints endpoint and model. |
| `python/storopt_ai/gemini.py` | Untouched. Still works via `--provider gemini`. |
| `src/` | Three help strings that said "Gemini API key". No logic changed. |

The output shape the GUI reads — `{summary, forecast_note, recommendations[],
source}` — is identical. `src/gui/advice.c` and `window.c` never knew which
model was behind it, and still don't.

### Two behaviours worth knowing about

**Structured output is negotiated, not assumed.** Gemini guaranteed the reply
matched a schema. Open models don't, and different backends stop at different
points, so `hf.py` tries three tiers and falls back automatically:
`json_schema` (server constrains decoding) → `json_object` (valid JSON, any
shape) → nothing (a hardened extractor pulls the object out of ```` ```json ````
fences, preamble and trailing chatter). You do not have to configure this.

**Model output is now validated before it is shown.** `advisor.sanitise()`
runs on every answer:

- `"remove"` → `delete`, `"low risk"` → `low`, `"12345"` → `12345`
- any path the scan did not actually see is **dropped** — small models invent
  paths despite being told not to
- a suggested `command` is **refused** (not repaired) if it contains `sudo`,
  `;`, `&&`, `|`, backticks, `$(`, redirects, or a path under
  `/etc /usr /bin /sbin /lib /boot`
- a `delete` aimed at system paths, or one whose paths were all invented, is
  downgraded to `review` at `high` risk

This matters because the GUI renders `command` with a copy-to-clipboard
button. A hallucinated path inside an `rm -rf` that a user pastes into a shell
is data loss with your name on it. The check costs nothing and closes a hole
that existed with Gemini too.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `403` / rejected the token | Token lacks Inference Providers permission | Recreate it with that box ticked |
| `401` | Token typo, or `BUILTIN_API_KEY` still empty | `storopt-ai --show-key` |
| `404` model or route not found | Bad model id, or base URL missing/duplicating `/v1` | `storopt-ai --list-models` |
| `402` out of credits | Free monthly inference credits exhausted | Wait for reset, upgrade, or self-host (Step 5) |
| `503` model is loading | Cold start | Retry in a minute |
| Advice is generic / ignores the safety rules | Model too small | Move to a larger model |
| Recommendations appear with no paths | `sanitise()` dropped invented paths | Working as intended — the model made them up |
| GUI spinner runs for a minute | Open models are slower than Gemini was | Expected; smaller model or a faster provider |

Free tier is **free monthly credits, not unlimited** — a `402` is the quota,
not a bug. One "get advice" click is one call, so it goes a long way, but it
is finite. Self-hosting (Step 5) is the answer when it isn't.

---

## Reverting to Gemini

Kept working on purpose:

```bash
export GEMINI_API_KEY=...
storopt-ai --provider gemini --check
```
