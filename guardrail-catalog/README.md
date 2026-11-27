# Atomic NeMo Guardrails

Atomic NeMo Guardrails rails decomposed from the RHOAI default guardrails catalog (source: trustyai guardrail-catalog by Rob Geada). Unmodified; fixes are applied at config-build time in `src/asago_guardrails_recommender/recommend.py`.

Added on top of that catalog (not from Rob Geada's catalog):

- `hf_classifier_wolf-defender.yaml`: Wolf Defender prompt-injection classifier (ModernBERT, Apache-2.0,
  `RedHatAI/wolf-defender-prompt-injection`), the default injection model in the TrustyAI operator's
  default guardrails ConfigMaps. Labels `benign`/`injection`; windowed input flow.
- `regex_*.yaml`: NeMo `regex_detection` rails. Patterns are written from the signal definitions in
  `models.py` (`SIGNAL_VOCABULARY`), never tuned on attack data. They only catch explicit wording;
  intent-level checks stay with the self-check rails. `regex_action_confirmation` is an output rail and
  flags any confirmed action in the bot reply, authorised or not. It is not selected automatically, because most
  agentic replies are tool calls rather than text confirmations.

The upstream rail cards are unmodified, and the added cards follow the same form: each card declares input flows only, except `regex_action_confirmation`, which is an output rail.
Output support per detector family comes from `output_stages.yaml` in this directory, which `catalog.py` reads at load time to set each card's `output_flow` and placement. The config build takes only the card's detector config, rewritten for output (see `_output_stage` in `recommend.py`).
