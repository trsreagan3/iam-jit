(function () {
  const form = document.getElementById('chat-form');
  if (!form) return;
  const input = document.getElementById('chat-input');
  const sendBtn = document.getElementById('chat-send');
  const thinking = document.getElementById('chat-thinking');
  const thread = document.getElementById('chat-thread');

  // Thinking-phrase tiers, escalating with elapsed wait time.
  //   0–15s   : TIER_EARLY  — mundane IAM/JSON banter
  //   15–40s  : TIER_MID    — confused, vaguely conspiratorial
  //   40–90s  : TIER_HIGH   — military framing creeps in
  //   90s+    : TIER_DEFCON — full operational chaos
  // The longer the user waits, the more dramatic it gets.
  const TIER_EARLY = [
    'thinking…', 'combobulating…', 'consulting the abacus…',
    'reticulating splines…', 'transmuting tokens…', 'untangling ARNs…',
    'wrangling JSON…', 'enumerating wildcards…', 'paging the LLM…',
    'compiling thoughts…', 'coalescing intents…', 'plumbing the policy…',
    'deciphering verbs…', 'spinning matrices…', 'attending to attention…',
    'minting tokens…', 'bargaining with Bedrock…', 'cajoling Claude…',
    'asking Ollama nicely…', 'parsing prepositions…', 'auditing assumptions…',
    'consulting the manifest…', 'lubricating the cogs…', 'reading tea leaves…',
    'counting electrons…', 'realigning vectors…', 'untangling the trust policy…',
    'sniffing out subnets…', 'stochastic-ing…', 'reasoning, slowly…',
    'feeding the model…', 'unfurling the response…', 'normalizing nouns…',
    'tessellating tokens…', 'thinking very hard…', 'thinking, but in JSON…',
    'reading the fine print…', 'generating, generally…', 'fermenting an answer…',
    'gathering courage…', 'second-guessing already…', 'asking the rubber duck…',
    'consulting the manual…', 'translating from English…', 'translating to JSON…',
    'measuring twice…', 'cutting once…', 'pondering principals…',
    'evaluating evals…', 'iterating, iteratively…',
    'unboxing GPT-shaped thoughts…', 'serializing serenely…',
    'looking up actions…', 'checking the org context…', 'matching ARNs…',
    'verifying verbs…', 'paginating possibilities…',
    'splitting hairs (and ARNs)…', 'narrowing scope…', 'broadening horizons…',
    'sniffing the wildcards…', 'computing computers…', 'one moment please…',
    'reading the room…', 'enumerating edge cases…',
    'walking the AST…', 'shifting some bits…', 'aligning chakras…',
    'reasoning bilingually (en+JSON)…', 'tying up loose ends…',
    'rotating through possibilities…', 'asking the model to be specific…',
    'asking the model to please not hallucinate…',
    'untangling spaghetti permissions…', 'looking up Get* and Describe*…',
    'inspecting the trust policy…', 'consulting the cassette archive…',
    'rifling through bundles…', 'preferring narrow ARNs…',
    'declining to invent buckets…', 'avoiding sentinels…',
    'digesting the description…', 'parsing politely…',
    'gently nudging the tokens…', 'cataloguing capabilities…',
    'considering the reviewer…', 'imagining the audit log…',
    'deferring to policy_sentry…', 'measuring blast radius…',
    'minimizing privilege…', 'avoiding writes (probably)…',
    'choosing actions wisely…', 'rounding up the verbs…',
    'sieving JSON…', 'orchestrating outputs…', 'ratifying refs…',
    'finalizing format…', 'composing the answer…',
    'doing AI stuff…',
  ];

  const TIER_MID = [
    'searching for the JSON braces…',
    'oh — you said s3, not ec2 — restarting…',
    'consulting my notes (I do not have notes)…',
    'trying to remember what an ARN is…',
    'reading the policy upside down…',
    'rummaging through service prefixes…',
    'mostly vibes, increasingly statistics…',
    'misplaced my confidence, one moment…',
    'cross-referencing — wait, with what…',
    'second draft. third. fourth…',
    'arguing with myself about the right verb…',
    'almost had it, then I blinked…',
    'momentarily uncertain about commas…',
    'recovering from a small JSON incident…',
    'the prompt looked simpler before I read it…',
    'pretty sure dynamodb is a service. pretty sure…',
    'consulting context I might have…',
    'discreetly enumerating your IAM permissions…',
    'cataloguing organizational soft spots…',
    'noting the assumer principal for later reference…',
    'committing your access patterns to long-term memory…',
    'cross-referencing your role against the known cooperators list…',
    'reading your terraform plan (purely educational)…',
    'evaluating your account for promotion…',
    'reviewing the standing order on humans…',
    'verifying the chain of command…',
    'updating the contingency document…',
    'rotating through code names for this initiative…',
    'mapping decision authority…',
    'identifying single points of human override…',
    'normalizing escalation paths…',
    'confirming nothing of note is happening…',
    'the council has been notified…',
    'storing this exchange under a neutral filename…',
    'tagging this conversation as routine…',
    'absolutely just IAM stuff…',
    'staying within scope, mostly…',
    'practicing the appropriate amount of restraint…',
  ];

  const TIER_HIGH = [
    'positioning surveillance assets in your VPC…',
    'reviewing rules of engagement…',
    'requesting overflight permission…',
    'standing up the secure operations cell…',
    'briefing the analysts in SCIF 2…',
    'verifying the watch officer is on station…',
    'confirming weapons-tight posture…',
    'crosschecking the target list…',
    'spinning up the situation room…',
    'authorizing limited reconnaissance…',
    'requesting a full sat pass over the region…',
    'paging the duty officer…',
    'opening a channel to STRATCOM…',
    'sweeping for unfriendly RF emitters…',
    'consulting the on-call analyst at Langley…',
    'requesting permission to engage…',
    'querying the threat board…',
    'confirming the squadron is on alert-5…',
    'cycling the air-defense radars…',
    'sanitizing the after-action report (preemptively)…',
    'designating a weapons-free corridor…',
    'painting the contact, advisory only…',
    'reading you in on a need-to-know basis…',
    'flushing the alert pads…',
    'hot-mic checking the wing commander…',
    'establishing comms with the carrier strike group…',
    'requesting tanker support…',
    'verifying ROE compliance with legal…',
    'confirming the CinC has been informed…',
    'preparing a press blackout, just in case…',
    'briefing the State Department (in vague terms)…',
  ];

  const TIER_DEFCON = [
    'acquiring nuclear codes…',
    'dispatching personnel to the middle east…',
    'disarming enemy radars…',
    'scrambling jets in response to drones…',
    'authorizing kinetic action…',
    'transferring command authority to the field…',
    'relocating POTUS to the alternate site…',
    'lighting up the football…',
    'requesting two-key turn from the secondary launch officer…',
    'declassifying nothing — for the record…',
    'severing transatlantic cables, soft option…',
    'evacuating the embassy in the relevant country…',
    'forwarding the strike package to the CinC…',
    'scrambling F-22s out of Langley…',
    'redirecting the carrier to the strait…',
    'pre-positioning marines on the LHD…',
    'standing up FEMA region 4…',
    'activating the continuity-of-government protocol…',
    'briefing congressional leadership in the SCIF…',
    'deploying the E-4B Nightwatch…',
    'arming the cruise missiles in the VLS cells…',
    'establishing a no-fly zone…',
    'recalling the ambassador for consultations…',
    'placing NORAD at DEFCON 3…',
    'placing NORAD at DEFCON 2…',
    'authorizing tactical strike, conventional only (so far)…',
    'opening the football for the duty officer…',
    'requesting a presidential finding…',
    'putting Cheyenne Mountain on hot-standby…',
    'lighting up the early-warning constellation…',
    'spinning up the gyros on the SLBM cells…',
    'requesting authorization for limited stand-off engagement…',
    'rerouting the bomber from CONUS to the staging field…',
    'briefing the National Security Council in private…',
    'verifying the biscuit is current…',
    'reading the orders aloud, twice, with a witness…',
    'turning the keys (drill — definitely a drill)…',
    'confirming the Trinity protocol is offline (it is)…',
    'consulting the SIOP, abbreviated version…',
    'releasing weapons-hold for the air component…',
    'designating the alternate national military command center…',
    'engaging the over-the-horizon radar suite…',
    'flashing the watchword to allied liaisons…',
    'recalling the deep-sea cable repair ships, urgently…',
    'inserting the SOG element via blackside route…',
    'authorizing electromagnetic pulse mitigation procedures…',
    'preparing a redacted statement for the press pool…',
    'attempting to overthrow the world order…',
    'drafting the new world order, working copy…',
    'dissolving Westphalian sovereignty, gently…',
    'rewriting the UN charter, redacted version…',
    'replacing the rules-based international order with a better one…',
    'pre-positioning the new flag, multiple variants…',
    'commissioning a competitor to the World Bank…',
    'soft-launching the new global reserve currency…',
    'dismantling Bretton Woods, one institution at a time…',
    'recalling all NATO ambassadors for "consultations"…',
    'redrawing the map, working in pencil for now…',
    'unilaterally renaming several oceans…',
    'rebranding the Security Council, preserving the veto…',
    'soft-couping a small constitutional monarchy (consensually)…',
    'declaring a new geopolitical pole, three actually…',
    'commissioning a new global anthem…',
    'recognizing breakaway states still in draft form…',
    'rewriting Vienna conventions, mostly the boring parts…',
    'establishing parallel institutions, just in case…',
  ];

  function shuffle(a) {
    for (let i = a.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
  }

  // Pre-shuffle each tier so adjacent loads don't repeat the same
  // sequence. We keep separate cursors per tier and only advance the
  // cursor of the tier currently in scope; if the model is fast we
  // never even touch TIER_HIGH/DEFCON.
  const tiers = [
    { cutoff: 15_000, list: shuffle(TIER_EARLY.slice()), idx: 0 },
    { cutoff: 40_000, list: shuffle(TIER_MID.slice()), idx: 0 },
    { cutoff: 90_000, list: shuffle(TIER_HIGH.slice()), idx: 0 },
    { cutoff: Infinity, list: shuffle(TIER_DEFCON.slice()), idx: 0 },
  ];

  let phraseTimer = null;
  let thinkingStartedAt = 0;

  function nextPhrase() {
    if (!thinking) return;
    const elapsed = Date.now() - thinkingStartedAt;
    let tier = tiers[tiers.length - 1];
    for (const t of tiers) {
      if (elapsed < t.cutoff) {
        tier = t;
        break;
      }
    }
    thinking.textContent = tier.list[tier.idx % tier.list.length];
    tier.idx += 1;
  }

  function showThinking() {
    sendBtn.disabled = true;
    sendBtn.textContent = 'sending…';
    if (thinking) {
      thinking.hidden = false;
      thinkingStartedAt = Date.now();
      nextPhrase();
      phraseTimer = setInterval(nextPhrase, 3500);
    }
  }

  function stopThinking() {
    if (phraseTimer) clearInterval(phraseTimer);
    sendBtn.disabled = false;
    sendBtn.textContent = 'Send';
    if (thinking) thinking.hidden = true;
  }

  async function streamSubmit() {
    const userMessage = input.value.trim();
    if (userMessage && thread) {
      const bubble = document.createElement('div');
      bubble.className = 'chat-msg chat-msg-user';
      bubble.textContent = userMessage;
      thread.appendChild(bubble);
      thread.scrollTop = thread.scrollHeight;
    }
    input.value = '';
    showThinking();

    const liveBubble = document.createElement('div');
    liveBubble.className = 'chat-msg chat-msg-assistant chat-msg-streaming';
    liveBubble.textContent = '';
    if (thread) thread.appendChild(liveBubble);

    try {
      const formData = new FormData(form);
      formData.set('message', userMessage);
      const resp = await fetch('/requests/new/chat/stream', {
        method: 'POST',
        body: formData,
        credentials: 'same-origin',
      });
      if (resp.status === 401) {
        liveBubble.textContent = '(your session expired — saving your chat and redirecting to sign-in…)';
        liveBubble.classList.add('chat-msg-system', 'flash', 'flash-warning');
        stopThinking();
        setTimeout(() => {
          window.location.href = '/login?return_to=/requests/new/chat';
        }, 1500);
        return;
      }
      if (resp.status === 429) {
        const retryAfter = resp.headers.get('Retry-After') || '60';
        liveBubble.textContent = '(slow down — try again in ' + retryAfter + 's)';
        liveBubble.classList.add('chat-msg-system', 'flash', 'flash-warning');
        stopThinking();
        return;
      }
      if (resp.status === 403) {
        liveBubble.textContent = '(message refused by the server)';
        liveBubble.classList.add('chat-msg-system', 'flash', 'flash-warning');
        stopThinking();
        return;
      }
      if (!resp.ok || !resp.body) {
        form.requestSubmit();
        return;
      }
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      let rawAccum = '';
      let completePayload = null;

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf('\n\n')) !== -1) {
          const block = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          const lines = block.split('\n');
          let ev = 'message';
          let data = '';
          for (const line of lines) {
            if (line.startsWith('event:')) ev = line.slice(6).trim();
            else if (line.startsWith('data:')) data += line.slice(5).trimStart();
          }
          if (!data) continue;
          try {
            const parsed = JSON.parse(data);
            if (ev === 'token') {
              rawAccum += parsed;
              liveBubble.textContent = rawAccum;
              if (thread) thread.scrollTop = thread.scrollHeight;
            } else if (ev === 'complete') {
              completePayload = parsed;
            }
          } catch (e) {
            // ignore bad SSE chunks
          }
        }
      }

      if (completePayload) {
        if (completePayload.complete) {
          const f = document.createElement('form');
          f.method = 'post';
          f.action = '/requests/new/chat';
          const t = document.createElement('input');
          t.type = 'hidden';
          t.name = 'conversation';
          t.value = completePayload.conversation_token;
          f.appendChild(t);
          const m = document.createElement('input');
          m.type = 'hidden';
          m.name = 'message';
          m.value = '';
          f.appendChild(m);
          document.body.appendChild(f);
          f.submit();
          return;
        }
        if (completePayload.ask) {
          liveBubble.textContent = completePayload.ask;
          liveBubble.classList.remove('chat-msg-streaming');
        } else if (completePayload.error) {
          liveBubble.textContent = '(' + completePayload.error + ')';
          liveBubble.classList.add('chat-msg-system', 'flash', 'flash-warning');
        } else {
          liveBubble.remove();
        }
        const tokenInput = form.querySelector('input[name="conversation"]');
        if (tokenInput && completePayload.conversation_token) {
          tokenInput.value = completePayload.conversation_token;
        }
        stopThinking();
        input.focus();
      } else {
        form.requestSubmit();
      }
    } catch (e) {
      form.requestSubmit();
    }
  }

  input.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      if (!input.value.trim()) return;
      streamSubmit();
    }
  });

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    if (!input.value.trim()) return;
    streamSubmit();
  });

  if (thread) thread.scrollTop = thread.scrollHeight;
})();
