// Demo page: a small form + three one-click examples (one ALLOW, one
// WARN, one BLOCK). All three use real mainnet addresses and are
// deterministic: they do not depend on flaky explorer data.

export const demoHtml = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Payment Guard — demo</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:760px;margin:32px auto;padding:0 16px;color:#1a1a1a}
h1{font-size:22px} p{color:#444} label{display:block;margin:10px 0 4px;font-weight:600}
input,select{width:100%;padding:8px;border:1px solid #bbb;border-radius:6px;font-size:14px}
button{margin-top:14px;padding:10px 18px;font-size:15px;border-radius:6px;border:0;background:#111;color:#fff;cursor:pointer}
button.example{background:#eee;color:#111;margin-right:8px}
pre{background:#111;color:#d6ffd6;padding:14px;border-radius:8px;white-space:pre-wrap;word-break:break-word;font-size:13px}
.badge{display:inline-block;padding:2px 10px;border-radius:20px;font-weight:700}
.ALLOW{background:#d9f7d9}.WARN{background:#fff3c4}.BLOCK{background:#ffd6d6}
</style>
</head>
<body>
<h1>Payment &amp; Wallet Security Guard</h1>
<p>Screen a crypto transfer or token approval <b>before</b> you sign it. The guard checks the recipient, the amount and the spender against on-chain facts and a public scam list, then answers <b>ALLOW / WARN / BLOCK</b> with reasons you can verify. It only reads the chain — it never sends a transaction and never asks for a key.</p>

<h2>Try it</h2>
<button class="example" onclick="fillExample('allow')">1 · Safe transfer (ALLOW)</button>
<button class="example" onclick="fillExample('warn')">2 · Unlimited approval to a known router (WARN)</button>
<button class="example" onclick="fillExample('block')">3 · Unlimited approval to an unknown spender (BLOCK)</button>

<form id="f" onsubmit="return screen(event)">
<label>Chain</label>
<select id="chain"><option value="bsc">BSC (56)</option><option value="eth">Ethereum (1)</option><option value="base">Base (8453)</option></select>
<label>Kind</label>
<select id="kind"><option value="transfer">transfer</option><option value="approval">approval</option></select>
<label>From (sender)</label>
<input id="from" value="0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed">
<label>To (recipient)</label>
<input id="to" value="0x000000000000000000000000000000000000dEaD">
<label>Token (contract address, or "native")</label>
<input id="token" value="0x55d398326f99059fF775485246999027B3197955">
<label>Amount (integer base units, e.g. 10 USDT on BSC = 10000000000000000000)</label>
<input id="amount" value="10000000000000000000">
<label>Spender (only for approval)</label>
<input id="spender" value="">
<label>Approval amount (only for approval; blank = same as amount)</label>
<input id="approval_amount" value="">
<button type="submit">Screen it</button>
</form>

<h2>Result</h2>
<div id="verdict"></div>
<pre id="out">Press “Screen it” or one of the examples above.</pre>

<script>
const EXAMPLES = {
  allow: {chain:"bsc", kind:"transfer", from:"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", to:"0x000000000000000000000000000000000000dEaD", token:"0x55d398326f99059fF775485246999027B3197955", amount:"10000000000000000000", spender:"", approval_amount:""},
  warn: {chain:"bsc", kind:"approval", from:"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", to:"0x55d398326f99059fF775485246999027B3197955", token:"0x55d398326f99059fF775485246999027B3197955", amount:"10000000000000000000", spender:"0x10ED43C718714eb63d5aA57B78B54704E256024E", approval_amount:"115792089237316195423570985008687907853269984665640564039457584007913129639935"},
  block: {chain:"bsc", kind:"approval", from:"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", to:"0x55d398326f99059fF775485246999027B3197955", token:"0x55d398326f99059fF775485246999027B3197955", amount:"10000000000000000000", spender:"0x1111111111111111111111111111111111111111", approval_amount:"115792089237316195423570985008687907853269984665640564039457584007913129639935"}
};
function fillExample(name){
  const e = EXAMPLES[name];
  for (const k of Object.keys(e)) document.getElementById(k).value = e[k];
  screen(null);
}
async function screen(ev){
  if (ev) ev.preventDefault();
  const body = {
    chain: document.getElementById('chain').value,
    kind: document.getElementById('kind').value,
    from: document.getElementById('from').value.trim(),
    to: document.getElementById('to').value.trim(),
    token: document.getElementById('token').value.trim(),
    amount: document.getElementById('amount').value.trim(),
  };
  const spender = document.getElementById('spender').value.trim();
  const appr = document.getElementById('approval_amount').value.trim();
  if (body.kind === 'approval') { body.spender = spender; if (appr) body.approval_amount = appr; }
  document.getElementById('out').textContent = 'Screening… (reading the chain, usually < 1s)';
  document.getElementById('verdict').innerHTML = '';
  try {
    const r = await fetch('/screen', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
    const j = await r.json();
    document.getElementById('out').textContent = JSON.stringify(j, null, 2);
    if (j.decision) document.getElementById('verdict').innerHTML = '<span class="badge '+j.decision+'">'+j.decision+' · risk '+j.risk_score+'/100</span>';
  } catch (e) {
    document.getElementById('out').textContent = 'Error: ' + e.message;
  }
  return false;
}
</script>
</body>
</html>
`;
