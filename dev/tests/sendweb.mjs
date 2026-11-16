// PR2 接收頁金標：HTML 內聯 JS（WebCrypto）與 Rust `bw-crypto/send` 派生鏈
// 逐位元組對照。向量獨立產自 python（hmac/hashlib/openssl，同 send.sh 對照
// 鏈口徑），非任一語言的自證。跑法：`node dev/tests/sendweb.mjs`。
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const htmlPath = path.join(here, "../../bins/bitwarderd/assets/send-receive.html");
const html = readFileSync(htmlPath, "utf8");
const m = /\/\*JS-START\*\/([\s\S]*?)\/\*JS-END\*\//.exec(html);
if (!m) {
  console.error("FAIL: HTML 內找不到 JS-START/JS-END 標記段");
  process.exit(1);
}
// 佔位 nonce 在 node 側無意義（不發 fetch），留字串即可。
const BW = new Function(`${m[0].replaceAll("__BW_NONCE__", "test-nonce")}; return BW;`)();

const assert = (cond, msg) => {
  if (!cond) {
    console.error(`FAIL: ${msg}`);
    process.exit(1);
  }
  console.log(`ok: ${msg}`);
};
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const bytesFromHex = (h) => new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));

// —— 金標向量（python 獨立實作產出，2026-11-16）——
const SEED_HEX = "00112233445566778899aabbccddeeff";
// Rust bw-crypto send.rs::stretch_kat_against_official_derivation 同值：
const STRETCHED =
  "9f48c08ee2b16be3db943552165b1f2f646000c481ffbdc2ffd09ddaa169fbee" +
  "700493a8b6e374873f992029f01600e26940b004fe16ec0a32996a1fb021ba5c";
// Rust password_hash_kat 同值：
const PW_HASH = "IUfRQWngrzaQ9yDeP5jdidY+TbsIpwLrvaezPw/pemk=";
// type 2 信封（固定 IV 0f..10 遞減、明文 "Send-web-金標-42"，openssl 產）：
const ENVELOPE =
  "2.EA8ODQwLCgkIBwYFBAMCAQ==|4G4Iv1nHdU5tEo3Vbi9ZM6vrSHk1uSQOOJYsdLTOi0I=|emy4yV4zEzNRk1RPeySOGUgnigIcVc5AVmZLEjBw/mI=";
const PLAINTEXT = "Send-web-金標-42";

const seed = bytesFromHex(SEED_HEX);

// 1) seed → 拉伸 64 bytes（HKDF-SHA256 Expand-only 語意經 WebCrypto salt 等式）
const { encKey, macKey } = await BW.deriveSendKey(seed);
assert(
  hex(encKey) + hex(macKey) === STRETCHED,
  `拉伸金鑰與 Rust/python 金標逐位元組同值（got ${hex(encKey).slice(0, 8)}…）`
);

// 2) 取用密碼線格式（PBKDF2-HMAC-SHA256 100k、標準 b64 含填充）
assert((await BW.passwordHash("hunter2", seed)) === PW_HASH, "密碼哈希金標同值");

// 3) type 2 信封解密（MAC 先驗 + AES-256-CBC/PKCS7）
const plain = await BW.decryptEnvelope(ENVELOPE, encKey, macKey);
assert(
  new TextDecoder().decode(plain) === PLAINTEXT,
  "信封解密還原原文（跨實作閉環）"
);

// 4) MAC 篡改必拒（不得吐部分明文）
{
  const bad = ENVELOPE.replace(/(\|[^|]+)=\|/, "$1x|");
  let threw = false;
  try {
    await BW.decryptEnvelope(bad, encKey, macKey);
  } catch (e) {
    threw = true;
  }
  assert(threw, "MAC 不符時丟錯（降級/篡改不吞）");
}

// 5) 片段解析：官方形態與缺段
{
  const p = BW.parseHash("#/send/ACC-IDA/AAECAwQFBgcICQoLDA0ODw");
  assert(p && p.aid === "ACC-IDA" && hex(p.seed) === "000102030405060708090a0b0c0d0e0f",
    "parseHash 解出 accessId＋16B seed");
  assert(BW.parseHash("") === null, "缺片段回 null");
  assert(BW.parseHash("#/vault/AAECAwQFBgcICQoLDA0ODw") === null, "非 send 段回 null");
  assert(BW.parseHash("#/send/A/short") === null, "seed 長度不對回 null");
}

console.log("sendweb.mjs 全綠");
