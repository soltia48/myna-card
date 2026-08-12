# Fixtures

Files read from a JPKI **test** card — certificates issued under `O=JPKI-TEST`, holder data
synthetic. They are here so the parsers and the signature checks are tested against what a card
actually returns rather than against something hand-built to match the parser.

| File | 券面事項確認AP EF | Read with |
|---|---|---|
| `surface-0001.bin` | `0001`, age verification record | the 生年月日 key, `550217` |
| `surface-0002.bin` | `0002`, card face | 照合番号A |
| `surface-0004.bin` | `0004`, this AP's card-verifiable certificate | nothing |
| `surface-0005.bin` | `0005`, rendered 個人番号 | 照合番号A |

| File | 公的個人認証AP EF | Read with |
|---|---|---|
| `jpki-auth-cert.der` | `000A`, 利用者証明用証明書 | nothing |
| `jpki-auth-ca-cert.der` | `000B`, its CA certificate | nothing |
| `jpki-sign-cert.der` | `0001`, 署名用証明書 | the 署名用パスワード |

| File | 券面入力補助AP EF | Read with |
|---|---|---|
| `text-0001-physical.bin` | `0001`, the 個人番号 file **including its filler** | the PIN or 照合番号A |
| `text-0002.bin` | `0002`, 基本4情報 | the PIN or 照合番号B |
| `text-0003.bin` | `0003`, integrity record | the PIN or either 照合番号 |
| `text-0004.bin` | `0004`, this AP's card-verifiable certificate | nothing |
| `text-0006.bin` | `0006`, an unidentified public key | the PIN or either 照合番号 |
| `text-0007.bin` | `0007`, the AP's signing key with a signature over it | the PIN or either 照合番号 |

Not from a card:

| File | What it is |
|---|---|
| `cv-certificate-synthetic.bin` | a card-verifiable certificate built to the card's exact layout and signed with a key generated for the test, because the CA key for the real ones is not published |
| `cv-ca-key-synthetic.bin` | that key's public half, in the card's own `90`/`91` encoding |
