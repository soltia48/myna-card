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
| `jpki-sign-ca-cert.der` | `0002`, its CA certificate | nothing |

Two more, from a second JPKI test card issued in 2021, are here for one reason: they carry the
**same distinguished names** as the pair above and different keys, so a lookup that stops at the
name picks the wrong one.

| File | What it is |
|---|---|
| `jpki-auth-ca-cert-2019.der` | 利用者証明用CA of the other card, serial `00BFCD` |
| `jpki-sign-ca-cert-2019.der` | 署名用CA of the other card, serial `00C139` |

All four CA certificates are also carried as trust anchors in [`certs/test/`](../../certs/test/).
These copies are the record of what the EFs returned; those are what the crate embeds. A test
asserts they are the same bytes.

Both CA certificates are self-signed roots of the `O=JPKI-TEST` hierarchy, and each verifies its
own leaf and not the other's. Neither is one of the roots in [`certs/`](../../certs/) — J-LIS
publishes none for the test hierarchy — which is what makes them useful here: they are exactly the
case where a chain checks out against an anchor that came off the card being checked, and still
proves nothing.

| File | 券面入力補助AP EF | Read with |
|---|---|---|
| `text-0001-physical.bin` | `0001`, the 個人番号 file **including its filler** | the PIN or 照合番号A |
| `text-0002.bin` | `0002`, 基本4情報 | the PIN or 照合番号B |
| `text-0003.bin` | `0003`, integrity record | the PIN or either 照合番号 |
| `text-0004.bin` | `0004`, this AP's card-verifiable certificate | nothing |
| `text-0006.bin` | `0006`, the session key encryption public key | the PIN or either 照合番号 |
| `text-0007.bin` | `0007`, the AP's signing key with a signature over it | the PIN or either 照合番号 |

These two are not in any EF. They are data objects, read with `00 CA` while no DF is selected, and
stored as GET DATA returns them — the contents of the `7F21` template without the template itself.
`CardVerifiableCertificate::parse` takes either form, so they need no fixing up:

| File | MF data object | Read with |
|---|---|---|
| `mf-do-F8.bin` | `00F8`, a card-verifiable certificate, 証明者鍵ID → 被証明者鍵ID | nothing |
| `mf-do-7F21.bin` | `7F21`, the certificate below it in the same chain | nothing |

Not from a card:

| File | What it is |
|---|---|
| `cv-certificate-synthetic.bin` | a card-verifiable certificate built to the card's exact layout and signed with a key generated for the test |
| `cv-ca-key-synthetic.bin` | that key's public half, in the card's own `90`/`91` encoding |

The synthetic pair exists for the tampering cases, where a signature has to be *wrong* in a
controlled way and a real one cannot be produced. The real certificates need no such stand-in: they
verify against the CA table in `ca`, and are tested that way.
