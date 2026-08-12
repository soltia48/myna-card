# JPKI root certificates

The trust anchors for the 公的個人認証AP's X.509 certificates, downloaded from J-LIS:
<https://www.jpki.go.jp/ca/index.html>. Committed exactly as received, DER encoded, so they can be
compared byte for byte against that page.

They are compiled into the crate by `certificate::roots`, not read at run time — a trust anchor
loaded from a file beside the binary is one an attacker can replace.

| File | Issues | Generation | Valid | Serial |
|---|---|---|---|---|
| `authca01.cer` | 利用者証明用証明書 | 1 | 2015-10-20 to 2025-10-19 | `01` |
| `authca02.cer` | 利用者証明用証明書 | 2 | 2019-09-14 to 2029-09-14 | `0133C349` |
| `authca03.cer` | 利用者証明用証明書 | 3 | 2023-07-16 to 2033-07-15 | `06D18006` |
| `signca01.cer` | 署名用証明書 | 1 | 2015-10-20 to 2025-10-19 | `01` |
| `signca02.cer` | 署名用証明書 | 2 | 2019-09-14 to 2029-09-14 | `0132C4AB` |
| `signca03.cer` | 署名用証明書 | 3 | 2023-07-16 to 2033-07-15 | `067C6A21` |

The generation numbers are J-LIS's own, from the file names; nothing here invents them. The set is
complete as published, so three of each is all there is.

All six are self-signed, RSA-2048 and `sha256WithRSAEncryption`. The first pair has expired and is
kept anyway: certificates issued before 2025-10-19 still have to be checkable, which is why
`Certificate::verify_chain` takes the date as an argument instead of reading a clock.

## Why the card's own CA certificate is not enough

公的個人認証AP `0002` and `000B` hold CA certificates, and a card's certificate does verify against
them. That proves nothing on its own: both came off the same card, so a card that lied about one
would lie about the other. `Certificate::verify_to_root` ends at these files instead.

## test/ — the test hierarchy

J-LIS publishes no root for `O=JPKI-TEST`, so these four were read off two JPKI test cards, out of
公的個人認証AP `0002` and `000B`. They are here so that a test card can be exercised end to end.

| File | Issues | Serial | Valid |
|---|---|---|---|
| `test/authca-test-2019.cer` | 利用者証明用証明書 | `00BFCD` | 2019-03-09 to 2029-03-08 |
| `test/authca-test-2023.cer` | 利用者証明用証明書 | `218887` | 2023-03-23 to 2033-03-22 |
| `test/signca-test-2019.cer` | 署名用証明書 | `00C139` | 2019-07-17 to 2029-07-17 |
| `test/signca-test-2024.cer` | 署名用証明書 | `1EA8A8` | 2024-08-28 to 2034-08-28 |

**These have no generation number and the set is not known to be complete.** J-LIS publishes no
list for `O=JPKI-TEST`, so there is nothing to number them against and no way to tell whether more
exist — these are simply the ones two test cards happened to carry. The file names use the year
they were issued for that reason, and `Root::generation` is `None` for all four. Tell them apart by
serial or validity.

**They are not interchangeable with the production roots and the crate will not treat them as
such.** `roots::issuer_of` and `Certificate::verify_to_root` take an `Accept`, and the default
anyone should use — `Accept::ProductionOnly` — never returns one of these. A test card is not a
person's Individual Number Card, and code that decides whether to believe a cardholder must not
accept one.

Embedding them does buy something real. Read from the card, a test CA certificate is whatever the
card says it is; pinned here, a card presenting some *other* self-signed `O=JPKI-TEST` certificate
is rejected. The same four bytes-for-bytes live in `tests/fixtures/`, as the record of what those
EFs returned, and a test asserts the two copies have not drifted.

## A name does not identify a root

The three generations of each production root share one distinguished name, and so do the test
roots. Anything resolving an issuer has to narrow by name and then decide by signature — which is
what `roots::issuer_of` does, and why.

## What is not here

The 券面 applications use card-verifiable certificates, not X.509, and their trust anchors are a
different set held in `src/ca.rs`.

## Checking these files

```sh
for f in certs/*.cer; do openssl x509 -inform DER -in "$f" -noout -subject -dates -serial; done
```
