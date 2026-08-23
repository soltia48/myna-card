//! The applications hosted on the card.
//!
//! The card is organised as a set of dedicated files (DFs), each holding its own elementary
//! files (EFs) and its own key references. One module here corresponds to one application:
//!
//! | Module | Application | AID |
//! |---|---|---|
//! | [`common`] | 共通カードAP | `D3 92 10 00 31 00 01 01 01 00` |
//! | [`juki`] | 住基AP | `D3 92 10 00 31 00 01 01 04 01` |
//! | [`surface`] | 券面事項確認AP | `D3 92 10 00 31 00 01 01 04 02` |
//! | [`text`] | 券面入力補助AP | `D3 92 10 00 31 00 01 01 04 08` |
//! | [`jpki`] | 公的個人認証AP | `D3 92 F0 00 26 01 00 00 00 01` |
//!
//! Each module exposes its AID as `DF`, its file identifiers under `ef`, and a wrapper type that
//! selects the application and offers the operations that are known to work on it. The wrapper
//! borrows the [`Card`](crate::Card) for as long as it lives, which keeps a second application
//! from being used while one is selected.
//!
//! The contents of several EFs are not yet understood; those are reachable through the generic
//! `read_ef` and `read_record` methods rather than a named accessor.
//!
//! # Wrapper lifetime and state
//!
//! Each wrapper's `select` method sends SELECT FILE immediately and returns only after the card
//! accepts the AID. Dropping the wrapper releases its Rust borrow but sends no APDU: the
//! application remains current, and a security status established there remains on the physical
//! card. Selecting a *different* application clears the status of the application being left;
//! selecting the same one again does not reliably provide a clean session.
//!
//! The wrappers' `card` methods are escape hatches for lower-level operations. They do not
//! re-select the application afterward, so a caller that uses one to select another DF must not
//! assume subsequent wrapper methods still address the original application.
//!
//! # Short EF identifiers
//!
//! Every EF listed here has an identifier in `0001`-`001E`, so every one of them also has a short
//! EF identifier (JICSAP 4.2 (2)). A command carrying one selects the file and acts on it in a
//! single exchange. These wrappers do not use that — they issue an explicit SELECT FILE, which
//! works whatever the card supports — but [`Card::read_binary_chunk_sfi`](crate::Card::read_binary_chunk_sfi)
//! and [`Card::verify_sfi`](crate::Card::verify_sfi) are there if you want to halve the round
//! trips.
//!
//! # Enumerating what is on a card
//!
//! Selecting a DF by a *prefix* of its name is legal (JICSAP 4.2 (1)), so a SELECT FILE that
//! succeeds does not prove you reached the DF you meant. The specification's answer is the
//! application folder list file, which names the current DF and its children; see
//! [`crate::mf::ApplicationFolders`].

pub mod common;
pub mod jpki;
pub mod juki;
pub mod surface;
pub mod text;

/// The default AID of the GlobalPlatform Issuer Security Domain, selected when the card is powered
/// up.
pub const DEFAULT_DF: [u8; 7] = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00];
