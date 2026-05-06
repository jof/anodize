//! Wordlist encoding for human-transcribable share representation.
//!
//! Each byte maps to a unique 4–6 letter English word. Words are chosen
//! to be phonetically distinct, easy to spell, and unambiguous when read
//! aloud. The list has exactly 256 entries (one per byte value).
//!
//! Format: `WORD-WORD-WORD-WORD / WORD-WORD-WORD-WORD / ...`
//! Groups of 4 words separated by ` / ` for easy row tracking during
//! transcription.

use std::fmt;

/// 256 words, indexed by byte value. Selected for phonetic distinctness
/// and ease of transcription.
const WORDLIST: [&str; 256] = [
    "able", "acid", "aged", "also", "arch", "area", "army", "atom", // 0x00
    "aunt", "away", "back", "bake", "band", "bank", "bark", "base", // 0x08
    "bath", "bead", "beam", "bear", "beat", "beef", "bell", "belt", // 0x10
    "bend", "best", "bike", "bird", "bite", "blow", "blue", "blur", // 0x18
    "boat", "body", "bold", "bolt", "bomb", "bond", "bone", "book", // 0x20
    "born", "boss", "bowl", "bulk", "bump", "burn", "bush", "busy", // 0x28
    "buzz", "cafe", "cage", "cake", "calm", "came", "camp", "cane", // 0x30
    "cape", "card", "care", "cart", "case", "cash", "cast", "cave", // 0x38
    "cell", "chat", "chef", "chin", "chip", "chop", "city", "clad", // 0x40
    "clam", "clan", "claw", "clay", "clip", "club", "clue", "coal", // 0x48
    "coat", "code", "coil", "coin", "cold", "colt", "come", "cook", // 0x50
    "cool", "cope", "copy", "cord", "core", "corn", "cost", "crew", // 0x58
    "crop", "crow", "cube", "cult", "cups", "curb", "cure", "curl", // 0x60
    "cute", "damp", "dare", "dark", "dart", "dash", "data", "dawn", // 0x68
    "days", "dead", "deaf", "deal", "dear", "deck", "deed", "deem", // 0x70
    "deep", "deer", "demo", "dent", "deny", "desk", "dial", "dice", // 0x78
    "diet", "dine", "dirt", "disc", "dish", "dock", "does", "dome", // 0x80
    "done", "door", "dose", "down", "drag", "draw", "drip", "drop", // 0x88
    "drum", "dual", "duck", "dude", "duel", "duet", "duke", "dull", // 0x90
    "dune", "dusk", "dust", "duty", "each", "earn", "ease", "east", // 0x98
    "easy", "edge", "edit", "else", "emit", "ends", "envy", "epic", // 0xA0
    "even", "evil", "exam", "exit", "face", "fact", "fade", "fail", // 0xA8
    "fair", "fake", "fall", "fame", "fang", "farm", "fast", "fate", // 0xB0
    "fawn", "fear", "feat", "feed", "feel", "fell", "felt", "fern", // 0xB8
    "file", "fill", "film", "find", "fine", "fire", "firm", "fish", // 0xC0
    "fist", "five", "flag", "flat", "fled", "flew", "flex", "flip", // 0xC8
    "flow", "foam", "fold", "folk", "fond", "font", "food", "foot", // 0xD0
    "fork", "form", "fort", "foul", "four", "free", "frog", "from", // 0xD8
    "fuel", "full", "fund", "fury", "fuse", "gait", "gale", "game", // 0xE0
    "gang", "gate", "gave", "gaze", "gear", "gene", "gift", "gild", // 0xE8
    "girl", "give", "glad", "glow", "glue", "goat", "goes", "gold", // 0xF0
    "golf", "gone", "good", "grab", "gray", "grew", "grid", "grim", // 0xF8
];

#[derive(Debug)]
pub struct WordlistError(pub String);

impl fmt::Display for WordlistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for WordlistError {}

/// Build a reverse lookup map (word → byte value) at first use.
fn word_to_byte(word: &str) -> Option<u8> {
    let lower = word.to_ascii_lowercase();
    WORDLIST.iter().position(|&w| w == lower).map(|i| i as u8)
}

/// Encode bytes as a wordlist string.
///
/// Format: groups of 4 words joined by `-`, groups separated by ` / `.
/// Example: `able-acid-aged-also / arch-area-army-atom`
pub fn encode_words(bytes: &[u8]) -> String {
    let words: Vec<&str> = bytes.iter().map(|&b| WORDLIST[b as usize]).collect();
    let groups: Vec<String> = words.chunks(4).map(|g| g.join("-")).collect();
    groups.join(" / ")
}

/// Decode a wordlist string back to bytes.
///
/// Accepts any mix of `-` and ` / ` separators. Case-insensitive.
pub fn decode_words(input: &str) -> Result<Vec<u8>, WordlistError> {
    let normalized = input.replace(" / ", "-").replace('/', "-");
    let words: Vec<&str> = normalized
        .split('-')
        .map(|w| w.trim())
        .filter(|w| !w.is_empty())
        .collect();

    if words.is_empty() {
        return Err(WordlistError("empty input".into()));
    }

    words
        .iter()
        .map(|&w| word_to_byte(w).ok_or_else(|| WordlistError(format!("unknown word: {:?}", w))))
        .collect()
}

/// Return all wordlist entries matching a case-insensitive prefix.
pub fn prefix_matches(prefix: &str) -> Vec<&'static str> {
    let lower = prefix.to_ascii_lowercase();
    WORDLIST
        .iter()
        .copied()
        .filter(|w| w.starts_with(&lower))
        .collect()
}

/// Check if a word is in the wordlist (case-insensitive).
pub fn is_valid_word(word: &str) -> bool {
    word_to_byte(word).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_has_256_entries() {
        assert_eq!(WORDLIST.len(), 256);
    }

    #[test]
    fn wordlist_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for (i, word) in WORDLIST.iter().enumerate() {
            assert!(
                seen.insert(*word),
                "duplicate word {:?} at index {}",
                word,
                i
            );
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let data = vec![0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0x80, 0x40];
        let encoded = encode_words(&data);
        let decoded = decode_words(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_case_insensitive() {
        let data = vec![0x00, 0x01];
        let encoded = encode_words(&data).to_uppercase();
        let decoded = decode_words(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_unknown_word() {
        let err = decode_words("able-xyzzy-aged").unwrap_err();
        assert!(err.0.contains("xyzzy"));
    }

    #[test]
    fn all_bytes_roundtrip() {
        let all: Vec<u8> = (0..=255).collect();
        let encoded = encode_words(&all);
        let decoded = decode_words(&encoded).unwrap();
        assert_eq!(decoded, all);
    }

    #[test]
    fn prefix_matches_single() {
        let matches = prefix_matches("abl");
        assert_eq!(matches, vec!["able"]);
    }

    #[test]
    fn prefix_matches_multiple() {
        let matches = prefix_matches("ba");
        assert!(matches.len() > 1);
        for w in &matches {
            assert!(w.starts_with("ba"), "{w} should start with 'ba'");
        }
    }

    #[test]
    fn prefix_matches_case_insensitive() {
        let lower = prefix_matches("ab");
        let upper = prefix_matches("AB");
        assert_eq!(lower, upper);
    }

    #[test]
    fn prefix_matches_empty_prefix_returns_all() {
        let matches = prefix_matches("");
        assert_eq!(matches.len(), 256);
    }

    #[test]
    fn prefix_matches_no_match() {
        let matches = prefix_matches("zzz");
        assert!(matches.is_empty());
    }

    #[test]
    fn is_valid_word_accepts_known() {
        assert!(is_valid_word("able"));
        assert!(is_valid_word("ABLE"));
        assert!(is_valid_word("Able"));
    }

    #[test]
    fn is_valid_word_rejects_unknown() {
        assert!(!is_valid_word("xyzzy"));
        assert!(!is_valid_word(""));
    }
}
