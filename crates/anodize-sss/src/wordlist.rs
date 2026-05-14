//! Wordlist encoding for human-transcribable share representation.
//!
//! Each byte maps to a unique 4-letter English word. Words are chosen
//! for minimum pairwise Hamming distance ≥ 2: any single-character
//! transcription error produces a string that is not a valid word,
//! making mistakes immediately detectable. The list has exactly 256
//! entries (one per byte value).
//!
//! Format: `WORD-WORD-WORD-WORD / WORD-WORD-WORD-WORD / ...`
//! Groups of 4 words separated by ` / ` for easy row tracking during
//! transcription.

use std::fmt;

/// 256 words, indexed by byte value. Every pair differs in at least 2
/// character positions (Hamming distance ≥ 2).
const WORDLIST: [&str; 256] = [
    "abet", "able", "acre", "agog", "ague", "ahoy", "aids", "alas", // 0x00
    "also", "amen", "ammo", "aped", "area", "atom", "avid", "ayes", // 0x08
    "bait", "balk", "bane", "baud", "bawl", "beau", "bees", "beta", // 0x10
    "blot", "boar", "bogy", "boys", "bred", "brig", "buff", "bugs", // 0x18
    "buoy", "cake", "calf", "cash", "chad", "chew", "chit", "chum", // 0x20
    "clan", "clip", "cloy", "club", "coat", "coda", "come", "cool", // 0x28
    "cozy", "dank", "deaf", "deem", "deft", "dewy", "dirt", "disk", // 0x30
    "dons", "doom", "dour", "down", "draw", "dual", "dubs", "duct", // 0x38
    "duly", "dupe", "ease", "eats", "edit", "eyed", "fair", "fast", // 0x40
    "feel", "fens", "file", "fish", "flee", "flow", "foam", "foes", // 0x48
    "font", "fore", "from", "full", "fuse", "gall", "gape", "gems", // 0x50
    "gent", "gibe", "gins", "glib", "glut", "gone", "gram", "grid", // 0x58
    "guru", "halt", "harm", "haul", "have", "hazy", "hear", "help", // 0x60
    "herb", "high", "hind", "hips", "hobo", "hold", "hoop", "hope", // 0x68
    "huge", "hulk", "hums", "hung", "iced", "info", "iota", "isle", // 0x70
    "item", "jaws", "jigs", "jive", "john", "jolt", "kale", "keen", // 0x78
    "king", "kite", "labs", "lacy", "lamb", "lard", "lead", "lied", // 0x80
    "lily", "line", "list", "loft", "logs", "loon", "maid", "mart", // 0x88
    "mate", "mean", "melt", "mend", "mere", "mike", "mole", "moor", // 0x90
    "most", "muck", "mush", "nail", "name", "nary", "need", "nest", // 0x98
    "node", "nook", "oils", "ones", "ours", "oust", "oval", "over", // 0xA0
    "pads", "peck", "pegs", "pies", "pill", "pixy", "plop", "polo", // 0xA8
    "pomp", "posh", "prod", "pulp", "pure", "rage", "rams", "rang", // 0xB0
    "reek", "rhea", "ribs", "rice", "roll", "rosy", "rump", "rune", // 0xB8
    "rusk", "ruts", "sago", "sans", "scan", "seep", "sell", "shot", // 0xC0
    "silt", "sirs", "skim", "slap", "slit", "smog", "snow", "snub", // 0xC8
    "sock", "song", "spat", "spew", "stay", "sued", "sunk", "tags", // 0xD0
    "tamp", "team", "tern", "thaw", "thud", "tick", "tint", "tire", // 0xD8
    "tony", "tops", "tort", "tray", "trim", "twin", "unit", "used", // 0xE0
    "vain", "veto", "vise", "void", "vote", "wack", "wade", "wand", // 0xE8
    "warn", "wasp", "wavy", "ways", "weds", "wept", "wham", "whir", // 0xF0
    "wink", "wipe", "wits", "work", "wren", "yawn", "yeah", "yoke", // 0xF8
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

    #[test]
    fn wordlist_min_hamming_distance_is_2() {
        for i in 0..WORDLIST.len() {
            for j in (i + 1)..WORDLIST.len() {
                let a = WORDLIST[i].as_bytes();
                let b = WORDLIST[j].as_bytes();
                assert_eq!(
                    a.len(),
                    b.len(),
                    "length mismatch: {} vs {}",
                    WORDLIST[i],
                    WORDLIST[j]
                );
                let dist: usize = a.iter().zip(b.iter()).filter(|(x, y)| x != y).count();
                assert!(
                    dist >= 2,
                    "Hamming distance {} < 2 between {:?} (0x{:02X}) and {:?} (0x{:02X})",
                    dist,
                    WORDLIST[i],
                    i,
                    WORDLIST[j],
                    j
                );
            }
        }
    }
}
