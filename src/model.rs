//! Stateful game-server objects and the protocol-facing player model.
//!
//! Most server state is kept in reference-counted objects guarded by mutexes.
//! Mutable state is protected by a `Mutex` or `RwLock`, while wire-facing
//! methods keep a small, imperative shape so packet behavior stays explicit.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as FmtWrite;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose, Engine as _};
use npcserver as npc_runtime;
use ring::hmac;
use serde::{Deserialize, Serialize};

use crate::config::{FileSystem, Logger, Settings};
use crate::network::{
    zlib_compress, zlib_decompress, zlib_decompress_with_fallback, Buffer, Encryption,
    SocketManager, SocketStub,
};
use crate::protocol::*;
use crate::websocket::{
    has_websocket_upgrade, is_websocket_request_prefix, make_websocket_frame,
    parse_websocket_frame, sniff_game_connection, write_raw, ReplayStream, WebSocketFrame,
    WEBSOCKET_BINARY_OPCODE, WEBSOCKET_CLOSE_OPCODE, WEBSOCKET_CONTINUATION_OPCODE, WEBSOCKET_GUID,
    WEBSOCKET_MAX_FRAME_PAYLOAD, WEBSOCKET_MAX_HANDSHAKE_SIZE, WEBSOCKET_PING_OPCODE,
    WEBSOCKET_PONG_OPCODE,
};
use crate::APP_VERSION;

pub static DEBUG_MODE: AtomicBool = AtomicBool::new(false);
pub static PACKET_DEBUG_MODE: AtomicBool = AtomicBool::new(false);

pub const SCRIPT_HELP_CACHE_TTL: Duration = Duration::from_secs(30 * 60);
pub const DEFAULT_SCRIPT_SCAN_MAX_RESULTS: usize = 20;
pub const SCRIPT_SCAN_CONTEXT_LINES: usize = 2;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ScriptHelpEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub type_name: String,
    pub params: Vec<String>,
    pub returns: String,
    pub scope: String,
    pub description: String,
}

impl ScriptHelpEntry {
    pub fn script_help_line(&self) -> String {
        let name = self.name.trim();
        if name.is_empty() {
            return String::new();
        }
        let mut line = name.to_string();
        if self.type_name.eq_ignore_ascii_case("function") {
            line.push('(');
            line.push_str(&self.params.join(", "));
            line.push(')');
        }
        let returns = self.returns.trim();
        let description = clean_script_help_description(&self.description);
        if !returns.is_empty() && !returns.eq_ignore_ascii_case("void") {
            line.push_str(" - returns ");
            line.push_str(returns);
        }
        if !description.is_empty() {
            if description
                .to_ascii_lowercase()
                .contains(&line.to_ascii_lowercase())
            {
                return description;
            }
            line.push_str(" - ");
            line.push_str(&description);
        }
        line
    }
    pub fn scriptHelpLine(&self) -> String {
        self.script_help_line()
    }
}

fn clean_script_help_description(value: &str) -> String {
    let value = value.trim();
    match value.to_ascii_lowercase().as_str() {
        "" | "clientside:" | "serverside:" | "no matching script function found!" => String::new(),
        _ => value.to_string(),
    }
}

#[derive(Clone, Debug)]
struct ScriptScanRoot {
    name: String,
    path: String,
    level_only: bool,
}

#[derive(Clone, Debug)]
pub struct ScriptScanMatch {
    pub path: String,
    pub display: String,
    pub lines: Vec<String>,
}

fn script_scan_roots(scope: &str) -> Vec<ScriptScanRoot> {
    let groups = vec![
        (
            "npcs",
            vec![ScriptScanRoot {
                name: "npcs".to_string(),
                path: "npcs".to_string(),
                level_only: false,
            }],
        ),
        (
            "weapons",
            vec![ScriptScanRoot {
                name: "weapons".to_string(),
                path: "weapons".to_string(),
                level_only: false,
            }],
        ),
        (
            "classes",
            vec![ScriptScanRoot {
                name: "classes".to_string(),
                path: "scripts".to_string(),
                level_only: false,
            }],
        ),
        (
            "levels",
            vec![
                ScriptScanRoot {
                    name: "levels".to_string(),
                    path: "levels".to_string(),
                    level_only: true,
                },
                ScriptScanRoot {
                    name: "levels".to_string(),
                    path: String::new(),
                    level_only: true,
                },
                ScriptScanRoot {
                    name: "levels".to_string(),
                    path: "world/levels".to_string(),
                    level_only: true,
                },
                ScriptScanRoot {
                    name: "ganis".to_string(),
                    path: "world/ganis".to_string(),
                    level_only: false,
                },
            ],
        ),
    ];
    let all = groups
        .iter()
        .flat_map(|(_, roots)| roots.iter().cloned())
        .collect::<Vec<_>>();
    let scope = scope.trim().to_ascii_lowercase();
    let mut roots = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for token in scope.split('/') {
        let selected: Option<&[ScriptScanRoot]> = match token {
            "scripts" | "all" => Some(&all),
            "npcs" => Some(&groups[0].1),
            "weapons" => Some(&groups[1].1),
            "classes" => Some(&groups[2].1),
            "levels" => Some(&groups[3].1),
            _ => None,
        };
        if let Some(selected) = selected {
            for root in selected {
                if seen.insert(root.path.clone()) {
                    roots.push(root.clone());
                }
            }
        }
    }
    roots
}

fn parse_script_scan_args(arg: &str) -> Option<(String, String)> {
    let fields = arg.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 2 {
        return None;
    }
    let scope = fields[0].to_string();
    if script_scan_roots(&scope).is_empty() {
        return None;
    }
    let query = fields[1..].join(" ");
    if query.is_empty() {
        None
    } else {
        Some((scope, query))
    }
}

fn is_script_scan_text_file(path: &Path, level_only: bool) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match extension.as_str() {
        "nw" | "zelda" | "graal" | "gmap" => true,
        "txt" | "gani" => !level_only,
        _ => false,
    }
}

fn walk_script_scan_files(path: &Path, output: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    let mut entries = entries.flatten().collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            walk_script_scan_files(&path, output);
        } else {
            output.push(path);
        }
    }
}

fn script_scan_display_name(root: &ScriptScanRoot, relative_path: &str, data: &[u8]) -> String {
    match root.name.as_str() {
        "weapons" => parse_weapon(&String::from_utf8_lossy(data))
            .map(|weapon| weapon.name)
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| {
                Path::new(relative_path)
                    .file_name()
                    .map(|value| value.to_string_lossy().into_owned())
                    .unwrap_or_default()
            }),
        "npcs" => parse_database_npc(&String::from_utf8_lossy(data))
            .map(|npc| npc.npc_name())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| {
                Path::new(relative_path)
                    .file_name()
                    .map(|value| value.to_string_lossy().into_owned())
                    .unwrap_or_default()
            }),
        "classes" => Path::new(relative_path)
            .file_stem()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_default(),
        _ => Path::new(relative_path)
            .file_name()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_default(),
    }
}

fn script_scan_context(data: &[u8], query: &str) -> Option<Vec<String>> {
    let text = String::from_utf8_lossy(data)
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let lines = text.split('\n').collect::<Vec<_>>();
    let query = query.to_ascii_lowercase();
    let mut matching = vec![false; lines.len()];
    for (index, line) in lines.iter().enumerate() {
        if line.to_ascii_lowercase().contains(&query) {
            let start = index.saturating_sub(SCRIPT_SCAN_CONTEXT_LINES);
            let end = (index + SCRIPT_SCAN_CONTEXT_LINES).min(lines.len().saturating_sub(1));
            for value in &mut matching[start..=end] {
                *value = true;
            }
        }
    }
    if !matching.iter().any(|value| *value) {
        return None;
    }
    let mut output = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if !matching[index] {
            index += 1;
            continue;
        }
        if !output.is_empty() {
            output.push("---".to_string());
        }
        while index < lines.len() && matching[index] {
            let prefix = if lines[index].to_ascii_lowercase().contains(&query) {
                '>'
            } else {
                ' '
            };
            let line = if lines[index].len() > 512 {
                format!(
                    "{}...",
                    String::from_utf8_lossy(&lines[index].as_bytes()[..512])
                )
            } else {
                lines[index].to_string()
            };
            output.push(format!("{prefix}{}: {line}", index + 1));
            index += 1;
        }
    }
    Some(output)
}

fn script_help_wildcard_match(query: &str, value: &str) -> bool {
    let pattern = query.trim().to_ascii_lowercase();
    let value = value.to_ascii_lowercase();
    let pattern = format!("*{pattern}*");
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut table = vec![vec![false; value.len() + 1]; pattern.len() + 1];
    table[0][0] = true;
    for (index, token) in pattern.iter().enumerate() {
        for value_index in 0..=value.len() {
            table[index + 1][value_index] = if *token == b'*' {
                table[index][value_index] || (value_index > 0 && table[index + 1][value_index - 1])
            } else {
                value_index > 0 && table[index][value_index - 1] && *token == value[value_index - 1]
            };
        }
    }
    table[pattern.len()][value.len()]
}

pub fn wildcard_script_help_match(query: &str, value: &str) -> bool {
    script_help_wildcard_match(query, value)
}

fn parse_gs2_join_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.len() < 4 || !trimmed[..4].eq_ignore_ascii_case("join") {
        return None;
    }
    let mut value = trimmed[4..].trim();
    if value.starts_with('(') {
        if !value.ends_with(')') {
            return None;
        }
        value = value[1..value.len() - 1].trim();
    } else {
        value = value.trim_end_matches(';').trim();
    }
    if value.ends_with(';') {
        value = value[..value.len() - 1].trim();
    }
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value = &value[1..value.len() - 1];
    }
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return None;
    }
    Some(value.to_string())
}

fn gs2_script_has_exact_event(script: &str, event_name: &str) -> bool {
    let wanted = event_name.trim();
    if wanted.is_empty() {
        return false;
    }
    for raw in script.lines() {
        let mut line = raw.trim_start();
        if line
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("public"))
        {
            line = line[6..].trim_start();
        }
        if line
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("function"))
        {
            let remainder = line[8..].trim_start();
            if remainder
                .get(..wanted.len())
                .is_some_and(|name| name.eq_ignore_ascii_case(wanted))
                && remainder[wanted.len()..].trim_start().starts_with('(')
            {
                return true;
            }
        }
    }
    false
}

fn gs2_script_has_event(script: &str, event_name: &str) -> bool {
    let event_name = event_name.trim();
    if event_name.is_empty() {
        return false;
    }
    if let Some(index) = event_name.rfind('.') {
        if gs2_script_has_event(script, &event_name[index + 1..]) {
            return true;
        }
    }
    gs2_script_has_exact_event(script, event_name)
}

fn sanitize_gs2_identifier(value: &str) -> String {
    let mut output = value
        .chars()
        .map(|value| {
            if value.is_ascii_alphanumeric() || value == '_' {
                value
            } else {
                '_'
            }
        })
        .collect::<String>();
    if output.is_empty() {
        output = "class".to_string();
    }
    output
}

pub fn debug_mode() -> bool {
    DEBUG_MODE.load(Ordering::Relaxed)
}
pub fn packet_debug_mode() -> bool {
    PACKET_DEBUG_MODE.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// File permissions

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum PermissionType {
    Read = 0,
    Write = 1,
    Count = 2,
}

pub const PermissionRead: PermissionType = PermissionType::Read;
pub const PermissionWrite: PermissionType = PermissionType::Write;
pub const PermissionCount: PermissionType = PermissionType::Count;

/// Compatibility representation for the exported `Permission` type. The
/// fields are intentionally unexported; the server uses `PermissionRule`
/// internally so compiled path expressions remain ownership-safe in Rust.
#[derive(Clone, Debug)]
pub struct Permission {
    flags: [bool; 2],
    segments: Vec<PermissionRegex>,
}

#[derive(Clone, Debug)]
struct PermissionRule {
    flags: [bool; 2],
    segments: Vec<PermissionRegex>,
}

#[derive(Clone, Debug)]
struct PermissionRegex {
    expression: PermissionRegexNode,
}

#[derive(Clone, Debug)]
enum PermissionRegexNode {
    Empty,
    Literal(char),
    Any,
    Class(PermissionCharClass),
    Concat(Vec<PermissionRegexNode>),
    Alternate(Vec<PermissionRegexNode>),
    Repeat {
        node: Box<PermissionRegexNode>,
        min: usize,
        max: Option<usize>,
    },
    Start,
    End,
    WordBoundary(bool),
}

#[derive(Clone, Debug)]
struct PermissionCharClass {
    negated: bool,
    items: Vec<PermissionCharClassItem>,
}

#[derive(Clone, Debug)]
enum PermissionCharClassItem {
    Character(char),
    Range(char, char),
    Predicate {
        predicate: PermissionCharacterPredicate,
        negated: bool,
    },
}

#[derive(Clone, Copy, Debug)]
enum PermissionCharacterPredicate {
    Digit,
    Space,
    Word,
    Letter,
    Uppercase,
    Lowercase,
    Number,
    Greek,
}

impl PermissionRegex {
    fn compile(segment: &str) -> Option<Self> {
        // Replace every '*' before compiling each path segment. In particular,
        // an escaped '*' is transformed too because replacement is deliberate.
        let expanded = segment.replace('*', ".*");
        let mut parser = PermissionRegexParser::new(&expanded);
        parser.parse().map(|expression| Self { expression })
    }

    fn is_match(&self, value: &str) -> bool {
        let text = value.chars().collect::<Vec<_>>();
        match_permission_regex_node(&self.expression, &text, 0).contains(&text.len())
    }
}

struct PermissionRegexParser {
    input: Vec<char>,
    position: usize,
}

impl PermissionRegexParser {
    fn new(input: &str) -> Self {
        Self {
            input: input.chars().collect(),
            position: 0,
        }
    }

    fn parse(&mut self) -> Option<PermissionRegexNode> {
        let expression = self.parse_alternate()?;
        if self.position == self.input.len() {
            Some(expression)
        } else {
            None
        }
    }

    fn peek(&self) -> Option<char> {
        self.input.get(self.position).copied()
    }

    fn next(&mut self) -> Option<char> {
        let value = self.peek()?;
        self.position += 1;
        Some(value)
    }

    fn consume(&mut self, value: char) -> bool {
        if self.peek() == Some(value) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn parse_alternate(&mut self) -> Option<PermissionRegexNode> {
        let mut alternatives = vec![self.parse_concatenated()?];
        while self.consume('|') {
            alternatives.push(self.parse_concatenated()?);
        }
        if alternatives.len() == 1 {
            Some(alternatives.remove(0))
        } else {
            Some(PermissionRegexNode::Alternate(alternatives))
        }
    }

    fn parse_concatenated(&mut self) -> Option<PermissionRegexNode> {
        let mut nodes = Vec::new();
        while let Some(value) = self.peek() {
            if value == ')' || value == '|' {
                break;
            }
            nodes.push(self.parse_repeated()?);
        }
        if nodes.is_empty() {
            Some(PermissionRegexNode::Empty)
        } else if nodes.len() == 1 {
            Some(nodes.remove(0))
        } else {
            Some(PermissionRegexNode::Concat(nodes))
        }
    }

    fn parse_repeated(&mut self) -> Option<PermissionRegexNode> {
        let mut node = self.parse_atom()?;
        match self.peek() {
            Some('*') => {
                self.position += 1;
                node = PermissionRegexNode::Repeat {
                    node: Box::new(node),
                    min: 0,
                    max: None,
                };
            }
            Some('+') => {
                self.position += 1;
                node = PermissionRegexNode::Repeat {
                    node: Box::new(node),
                    min: 1,
                    max: None,
                };
            }
            Some('?') => {
                self.position += 1;
                node = PermissionRegexNode::Repeat {
                    node: Box::new(node),
                    min: 0,
                    max: Some(1),
                };
            }
            Some('{') => {
                let start = self.position;
                self.position += 1;
                let Some(min) = self.parse_decimal() else {
                    self.position = start;
                    return None;
                };
                let max = if self.consume('}') {
                    Some(min)
                } else if self.consume(',') {
                    if self.consume('}') {
                        None
                    } else {
                        let max = self.parse_decimal()?;
                        if !self.consume('}') || max < min {
                            return None;
                        }
                        Some(max)
                    }
                } else {
                    return None;
                };
                node = PermissionRegexNode::Repeat {
                    node: Box::new(node),
                    min,
                    max,
                };
            }
            _ => {}
        }
        // Reject a second repetition operator rather than treating it as a
        // literal. Leave it for parse() to reject here.
        if matches!(self.peek(), Some('*' | '+' | '?' | '{')) {
            return None;
        }
        Some(node)
    }

    fn parse_decimal(&mut self) -> Option<usize> {
        let start = self.position;
        let mut value = 0usize;
        while let Some(ch) = self.peek() {
            if !ch.is_ascii_digit() {
                break;
            }
            self.position += 1;
            value = value
                .checked_mul(10)?
                .checked_add((ch as u8 - b'0') as usize)?;
        }
        (self.position != start).then_some(value)
    }

    fn parse_atom(&mut self) -> Option<PermissionRegexNode> {
        match self.next()? {
            '(' => {
                // Named and non-capturing groups are accepted for matching.
                // Captures are not used by FilePermissions, so discard their
                // names while retaining their expression.
                if self.consume('?') {
                    match self.next()? {
                        ':' => {}
                        'P' if self.consume('<') => self.consume_group_name('>')?,
                        '<' => self.consume_group_name('>')?,
                        _ => return None,
                    }
                }
                let expression = self.parse_alternate()?;
                if !self.consume(')') {
                    return None;
                }
                Some(expression)
            }
            '[' => self.parse_class(),
            '.' => Some(PermissionRegexNode::Any),
            '^' => Some(PermissionRegexNode::Start),
            '$' => Some(PermissionRegexNode::End),
            '\\' => self.parse_escape(false),
            '*' | '+' | '?' | '{' => None,
            ')' => None,
            value => Some(PermissionRegexNode::Literal(value)),
        }
    }

    fn consume_group_name(&mut self, terminator: char) -> Option<()> {
        while let Some(value) = self.next() {
            if value == terminator {
                return Some(());
            }
            if !(value.is_ascii_alphanumeric() || value == '_') {
                return None;
            }
        }
        None
    }

    fn parse_escape(&mut self, in_class: bool) -> Option<PermissionRegexNode> {
        let value = self.next()?;
        let literal = match value {
            'a' => Some('\x07'),
            'f' => Some('\x0c'),
            't' => Some('\t'),
            'n' => Some('\n'),
            'r' => Some('\r'),
            'v' => Some('\x0b'),
            'b' if in_class => Some('\x08'),
            'b' => return Some(PermissionRegexNode::WordBoundary(true)),
            'B' if !in_class => return Some(PermissionRegexNode::WordBoundary(false)),
            'd' if !in_class => {
                return Some(permission_predicate_node(
                    PermissionCharacterPredicate::Digit,
                    false,
                ))
            }
            'D' if !in_class => {
                return Some(permission_predicate_node(
                    PermissionCharacterPredicate::Digit,
                    true,
                ))
            }
            's' if !in_class => {
                return Some(permission_predicate_node(
                    PermissionCharacterPredicate::Space,
                    false,
                ))
            }
            'S' if !in_class => {
                return Some(permission_predicate_node(
                    PermissionCharacterPredicate::Space,
                    true,
                ))
            }
            'w' if !in_class => {
                return Some(permission_predicate_node(
                    PermissionCharacterPredicate::Word,
                    false,
                ))
            }
            'W' if !in_class => {
                return Some(permission_predicate_node(
                    PermissionCharacterPredicate::Word,
                    true,
                ))
            }
            'p' | 'P' if !in_class => {
                let negated = value == 'P';
                let predicate = self.parse_unicode_predicate()?;
                return Some(permission_predicate_node(predicate, negated));
            }
            'A' if !in_class => return Some(PermissionRegexNode::Start),
            'z' if !in_class => return Some(PermissionRegexNode::End),
            'Q' if !in_class => {
                let mut nodes = Vec::new();
                loop {
                    let value = self.next()?;
                    if value == '\\' && self.peek() == Some('E') {
                        self.position += 1;
                        break;
                    }
                    nodes.push(PermissionRegexNode::Literal(value));
                }
                return Some(if nodes.is_empty() {
                    PermissionRegexNode::Empty
                } else if nodes.len() == 1 {
                    nodes.remove(0)
                } else {
                    PermissionRegexNode::Concat(nodes)
                });
            }
            'x' => return self.parse_hex_escape(),
            'u' if !in_class => return self.parse_fixed_hex_escape(4),
            'U' if !in_class => return self.parse_fixed_hex_escape(8),
            '0'..='7' => {
                let mut value = (value as u32) - ('0' as u32);
                for _ in 0..2 {
                    let Some(next) = self.peek() else { break };
                    if !('0'..='7').contains(&next) {
                        break;
                    }
                    self.position += 1;
                    value = value * 8 + (next as u32 - '0' as u32);
                }
                Some(char::from_u32(value)?)
            }
            value => Some(value),
        };
        Some(PermissionRegexNode::Literal(literal?))
    }

    fn parse_hex_escape(&mut self) -> Option<PermissionRegexNode> {
        if self.consume('{') {
            let start = self.position;
            let mut value = 0u32;
            while let Some(ch) = self.peek() {
                if ch == '}' {
                    break;
                }
                let digit = ch.to_digit(16)?;
                self.position += 1;
                value = value.checked_mul(16)?.checked_add(digit)?;
            }
            if self.position == start || !self.consume('}') {
                return None;
            }
            return Some(PermissionRegexNode::Literal(char::from_u32(value)?));
        }
        self.parse_fixed_hex_escape(2)
    }

    fn parse_fixed_hex_escape(&mut self, count: usize) -> Option<PermissionRegexNode> {
        let mut value = 0u32;
        for _ in 0..count {
            value = value
                .checked_mul(16)?
                .checked_add(self.next()?.to_digit(16)?)?;
        }
        Some(PermissionRegexNode::Literal(char::from_u32(value)?))
    }

    fn parse_unicode_predicate(&mut self) -> Option<PermissionCharacterPredicate> {
        let mut name = String::new();
        if self.consume('{') {
            while let Some(value) = self.next() {
                if value == '}' {
                    return permission_unicode_predicate(&name);
                }
                name.push(value);
            }
            None
        } else {
            name.push(self.next()?);
            permission_unicode_predicate(&name)
        }
    }

    fn parse_class(&mut self) -> Option<PermissionRegexNode> {
        let negated = self.consume('^');
        let mut items = Vec::new();
        let mut first = true;
        while let Some(value) = self.peek() {
            if value == ']' && !first {
                self.position += 1;
                if items.is_empty() {
                    return None;
                }
                return Some(PermissionRegexNode::Class(PermissionCharClass {
                    negated,
                    items,
                }));
            }
            let left = self.parse_class_item()?;
            first = false;
            if self.peek() == Some('-') {
                self.position += 1;
                if self.peek() != Some(']') && self.peek().is_some() {
                    let right = self.parse_class_item()?;
                    match (left, right) {
                        (
                            PermissionCharClassItem::Character(start),
                            PermissionCharClassItem::Character(end),
                        ) if start <= end => items.push(PermissionCharClassItem::Range(start, end)),
                        _ => return None,
                    }
                    continue;
                }
                items.push(left);
                items.push(PermissionCharClassItem::Character('-'));
            } else {
                items.push(left);
            }
        }
        None
    }

    fn parse_class_item(&mut self) -> Option<PermissionCharClassItem> {
        match self.next()? {
            '\\' => {
                let value = self.next()?;
                match value {
                    'd' => Some(PermissionCharClassItem::Predicate {
                        predicate: PermissionCharacterPredicate::Digit,
                        negated: false,
                    }),
                    'D' => Some(PermissionCharClassItem::Predicate {
                        predicate: PermissionCharacterPredicate::Digit,
                        negated: true,
                    }),
                    's' => Some(PermissionCharClassItem::Predicate {
                        predicate: PermissionCharacterPredicate::Space,
                        negated: false,
                    }),
                    'S' => Some(PermissionCharClassItem::Predicate {
                        predicate: PermissionCharacterPredicate::Space,
                        negated: true,
                    }),
                    'w' => Some(PermissionCharClassItem::Predicate {
                        predicate: PermissionCharacterPredicate::Word,
                        negated: false,
                    }),
                    'W' => Some(PermissionCharClassItem::Predicate {
                        predicate: PermissionCharacterPredicate::Word,
                        negated: true,
                    }),
                    'p' | 'P' => Some(PermissionCharClassItem::Predicate {
                        predicate: self.parse_unicode_predicate()?,
                        negated: value == 'P',
                    }),
                    'a' => Some(PermissionCharClassItem::Character('\x07')),
                    'f' => Some(PermissionCharClassItem::Character('\x0c')),
                    't' => Some(PermissionCharClassItem::Character('\t')),
                    'n' => Some(PermissionCharClassItem::Character('\n')),
                    'r' => Some(PermissionCharClassItem::Character('\r')),
                    'v' => Some(PermissionCharClassItem::Character('\x0b')),
                    'b' => Some(PermissionCharClassItem::Character('\x08')),
                    'x' => match self.parse_hex_escape()? {
                        PermissionRegexNode::Literal(value) => {
                            Some(PermissionCharClassItem::Character(value))
                        }
                        _ => None,
                    },
                    '0'..='7' => {
                        let mut number = (value as u32) - ('0' as u32);
                        for _ in 0..2 {
                            let Some(next) = self.peek() else { break };
                            if !('0'..='7').contains(&next) {
                                break;
                            }
                            self.position += 1;
                            number = number * 8 + (next as u32 - '0' as u32);
                        }
                        Some(PermissionCharClassItem::Character(char::from_u32(number)?))
                    }
                    value => Some(PermissionCharClassItem::Character(value)),
                }
            }
            value => Some(PermissionCharClassItem::Character(value)),
        }
    }
}

fn permission_predicate_node(
    predicate: PermissionCharacterPredicate,
    negated: bool,
) -> PermissionRegexNode {
    PermissionRegexNode::Class(PermissionCharClass {
        negated: false,
        items: vec![PermissionCharClassItem::Predicate { predicate, negated }],
    })
}

fn permission_unicode_predicate(name: &str) -> Option<PermissionCharacterPredicate> {
    match name {
        "L" | "Letter" | "LC" => Some(PermissionCharacterPredicate::Letter),
        "Lu" | "Upper" | "Uppercase_Letter" => Some(PermissionCharacterPredicate::Uppercase),
        "Ll" | "Lower" | "Lowercase_Letter" => Some(PermissionCharacterPredicate::Lowercase),
        "N" | "Number" | "Nd" | "Decimal_Number" => Some(PermissionCharacterPredicate::Number),
        "Greek" => Some(PermissionCharacterPredicate::Greek),
        _ => None,
    }
}

fn permission_is_word(value: char) -> bool {
    value.is_ascii_alphanumeric() || value == '_'
}

fn permission_predicate_matches(predicate: PermissionCharacterPredicate, value: char) -> bool {
    match predicate {
        PermissionCharacterPredicate::Digit => value.is_ascii_digit(),
        PermissionCharacterPredicate::Space => {
            matches!(value, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c')
        }
        PermissionCharacterPredicate::Word => permission_is_word(value),
        PermissionCharacterPredicate::Letter => value.is_alphabetic(),
        PermissionCharacterPredicate::Uppercase => value.is_uppercase(),
        PermissionCharacterPredicate::Lowercase => value.is_lowercase(),
        PermissionCharacterPredicate::Number => value.is_numeric(),
        PermissionCharacterPredicate::Greek => {
            matches!(value as u32, 0x0370..=0x03ff | 0x1f00..=0x1fff)
        }
    }
}

fn permission_class_matches(class: &PermissionCharClass, value: char) -> bool {
    let matched = class.items.iter().any(|item| match item {
        PermissionCharClassItem::Character(expected) => *expected == value,
        PermissionCharClassItem::Range(start, end) => *start <= value && value <= *end,
        PermissionCharClassItem::Predicate { predicate, negated } => {
            permission_predicate_matches(*predicate, value) != *negated
        }
    });
    matched != class.negated
}

fn match_permission_regex_node(
    node: &PermissionRegexNode,
    text: &[char],
    position: usize,
) -> HashSet<usize> {
    match node {
        PermissionRegexNode::Empty => HashSet::from([position]),
        PermissionRegexNode::Literal(value) => {
            if text.get(position) == Some(value) {
                HashSet::from([position + 1])
            } else {
                HashSet::new()
            }
        }
        PermissionRegexNode::Any => {
            if text.get(position).is_some_and(|value| *value != '\n') {
                HashSet::from([position + 1])
            } else {
                HashSet::new()
            }
        }
        PermissionRegexNode::Class(class) => {
            if text
                .get(position)
                .is_some_and(|value| permission_class_matches(class, *value))
            {
                HashSet::from([position + 1])
            } else {
                HashSet::new()
            }
        }
        PermissionRegexNode::Concat(nodes) => {
            let mut positions = HashSet::from([position]);
            for child in nodes {
                let mut next = HashSet::new();
                for current in positions {
                    next.extend(match_permission_regex_node(child, text, current));
                }
                positions = next;
                if positions.is_empty() {
                    break;
                }
            }
            positions
        }
        PermissionRegexNode::Alternate(nodes) => {
            let mut positions = HashSet::new();
            for child in nodes {
                positions.extend(match_permission_regex_node(child, text, position));
            }
            positions
        }
        PermissionRegexNode::Repeat { node, min, max } => {
            let mut current = HashSet::from([position]);
            let mut result = HashSet::new();
            let mut seen = HashSet::from([position]);
            let mut count = 0usize;
            loop {
                if count >= *min {
                    result.extend(current.iter().copied());
                }
                if max.is_some_and(|limit| count >= limit) {
                    break;
                }
                let mut next = HashSet::new();
                for current_position in &current {
                    next.extend(match_permission_regex_node(node, text, *current_position));
                }
                if next.is_empty() {
                    break;
                }
                count = count.saturating_add(1);
                if max.is_none() && count >= *min {
                    let new_positions = next
                        .iter()
                        .filter(|value| !seen.contains(value))
                        .copied()
                        .collect::<HashSet<_>>();
                    if new_positions.is_empty() {
                        break;
                    }
                    seen.extend(new_positions);
                }
                current = next;
            }
            result
        }
        PermissionRegexNode::Start => {
            if position == 0 {
                HashSet::from([position])
            } else {
                HashSet::new()
            }
        }
        PermissionRegexNode::End => {
            if position == text.len() {
                HashSet::from([position])
            } else {
                HashSet::new()
            }
        }
        PermissionRegexNode::WordBoundary(wanted) => {
            let before = position
                .checked_sub(1)
                .and_then(|index| text.get(index))
                .is_some_and(|value| permission_is_word(*value));
            let after = text
                .get(position)
                .is_some_and(|value| permission_is_word(*value));
            if (before != after) == *wanted {
                HashSet::from([position])
            } else {
                HashSet::new()
            }
        }
    }
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut table = vec![vec![false; value.len() + 1]; pattern.len() + 1];
    table[0][0] = true;
    for (index, pattern_byte) in pattern.iter().enumerate() {
        if *pattern_byte == b'*' {
            table[index + 1][0] = table[index][0];
            for value_index in 0..value.len() {
                table[index + 1][value_index + 1] =
                    table[index][value_index + 1] || table[index + 1][value_index];
            }
        } else {
            for value_index in 0..value.len() {
                table[index + 1][value_index + 1] =
                    table[index][value_index] && *pattern_byte == value[value_index];
            }
        }
    }
    table[pattern.len()][value.len()]
}

#[derive(Debug)]
struct FilePermissionState {
    allow: Vec<PermissionRule>,
    deny: Vec<PermissionRule>,
}

#[derive(Debug)]
pub struct FilePermissions {
    state: RwLock<FilePermissionState>,
}

impl Clone for FilePermissions {
    fn clone(&self) -> Self {
        let state = self.state.read().unwrap();
        Self {
            state: RwLock::new(FilePermissionState {
                allow: state.allow.clone(),
                deny: state.deny.clone(),
            }),
        }
    }
}

impl Default for FilePermissions {
    fn default() -> Self {
        Self::new()
    }
}

impl FilePermissions {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(FilePermissionState {
                allow: Vec::new(),
                deny: Vec::new(),
            }),
        }
    }
    pub fn NewFilePermissions() -> Self {
        Self::new()
    }

    pub fn has_permission(&self, path: &str, permission: PermissionType) -> bool {
        let state = self.state.read().unwrap();
        let index = permission as usize;
        if state
            .deny
            .iter()
            .any(|rule| rule.flags[index] && rule_matches(path, rule))
        {
            return false;
        }
        state
            .allow
            .iter()
            .any(|rule| rule.flags[index] && rule_matches(path, rule))
    }
    pub fn HasPermission(&self, path: &str, permission: PermissionType) -> bool {
        self.has_permission(path, permission)
    }

    pub fn add_permission(&self, permission: &str) {
        let mut state = self.state.write().unwrap();
        add_permission_unsafe(permission, &mut state);
    }
    pub fn AddPermission(&self, permission: &str) {
        self.add_permission(permission)
    }

    pub fn load_permissions(&self, permissions: &str) {
        let mut state = self.state.write().unwrap();
        state.allow.clear();
        state.deny.clear();
        for line in split_input(permissions, '\n') {
            add_permission_unsafe(line, &mut state);
        }
    }
    pub fn LoadPermissions(&self, permissions: &str) {
        self.load_permissions(permissions)
    }
}

fn add_permission_unsafe(value: &str, state: &mut FilePermissionState) {
    let mut rule = PermissionRule {
        flags: [false, false],
        segments: Vec::new(),
    };
    let mut raw_segments = Vec::new();
    let mut negative = false;
    let mut start = 0;
    if value.as_bytes().first() == Some(&b'-') {
        negative = true;
        start = 1;
    }
    if let Some(space) = value[start..].find(' ') {
        for byte in value[start..start + space].bytes() {
            if byte == b'r' {
                rule.flags[PermissionType::Read as usize] = true;
            }
            if byte == b'w' {
                rule.flags[PermissionType::Write as usize] = true;
            }
        }
        raw_segments = split_input(&value[start + space + 1..], '/')
            .into_iter()
            .map(str::to_string)
            .collect();
    } else {
        for byte in value[start..].bytes() {
            if byte == b'r' {
                rule.flags[PermissionType::Read as usize] = true;
            }
            if byte == b'w' {
                rule.flags[PermissionType::Write as usize] = true;
            }
        }
    }
    if raw_segments.is_empty() {
        return;
    }
    rule.segments = raw_segments
        .iter()
        .filter_map(|segment| PermissionRegex::compile(segment))
        .collect();
    // Append the Permission whenever the path contained at least one segment,
    // even when one or more individual expression compilations failed. This
    // keeps malformed rules' segment-count behavior stable.
    if negative {
        state.deny.push(rule);
    } else {
        state.allow.push(rule);
    }
}

fn rule_matches(path: &str, rule: &PermissionRule) -> bool {
    let path_segments = split_input(path, '/');
    !path_segments.is_empty()
        && path_segments.len() == rule.segments.len()
        && path_segments
            .iter()
            .zip(rule.segments.iter())
            .all(|(value, pattern)| pattern.is_match(value))
}

pub fn split_input(input: &str, delimiter: char) -> Vec<&str> {
    let mut result = Vec::new();
    let mut start = 0;
    for (index, ch) in input.char_indices() {
        if ch == delimiter {
            result.push(&input[start..index]);
            start = index + ch.len_utf8();
        }
    }
    if start < input.len() {
        result.push(&input[start..]);
    }
    result
}

// ---------------------------------------------------------------------------
// Character/account state

#[derive(Clone, Debug, Default)]
pub struct Character {
    pub nickname: String,
    pub body_image: String,
    pub head_image: String,
    pub sword_image: String,
    pub shield_image: String,
    pub horse_image: String,
    pub gani: String,
    pub chat_message: String,
    pub sprite: u8,
    pub colors: [u8; 5],
    pub hitpoints: i32,
    pub gralats: i32,
    pub arrows: i32,
    pub bombs: i32,
    pub glove_power: i32,
    pub sword_power: i32,
    pub shield_power: i32,
    pub gani_attributes: [String; 30],
    pub ap: i32,
    pub bow_power: i32,
    pub bow_image: String,
}

#[derive(Debug)]
pub struct Account {
    pub account_name: String,
    pub community_name: String,
    pub email: String,
    pub admin_ip: String,
    pub ban_reason: String,
    pub ban_length: String,
    pub ban_type: String,
    pub account_comments: String,
    pub level_name: String,
    pub account_ip_str: String,
    pub account_ip: u32,
    pub is_banned: bool,
    pub is_guest: bool,
    pub is_external: bool,
    pub is_load_only: bool,
    pub is_staff: bool,
    pub admin_rights: i32,
    pub device_id: i64,
    pub character: Character,
    pub language: String,
    pub x: i16,
    pub y: i16,
    pub z: i16,
    pub alignment: i32,
    pub elo_rating: f32,
    pub elo_deviation: f32,
    pub max_hitpoints: u8,
    pub mp: u8,
    pub ap_counter: u8,
    pub horse_bomb_count: u8,
    pub kills: u32,
    pub deaths: u32,
    pub additional_flags: u32,
    pub rupees: u32,
    pub carry_sprite: u8,
    pub online_time: i32,
    pub status: i32,
    pub udp_port: i32,
    pub last_spar_time: SystemTime,
    pub attach_npc: u32,
    pub status_msg: u8,
    pub g_attribs: [String; 30],
    pub os: String,
    pub env_code_page: i32,
    pub flag_list: HashMap<String, String>,
    pub chest_list: Vec<String>,
    pub folder_list: Vec<String>,
    pub weapon_list: Vec<String>,
    pub private_message_server_list: Vec<String>,
    pub folder_rights: FilePermissions,
    pub last_folder: String,
    server: Option<Weak<Server>>,
}

impl Default for Account {
    fn default() -> Self {
        Self {
            account_name: String::new(),
            community_name: String::new(),
            email: String::new(),
            admin_ip: String::new(),
            ban_reason: String::new(),
            ban_length: String::new(),
            ban_type: String::new(),
            account_comments: String::new(),
            level_name: String::new(),
            account_ip_str: String::new(),
            account_ip: 0,
            is_banned: false,
            is_guest: false,
            is_external: false,
            is_load_only: false,
            is_staff: false,
            admin_rights: 0,
            device_id: 0,
            character: Character::default(),
            language: String::new(),
            x: 0,
            y: 0,
            z: 0,
            alignment: 0,
            elo_rating: 0.0,
            elo_deviation: 0.0,
            max_hitpoints: 0,
            mp: 0,
            ap_counter: 0,
            horse_bomb_count: 0,
            kills: 0,
            deaths: 0,
            additional_flags: 0,
            rupees: 0,
            carry_sprite: 0,
            online_time: 0,
            status: 0,
            udp_port: 0,
            last_spar_time: UNIX_EPOCH,
            attach_npc: 0,
            status_msg: 0,
            g_attribs: std::array::from_fn(|_| String::new()),
            os: String::new(),
            env_code_page: 0,
            flag_list: HashMap::new(),
            chest_list: Vec::new(),
            folder_list: Vec::new(),
            weapon_list: Vec::new(),
            private_message_server_list: Vec::new(),
            folder_rights: FilePermissions::new(),
            last_folder: String::new(),
            server: None,
        }
    }
}

impl Account {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn NewAccount() -> Self {
        Self::new()
    }
    pub fn set_server(&mut self, server: &Arc<Server>) {
        self.server = Some(Arc::downgrade(server));
    }
    pub fn SetServer(&mut self, server: &Arc<Server>) {
        self.set_server(server)
    }
    pub fn set_flag(&mut self, name: &str, value: &str) {
        self.flag_list.insert(name.to_string(), value.to_string());
    }
    pub fn SetFlag(&mut self, name: &str, value: &str) {
        self.set_flag(name, value)
    }
    pub fn get_flag(&self, name: &str) -> String {
        self.flag_list.get(name).cloned().unwrap_or_default()
    }
    pub fn GetFlag(&self, name: &str) -> String {
        self.get_flag(name)
    }
    pub fn delete_flag(&mut self, name: &str) {
        self.flag_list.remove(name);
    }
    pub fn DeleteFlag(&mut self, name: &str) {
        self.delete_flag(name)
    }

    pub fn apply_guest_pcid(&mut self, pc_id: &str) -> bool {
        let pc_id = pc_id.trim();
        if pc_id.is_empty()
            || !(self.is_guest
                || self.account_name.eq_ignore_ascii_case("guest")
                || self.account_name.to_ascii_lowercase().starts_with("pc:"))
        {
            return false;
        }
        let old_account = self.account_name.clone();
        let old_community = self.community_name.clone();
        self.is_guest = true;
        self.is_load_only = true;
        self.account_name = format!("pc:{pc_id}");
        self.community_name = "guest".to_string();
        old_account != self.account_name || old_community != self.community_name
    }
    pub fn applyGuestPCID(&mut self, pc_id: &str) -> bool {
        self.apply_guest_pcid(pc_id)
    }
    pub fn get_x(&self) -> f32 {
        f32::from(self.x) / 16.0
    }
    pub fn get_y(&self) -> f32 {
        f32::from(self.y) / 16.0
    }
    pub fn get_z(&self) -> f32 {
        f32::from(self.z)
    }
    pub fn set_x(&mut self, value: f32) {
        self.x = (value * 16.0) as i16;
    }
    pub fn set_y(&mut self, value: f32) {
        self.y = (value * 16.0) as i16;
    }
    pub fn set_z(&mut self, value: f32) {
        self.z = value as i16;
    }

    pub fn load_account(&mut self, account_name: &str, ignore_nick: bool) -> bool {
        let server = match self.server.as_ref().and_then(Weak::upgrade) {
            Some(value) => value,
            None => return false,
        };
        self.account_name = account_name.to_string();
        let mut file_path = None;
        for candidate in account_file_read_paths(account_name) {
            if let Ok(data) = server.config.load_file(&candidate) {
                if !data.is_empty() {
                    file_path = Some(candidate);
                    break;
                }
            }
        }
        let file_path = match file_path {
            Some(path) => path,
            None => {
                let path = account_file_write_path(account_name);
                if server
                    .config
                    .save_file(&path, default_account_data(account_name).as_bytes())
                    .is_err()
                {
                    return false;
                }
                path
            }
        };
        let lines = match server.config.load_file_as_lines(&file_path) {
            Ok(value) => value,
            Err(_) => return false,
        };
        if lines.first().map(String::as_str) != Some("GRACC001") {
            return false;
        }
        self.flag_list.clear();
        self.weapon_list.clear();
        self.chest_list.clear();
        self.folder_list.clear();
        self.admin_rights = 0;
        self.admin_ip.clear();
        self.is_staff = false;
        self.load_account_defaults(account_name, ignore_nick, &server);
        let mut has_account_weapons = false;
        for line in lines.iter().skip(1) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.splitn(2, ' ');
            let section = parts.next().unwrap_or_default();
            let Some(value) = parts.next() else {
                continue;
            };
            match section {
                "NICK" => {
                    if !ignore_nick {
                        self.character.nickname = value.to_string();
                    }
                    self.character.nickname = self.character.nickname.chars().take(223).collect();
                }
                "COMMUNITYNAME" => self.community_name = value.to_string(),
                "LEVEL" => self.level_name = value.to_string(),
                "X" => self.set_x(value.parse::<f32>().unwrap_or(0.0)),
                "Y" => self.set_y(value.parse::<f32>().unwrap_or(0.0)),
                "Z" => self.set_z(value.parse::<f32>().unwrap_or(0.0)),
                "MAXHP" => {
                    self.max_hitpoints = (value.parse::<f32>().unwrap_or(0.0) as i32 & 0xff) as u8
                }
                "HP" => self.character.hitpoints = value.parse::<f32>().unwrap_or(0.0) as i32,
                "RUPEES" => self.character.gralats = parse_i32(value),
                "ANI" => self.character.gani = value.to_string(),
                "ARROWS" => self.character.arrows = parse_i32(value),
                "BOMBS" => self.character.bombs = parse_i32(value),
                "GLOVEP" => self.character.glove_power = parse_i32(value),
                "SHIELDP" => self.character.shield_power = parse_i32(value),
                "SWORDP" => self.character.sword_power = parse_i32(value),
                "BOWP" => self.character.bow_power = parse_i32(value),
                "BOW" => self.character.bow_image = value.to_string(),
                "HEAD" => self.character.head_image = value.to_string(),
                "BODY" => self.character.body_image = value.to_string(),
                "SWORD" => self.character.sword_image = value.to_string(),
                "SHIELD" => self.character.shield_image = value.to_string(),
                "COLORS" => {
                    for (index, part) in value.splitn(5, ',').enumerate() {
                        self.character.colors[index] = parse_i32(part) as u8;
                    }
                }
                "SPRITE" => self.character.sprite = parse_i32(value) as u8,
                "STATUS" => self.status = parse_i32(value),
                "MP" => self.mp = parse_i32(value) as u8,
                "AP" => self.character.ap = parse_i32(value),
                "APCOUNTER" => self.ap_counter = parse_i32(value) as u8,
                "ONSECS" => self.online_time = parse_i32(value),
                "IP" => {
                    self.account_ip = value.parse::<i64>().unwrap_or(0) as u32;
                    self.account_ip_str = value.to_string();
                }
                "LANGUAGE" => {
                    self.language = value.to_string();
                    if self.language.is_empty() {
                        self.language = "English".to_string();
                    }
                }
                "KILLS" => self.kills = parse_i32(value) as u32,
                "DEATHS" => self.deaths = parse_i32(value) as u32,
                "RATING" => self.elo_rating = value.parse().unwrap_or(0.0),
                "DEVIATION" => self.elo_deviation = value.parse().unwrap_or(0.0),
                "FLAG" => {
                    let mut flag = value.splitn(2, '=');
                    self.set_flag(
                        flag.next().unwrap_or_default(),
                        flag.next().unwrap_or_default(),
                    );
                }
                "WEAPON" => {
                    if !has_account_weapons {
                        self.weapon_list.clear();
                        has_account_weapons = true;
                    }
                    self.weapon_list.push(value.to_string());
                }
                "CHEST" => self.chest_list.push(value.to_string()),
                "BANNED" => self.is_banned = parse_i32(value) != 0,
                "BANREASON" => self.ban_reason = value.to_string(),
                "BANLENGTH" => self.ban_length = value.to_string(),
                "BANTYPE" => self.ban_type = value.to_string(),
                "COMMENTS" => self.account_comments = value.to_string(),
                "EMAIL" => self.email = value.to_string(),
                "LOCALRIGHTS" => self.admin_rights = parse_i32(value),
                "IPRANGE" => self.admin_ip = value.to_string(),
                "LOADONLY" => self.is_load_only = parse_i32(value) != 0,
                "FOLDERRIGHT" => self.folder_list.push(value.to_string()),
                "LASTFOLDER" => self.last_folder = value.to_string(),
                _ if section.starts_with("ATTR") => {
                    if let Ok(index) = section[4..].parse::<usize>() {
                        if (1..=30).contains(&index) {
                            self.character.gani_attributes[index - 1] = value.to_string();
                        }
                    }
                }
                _ => {}
            }
        }
        self.normalize_health();
        self.is_staff = self.admin_rights > 0;
        if account_name.eq_ignore_ascii_case("guest") {
            self.is_load_only = true;
            self.is_guest = true;
            self.community_name = "guest".to_string();
            if self.device_id > 0 {
                self.account_name = format!("pc:{}", self.device_id);
            } else {
                self.account_name = server.next_guest_pc_account_name();
            }
        } else {
            self.community_name = account_name.to_string();
        }
        true
    }
    pub fn LoadAccount(&mut self, account_name: &str, ignore_nick: bool) -> bool {
        self.load_account(account_name, ignore_nick)
    }

    fn load_account_defaults(&mut self, account_name: &str, ignore_nick: bool, server: &Server) {
        if !ignore_nick {
            self.character.nickname = account_name.to_string();
        }
        self.community_name = account_name.to_string();
        self.level_name = "onlinestartlocal.nw".to_string();
        if let Some(value) = nonempty(&server.settings.get("startlevel")) {
            self.level_name = value;
        }
        self.set_x(30.0);
        self.set_y(30.5);
        self.set_z(0.0);
        self.max_hitpoints = 3;
        self.character.hitpoints = 3;
        self.character.gralats = 0;
        self.character.gani = "idle".to_string();
        self.character.arrows = 10;
        self.character.bombs = 5;
        self.character.glove_power = 1;
        self.character.shield_power = 1;
        self.character.sword_power = 1;
        self.character.bow_power = 1;
        self.character.bow_image.clear();
        self.character.head_image = "head0.png".to_string();
        self.character.body_image = "body.png".to_string();
        self.character.sword_image = "sword1.png".to_string();
        self.character.shield_image = "shield1.png".to_string();
        self.character.colors = [2, 0, 10, 4, 18];
        self.character.sprite = 2;
        self.status = 20;
        self.mp = 0;
        self.character.ap = 50;
        self.ap_counter = 60;
        self.online_time = 0;
        self.account_ip = 0;
        self.account_ip_str = "0".to_string();
        self.language = "English".to_string();
        self.kills = 0;
        self.deaths = 0;
        self.elo_rating = 1500.0;
        self.elo_deviation = 350.0;
        self.is_banned = false;
        self.ban_reason.clear();
        self.ban_length.clear();
        self.account_comments.clear();
        self.email.clear();
        self.admin_rights = 0;
        self.admin_ip = "0.0.0.0".to_string();
        self.is_load_only = false;
        self.last_folder.clear();
        self.weapon_list = vec![
            "bomb".to_string(),
            "bow".to_string(),
            "-gr_movement".to_string(),
        ];
    }

    pub fn normalize_health(&mut self) {
        if self.max_hitpoints == 0 {
            self.max_hitpoints = 3;
        }
        if self.max_hitpoints > 20 {
            self.max_hitpoints = 20;
        }
        if self.character.hitpoints <= 0 {
            self.character.hitpoints = i32::from(self.max_hitpoints);
        }
        if self.character.hitpoints > i32::from(self.max_hitpoints) {
            self.character.hitpoints = i32::from(self.max_hitpoints);
        }
    }
    pub fn NormalizeHealth(&mut self) {
        self.normalize_health()
    }

    pub fn save_account(&self) -> bool {
        let server = match self.server.as_ref().and_then(Weak::upgrade) {
            Some(value) => value,
            None => return false,
        };
        if self.is_load_only || self.account_name.is_empty() {
            return false;
        }
        let mut out = String::from("GRACC001\r\n");
        macro_rules! line {
            ($key:expr, $value:expr) => {{
                let _ = writeln!(out, "{} {}\r", $key, $value);
            }};
        }
        line!("NAME", self.account_name);
        line!("NICK", self.character.nickname);
        line!("COMMUNITYNAME", self.community_name);
        line!("LEVEL", self.level_name);
        line!("X", format!("{:.2}", self.get_x()));
        line!("Y", format!("{:.2}", self.get_y()));
        line!("Z", self.z);
        line!("MAXHP", self.max_hitpoints);
        line!("HP", self.character.hitpoints);
        line!("RUPEES", self.character.gralats);
        line!("ANI", self.character.gani);
        line!("ARROWS", self.character.arrows);
        line!("BOMBS", self.character.bombs);
        line!("GLOVEP", self.character.glove_power);
        line!("SHIELDP", self.character.shield_power);
        line!("SWORDP", self.character.sword_power);
        line!("BOWP", self.character.bow_power);
        line!("BOW", self.character.bow_image);
        line!("HEAD", self.character.head_image);
        line!("BODY", self.character.body_image);
        line!("SWORD", self.character.sword_image);
        line!("SHIELD", self.character.shield_image);
        line!(
            "COLORS",
            self.character
                .colors
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        line!("SPRITE", self.character.sprite);
        line!("STATUS", self.status);
        line!("MP", self.mp);
        line!("AP", self.character.ap);
        line!("APCOUNTER", self.ap_counter);
        line!("ONSECS", self.online_time);
        line!("IP", self.account_ip);
        line!("LANGUAGE", self.language);
        line!("KILLS", self.kills);
        line!("DEATHS", self.deaths);
        line!("RATING", format!("{:.6}", self.elo_rating));
        line!("DEVIATION", format!("{:.6}", self.elo_deviation));
        for (index, value) in self.character.gani_attributes.iter().enumerate() {
            if !value.is_empty() {
                line!(format!("ATTR{}", index + 1), value);
            }
        }
        for value in &self.chest_list {
            line!("CHEST", value);
        }
        for value in &self.weapon_list {
            line!("WEAPON", value);
        }
        for (key, value) in &self.flag_list {
            if value.is_empty() {
                line!("FLAG", key);
            } else {
                line!("FLAG", format!("{}={}", key, value));
            }
        }
        out.push_str("\r\n");
        line!("BANNED", if self.is_banned { 1 } else { 0 });
        line!("BANREASON", self.ban_reason);
        line!("BANLENGTH", self.ban_length);
        if !self.ban_type.is_empty() {
            line!("BANTYPE", self.ban_type);
        }
        line!("COMMENTS", self.account_comments);
        line!("EMAIL", self.email);
        line!("LOCALRIGHTS", self.admin_rights);
        line!("IPRANGE", self.admin_ip);
        line!("LOADONLY", if self.is_load_only { 1 } else { 0 });
        for value in &self.folder_list {
            line!("FOLDERRIGHT", value);
        }
        line!("LASTFOLDER", self.last_folder);
        server
            .config
            .save_file(account_file_write_path(&self.account_name), out.as_bytes())
            .is_ok()
    }
    pub fn SaveAccount(&self) -> bool {
        self.save_account()
    }
}

pub fn account_file_write_path(account_name: &str) -> String {
    let account_name = account_name.trim();
    if account_name.eq_ignore_ascii_case("(npcserver)") {
        return format!("accounts/nc/{account_name}.txt");
    }
    let folder = if account_name.len() >= 2 && account_name.is_char_boundary(2) {
        account_name[..2].to_ascii_lowercase()
    } else {
        account_name.to_ascii_lowercase()
    };
    format!("accounts/{folder}/{account_name}.txt")
}
pub fn account_file_read_paths(account_name: &str) -> Vec<String> {
    let write = account_file_write_path(account_name);
    let flat = format!("accounts/{}.txt", account_name.trim());
    if write == flat {
        vec![flat]
    } else {
        vec![write, flat]
    }
}

pub fn default_account_data(account_name: &str) -> String {
    format!("GRACC001\r\nNAME {0}\r\nNICK {0}\r\nCOMMUNITYNAME {0}\r\nLEVEL onlinestartlocal.nw\r\nX 30.00\r\nY 30.50\r\nZ 0.00\r\nMAXHP 3.00\r\nHP 3.00\r\nRUPEES 0\r\nANI idle\r\nARROWS 10\r\nBOMBS 5\r\nGLOVEP 1\r\nSHIELDP 1\r\nSWORDP 1\r\nBOWP 1\r\nBOW \r\nHEAD head0.png\r\nBODY body.png\r\nSWORD sword1.png\r\nSHIELD shield1.png\r\nCOLORS 2,0,10,4,18\r\nSPRITE 2\r\nSTATUS 20\r\nMP 0\r\nAP 50\r\nAPCOUNTER 60\r\nONSECS 0\r\nIP 0\r\nLANGUAGE English\r\nKILLS 0\r\nDEATHS 0\r\nRATING 1500.00\r\nDEVIATION 350.00\r\nWEAPON bomb\r\nWEAPON bow\r\nWEAPON -gr_movement\r\n\r\nBANNED 0\r\nBANREASON \r\nBANLENGTH \r\nCOMMENTS \r\nEMAIL \r\nLOCALRIGHTS 0\r\nIPRANGE 0.0.0.0\r\nLASTFOLDER \r\n", account_name)
}

pub fn login_pc_id(identity: &str) -> Option<i64> {
    let value = identity.trim();
    if value.is_empty() || !value.bytes().all(|v| v.is_ascii_digit()) {
        return None;
    }
    value.parse::<i64>().ok().filter(|v| *v > 0)
}

fn parse_i32(value: &str) -> i32 {
    value.parse::<i32>().unwrap_or(0)
}
fn nonempty(value: &str) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value.trim().to_string())
    }
}

// ---------------------------------------------------------------------------
// Levels, signs, maps, and level items

pub type LevelItemType = i32;
pub const ITEM_GREEN_RUPEE: LevelItemType = 0;
pub const ITEM_BLUE_RUPEE: LevelItemType = 1;
pub const ITEM_RED_RUPEE: LevelItemType = 2;
pub const ITEM_BOMBS: LevelItemType = 3;
pub const ITEM_DARTS: LevelItemType = 4;
pub const ITEM_HEART: LevelItemType = 5;
pub const ITEM_GLOVE1: LevelItemType = 6;
pub const ITEM_BOW: LevelItemType = 7;
pub const ITEM_BOMB: LevelItemType = 8;
pub const ITEM_SHIELD: LevelItemType = 9;
pub const ITEM_SWORD: LevelItemType = 10;
pub const ITEM_FULL_HEART: LevelItemType = 11;
pub const ITEM_SUPER_BOMB: LevelItemType = 12;
pub const ITEM_BATTLE_AXE: LevelItemType = 13;
pub const ITEM_GOLDEN_SWORD: LevelItemType = 14;
pub const ITEM_MIRROR_SHIELD: LevelItemType = 15;
pub const ITEM_GLOVE2: LevelItemType = 16;
pub const ITEM_LIZARD_SHIELD: LevelItemType = 17;
pub const ITEM_LIZARD_SWORD: LevelItemType = 18;
pub const ITEM_GOLD_RUPEE: LevelItemType = 19;
pub const ITEM_FIREBALL: LevelItemType = 20;
pub const ITEM_FIREBLAST: LevelItemType = 21;
pub const ITEM_NUKESHOT: LevelItemType = 22;
pub const ITEM_JOLTBOMB: LevelItemType = 23;
pub const ITEM_SPINATTACK: LevelItemType = 24;

#[derive(Clone, Debug, Default)]
pub struct LevelTiles {
    pub width: usize,
    pub height: usize,
    pub tiles: Vec<i16>,
}

#[derive(Clone, Debug)]
pub struct LevelBoardChange {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub new_tiles: Vec<u8>,
    pub old_tiles: Vec<u8>,
    pub time: SystemTime,
    pub timeout: Option<SystemTime>,
}

impl LevelBoardChange {
    pub fn new(
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        new_tiles: Vec<u8>,
        old_tiles: Vec<u8>,
        respawn: Option<Duration>,
    ) -> Self {
        Self {
            x,
            y,
            width,
            height,
            new_tiles,
            old_tiles,
            time: SystemTime::now(),
            timeout: respawn.map(|value| SystemTime::now() + value),
        }
    }
    pub fn NewLevelBoardChange(
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        new_tiles: Vec<u8>,
        old_tiles: Vec<u8>,
        respawn: Duration,
    ) -> Self {
        Self::new(x, y, width, height, new_tiles, old_tiles, Some(respawn))
    }
    pub fn get_board_str(&self) -> Vec<u8> {
        let mut buf = Buffer::new();
        buf.write_byte(self.x as u8)
            .write_byte(self.y as u8)
            .write_byte(self.width as u8)
            .write_byte(self.height as u8)
            .write(&self.new_tiles);
        buf.data
    }
    pub fn GetBoardStr(&self) -> Vec<u8> {
        self.get_board_str()
    }
    pub fn swap_tiles(&mut self) {
        std::mem::swap(&mut self.new_tiles, &mut self.old_tiles);
    }
    pub fn SwapTiles(&mut self) {
        self.swap_tiles()
    }
    pub fn get_x(&self) -> i32 {
        self.x
    }
    pub fn GetX(&self) -> i32 {
        self.x
    }
    pub fn get_y(&self) -> i32 {
        self.y
    }
    pub fn GetY(&self) -> i32 {
        self.y
    }
    pub fn get_width(&self) -> i32 {
        self.width
    }
    pub fn GetWidth(&self) -> i32 {
        self.width
    }
    pub fn get_height(&self) -> i32 {
        self.height
    }
    pub fn GetHeight(&self) -> i32 {
        self.height
    }
    pub fn get_tiles(&self) -> &[u8] {
        &self.new_tiles
    }
    pub fn GetTiles(&self) -> &[u8] {
        &self.new_tiles
    }
    pub fn get_mod_time(&self) -> SystemTime {
        self.time
    }
    pub fn GetModTime(&self) -> SystemTime {
        self.time
    }
    pub fn set_mod_time(&mut self, value: SystemTime) {
        self.time = value
    }
    pub fn SetModTime(&mut self, value: SystemTime) {
        self.set_mod_time(value)
    }
    pub fn get_timeout(&self) -> Option<SystemTime> {
        self.timeout
    }
    pub fn GetTimeout(&self) -> Option<SystemTime> {
        self.timeout
    }
    pub fn is_expired(&self) -> bool {
        self.timeout
            .map(|value| SystemTime::now() > value)
            .unwrap_or(false)
    }
    pub fn IsExpired(&self) -> bool {
        self.is_expired()
    }
}

#[derive(Clone, Debug, Default)]
pub struct LevelChest {
    pub x: i32,
    pub y: i32,
    pub item_type: LevelItemType,
    pub sign_index: i32,
}
#[derive(Clone, Debug)]
pub struct LevelHorse {
    pub image: String,
    pub x: f32,
    pub y: f32,
    pub dir: u8,
    pub bushes: u8,
    pub expires_at: SystemTime,
}
impl Default for LevelHorse {
    fn default() -> Self {
        Self {
            image: String::new(),
            x: 0.0,
            y: 0.0,
            dir: 0,
            bushes: 0,
            expires_at: UNIX_EPOCH,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LevelItem {
    pub x: f32,
    pub y: f32,
    pub item_type: LevelItemType,
    pub expires_at: SystemTime,
}
impl Default for LevelItem {
    fn default() -> Self {
        Self {
            x: 0.0,
            y: 0.0,
            item_type: ITEM_GREEN_RUPEE,
            expires_at: UNIX_EPOCH,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct LevelLink {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub dest_level: String,
    pub dest_x: f32,
    pub dest_y: f32,
    pub dest_x_text: String,
    pub dest_y_text: String,
}

impl LevelLink {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn NewLevelLink() -> Self {
        Self::new()
    }
    pub fn get_link_str(&self) -> String {
        let dest_x = if self.dest_x_text.is_empty() {
            format_level_link_coordinate(self.dest_x)
        } else {
            self.dest_x_text.clone()
        };
        let dest_y = if self.dest_y_text.is_empty() {
            format_level_link_coordinate(self.dest_y)
        } else {
            self.dest_y_text.clone()
        };
        format!(
            "{} {} {} {} {} {} {}",
            self.dest_level,
            self.x as i32,
            self.y as i32,
            self.width as i32,
            self.height as i32,
            dest_x,
            dest_y
        )
    }
    pub fn GetLinkStr(&self) -> String {
        self.get_link_str()
    }
    pub fn parse_link_str(&mut self, parts: &[&str]) {
        if parts.len() < 7 {
            return;
        }
        let offset = parts.len() - 7;
        self.dest_level = parts[..1 + offset].join(" ");
        self.x = parts[1 + offset].parse().unwrap_or(0.0);
        self.y = parts[2 + offset].parse().unwrap_or(0.0);
        self.width = parts[3 + offset].parse().unwrap_or(0.0);
        self.height = parts[4 + offset].parse().unwrap_or(0.0);
        self.dest_x_text = parts[5 + offset].to_string();
        self.dest_y_text = parts[6 + offset].to_string();
        self.dest_x = parts[5 + offset].parse().unwrap_or(0.0);
        self.dest_y = parts[6 + offset].parse().unwrap_or(0.0);
    }
    pub fn ParseLinkStr(&mut self, parts: &[&str]) {
        self.parse_link_str(parts)
    }
    pub fn get_new_level(&self) -> &str {
        &self.dest_level
    }
    pub fn GetNewLevel(&self) -> &str {
        &self.dest_level
    }
    pub fn get_new_x(&self) -> f32 {
        self.dest_x
    }
    pub fn GetNewX(&self) -> f32 {
        self.dest_x
    }
    pub fn get_new_y(&self) -> f32 {
        self.dest_y
    }
    pub fn GetNewY(&self) -> f32 {
        self.dest_y
    }
    pub fn get_x(&self) -> f32 {
        self.x
    }
    pub fn GetX(&self) -> f32 {
        self.x
    }
    pub fn get_y(&self) -> f32 {
        self.y
    }
    pub fn GetY(&self) -> f32 {
        self.y
    }
    pub fn get_width(&self) -> f32 {
        self.width
    }
    pub fn GetWidth(&self) -> f32 {
        self.width
    }
    pub fn get_height(&self) -> f32 {
        self.height
    }
    pub fn GetHeight(&self) -> f32 {
        self.height
    }
    pub fn set_new_level(&mut self, value: &str) {
        self.dest_level = value.to_string()
    }
    pub fn SetNewLevel(&mut self, value: &str) {
        self.set_new_level(value)
    }
    pub fn set_new_x(&mut self, value: f32) {
        self.dest_x = value;
        self.dest_x_text.clear();
    }
    pub fn SetNewX(&mut self, value: f32) {
        self.set_new_x(value)
    }
    pub fn set_new_y(&mut self, value: f32) {
        self.dest_y = value;
        self.dest_y_text.clear();
    }
    pub fn SetNewY(&mut self, value: f32) {
        self.set_new_y(value)
    }
    pub fn set_x(&mut self, value: f32) {
        self.x = value
    }
    pub fn SetX(&mut self, value: f32) {
        self.set_x(value)
    }
    pub fn set_y(&mut self, value: f32) {
        self.y = value
    }
    pub fn SetY(&mut self, value: f32) {
        self.set_y(value)
    }
    pub fn set_width(&mut self, value: f32) {
        self.width = value
    }
    pub fn SetWidth(&mut self, value: f32) {
        self.set_width(value)
    }
    pub fn set_height(&mut self, value: f32) {
        self.height = value
    }
    pub fn SetHeight(&mut self, value: f32) {
        self.set_height(value)
    }
}

fn format_level_link_coordinate(value: f32) -> String {
    format!("{value}")
}

const SIGN_TEXT: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!?-.,#>()#####\"####':/~&### <####;\n";
const SIGN_SYMBOLS: &[u8] = b"ABXYudlrhxyz#4.";
const CTAB_LEN: [usize; 15] = [1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 2, 2, 1];
const CTAB_INDEX: [usize; 15] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 15, 17];
const CTAB: &[u8] = &[
    91, 92, 93, 94, 77, 78, 79, 80, 74, 75, 71, 72, 73, 86, 86, 87, 88, 67,
];

#[derive(Clone, Debug, Default)]
pub struct LevelSign {
    pub x: i32,
    pub y: i32,
    pub text: String,
    pub unformatted_text: String,
}

impl LevelSign {
    pub fn new(x: i32, y: i32, sign: &str, encoded: bool) -> Self {
        if encoded {
            Self {
                x,
                y,
                text: sign.to_string(),
                unformatted_text: decode_sign_code(sign.as_bytes()),
            }
        } else {
            Self {
                x,
                y,
                unformatted_text: sign.to_string(),
                text: encode_sign(sign),
            }
        }
    }
    pub fn NewLevelSign(x: i32, y: i32, sign: &str, encoded: bool) -> Self {
        Self::new(x, y, sign, encoded)
    }
    pub fn get_sign_str(&self, player: Option<&Player>) -> Vec<u8> {
        let mut buf = Buffer::new();
        buf.write_gchar(self.x as u8).write_gchar(self.y as u8);
        if player.is_some() {
            let text = player
                .map(|value| value.translate(&self.unformatted_text))
                .unwrap_or_else(|| self.unformatted_text.clone());
            buf.write(&encode_sign(&text).into_bytes());
        } else {
            buf.write(self.text.as_bytes());
        }
        buf.data
    }
    pub fn GetSignStr(&self, player: Option<&Player>) -> Vec<u8> {
        self.get_sign_str(player)
    }
    pub fn get_x(&self) -> i32 {
        self.x
    }
    pub fn GetX(&self) -> i32 {
        self.x
    }
    pub fn get_y(&self) -> i32 {
        self.y
    }
    pub fn GetY(&self) -> i32 {
        self.y
    }
    pub fn get_text(&self) -> &str {
        &self.text
    }
    pub fn GetText(&self) -> &str {
        &self.text
    }
    pub fn get_utext(&self) -> &str {
        &self.unformatted_text
    }
    pub fn GetUText(&self) -> &str {
        &self.unformatted_text
    }
    pub fn set_x(&mut self, value: i32) {
        self.x = value
    }
    pub fn SetX(&mut self, value: i32) {
        self.set_x(value)
    }
    pub fn set_y(&mut self, value: i32) {
        self.y = value
    }
    pub fn SetY(&mut self, value: i32) {
        self.set_y(value)
    }
    pub fn set_text(&mut self, value: &str) {
        self.text = value.to_string();
        self.unformatted_text = decode_sign_code(value.as_bytes());
    }
    pub fn SetText(&mut self, value: &str) {
        self.set_text(value)
    }
    pub fn set_utext(&mut self, value: &str) {
        self.unformatted_text = value.to_string();
        self.text = encode_sign(value);
    }
    pub fn SetUText(&mut self, value: &str) {
        self.set_utext(value)
    }
}

pub fn encode_sign_code(text: &str) -> Vec<u8> {
    let mut buf = Buffer::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let mut letter = bytes[index];
        if letter == b'#' && index + 1 < bytes.len() {
            index += 1;
            letter = bytes[index];
            if let Some(code) = SIGN_SYMBOLS.iter().position(|value| *value == letter) {
                for offset in 0..CTAB_LEN[code] {
                    buf.write_gchar(CTAB[CTAB_INDEX[code] + offset].saturating_sub(32));
                }
                index += 1;
                continue;
            }
            index -= 1;
            letter = b'#';
        }
        let code = if letter == b'#' {
            Some(86usize)
        } else {
            SIGN_TEXT.iter().position(|value| *value == letter)
        };
        if let Some(code) = code {
            buf.write_gchar(code as u8);
        } else if letter != b'\r' {
            buf.write_gchar(86 - 32).write_byte(10).write_gchar(69 - 32);
            for digit in letter.to_string().bytes() {
                if let Some(value) = SIGN_TEXT.iter().position(|candidate| *candidate == digit) {
                    buf.write_gchar(value as u8);
                }
            }
            buf.write_gchar(70 - 32);
        }
        index += 1;
    }
    buf.data
}

pub fn decode_sign_code(data: &[u8]) -> String {
    let mut buf = Buffer::from_bytes(data);
    let mut result = String::new();
    while buf.remaining() > 0 {
        let letter = buf.read_gchar();
        if let Some(code_id) = CTAB.iter().position(|value| *value == letter) {
            if let Some(code_index) = CTAB_INDEX.iter().position(|value| *value == code_id) {
                result.push('#');
                result.push(SIGN_SYMBOLS[code_index] as char);
            }
        } else if (letter as usize) < SIGN_TEXT.len() {
            result.push(SIGN_TEXT[letter as usize] as char);
        }
    }
    result.replace("#K(13)", "")
}

pub fn encode_sign(text: &str) -> String {
    let mut result = Vec::new();
    for line in text.split('\n') {
        result.extend_from_slice(&encode_sign_code(&format!("{line}\n")));
    }
    String::from_utf8_lossy(&result).into_owned()
}

pub fn item_name(item_type: LevelItemType) -> &'static str {
    const ITEMS: [&str; 25] = [
        "greenrupee",
        "bluerupee",
        "redrupee",
        "bombs",
        "darts",
        "heart",
        "glove1",
        "bow",
        "bomb",
        "shield",
        "sword",
        "fullheart",
        "superbomb",
        "battleaxe",
        "goldensword",
        "mirrorshield",
        "glove2",
        "lizardshield",
        "lizardsword",
        "goldrupee",
        "fireball",
        "fireblast",
        "nukeshot",
        "joltbomb",
        "spinattack",
    ];
    ITEMS.get(item_type as usize).copied().unwrap_or("")
}
pub fn item_id(name: &str) -> LevelItemType {
    const ITEMS: [&str; 25] = [
        "greenrupee",
        "bluerupee",
        "redrupee",
        "bombs",
        "darts",
        "heart",
        "glove1",
        "bow",
        "bomb",
        "shield",
        "sword",
        "fullheart",
        "superbomb",
        "battleaxe",
        "goldensword",
        "mirrorshield",
        "glove2",
        "lizardshield",
        "lizardsword",
        "goldrupee",
        "fireball",
        "fireblast",
        "nukeshot",
        "joltbomb",
        "spinattack",
    ];
    ITEMS
        .iter()
        .position(|value| *value == name)
        .map(|value| value as i32)
        .unwrap_or(-1)
}

fn is_respawning_tile(tile: i16) -> bool {
    matches!(
        tile,
        0x1ff | 0x3ff | 0x2ac | 0x002 | 0x200 | 0x022 | 0x3de | 0x1a4 | 0x14a | 0x674 | 0x72a
    )
}

fn is_rupee_item(item_type: LevelItemType) -> bool {
    matches!(
        item_type,
        ITEM_GREEN_RUPEE | ITEM_BLUE_RUPEE | ITEM_RED_RUPEE | ITEM_GOLD_RUPEE
    )
}

fn rupee_item_value(item_type: LevelItemType) -> i32 {
    match item_type {
        ITEM_GOLD_RUPEE => 100,
        ITEM_RED_RUPEE => 30,
        ITEM_BLUE_RUPEE => 5,
        ITEM_GREEN_RUPEE => 1,
        _ => 0,
    }
}

fn npc_has_joined_class(npc: &Arc<NPC>, class_name: &str) -> bool {
    if class_name.trim().is_empty() {
        return false;
    }
    let (classes, script) = {
        let state = npc.state.lock().unwrap();
        (
            state.vm_this.get("__classes").cloned(),
            state.script.clone(),
        )
    };
    if let Some(serde_json::Value::Array(values)) = classes {
        if values.iter().any(|value| {
            value
                .as_str()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case(class_name.trim()))
        }) {
            return true;
        }
    }
    script
        .lines()
        .filter_map(parse_gs2_join_line)
        .any(|value| value.trim().eq_ignore_ascii_case(class_name.trim()))
}

fn shorts_to_bytes(shorts: &[i16]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(shorts.len() * 2);
    for value in shorts {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes
}

fn bytes_to_shorts(bytes: &[u8]) -> Vec<i16> {
    bytes
        .chunks_exact(2)
        .map(|chunk| i16::from_be_bytes([chunk[0], chunk[1]]))
        .collect()
}

#[derive(Clone)]
pub struct LevelBaddy {
    pub baddy_type: u8,
    pub id: u8,
    pub power: u8,
    pub mode: u8,
    pub ani: u8,
    pub dir: u8,
    pub x: f32,
    pub y: f32,
    pub start_x: f32,
    pub start_y: f32,
    pub image: String,
    pub verses: [String; 3],
    pub can_respawn: bool,
    pub has_custom_image: bool,
    pub timeout: Option<SystemTime>,
    pub level: Option<Arc<Level>>,
    pub server: Weak<Server>,
}
impl LevelBaddy {
    pub fn new(
        x: f32,
        y: f32,
        baddy_type: u8,
        level: Option<Arc<Level>>,
        server: &Arc<Server>,
    ) -> Self {
        let baddy_type = if baddy_type >= 10 { 0 } else { baddy_type };
        let mut value = Self {
            baddy_type,
            id: 0,
            power: 0,
            mode: 0,
            ani: 0,
            dir: 0,
            x,
            y,
            start_x: x,
            start_y: y,
            image: String::new(),
            verses: std::array::from_fn(|_| String::new()),
            can_respawn: true,
            has_custom_image: false,
            timeout: None,
            level,
            server: Arc::downgrade(server),
        };
        value.reset();
        value
    }
    pub fn NewLevelBaddy(
        x: f32,
        y: f32,
        baddy_type: u8,
        level: Option<Arc<Level>>,
        server: &Arc<Server>,
    ) -> Self {
        Self::new(x, y, baddy_type, level, server)
    }
    pub fn reset(&mut self) {
        const MODES: [u8; 10] = [0, 0, 0, 0, 6, 7, 0, 0, 0, 0];
        const POWERS: [u8; 10] = [2, 3, 4, 3, 2, 1, 1, 6, 12, 8];
        const IMAGES: [&str; 10] = [
            "baddygray.png",
            "baddyblue.png",
            "baddyred.png",
            "baddyblue.png",
            "baddygray.png",
            "baddyhare.png",
            "baddyoctopus.png",
            "baddygold.png",
            "baddylizardon.png",
            "baddydragon.png",
        ];
        self.mode = MODES[self.baddy_type as usize];
        self.x = self.start_x;
        self.y = self.start_y;
        self.power = POWERS[self.baddy_type as usize];
        self.image = IMAGES[self.baddy_type as usize].to_string();
        self.dir = (2 << 2) | 2;
        self.ani = 0;
        self.has_custom_image = false;
    }
    pub fn get_prop(&self, prop_id: u8, client_version: i32) -> Vec<u8> {
        let mut buf = Buffer::new();
        match prop_id {
            BDPROP_ID => {
                buf.write_byte(self.id);
            }
            BDPROP_X => {
                buf.write_byte((self.x * 2.0) as u8);
            }
            BDPROP_Y => {
                buf.write_byte((self.y * 2.0) as u8);
            }
            BDPROP_TYPE => {
                buf.write_byte(self.baddy_type);
            }
            BDPROP_POWERIMAGE => {
                buf.write_byte(self.power);
                let mut image = self.image.clone();
                let default_image = match self.baddy_type {
                    0 => "baddygray.png",
                    1 => "baddyblue.png",
                    2 => "baddyred.png",
                    3 => "baddyblue.png",
                    4 => "baddygray.png",
                    5 => "baddyhare.png",
                    6 => "baddyoctopus.png",
                    7 => "baddygold.png",
                    8 => "baddylizardon.png",
                    9 => "baddydragon.png",
                    _ => "",
                };
                if client_version < 201 && self.image == default_image {
                    image = image.replace(".png", ".gif");
                }
                buf.write_string(&image);
            }
            BDPROP_MODE => {
                buf.write_byte(self.mode);
            }
            BDPROP_ANI => {
                buf.write_byte(self.ani);
            }
            BDPROP_DIR => {
                buf.write_byte(self.dir);
            }
            BDPROP_VERSESIGHT..=BDPROP_VERSEATTACK => {
                buf.write_string(&self.verses[(prop_id - BDPROP_VERSESIGHT) as usize]);
            }
            _ => {}
        }
        buf.data
    }
    pub fn get_props(&self, client_version: i32) -> Vec<u8> {
        let mut out = Buffer::new();
        for prop in 1..BDPROP_COUNT {
            out.write_byte(prop)
                .write(&self.get_prop(prop, client_version));
        }
        out.data
    }
    pub fn set_props(&mut self, data: &[u8]) {
        let mut buf = Buffer::from_bytes(data);
        while buf.remaining() > 0 {
            let prop = buf.read_gchar();
            match prop {
                BDPROP_ID => self.id = buf.read_gchar(),
                BDPROP_X => self.x = (f32::from(buf.read_gchar()) / 2.0).min(63.5),
                BDPROP_Y => self.y = (f32::from(buf.read_gchar()) / 2.0).min(63.5),
                BDPROP_TYPE => self.baddy_type = buf.read_gchar(),
                BDPROP_POWERIMAGE => {
                    self.power = buf.read_gchar();
                    if buf.remaining() > 0 {
                        let length = buf.read_gchar() as usize;
                        if length > 0 && length <= buf.remaining() {
                            let image =
                                String::from_utf8_lossy(&buf.read_bytes(length)).into_owned();
                            if image.is_empty() {
                                self.image = match self.baddy_type {
                                    0 => "baddygray.png",
                                    1 => "baddyblue.png",
                                    2 => "baddyred.png",
                                    3 => "baddyblue.png",
                                    4 => "baddygray.png",
                                    5 => "baddyhare.png",
                                    6 => "baddyoctopus.png",
                                    7 => "baddygold.png",
                                    8 => "baddylizardon.png",
                                    9 => "baddydragon.png",
                                    _ => "baddygray.png",
                                }
                                .to_string();
                            } else if !self.has_custom_image {
                                self.image = image;
                                self.has_custom_image = true;
                            }
                        }
                    }
                }
                BDPROP_MODE => {
                    self.mode = buf.read_gchar();
                    let now = SystemTime::now();
                    if self.baddy_type == 4 && self.mode == BDMODE_HURT {
                        self.timeout = now.checked_add(Duration::from_secs(2));
                    } else if self.mode == BDMODE_DIE {
                        self.timeout = now.checked_add(Duration::from_secs(2));
                        if self
                            .server
                            .upgrade()
                            .is_some_and(|server| server.settings.get_bool("baddyitems", false))
                        {
                            self.schedule_drop_item();
                        }
                    } else if self.mode == BDMODE_DEAD {
                        if self.can_respawn {
                            let seconds = self
                                .server
                                .upgrade()
                                .map(|server| server.settings.get_int("baddyrespawntime", 60))
                                .unwrap_or(60);
                            self.timeout = if seconds >= 0 {
                                now.checked_add(Duration::from_secs(seconds as u64))
                            } else {
                                now.checked_sub(Duration::from_secs(seconds.unsigned_abs() as u64))
                            };
                        } else if let Some(level) = &self.level {
                            level.remove_baddy(self.id);
                        }
                    }
                }
                BDPROP_ANI => self.ani = buf.read_gchar(),
                BDPROP_DIR => self.dir = buf.read_gchar(),
                BDPROP_VERSESIGHT..=BDPROP_VERSEATTACK => {
                    let index = usize::from(prop - BDPROP_VERSESIGHT);
                    if index < self.verses.len() && buf.remaining() > 0 {
                        let length = buf.read_gchar() as usize;
                        if length > 0 && length <= buf.remaining() {
                            self.verses[index] =
                                String::from_utf8_lossy(&buf.read_bytes(length)).into_owned();
                        }
                    }
                }
                _ => {}
            }
        }
    }
    fn schedule_drop_item(&self) {
        let Some(server) = self.server.upgrade() else {
            return;
        };
        let Some(level) = self.level.clone() else {
            return;
        };
        let x = self.x;
        let y = self.y;
        thread::spawn(move || {
            let item_type = match rand::random::<u32>() % 12 {
                6..=9 => ITEM_GREEN_RUPEE,
                _ => -1,
            };
            if item_type < 0 {
                return;
            }
            if level.add_item_for_server(&server, x, y, item_type) {
                let mut packet = Buffer::new();
                packet
                    .write_byte(PLO_ITEMADD)
                    .write_byte((x * 2.0) as u8)
                    .write_byte((y * 2.0) as u8)
                    .write_byte(item_type as u8);
                for id in level.get_players() {
                    if let Some(player) = server.get_player(id) {
                        player.send(&packet);
                    }
                }
            }
        });
    }
    pub fn setProps(&mut self, data: &[u8]) {
        self.set_props(data)
    }
    pub fn set_id(&mut self, id: u8) {
        self.id = id;
    }
}

struct LevelState {
    file_name: String,
    file_version: String,
    actual_level_name: String,
    level_name: String,
    mod_time: SystemTime,
    is_sparring_zone: bool,
    is_singleplayer: bool,
    map_x: i32,
    map_y: i32,
    map_ref: Option<Arc<Map>>,
    tiles: HashMap<u8, LevelTiles>,
    baddies: HashMap<u8, Arc<LevelBaddy>>,
    board_changes: Vec<LevelBoardChange>,
    chests: Vec<LevelChest>,
    horses: Vec<LevelHorse>,
    items: Vec<LevelItem>,
    links: Vec<LevelLink>,
    signs: Vec<LevelSign>,
    npcs: HashMap<u32, Arc<NPC>>,
    players: Vec<u16>,
}

pub struct Level {
    state: RwLock<LevelState>,
}

impl Level {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(LevelState {
                file_name: String::new(),
                file_version: String::new(),
                actual_level_name: String::new(),
                level_name: String::new(),
                mod_time: UNIX_EPOCH,
                is_sparring_zone: false,
                is_singleplayer: false,
                map_x: 0,
                map_y: 0,
                map_ref: None,
                tiles: HashMap::new(),
                baddies: HashMap::new(),
                board_changes: Vec::new(),
                chests: Vec::new(),
                horses: Vec::new(),
                items: Vec::new(),
                links: Vec::new(),
                signs: Vec::new(),
                npcs: HashMap::new(),
                players: Vec::new(),
            }),
        }
    }
    pub fn NewLevel() -> Self {
        Self::new()
    }
    pub fn get_name(&self) -> String {
        self.state.read().unwrap().level_name.clone()
    }
    pub fn getName(&self) -> String {
        self.get_name()
    }
    pub fn GetName(&self) -> String {
        self.get_name()
    }
    pub fn get_mod_time(&self) -> SystemTime {
        self.state.read().unwrap().mod_time
    }
    pub fn GetModTime(&self) -> SystemTime {
        self.get_mod_time()
    }
    pub fn set_level_name(&self, value: &str) {
        self.state.write().unwrap().level_name = value.to_string();
    }
    pub fn set_sparring_zone(&self, value: bool) {
        self.state.write().unwrap().is_sparring_zone = value;
    }
    pub fn set_singleplayer(&self, value: bool) {
        self.state.write().unwrap().is_singleplayer = value;
    }
    pub fn add_player(&self, player: &Player) {
        let mut state = self.state.write().unwrap();
        if !state.players.contains(&player.id()) {
            state.players.push(player.id());
        }
    }
    pub fn addPlayer(&self, player: &Player) {
        self.add_player(player)
    }
    pub fn remove_player(&self, player: &Player) {
        self.state
            .write()
            .unwrap()
            .players
            .retain(|id| *id != player.id());
    }
    pub fn removePlayer(&self, player: &Player) {
        self.remove_player(player)
    }
    pub fn get_players(&self) -> Vec<u16> {
        self.state.read().unwrap().players.clone()
    }
    pub fn getPlayers(&self) -> Vec<u16> {
        self.get_players()
    }
    pub fn add_npc(&self, npc: Arc<NPC>) {
        self.state.write().unwrap().npcs.insert(npc.id(), npc);
    }
    pub fn addNPC(&self, npc: Arc<NPC>) {
        self.add_npc(npc)
    }
    pub fn remove_npc(&self, id: u32) -> Option<Arc<NPC>> {
        self.state.write().unwrap().npcs.remove(&id)
    }
    pub fn removeNPC(&self, id: u32) -> Option<Arc<NPC>> {
        self.remove_npc(id)
    }
    pub fn get_npcs(&self) -> Vec<Arc<NPC>> {
        self.state.read().unwrap().npcs.values().cloned().collect()
    }
    pub fn getNPCs(&self) -> Vec<Arc<NPC>> {
        self.get_npcs()
    }
    pub fn get_board_packet(&self) -> Vec<u8> {
        let state = self.state.read().unwrap();
        let mut buf = Buffer::new();
        buf.write_gchar(PLO_BOARDPACKET);
        if let Some(main_layer) = state.tiles.get(&0) {
            if main_layer.tiles.len() == 4096 {
                for tile in &main_layer.tiles {
                    buf.write_byte((*tile as u16 & 0xff) as u8)
                        .write_byte((*tile as u16 >> 8) as u8);
                }
            } else {
                buf.write(&vec![0; 8192]);
            }
        } else {
            buf.write(&vec![0; 8192]);
        }
        buf.write_byte(b'\n');
        buf.data
    }
    pub fn getBoardPacket(&self) -> Vec<u8> {
        self.get_board_packet()
    }
    pub fn board_changes(&self) -> Vec<LevelBoardChange> {
        self.state.read().unwrap().board_changes.clone()
    }
    pub fn chests(&self) -> Vec<LevelChest> {
        self.state.read().unwrap().chests.clone()
    }
    pub fn links(&self) -> Vec<LevelLink> {
        self.state.read().unwrap().links.clone()
    }
    pub fn signs(&self) -> Vec<LevelSign> {
        self.state.read().unwrap().signs.clone()
    }
    pub fn items(&self) -> Vec<LevelItem> {
        self.state.read().unwrap().items.clone()
    }
    pub fn add_board_change(&self, change: LevelBoardChange) {
        self.state.write().unwrap().board_changes.push(change);
    }
    pub fn add_item(&self, item: LevelItem) {
        self.state.write().unwrap().items.push(item);
    }
    pub fn add_link(&self, link: LevelLink) {
        self.state.write().unwrap().links.push(link);
    }
    pub fn add_sign(&self, sign: LevelSign) {
        self.state.write().unwrap().signs.push(sign);
    }
    pub fn get_tile(&self, layer: u8, x: usize, y: usize) -> i16 {
        self.state
            .read()
            .unwrap()
            .tiles
            .get(&layer)
            .and_then(|tiles| tiles.tiles.get(x + y * 64))
            .copied()
            .unwrap_or(0)
    }
    pub fn set_tile(&self, layer: u8, x: usize, y: usize, value: i16) {
        let mut state = self.state.write().unwrap();
        let layer = state.tiles.entry(layer).or_insert_with(|| LevelTiles {
            width: 64,
            height: 64,
            tiles: vec![0; 4096],
        });
        if x < 64 && y < 64 {
            layer.tiles[x + y * 64] = value;
        }
    }

    pub fn alter_board(
        &self,
        server: &Server,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        tiles: &[i16],
    ) -> bool {
        if x < 0
            || y < 0
            || width <= 0
            || height <= 0
            || x + width > 64
            || y + height > 64
            || tiles.len() < (width * height) as usize
        {
            return false;
        }
        let (old_tiles, old_tile) = {
            let mut state = self.state.write().unwrap();
            state.tiles.entry(0).or_insert_with(|| LevelTiles {
                width: 64,
                height: 64,
                tiles: vec![0; 4096],
            });
            let mut old = Vec::with_capacity((width * height) as usize);
            for yy in 0..height {
                for xx in 0..width {
                    old.push(state.tiles[&0].tiles[(x + xx + (y + yy) * 64) as usize]);
                }
            }
            for index in (0..state.board_changes.len()).rev() {
                let change = &state.board_changes[index];
                if change.x >= x
                    && change.x + change.width <= x + width
                    && change.y >= y
                    && change.y + change.height <= y + height
                {
                    state.board_changes.remove(index);
                }
            }
            for yy in 0..height {
                for xx in 0..width {
                    state.tiles.get_mut(&0).unwrap().tiles[(x + xx + (y + yy) * 64) as usize] =
                        tiles[(xx + yy * width) as usize];
                }
            }
            let first = old.first().copied().unwrap_or_default();
            (old, first)
        };
        let timeout = if is_respawning_tile(old_tile) {
            let respawn_seconds = server.settings.get_int("respawntime", 15);
            if respawn_seconds >= 0 {
                SystemTime::now().checked_add(Duration::from_secs(respawn_seconds as u64))
            } else {
                None
            }
        } else {
            None
        };
        let new_bytes = shorts_to_bytes(&tiles[..(width * height) as usize]);
        let old_bytes = shorts_to_bytes(&old_tiles);
        self.state
            .write()
            .unwrap()
            .board_changes
            .push(LevelBoardChange {
                x,
                y,
                width,
                height,
                new_tiles: new_bytes,
                old_tiles: old_bytes,
                time: SystemTime::now(),
                timeout,
            });
        true
    }
    pub fn alterBoard(
        &self,
        server: &Server,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        tiles: &[i16],
    ) -> bool {
        self.alter_board(server, x, y, width, height, tiles)
    }

    pub fn process_board_respawns(&self, server: &Server) {
        let now = SystemTime::now();
        let mut respawns = Vec::new();
        {
            let mut state = self.state.write().unwrap();
            let mut index = 0;
            while index < state.board_changes.len() {
                let change = &state.board_changes[index];
                let expired = change
                    .timeout
                    .map(|timeout| now >= timeout)
                    .unwrap_or(false);
                if expired && !change.old_tiles.is_empty() {
                    let change = state.board_changes.remove(index);
                    let old_tiles = bytes_to_shorts(&change.old_tiles);
                    let layer = state.tiles.entry(0).or_insert_with(|| LevelTiles {
                        width: 64,
                        height: 64,
                        tiles: vec![0; 4096],
                    });
                    let mut offset = 0usize;
                    for yy in 0..change.height {
                        for xx in 0..change.width {
                            if let Some(tile) = old_tiles.get(offset) {
                                layer.tiles[(change.x + xx + (change.y + yy) * 64) as usize] =
                                    *tile;
                            }
                            offset += 1;
                        }
                    }
                    respawns.push((change.x, change.y, change.width, change.height, old_tiles));
                } else {
                    index += 1;
                }
            }
        }
        for (x, y, width, height, tiles) in respawns {
            server.broadcast_board_modify(
                self,
                x as i16,
                y as i16,
                width as i16,
                height as i16,
                &tiles,
            );
        }
    }

    pub fn add_item_at(&self, x: f32, y: f32, item_type: LevelItemType) {
        if item_name(item_type).is_empty() {
            return;
        }
        self.state.write().unwrap().items.push(LevelItem {
            x,
            y,
            item_type,
            expires_at: SystemTime::now() + Duration::from_secs(10),
        });
    }
    pub fn addItem(&self, x: f32, y: f32, item_type: LevelItemType) {
        self.add_item_at(x, y, item_type)
    }
    pub fn remove_item_at(&self, x: f32, y: f32) -> LevelItemType {
        let mut state = self.state.write().unwrap();
        if let Some(index) = state
            .items
            .iter()
            .position(|item| item.x == x && item.y == y)
        {
            return state.items.remove(index).item_type;
        }
        -1
    }
    pub fn removeItem(&self, x: f32, y: f32) -> LevelItemType {
        self.remove_item_at(x, y)
    }
    fn process_item_timeouts(&self, server: &Server) {
        let now = SystemTime::now();
        let expired = {
            let mut state = self.state.write().unwrap();
            let mut expired = Vec::new();
            let mut index = 0;
            while index < state.items.len() {
                if state.items[index].expires_at != UNIX_EPOCH
                    && now >= state.items[index].expires_at
                {
                    expired.push(state.items.remove(index));
                } else {
                    index += 1;
                }
            }
            expired
        };
        for item in expired {
            let mut packet = Buffer::new();
            packet
                .write_byte(PLO_ITEMDEL)
                .write_gchar((item.x * 2.0) as u8)
                .write_gchar((item.y * 2.0) as u8)
                .write_gchar(item.item_type as u8);
            for id in self.get_players() {
                if let Some(player) = server.get_player(id) {
                    if player.has_connection() {
                        player.send(&packet);
                    }
                }
            }
        }
    }
    fn process_horse_timeouts(&self, server: &Server) {
        let now = SystemTime::now();
        let expired = {
            let mut state = self.state.write().unwrap();
            let mut expired = Vec::new();
            let mut index = 0;
            while index < state.horses.len() {
                if state.horses[index].expires_at != UNIX_EPOCH
                    && now >= state.horses[index].expires_at
                {
                    expired.push(state.horses.remove(index));
                } else {
                    index += 1;
                }
            }
            expired
        };
        for horse in expired {
            let mut packet = Buffer::new();
            packet
                .write_byte(PLO_HORSEDEL)
                .write_gchar((horse.x * 2.0) as u8)
                .write_gchar((horse.y * 2.0) as u8);
            for id in self.get_players() {
                if let Some(player) = server.get_player(id) {
                    if player.has_connection() {
                        player.send(&packet);
                    }
                }
            }
        }
    }
    fn process_baddy_timeouts(&self, server: &Server) {
        let baddies = self
            .state
            .read()
            .unwrap()
            .baddies
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for baddy in baddies {
            let now = SystemTime::now();
            if baddy.timeout.is_none_or(|timeout| now < timeout) {
                continue;
            }
            let mut updated = (*baddy).clone();
            updated.timeout = None;
            let mut remove = false;
            let props =
                if updated.baddy_type == 4 && updated.mode == BDMODE_HURT && updated.power == 1 {
                    updated.mode = BDMODE_SWAMPSHOT;
                    vec![BDPROP_MODE, BDMODE_SWAMPSHOT]
                } else if updated.mode == BDMODE_DIE {
                    updated.mode = BDMODE_DEAD;
                    if updated.can_respawn {
                        let seconds = server.settings.get_int("baddyrespawntime", 60);
                        updated.timeout = if seconds >= 0 {
                            now.checked_add(Duration::from_secs(seconds as u64))
                        } else {
                            now.checked_sub(Duration::from_secs(seconds.unsigned_abs() as u64))
                        };
                    } else {
                        remove = true;
                    }
                    vec![BDPROP_MODE, BDMODE_DEAD]
                } else {
                    updated.reset();
                    updated.get_props(server.settings.get_int("clientversion", 0))
                };
            if remove {
                self.remove_baddy(updated.id);
            } else {
                self.state
                    .write()
                    .unwrap()
                    .baddies
                    .insert(updated.id, Arc::new(updated.clone()));
            }
            let mut packet = Buffer::new();
            packet
                .write_byte(PLO_BADDYPROPS)
                .write_gchar(updated.id)
                .write(&props);
            for id in self.get_players() {
                if let Some(player) = server.get_player(id) {
                    if player.has_connection() {
                        player.send(&packet);
                    }
                }
            }
        }
    }
    fn add_item_for_server(
        &self,
        server: &Server,
        x: f32,
        y: f32,
        item_type: LevelItemType,
    ) -> bool {
        if !server.npc_server_running() {
            self.add_item_at(x, y, item_type);
            return true;
        }
        let class_name = if is_rupee_item(item_type) {
            "gralats"
        } else if item_type == ITEM_DARTS {
            "darts"
        } else {
            self.add_item_at(x, y, item_type);
            return true;
        };
        if server.get_class(class_name).is_none() {
            self.add_item_at(x, y, item_type);
            return true;
        }
        let pixel_x = ((x - 0.5) * 16.0) as i32;
        let pixel_y = ((y - 0.5) * 16.0) as i32;
        for npc in self.get_npcs() {
            if !npc.matches_trigger_area(pixel_x, pixel_y, 32, 32)
                || !npc_has_joined_class(&npc, class_name)
            {
                continue;
            }
            {
                let mut state = npc.state.lock().unwrap();
                if item_type == ITEM_DARTS {
                    state.character.arrows += 1;
                    let arrows = state.character.arrows;
                    state
                        .vm_this
                        .insert("darts".to_string(), serde_json::Value::from(arrows));
                    state
                        .vm_this
                        .insert("arrows".to_string(), serde_json::Value::from(arrows));
                } else {
                    state.character.gralats += rupee_item_value(item_type);
                    let gralats = state.character.gralats;
                    state
                        .vm_this
                        .insert("gralats".to_string(), serde_json::Value::from(gralats));
                }
            }
            server.run_server_side_npc_event_for_player(&npc, "update", None, &[]);
            server.send_npc_props_to_level(&npc);
            return false;
        }

        let level = server.get_level(&self.get_name());
        let npc = Arc::new(NPC::new(NPCType::LEVELNPC));
        {
            let mut state = npc.state.lock().unwrap();
            state.x = (x * 16.0).round() as i16;
            state.y = (y * 16.0).round() as i16;
            state.script = format!("join(\"{class_name}\");");
            state.script_type = "LOCALN".to_string();
            state.level = level.clone();
            if item_type == ITEM_DARTS {
                state.character.arrows = 1;
                state
                    .vm_this
                    .insert("darts".to_string(), serde_json::Value::from(1));
                state
                    .vm_this
                    .insert("arrows".to_string(), serde_json::Value::from(1));
            } else {
                let value = rupee_item_value(item_type);
                state.character.gralats = value;
                state
                    .vm_this
                    .insert("gralats".to_string(), serde_json::Value::from(value));
            }
        }
        if !server.add_npc(npc.clone()) {
            self.add_item_at(x, y, item_type);
            return true;
        }
        self.add_npc(npc.clone());
        server.send_npc_props_to_level(&npc);
        server.run_server_side_npc_event_for_player(&npc, "onCreated", None, &[]);
        server.send_npc_props_to_level(&npc);
        false
    }
    pub fn chest_key(&self, chest: &LevelChest) -> String {
        let level_name = self.get_name();
        let name = Path::new(&level_name)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        format!("{}:{}:{name}", chest.x, chest.y)
    }
    pub fn getChestKey(&self, chest: &LevelChest) -> String {
        self.chest_key(chest)
    }
    pub fn remove_baddy(&self, id: u8) {
        self.state.write().unwrap().baddies.remove(&id);
    }
    pub fn removeBaddy(&self, id: u8) {
        self.remove_baddy(id)
    }

    fn attach_entity_levels(&self, level: &Arc<Level>) {
        let npcs = {
            let mut state = self.state.write().unwrap();
            for baddy in state.baddies.values_mut() {
                let mut value = (**baddy).clone();
                value.level = Some(level.clone());
                *baddy = Arc::new(value);
            }
            state.npcs.values().cloned().collect::<Vec<_>>()
        };
        for npc in npcs {
            npc.set_level(Some(level.clone()));
        }
    }

    pub fn load_level(&self, server: &Server, level_name: &str) -> bool {
        let level_arc = server
            .levels
            .read()
            .unwrap()
            .values()
            .find(|level| std::ptr::eq(level.as_ref(), self))
            .cloned();
        self.load_level_with_arc(server, level_name, level_arc)
    }
    fn load_level_with_arc(
        &self,
        server: &Server,
        level_name: &str,
        level_arc: Option<Arc<Level>>,
    ) -> bool {
        if level_name.to_ascii_lowercase().ends_with(".nw") {
            return self.load_nw(server, level_name, level_arc);
        }
        if level_name.to_ascii_lowercase().ends_with(".zelda") {
            return self.load_zelda(server, level_name, level_arc);
        }
        false
    }
    pub fn loadLevel(&self, server: &Server, level_name: &str) -> bool {
        self.load_level(server, level_name)
    }
    fn load_nw(&self, server: &Server, level_name: &str, level_arc: Option<Arc<Level>>) -> bool {
        {
            let mut state = self.state.write().unwrap();
            state.file_name = level_name.to_string();
            state.level_name = level_name.to_string();
        }
        let lines = match server.config.load_file_as_lines(level_name) {
            Ok(value) if !value.is_empty() => value,
            _ => return false,
        };
        let mut state = self.state.write().unwrap();
        state.file_version = lines[0].clone();
        if let Ok(mod_time) = server.config.file_mod_time(level_name) {
            state.mod_time = mod_time;
        }
        let mut index = 0;
        let server_arc = server.self_weak.upgrade();
        let mut created_npcs = Vec::new();
        while index < lines.len() {
            let line = lines[index].trim();
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                index += 1;
                continue;
            }
            match parts[0] {
                "BOARD" if parts.len() == 6 => {
                    let x = parts[1].parse::<i32>().unwrap_or(0);
                    let y = parts[2].parse::<i32>().unwrap_or(0);
                    let width = parts[3].parse::<i32>().unwrap_or(0);
                    let layer = parts[4].parse::<i32>().unwrap_or(0) as u8;
                    let bytes = parts[5].as_bytes();
                    if x >= 0
                        && x < 64
                        && y >= 0
                        && y < 64
                        && width > 0
                        && x + width <= 64
                        && bytes.len() >= (width as usize) * 2
                    {
                        let tiles = state.tiles.entry(layer).or_insert_with(|| LevelTiles {
                            width: 64,
                            height: 64,
                            tiles: vec![0; 4096],
                        });
                        for offset in 0..width as usize {
                            tiles.tiles[x as usize + offset + y as usize * 64] =
                                ((base64_pos(bytes[offset * 2]) << 6)
                                    | base64_pos(bytes[offset * 2 + 1]))
                                    as i16;
                        }
                    }
                }
                "CHEST" if (4..=5).contains(&parts.len()) => {
                    let sign_index = parts
                        .get(4)
                        .and_then(|value| value.parse::<i32>().ok())
                        .unwrap_or(-1);
                    state.chests.push(LevelChest {
                        x: parse_i32(parts[1]),
                        y: parse_i32(parts[2]),
                        item_type: item_id(parts[3]),
                        sign_index,
                    });
                }
                "LINK" if parts.len() >= 8 => {
                    let mut link = LevelLink::default();
                    link.parse_link_str(&parts[1..]);
                    state.links.push(link);
                }
                "SIGN" if parts.len() == 3 => {
                    let x = parse_i32(parts[1]);
                    let y = parse_i32(parts[2]);
                    let mut text = String::new();
                    index += 1;
                    while index < lines.len() && lines[index].trim() != "SIGNEND" {
                        text.push_str(&lines[index]);
                        text.push('\n');
                        index += 1;
                    }
                    state.signs.push(LevelSign::new(x, y, &text, false));
                }
                "BADDY" if parts.len() == 4 => {
                    let Some(server_arc) = server_arc.as_ref() else {
                        index += 1;
                        continue;
                    };
                    let mut baddy = LevelBaddy::new(
                        parse_i32(parts[1]) as f32,
                        parse_i32(parts[2]) as f32,
                        parts[3].parse::<u8>().unwrap_or(0),
                        level_arc.clone(),
                        server_arc,
                    );
                    baddy.id = state.baddies.len() as u8;
                    state.baddies.insert(baddy.id, Arc::new(baddy));
                }
                "NPC" if parts.len() >= 4 => {
                    let Some(_server_arc) = server_arc.as_ref() else {
                        index += 1;
                        continue;
                    };
                    let image = if parts.len() > 4 {
                        parts[1..parts.len() - 2].join(" ")
                    } else {
                        parts[1].to_string()
                    };
                    let x = parts[2].parse::<f32>().unwrap_or(0.0);
                    let y = parts[3].parse::<f32>().unwrap_or(0.0);
                    let mut script = String::new();
                    index += 1;
                    while index < lines.len() && lines[index].trim() != "NPCEND" {
                        script.push_str(&lines[index]);
                        script.push('\n');
                        index += 1;
                    }
                    let npc = Arc::new(NPC::new(NPCType::LEVELNPC));
                    npc.set_position((x * 16.0) as i16, (y * 16.0) as i16, 0);
                    npc.set_image(&image);
                    npc.set_script(&script);
                    npc.set_level(level_arc.clone());
                    if server.add_npc(npc.clone()) {
                        state.npcs.insert(npc.id(), npc.clone());
                        created_npcs.push(npc);
                    }
                }
                _ => {}
            }
            index += 1;
        }
        drop(state);
        for npc in created_npcs {
            server.run_server_side_npc_event_for_player(&npc, "onCreated", None, &[]);
        }
        true
    }
    fn load_zelda(&self, server: &Server, level_name: &str, level_arc: Option<Arc<Level>>) -> bool {
        let level_name = level_name.trim();
        let candidates = if level_name.to_ascii_lowercase().ends_with(".zelda") {
            vec![level_name.to_string()]
        } else {
            vec![
                format!("world/levels/{level_name}.zelda"),
                format!("world/{level_name}.zelda"),
            ]
        };
        let Some((file_name, data)) = candidates.into_iter().find_map(|candidate| {
            server
                .config
                .load_file(&candidate)
                .ok()
                .map(|data| (candidate, data))
        }) else {
            return false;
        };
        // Record these fields immediately after locating the file, before
        // validating its contents. Keep the state change observable while
        // retaining bounds checks for malformed files.
        {
            let mut state = self.state.write().unwrap();
            state.file_name = file_name.clone();
            state.level_name = level_name.to_string();
        }
        if data.len() < 8 {
            return false;
        }
        let version = String::from_utf8_lossy(&data[..8]);
        let bits = if version == "Z3-V1.03" {
            12u32
        } else if version == "Z3-V1.04" {
            13u32
        } else {
            return false;
        };

        let mut pos = 8usize;
        let mut bit_buffer = 0u32;
        let mut bit_read = 0u32;
        let mut board_index = 0usize;
        let mut count = 1usize;
        let mut double_mode = false;
        let mut pair = [-1i16; 2];
        let control_bit = if bits == 12 { 0x800u16 } else { 0x1000u16 };
        let mask = if bits == 12 { 0xfffu32 } else { 0x1fffu32 };
        let mut board = vec![0i16; 4096];
        while board_index < board.len() && pos < data.len() {
            while bit_read < bits && pos < data.len() {
                bit_buffer |= u32::from(data[pos]) << bit_read;
                bit_read += 8;
                pos += 1;
            }
            if bit_read < bits {
                break;
            }
            let code = (bit_buffer & mask) as u16;
            bit_buffer >>= bits;
            bit_read -= bits;
            if code & control_bit != 0 {
                if code & 0x100 != 0 {
                    double_mode = true;
                }
                count = usize::from(code & 0xff);
                continue;
            }
            if count == 1 {
                board[board_index] = code as i16;
                board_index += 1;
                continue;
            }
            if double_mode {
                if pair[0] == -1 {
                    pair[0] = code as i16;
                    continue;
                }
                pair[1] = code as i16;
                for _ in 0..count {
                    if board_index >= board.len().saturating_sub(1) {
                        break;
                    }
                    board[board_index] = pair[0];
                    board_index += 1;
                    board[board_index] = pair[1];
                    board_index += 1;
                }
                pair = [-1, -1];
                double_mode = false;
                count = 1;
            } else {
                for _ in 0..count {
                    if board_index >= board.len() {
                        break;
                    }
                    board[board_index] = code as i16;
                    board_index += 1;
                }
                count = 1;
            }
        }

        let mut links = Vec::new();
        while pos < data.len() {
            let Some(line) = read_line_bytes(&data, &mut pos) else {
                break;
            };
            if line.is_empty() || line == b"#" {
                break;
            }
            let line_text = String::from_utf8_lossy(&line);
            let fields: Vec<&str> = line_text.split_whitespace().collect();
            if fields.len() < 8 {
                continue;
            }
            let mut link = LevelLink::default();
            link.x = fields[0].parse().unwrap_or(0.0);
            link.y = fields[1].parse().unwrap_or(0.0);
            link.dest_x = fields[3].parse().unwrap_or(0.0);
            link.dest_y = fields[4].parse().unwrap_or(0.0);
            link.width = fields[5].parse().unwrap_or(0.0);
            link.height = fields[6].parse().unwrap_or(0.0);
            link.dest_level = fields[7..].join(" ");
            links.push(link);
        }

        let mut baddies = Vec::new();
        while pos + 3 <= data.len() {
            let x = data[pos];
            let y = data[pos + 1];
            let baddy_type = data[pos + 2];
            pos += 3;
            if x == 0xff && y == 0xff && baddy_type == 0xff {
                if pos < data.len() && data[pos] == b'\n' {
                    pos += 1;
                }
                break;
            }
            let verses = if bits == 13 {
                let line = read_line_bytes(&data, &mut pos).unwrap_or_default();
                let mut values = line
                    .split(|value| *value == b'\\')
                    .map(|value| String::from_utf8_lossy(value).into_owned())
                    .collect::<Vec<_>>();
                values.truncate(3);
                values
            } else {
                Vec::new()
            };
            baddies.push((x as i8 as f32, y as i8 as f32, baddy_type, verses));
        }

        let mut signs = Vec::new();
        while pos < data.len() {
            let Some(line) = read_line_bytes(&data, &mut pos) else {
                break;
            };
            if line.is_empty() {
                break;
            }
            if line.len() >= 2 {
                signs.push(LevelSign::new(
                    i32::from(line[0] as i8),
                    i32::from(line[1] as i8),
                    &String::from_utf8_lossy(&line[2..]),
                    true,
                ));
            }
        }

        let mut state = self.state.write().unwrap();
        state.file_name = file_name.clone();
        state.level_name = level_name.to_string();
        state.tiles.insert(
            0,
            LevelTiles {
                width: 64,
                height: 64,
                tiles: board,
            },
        );
        state.links = links;
        state.signs = signs;
        state.baddies.clear();
        if let Some(server_arc) = server.self_weak.upgrade() {
            for (x, y, baddy_type, verses) in baddies {
                let mut baddy = LevelBaddy::new(x, y, baddy_type, level_arc.clone(), &server_arc);
                baddy.id = state.baddies.len() as u8;
                for (index, verse) in verses.into_iter().enumerate() {
                    baddy.verses[index] = verse;
                }
                state.baddies.insert(baddy.id, Arc::new(baddy));
            }
        }
        true
    }
    pub fn reload(&self, server: &Arc<Server>) -> bool {
        let name = {
            let state = self.state.read().unwrap();
            if state.file_name.is_empty() {
                state.level_name.clone()
            } else {
                state.file_name.clone()
            }
        };
        let npc_ids = self
            .state
            .read()
            .unwrap()
            .npcs
            .keys()
            .copied()
            .collect::<Vec<_>>();
        for id in npc_ids {
            server.delete_npc(id);
        }
        let players = self.state.read().unwrap().players.clone();
        {
            let mut state = self.state.write().unwrap();
            state.file_version.clear();
            state.actual_level_name.clear();
            state.mod_time = UNIX_EPOCH;
            state.is_sparring_zone = false;
            state.is_singleplayer = false;
            state.map_x = 0;
            state.map_y = 0;
            state.map_ref = None;
            state.tiles.clear();
            state.baddies.clear();
            state.board_changes.clear();
            state.chests.clear();
            state.horses.clear();
            state.items.clear();
            state.links.clear();
            state.signs.clear();
            state.npcs.clear();
            state.players = players;
        }
        self.load_level(server, &name)
    }
    pub fn Reload(&self, server: &Arc<Server>) -> bool {
        self.reload(server)
    }
}

fn base64_pos(value: u8) -> u16 {
    match value {
        b'a'..=b'z' => u16::from(value - b'a' + 26),
        b'A'..=b'Z' => u16::from(value - b'A'),
        b'0'..=b'9' => u16::from(value - b'0' + 52),
        b'+' => 62,
        b'/' => 63,
        _ => 0,
    }
}

fn read_line_bytes(data: &[u8], position: &mut usize) -> Option<Vec<u8>> {
    if *position >= data.len() {
        return None;
    }
    let start = *position;
    while *position < data.len() && data[*position] != b'\n' {
        *position += 1;
    }
    let line = data[start..*position].to_vec();
    if *position < data.len() {
        *position += 1;
    }
    Some(line)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum MapType {
    BigMap = 0,
    Gmap = 1,
}
pub const MapTypeBigMap: MapType = MapType::BigMap;
pub const MapTypeGmap: MapType = MapType::Gmap;
pub const MAP_TYPE_BIG_MAP: MapType = MapType::BigMap;
pub const MAP_TYPE_GMAP: MapType = MapType::Gmap;

#[derive(Clone, Debug, Default)]
pub struct MapLevel {
    pub map_x: i32,
    pub map_y: i32,
}
struct MapState {
    map_type: MapType,
    mod_time: SystemTime,
    width: i32,
    height: i32,
    group_map: bool,
    load_full_map: bool,
    map_name: String,
    map_image: String,
    mini_map_image: String,
    levels: HashMap<String, MapLevel>,
    level_list: Vec<String>,
    preload_level_list: Vec<String>,
}
pub struct Map {
    state: RwLock<MapState>,
    server: RwLock<Option<Weak<Server>>>,
}

impl Map {
    pub fn new(map_type: MapType, group_map: bool) -> Self {
        Self {
            state: RwLock::new(MapState {
                map_type,
                mod_time: UNIX_EPOCH,
                width: 0,
                height: 0,
                group_map,
                load_full_map: false,
                map_name: String::new(),
                map_image: String::new(),
                mini_map_image: String::new(),
                levels: HashMap::new(),
                level_list: Vec::new(),
                preload_level_list: Vec::new(),
            }),
            server: RwLock::new(None),
        }
    }
    pub fn NewMap(map_type: MapType, group_map: bool) -> Self {
        Self::new(map_type, group_map)
    }
    pub fn set_server(&self, server: &Arc<Server>) {
        *self.server.write().unwrap() = Some(Arc::downgrade(server));
    }
    pub fn is_level_on_map(&self, level: &str) -> Option<(i32, i32)> {
        self.state
            .read()
            .unwrap()
            .levels
            .get(&level.to_ascii_lowercase())
            .map(|v| (v.map_x, v.map_y))
    }
    pub fn IsLevelOnMap(&self, level: &str) -> (bool, i32, i32) {
        self.is_level_on_map(level)
            .map(|(x, y)| (true, x, y))
            .unwrap_or((false, -1, -1))
    }
    pub fn get_level_at(&self, x: i32, y: i32) -> String {
        let state = self.state.read().unwrap();
        if x < 0 || y < 0 || x >= state.width || y >= state.height {
            return String::new();
        }
        state.level_list[(x + y * state.width) as usize].clone()
    }
    pub fn GetLevelAt(&self, x: i32, y: i32) -> String {
        self.get_level_at(x, y)
    }
    pub fn get_map_name(&self) -> String {
        self.state.read().unwrap().map_name.clone()
    }
    pub fn GetMapName(&self) -> String {
        self.get_map_name()
    }
    pub fn get_type(&self) -> MapType {
        self.state.read().unwrap().map_type
    }
    pub fn GetType(&self) -> MapType {
        self.get_type()
    }
    pub fn get_width(&self) -> i32 {
        self.state.read().unwrap().width
    }
    pub fn GetWidth(&self) -> i32 {
        self.get_width()
    }
    pub fn get_height(&self) -> i32 {
        self.state.read().unwrap().height
    }
    pub fn GetHeight(&self) -> i32 {
        self.get_height()
    }
    pub fn is_big_map(&self) -> bool {
        self.get_type() == MapType::BigMap
    }
    pub fn IsBigMap(&self) -> bool {
        self.is_big_map()
    }
    pub fn is_gmap(&self) -> bool {
        self.get_type() == MapType::Gmap
    }
    pub fn IsGmap(&self) -> bool {
        self.is_gmap()
    }
    pub fn is_group_map(&self) -> bool {
        self.state.read().unwrap().group_map
    }
    pub fn IsGroupMap(&self) -> bool {
        self.is_group_map()
    }
    pub fn load(&self, file_name: &str) -> io::Result<()> {
        let server = self
            .server
            .read()
            .unwrap()
            .as_ref()
            .and_then(Weak::upgrade)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "map has no server"))?;
        let data = server.config.load_file(file_name)?;
        let mut state = self.state.write().unwrap();
        state.map_name = file_name.to_string();
        state.mod_time = server.config.file_mod_time(file_name).unwrap_or(UNIX_EPOCH);
        state.levels.clear();
        state.width = 0;
        state.height = 0;
        match state.map_type {
            MapType::BigMap => {
                let mut rows = Vec::new();
                for raw_line in String::from_utf8_lossy(&data).split('\n') {
                    let line = raw_line.trim_end_matches('\r').trim();
                    if line.is_empty() {
                        continue;
                    }
                    let row = unescape_tokens(line)
                        .split('\n')
                        .map(str::to_string)
                        .collect::<Vec<_>>();
                    let empty = row.iter().filter(|value| value.is_empty()).count();
                    state.width = state.width.max((row.len() - empty) as i32);
                    rows.push(row);
                }
                state.height = rows.len() as i32;
                let width = state.width.max(0) as usize;
                state.level_list = vec![String::new(); width * state.height.max(0) as usize];
                for (y, row) in rows.iter().enumerate() {
                    for (x, value) in row.iter().take(width).enumerate() {
                        let value = value.to_ascii_lowercase();
                        state.level_list[x + y * width] = value.clone();
                        if !value.is_empty() {
                            state.levels.insert(
                                value,
                                MapLevel {
                                    map_x: x as i32,
                                    map_y: y as i32,
                                },
                            );
                        }
                    }
                }
            }
            MapType::Gmap => {
                let lines = String::from_utf8_lossy(&data)
                    .split('\n')
                    .map(|line| line.trim_end_matches('\r').to_string())
                    .collect::<Vec<_>>();
                let mut index = 0usize;
                while index < lines.len() {
                    let line = lines[index].trim();
                    let parts: Vec<_> = line.split_whitespace().collect();
                    if parts.is_empty() {
                        index += 1;
                        continue;
                    }
                    match parts[0] {
                        "WIDTH" if parts.len() == 2 => state.width = parts[1].parse().unwrap_or(0),
                        "HEIGHT" if parts.len() == 2 => {
                            state.height = parts[1].parse().unwrap_or(0)
                        }
                        "LEVELNAMES" => {
                            index += 1;
                            let mut map_y = 0i32;
                            state.level_list = vec![
                                String::new();
                                (state.width.max(0) * state.height.max(0))
                                    as usize
                            ];
                            while index < lines.len() {
                                let row = lines[index].trim();
                                if row == "LEVELNAMESEND" {
                                    break;
                                }
                                if !row.is_empty() && map_y < state.height {
                                    for (map_x, level_name) in
                                        unescape_tokens(row).split('\n').enumerate()
                                    {
                                        if (map_x as i32) < state.width && level_name != "\r" {
                                            let level_name = level_name.to_ascii_lowercase();
                                            let map_width = state.width as usize;
                                            state.level_list[map_x + map_y as usize * map_width] =
                                                level_name.clone();
                                            state.levels.insert(
                                                level_name,
                                                MapLevel {
                                                    map_x: map_x as i32,
                                                    map_y,
                                                },
                                            );
                                        }
                                    }
                                    map_y += 1;
                                }
                                index += 1;
                            }
                        }
                        "MAPIMG" if parts.len() == 2 => state.map_image = parts[1].to_string(),
                        "MINIMAPIMG" if parts.len() == 2 => {
                            state.mini_map_image = parts[1].to_string()
                        }
                        "LOADFULLMAP" => state.load_full_map = true,
                        "LOADATSTART" => {
                            state.load_full_map = false;
                            index += 1;
                            while index < lines.len() {
                                if lines[index].trim() == "LOADATSTARTEND" {
                                    break;
                                }
                                for level_name in unescape_tokens(&lines[index]).split('\n') {
                                    state
                                        .preload_level_list
                                        .push(level_name.to_ascii_lowercase());
                                }
                                index += 1;
                            }
                        }
                        _ => {}
                    }
                    index += 1;
                }
            }
        }
        Ok(())
    }
    pub fn Load(&self, file_name: &str) -> io::Result<()> {
        self.load(file_name)
    }
    pub fn load_map_levels(&self) {
        let server = self.server.read().unwrap().as_ref().and_then(Weak::upgrade);
        let Some(server) = server else { return };
        let state = self.state.read().unwrap();
        let names = if state.load_full_map {
            state.level_list.clone()
        } else {
            state.preload_level_list.clone()
        };
        drop(state);
        for name in &names {
            if !name.is_empty() {
                let _ = server.get_level(name);
            }
        }
    }
    pub fn LoadMapLevels(&self) {
        self.load_map_levels()
    }
}

pub fn unescape_tokens(value: &str) -> String {
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('s') => out.push(' '),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}
pub fn guntokenize(value: &str) -> String {
    unescape_tokens(value)
}

fn parse_po_translations(data: &str) -> HashMap<String, String> {
    let lines = data.replace('\r', "");
    let lines = lines.split('\n').collect::<Vec<_>>();
    let mut translations = HashMap::new();
    let mut index = 0usize;
    while index < lines.len() {
        let line = lines[index].trim();
        if !line.starts_with("msgid ") {
            index += 1;
            continue;
        }
        let mut key = parse_po_string(&line[6..]);
        index += 1;
        while index < lines.len() && lines[index].trim_start().starts_with('"') {
            key.push('\n');
            key.push_str(&parse_po_string(lines[index].trim()));
            index += 1;
        }
        if index >= lines.len() || !lines[index].trim().starts_with("msgstr ") {
            continue;
        }
        let mut value = parse_po_string(lines[index].trim()[7..].trim());
        index += 1;
        while index < lines.len() && lines[index].trim_start().starts_with('"') {
            value.push('\n');
            value.push_str(&parse_po_string(lines[index].trim()));
            index += 1;
        }
        translations.insert(key, value);
    }
    translations
}

fn parse_po_string(value: &str) -> String {
    let value = value.trim();
    serde_json::from_str::<String>(value).unwrap_or_else(|_| value.trim_matches('"').to_string())
}

// Text packets use the same comma/quote tokenizer as the reference server.
// This is intentionally separate from the settings/token parser above: the
// text protocol preserves quotes and treats a doubled quote as data.
fn gtokenize_text(value: &str) -> String {
    let mut text = value.replace("\r\n", "\n").replace('\r', "\n");
    if text.is_empty() {
        return String::new();
    }
    if !text.ends_with('\n') {
        text.push('\n');
    }
    let mut fields = Vec::new();
    for line in text[..text.len() - 1].split('\n') {
        let complex = line.trim().is_empty()
            || line
                .bytes()
                .any(|byte| !(33..=126).contains(&byte) || byte == b',' || byte == b'/');
        if complex {
            let escaped = line.replace('\\', "\\\\").replace('"', "\"\"");
            fields.push(format!("\"{escaped}\""));
        } else {
            fields.push(line.to_string());
        }
    }
    fields.join(",")
}

fn guntokenize_text(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut in_quote = false;
    let mut index = 0usize;
    if bytes.first() == Some(&b'"') {
        in_quote = true;
        index = 1;
    }
    while index < bytes.len() {
        match bytes[index] {
            b',' => {
                if in_quote {
                    out.push(b',');
                } else {
                    out.push(b'\n');
                    while index + 1 < bytes.len() && bytes[index + 1] == b' ' {
                        index += 1;
                    }
                    if index + 1 < bytes.len() && bytes[index + 1] == b'"' {
                        in_quote = true;
                        index += 1;
                    }
                }
            }
            b'"' => {
                if in_quote {
                    if index + 1 < bytes.len() && bytes[index + 1] == b'"' {
                        out.push(b'"');
                        index += 1;
                    } else if index + 1 < bytes.len() && bytes[index + 1] == b',' {
                        in_quote = false;
                    }
                } else {
                    out.push(b'"');
                }
            }
            b'\\' if index + 1 < bytes.len() && bytes[index + 1] == b'\\' => {
                out.push(b'\\');
                index += 1;
            }
            byte => out.push(byte),
        }
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_text_request(
    packet: &[u8],
    require_option: bool,
) -> Option<(String, String, String, String, Vec<String>)> {
    if packet.len() <= 1 {
        return None;
    }
    let raw = String::from_utf8_lossy(&packet[1..]).into_owned();
    let mut data = raw.clone();
    let comma_style = if data.contains('\u{1}') {
        data = data.replace('\u{1}', "\n");
        data = data.trim_end_matches('\n').to_string();
        false
    } else if data.contains(',') {
        data = guntokenize_text(&data);
        true
    } else {
        false
    };
    let parts = data.splitn(4, '\n').map(str::to_string).collect::<Vec<_>>();
    if parts.len() < 2 || (require_option && parts.len() < 3) {
        return None;
    }
    let mut weapon = IRC_BYTES.to_string();
    let mut type_name = parts[0].clone();
    let mut option = parts[1].clone();
    if parts.len() >= 3
        && (comma_style || !parts[2].is_empty() || (!parts[0].is_empty() && !parts[1].is_empty()))
    {
        weapon = parts[0].clone();
        type_name = parts[1].clone();
        option = parts[2].clone();
    }
    let extra = parts
        .get(3)
        .map(|value| value.split('\n').map(str::to_string).collect())
        .unwrap_or_default();
    // Keep the original text byte-for-byte for list-server forwarding while
    // exposing decoded fields for local fallback responses.
    Some((raw, weapon, type_name, option, extra))
}

// ---------------------------------------------------------------------------
// NPCs, scripts, and list-server records

#[derive(Clone)]
struct NPCState {
    id: u32,
    npc_type: NPCType,
    x: i16,
    y: i16,
    z: i16,
    width: i32,
    height: i32,
    image: String,
    script: String,
    npc_name: String,
    scripter: String,
    script_type: String,
    timeout: i32,
    sprite: u8,
    vis_flags: u8,
    block_flags: u8,
    hurt_x: f32,
    hurt_y: f32,
    saves: [u8; 10],
    flag_list: HashMap<String, String>,
    character: Character,
    weapon_name: String,
    script_data: String,
    vm_this: HashMap<String, serde_json::Value>,
    vm_revision: i64,
    level: Option<Arc<Level>>,
}

pub struct NPC {
    state: Mutex<NPCState>,
}

impl NPC {
    pub fn new(npc_type: NPCType) -> Self {
        Self {
            state: Mutex::new(NPCState {
                id: 0,
                npc_type,
                x: 30 * 16,
                y: 30 * 16,
                z: 0,
                width: 0,
                height: 0,
                image: String::new(),
                script: String::new(),
                npc_name: String::new(),
                scripter: String::new(),
                script_type: String::new(),
                timeout: 0,
                sprite: 0,
                vis_flags: NPCVISFLAG_VISIBLE,
                block_flags: 0,
                hurt_x: 0.0,
                hurt_y: 0.0,
                saves: [0; 10],
                flag_list: HashMap::new(),
                character: Character::default(),
                weapon_name: String::new(),
                script_data: String::new(),
                vm_this: HashMap::new(),
                vm_revision: 0,
                level: None,
            }),
        }
    }
    pub fn NewNPC(npc_type: NPCType) -> Self {
        Self::new(npc_type)
    }
    pub fn id(&self) -> u32 {
        self.state.lock().unwrap().id
    }
    pub fn get_id(&self) -> u32 {
        self.id()
    }
    pub fn getId(&self) -> u32 {
        self.id()
    }
    pub fn set_id(&self, id: u32) {
        self.state.lock().unwrap().id = id;
    }
    pub fn setId(&self, id: u32) {
        self.set_id(id)
    }
    pub fn npc_type(&self) -> NPCType {
        self.state.lock().unwrap().npc_type
    }
    pub fn set_level(&self, level: Option<Arc<Level>>) {
        self.state.lock().unwrap().level = level;
    }
    pub fn level(&self) -> Option<Arc<Level>> {
        self.state.lock().unwrap().level.clone()
    }
    pub fn npc_name(&self) -> String {
        self.state.lock().unwrap().npc_name.clone()
    }
    pub fn scripter(&self) -> String {
        self.state.lock().unwrap().scripter.clone()
    }
    pub fn script_type(&self) -> String {
        self.state.lock().unwrap().script_type.clone()
    }
    pub fn level_name(&self) -> String {
        self.state
            .lock()
            .unwrap()
            .level
            .as_ref()
            .map(|level| level.get_name())
            .unwrap_or_default()
    }
    pub fn set_scripter(&self, value: &str) {
        self.state.lock().unwrap().scripter = value.to_string();
    }
    pub fn set_script_type(&self, value: &str) {
        self.state.lock().unwrap().script_type = value.to_string();
    }
    pub fn flags(&self) -> HashMap<String, String> {
        self.state.lock().unwrap().flag_list.clone()
    }
    pub fn set_flags(&self, flags: HashMap<String, String>) {
        self.state.lock().unwrap().flag_list = flags;
    }
    pub fn reset_script(&self) {
        let mut state = self.state.lock().unwrap();
        state.script.clear();
        state.vm_this.clear();
        state.vm_revision = state.vm_revision.wrapping_add(1);
    }
    fn replace_script(&self, script: &str) {
        let mut state = self.state.lock().unwrap();
        state.script = script.to_string();
        state.vm_this.clear();
        state.vm_revision = state.vm_revision.wrapping_add(1);
    }
    pub fn set_flag(&self, name: &str, value: &str) {
        self.state
            .lock()
            .unwrap()
            .flag_list
            .insert(name.to_string(), value.to_string());
    }
    pub fn get_flag(&self, name: &str) -> String {
        self.state
            .lock()
            .unwrap()
            .flag_list
            .get(name)
            .cloned()
            .unwrap_or_default()
    }
    pub fn variable_dump(&self) -> String {
        let state = self.state.lock().unwrap();
        let name = if state.npc_name.is_empty() {
            format!("npcs[{}]", state.id)
        } else {
            state.npc_name.clone()
        };
        let mut out = String::new();
        let _ = writeln!(out, "Variables dump from npc {name}\n");
        if !state.script_type.is_empty() {
            let _ = writeln!(out, "{name}.type: {}", state.script_type);
        }
        if !state.scripter.is_empty() {
            let _ = writeln!(out, "{name}.scripter: {}", state.scripter);
        }
        if let Some(level) = &state.level {
            if !level.get_name().is_empty() {
                let _ = writeln!(out, "{name}.level: {}", level.get_name());
            }
        }
        out.push_str("\nAttributes:\n");
        let _ = writeln!(out, "{name}.id: {}", state.id);
        if !state.image.is_empty() {
            let _ = writeln!(out, "{name}.image: {}", state.image);
        }
        if !state.script.is_empty() {
            let _ = writeln!(out, "{name}.script: size: {}", state.script.len());
        }
        if !state.character.head_image.is_empty() {
            let _ = writeln!(out, "{name}.head: {}", state.character.head_image);
        }
        if !state.character.body_image.is_empty() {
            let _ = writeln!(out, "{name}.body: {}", state.character.body_image);
        }
        if !state.npc_name.is_empty() {
            let _ = writeln!(out, "{name}.name: {}", state.npc_name);
        }
        if !state.script_type.is_empty() {
            let _ = writeln!(out, "{name}.type: {}", state.script_type);
        }
        if let Some(level) = &state.level {
            if !level.get_name().is_empty() {
                let _ = writeln!(out, "{name}.level: {}", level.get_name());
            }
        }
        for (index, value) in state.saves.iter().enumerate() {
            if *value > 0 {
                let _ = writeln!(out, "{name}.save[{index}]: {value}");
            }
        }
        if state.timeout > 0 {
            let _ = writeln!(out, "{name}.timeout: {:.2}", state.timeout as f32 * 0.05);
        }
        if !state.flag_list.is_empty() {
            out.push_str("\nnpc.Flags:\n");
            let mut keys: Vec<_> = state.flag_list.keys().collect();
            keys.sort();
            for key in keys {
                let _ = writeln!(out, "{name}.flags[\"{key}\"]: {}", state.flag_list[key]);
            }
        }
        out
    }
    pub fn variableDump(&self) -> String {
        self.variable_dump()
    }
    pub fn snapshot(&self) -> NPCSnapshot {
        let state = self.state.lock().unwrap();
        NPCSnapshot {
            id: state.id,
            npc_type: state.npc_type,
            x: state.x,
            y: state.y,
            z: state.z,
            image: state.image.clone(),
            script: state.script.clone(),
            npc_name: state.npc_name.clone(),
            script_type: state.script_type.clone(),
            vis_flags: state.vis_flags,
            block_flags: state.block_flags,
            sprite: state.character.sprite,
            character: state.character.clone(),
            level: state.level.clone(),
        }
    }
    pub fn set_position(&self, x: i16, y: i16, z: i16) {
        let mut state = self.state.lock().unwrap();
        state.x = x;
        state.y = y;
        state.z = z;
    }
    pub fn set_image(&self, image: &str) {
        self.state.lock().unwrap().image = image.to_string();
    }
    pub fn set_script(&self, script: &str) {
        self.state.lock().unwrap().script = script.to_string();
    }
    pub fn set_name(&self, name: &str) {
        self.state.lock().unwrap().npc_name = name.to_string();
    }
    pub fn weapon_name(&self) -> String {
        self.state.lock().unwrap().weapon_name.clone()
    }
    pub fn set_weapon_name(&self, name: &str) {
        self.state.lock().unwrap().weapon_name = name.to_string();
    }
    fn has_script(&self) -> bool {
        !self.state.lock().unwrap().script.trim().is_empty()
    }
    fn matches_trigger_point(&self, x: i32, y: i32) -> bool {
        let state = self.state.lock().unwrap();
        if state.vis_flags & NPCVISFLAG_VISIBLE == 0 {
            return false;
        }
        let width = if state.width <= 0 { 32 } else { state.width };
        let height = if state.height <= 0 { 32 } else { state.height };
        x >= i32::from(state.x)
            && y >= i32::from(state.y)
            && x <= i32::from(state.x) + width
            && y <= i32::from(state.y) + height
    }
    fn matches_trigger_area(&self, x: i32, y: i32, width: i32, height: i32) -> bool {
        let state = self.state.lock().unwrap();
        if state.vis_flags & NPCVISFLAG_VISIBLE == 0 {
            return false;
        }
        let npc_width = if state.width <= 0 { 32 } else { state.width };
        let npc_height = if state.height <= 0 { 32 } else { state.height };
        x < i32::from(state.x) + npc_width
            && x + width > i32::from(state.x)
            && y < i32::from(state.y) + npc_height
            && y + height > i32::from(state.y)
    }
    pub fn set_timeout(&self, value: i32) {
        self.state.lock().unwrap().timeout = value;
    }
    pub fn timeout(&self) -> i32 {
        self.state.lock().unwrap().timeout
    }
    fn run_timeout(self: &Arc<Self>, server: &Server) {
        server.run_server_side_npc_event_for_player(self, "onTimeout", None, &[]);
    }
    fn apply_props(&self, props: &[u8]) {
        let mut state = self.state.lock().unwrap();
        let mut buf = Buffer::from_bytes(props);
        while buf.remaining() > 0 {
            let prop = buf.read_gchar();
            match prop {
                NPCPROP_IMAGE => state.image = buf.read_gchar_string(),
                NPCPROP_SCRIPT => {
                    let length = buf.read_gshort() as usize;
                    state.script =
                        String::from_utf8_lossy(&buf.read_bytes(length.min(buf.remaining())))
                            .into_owned();
                }
                NPCPROP_X => state.x = i16::from(buf.read_gchar()) * 8,
                NPCPROP_Y => state.y = i16::from(buf.read_gchar()) * 8,
                NPCPROP_Z => state.z = (i16::from(buf.read_gchar()) - 50) * 16,
                NPCPROP_POWER => state.character.hitpoints = i32::from(buf.read_gchar()),
                NPCPROP_RUPEES => state.character.gralats = buf.read_gint() as i32,
                NPCPROP_ARROWS => state.character.arrows = i32::from(buf.read_gchar()),
                NPCPROP_BOMBS => state.character.bombs = i32::from(buf.read_gchar()),
                NPCPROP_GLOVEPOWER => state.character.glove_power = i32::from(buf.read_gchar()),
                NPCPROP_SPRITE => {
                    let sprite = buf.read_gchar();
                    state.sprite = sprite;
                    state.character.sprite = sprite;
                }
                NPCPROP_VISFLAGS => state.vis_flags = buf.read_gchar(),
                NPCPROP_BLOCKFLAGS => state.block_flags = buf.read_gchar(),
                NPCPROP_MESSAGE => state.character.chat_message = buf.read_gchar_string(),
                NPCPROP_NICKNAME => state.character.nickname = buf.read_gchar_string(),
                NPCPROP_HORSEIMAGE => state.character.horse_image = buf.read_gchar_string(),
                NPCPROP_HEADIMAGE => {
                    let length = buf.read_gchar();
                    if length < 100 {
                        state.character.head_image = format!("head{length}.png");
                    } else {
                        state.character.head_image = String::from_utf8_lossy(
                            &buf.read_bytes(usize::from(length - 100).min(buf.remaining())),
                        )
                        .into_owned();
                    }
                }
                NPCPROP_BODYIMAGE => state.character.body_image = buf.read_gchar_string(),
                NPCPROP_ID => state.id = buf.read_gint(),
                NPCPROP_ALIGNMENT => state.character.ap = i32::from(buf.read_gchar()),
                NPCPROP_NAME => state.npc_name = buf.read_gchar_string(),
                NPCPROP_TYPE => {
                    state.npc_type = match buf.read_gchar() {
                        0 => NPCType::LEVELNPC,
                        1 => NPCType::PUTNPC,
                        2 => NPCType::PUTNPC,
                        _ => state.npc_type,
                    }
                }
                NPCPROP_X2 => state.x = decode_signed_gshort_coord(buf.read_gshort()),
                NPCPROP_Y2 => state.y = decode_signed_gshort_coord(buf.read_gshort()),
                NPCPROP_Z2 => state.z = decode_signed_gshort_coord(buf.read_gshort()),
                NPCPROP_GATTRIB1..=NPCPROP_GATTRIB5 => {
                    let index = usize::from(prop - NPCPROP_GATTRIB1);
                    state.character.gani_attributes[index] = buf.read_gchar_string();
                }
                NPCPROP_GATTRIB6..=NPCPROP_GATTRIB9 => {
                    let index = usize::from(prop - NPCPROP_GATTRIB6 + 5);
                    state.character.gani_attributes[index] = buf.read_gchar_string();
                }
                NPCPROP_GATTRIB10..=NPCPROP_GATTRIB30 => {
                    let index = usize::from(prop - NPCPROP_GATTRIB10 + 9);
                    state.character.gani_attributes[index] = buf.read_gchar_string();
                }
                _ => return,
            }
        }
    }
}

#[derive(Clone)]
pub struct NPCSnapshot {
    pub id: u32,
    pub npc_type: NPCType,
    pub x: i16,
    pub y: i16,
    pub z: i16,
    pub image: String,
    pub script: String,
    pub npc_name: String,
    pub script_type: String,
    pub vis_flags: u8,
    pub block_flags: u8,
    pub sprite: u8,
    pub character: Character,
    pub level: Option<Arc<Level>>,
}

#[derive(Clone, Debug)]
pub struct Weapon {
    pub name: String,
    pub image: String,
    pub script: String,
    pub bytecode: Vec<u8>,
    pub bytecode_file: String,
    pub vm_this: HashMap<String, serde_json::Value>,
    pub vm_revision: i64,
    pub def_player: bool,
    pub modified: bool,
}
impl Weapon {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            image: String::new(),
            script: String::new(),
            bytecode: Vec::new(),
            bytecode_file: String::new(),
            vm_this: HashMap::new(),
            vm_revision: 0,
            def_player: false,
            modified: false,
        }
    }
    pub fn NewWeapon(name: &str) -> Self {
        Self::new(name)
    }
}

#[derive(Clone, Debug)]
pub struct ScriptClass {
    pub name: String,
    pub script: String,
}
impl ScriptClass {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            script: String::new(),
        }
    }
    pub fn NewScriptClass(name: &str) -> Self {
        Self::new(name)
    }
}

#[derive(Clone, Debug)]
pub struct CachedListserverServer {
    pub name: String,
    pub server_type: String,
    pub player_count: i32,
    pub language: String,
    pub description: String,
    pub url: String,
    pub version: String,
    pub game_versions: String,
    pub latency: i32,
    pub updated: SystemTime,
}

/// Compatibility representation for the exported `CachedLevel` type. Its
/// fields are intentionally unexported.
#[derive(Clone)]
pub struct CachedLevel {
    level: Option<Arc<Level>>,
    mod_time: SystemTime,
}

impl Default for CachedListserverServer {
    fn default() -> Self {
        Self {
            name: String::new(),
            server_type: String::new(),
            player_count: 0,
            language: String::new(),
            description: String::new(),
            url: String::new(),
            version: String::new(),
            game_versions: String::new(),
            latency: 0,
            updated: UNIX_EPOCH,
        }
    }
}

pub struct ServerList {
    pub server: Weak<Server>,
    pub host: String,
    pub port: String,
    pub connected: AtomicBool,
    pub enabled: AtomicBool,
    pub description: Mutex<String>,
    pub codec: Mutex<u32>,
    pub send_queue: Mutex<Vec<Vec<u8>>>,
    pub read_buffer: Mutex<Vec<u8>>,
    pub last_receive: Mutex<SystemTime>,
    pub last_timer: Mutex<SystemTime>,
    pub last_connect: Mutex<SystemTime>,
    pub last_disconnect: Mutex<SystemTime>,
    pub next_connection_attempt: Mutex<SystemTime>,
    pub connection_attempts: AtomicU32,
    pub last_keepalive: Mutex<SystemTime>,
    pub last_idle_log: Mutex<SystemTime>,
}

// A list-server connection is kept out-of-line so the original public
// ServerList field layout remains usable by embedders that construct a
// descriptor before connecting it.
static SERVER_LIST_CONNECTIONS: OnceLock<Mutex<HashMap<usize, TcpStream>>> = OnceLock::new();

fn server_list_key(list: &ServerList) -> usize {
    list as *const ServerList as usize
}

fn server_list_connections() -> &'static Mutex<HashMap<usize, TcpStream>> {
    SERVER_LIST_CONNECTIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

impl ServerList {
    fn new_internal(server: &Weak<Server>, host: &str, port: &str) -> Self {
        Self {
            server: server.clone(),
            host: host.to_string(),
            port: port.to_string(),
            connected: AtomicBool::new(false),
            enabled: AtomicBool::new(false),
            description: Mutex::new(String::new()),
            // The zero value for ServerList.codec is GEN_1. The automatic
            // connection path switches to GEN_2 after the registration packet.
            codec: Mutex::new(ENCRYPT_GEN_1),
            send_queue: Mutex::new(Vec::new()),
            read_buffer: Mutex::new(Vec::new()),
            last_receive: Mutex::new(UNIX_EPOCH),
            last_timer: Mutex::new(UNIX_EPOCH),
            last_connect: Mutex::new(UNIX_EPOCH),
            last_disconnect: Mutex::new(UNIX_EPOCH),
            next_connection_attempt: Mutex::new(UNIX_EPOCH),
            connection_attempts: AtomicU32::new(0),
            last_keepalive: Mutex::new(UNIX_EPOCH),
            last_idle_log: Mutex::new(UNIX_EPOCH),
        }
    }
    pub fn new(server: &Arc<Server>, host: &str, port: &str) -> Arc<Self> {
        Arc::new(Self::new_internal(&Arc::downgrade(server), host, port))
    }
    pub fn new_endpoint(server: &Arc<Server>, host: &str, port: &str) -> Arc<Self> {
        Self::new(server, host, port)
    }
    pub fn NewServerList(server: &Arc<Server>) -> Arc<Self> {
        Self::new(server, "", "")
    }
    pub fn NewServerListEndpoint(server: &Arc<Server>, host: &str, port: &str) -> Arc<Self> {
        Self::new(server, host, port)
    }
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
    pub fn set_connected(&self, value: bool) {
        self.connected.store(value, Ordering::Relaxed);
    }
    pub fn do_timed_events(&self) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        let now = SystemTime::now();
        *self.last_timer.lock().unwrap() = now;
        if self.is_connected() {
            let connected_for = now
                .duration_since(*self.last_connect.lock().unwrap())
                .unwrap_or_default();
            if *self.last_connect.lock().unwrap() != UNIX_EPOCH
                && connected_for >= Duration::from_secs(30)
            {
                self.connection_attempts.store(0, Ordering::Relaxed);
            }
            let keepalive_due = now
                .duration_since(*self.last_keepalive.lock().unwrap())
                .unwrap_or_default()
                >= Duration::from_secs(60);
            if keepalive_due {
                *self.last_keepalive.lock().unwrap() = now;
                let ip = self
                    .server
                    .upgrade()
                    .map(|server| {
                        let value = server.settings.get("serverip");
                        if value.is_empty() {
                            "AUTO".to_string()
                        } else {
                            value
                        }
                    })
                    .unwrap_or_else(|| "AUTO".to_string());
                self.set_ip(&ip);
            }
            let _ = self.flush_send_queue();
            let _ = self.receive_available();
            return;
        }
        if now
            .duration_since(*self.next_connection_attempt.lock().unwrap())
            .is_err()
        {
            return;
        }
        if !self.connect_server() {
            let attempts = self
                .connection_attempts
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1)
                .min(8);
            self.connection_attempts.store(attempts, Ordering::Relaxed);
            let wait = (1u64 << attempts).min(300) + u64::from(rand::random::<u8>() % 5);
            *self.next_connection_attempt.lock().unwrap() = now + Duration::from_secs(wait);
        }
    }
    pub fn doTimedEvents(&self) {
        self.do_timed_events()
    }
    pub fn send_packet(&self, packet: &[u8]) {
        if !self.is_connected() {
            return;
        }
        let mut packet = packet.to_vec();
        if !packet.is_empty() && packet.last() != Some(&b'\n') {
            packet.push(b'\n');
        }
        let packet_len = packet.len();
        let encoded = match *self.codec.lock().unwrap() {
            ENCRYPT_GEN_1 => packet,
            ENCRYPT_GEN_2 => {
                let compressed = match zlib_compress(&packet) {
                    Ok(value) => value,
                    Err(_) => return,
                };
                let mut framed = Vec::with_capacity(compressed.len() + 2);
                framed.extend_from_slice(&(compressed.len() as u16).to_be_bytes());
                framed.extend_from_slice(&compressed);
                framed
            }
            _ => packet,
        };
        self.send_queue.lock().unwrap().push(encoded);
        if packet_debug_mode() {
            if let Some(server) = self.server.upgrade() {
                server.logger.packet_debug(&format!(
                    "[LISTSERVER] GEN_{}_{}",
                    *self.codec.lock().unwrap(),
                    if packet_len == 0 { "" } else { " Sending" }
                ));
            }
        }
    }
    pub fn SendPacket(&self, packet: &[u8]) {
        self.send_packet(packet)
    }
    pub fn set_name(&self, value: &str) {
        self.send_text(SVO_SETNAME, value);
    }
    pub fn SetName(&self, value: &str) {
        self.set_name(value)
    }
    pub fn set_desc(&self, value: &str) {
        self.send_text(SVO_SETDESC, value);
    }
    pub fn set_description(&self, value: &str) {
        self.set_desc(value)
    }
    pub fn SetDesc(&self, value: &str) {
        self.set_desc(value)
    }
    pub fn set_lang(&self, value: &str) {
        self.send_text(SVO_SETLANG, value);
    }
    pub fn SetLang(&self, value: &str) {
        self.set_lang(value)
    }
    pub fn set_vers(&self, value: &str) {
        self.send_text(SVO_SETVERS, value);
    }
    pub fn SetVers(&self, value: &str) {
        self.set_vers(value)
    }
    pub fn set_url(&self, value: &str) {
        self.send_text(SVO_SETURL, value);
    }
    pub fn SetUrl(&self, value: &str) {
        self.set_url(value)
    }
    pub fn set_ip(&self, value: &str) {
        self.send_text(SVO_SETIP, value);
    }
    pub fn SetIp(&self, value: &str) {
        self.set_ip(value)
    }
    pub fn set_port(&self, value: &str) {
        self.send_text(SVO_SETPORT, value);
    }
    pub fn SetPort(&self, value: &str) {
        self.set_port(value)
    }
    pub fn set_local_ip(&self, value: &str) {
        self.send_text(SVO_SETLOCALIP, value);
    }
    pub fn set_plyr(&self, value: i32) {
        let mut buf = Buffer::new();
        buf.write_gchar(SVO_SETPLYR).write_gint(value as u32);
        self.send_packet(&buf.data);
    }
    pub fn SetPlyr(&self, value: i32) {
        self.set_plyr(value)
    }

    pub fn verify_account(&self, account: &str) {
        let mut buf = Buffer::new();
        buf.write_gchar(SVO_VERIACC).write_string8_encoded(account);
        self.send_packet(&buf.data);
    }

    pub fn VerifyAccount(&self, account: &str) {
        self.verify_account(account)
    }

    fn connect_server(&self) -> bool {
        if !self.enabled.load(Ordering::Relaxed) || self.is_connected() {
            return self.is_connected();
        }
        let Some(server) = self.server.upgrade() else {
            return false;
        };
        let host = if self.host.is_empty() {
            server.settings.get("listip")
        } else {
            self.host.clone()
        };
        let port = if self.port.is_empty() {
            server.settings.get("listport")
        } else {
            self.port.clone()
        };
        if host.trim().is_empty() || port.trim().is_empty() {
            return false;
        }
        server.logger.write(&format!(
            ":: Initializing listserver socket ({}:{}).",
            host.trim(),
            port.trim()
        ));
        let address = if host.trim().contains(':') && !host.trim().starts_with('[') {
            format!("[{}]:{}", host.trim(), port.trim())
        } else {
            format!("{}:{}", host.trim(), port.trim())
        };
        let Some(socket_address) = address
            .to_socket_addrs()
            .ok()
            .and_then(|mut values| values.next())
        else {
            server.logger.error(&format!(
                "Could not connect listserver socket: invalid address {}",
                address
            ));
            return false;
        };
        let stream = match TcpStream::connect_timeout(&socket_address, Duration::from_secs(5)) {
            Ok(stream) => stream,
            Err(error) => {
                server
                    .logger
                    .error(&format!("Could not connect listserver socket: {error}"));
                return false;
            }
        };
        let _ = stream.set_nonblocking(true);
        let local_ip = stream
            .local_addr()
            .ok()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_default();
        server_list_connections()
            .lock()
            .unwrap()
            .insert(server_list_key(self), stream);
        self.clear_send_queue();
        self.read_buffer.lock().unwrap().clear();
        self.connected.store(true, Ordering::Relaxed);
        *self.last_receive.lock().unwrap() = SystemTime::now();
        *self.last_keepalive.lock().unwrap() = SystemTime::now();
        *self.last_idle_log.lock().unwrap() = UNIX_EPOCH;

        server.logger.write(&format!(
            ":: listserver - Connected ({}:{}).",
            host.trim(),
            port.trim()
        ));
        server.run_server_side_event_for_active_scripts(
            "onServerListerConnect",
            None,
            &[host.trim().to_string(), port.trim().to_string()],
        );

        // Registration is the sole GEN_1 packet. Every packet following it is
        // framed as GEN_2.
        *self.codec.lock().unwrap() = ENCRYPT_GEN_1;
        let mut register = Buffer::new();
        register
            .write_gchar(SVO_REGISTERV3)
            .write_string(APP_VERSION);
        self.send_packet(&register.data);
        *self.codec.lock().unwrap() = ENCRYPT_GEN_2;

        let hq_password = server.admin_settings.get("hq_password");
        let mut password = Buffer::new();
        password
            .write_gchar(SVO_SERVERHQPASS)
            .write_string8(&hq_password);
        self.send_packet(&password.data);

        let name = nonempty(&server.settings.get("name"))
            .unwrap_or_else(|| server.name.read().unwrap().clone());
        let description = nonempty(&server.settings.get("description"))
            .unwrap_or_else(|| server.name.read().unwrap().clone());
        let language =
            nonempty(&server.settings.get("language")).unwrap_or_else(|| "English".to_string());
        let url = server.settings.get("url");
        let ip = nonempty(&server.settings.get("serverip")).unwrap_or_else(|| "AUTO".to_string());
        let server_port =
            nonempty(&server.settings.get("serverport")).unwrap_or_else(|| "14802".to_string());
        let configured_local_ip = server.settings.get("localip");
        let mut local_ip = if configured_local_ip.is_empty() || configured_local_ip == "AUTO" {
            local_ip
        } else {
            configured_local_ip
        };
        if local_ip == "127.0.0.1" || local_ip == "127.0.1.1" {
            server.logger.warning(&format!(
                "Socket returned {} for its local ip! Not sending local ip to serverlist.",
                local_ip
            ));
            local_ip.clear();
        }
        let mut news = Buffer::new();
        news.write_gchar(SVO_NEWSERVER)
            .write_string8_encoded(&name)
            .write_string8_encoded(&description)
            .write_string8_encoded(&language)
            .write_string8_encoded(APP_VERSION)
            .write_string8_encoded(&url)
            .write_string8_encoded(&ip)
            .write_string8_encoded(&server_port)
            .write_string8_encoded(&local_ip);
        self.send_packet(&news.data);

        let hq_level = if server.settings.get_bool("onlystaff", false) {
            0
        } else {
            // Convert the configured integer to a byte before WriteGChar and
            // preserve wrapping for out-of-range values.
            server.admin_settings.get_int("hq_level", 1) as u8
        };
        let mut level = Buffer::new();
        level.write_gchar(SVO_SERVERHQLEVEL).write_gchar(hq_level);
        self.send_packet(&level.data);
        *self.last_connect.lock().unwrap() = SystemTime::now();
        self.send_version_config();
        self.send_players();
        // Flush the initial registration snapshot before returning from the
        // one-second timer callback so it is not delayed until the next tick.
        let _ = self.flush_send_queue();
        true
    }

    fn send_version_config(&self) {
        if !self.is_connected() {
            return;
        }
        let Some(server) = self.server.upgrade() else {
            return;
        };
        let mut buf = Buffer::new();
        buf.write_gchar(SVO_SENDTEXT).write(
            format!(
                "Listserver,settings,allowedversions,{}",
                server.allowed_versions_listserver_text()
            )
            .as_bytes(),
        );
        self.send_packet(&buf.data);
    }

    fn send_players(&self) {
        if !self.is_connected() {
            return;
        }
        let Some(server) = self.server.upgrade() else {
            return;
        };
        server.npc_server.sync_quiet();
        let mut clear = Buffer::new();
        clear.write_gchar(SVO_SETPLYR);
        self.send_packet(&clear.data);
        for player in server.get_all_players() {
            if is_listserver_player(&player) {
                self.send_player_add(&player);
            }
        }
        if server.fake_player_count.lock().unwrap().is_some() {
            self.set_plyr(server.listserver_player_count() as i32);
        }
    }
    pub fn sendPlayers(&self) {
        self.send_players()
    }

    fn send_player_add(&self, player: &Player) {
        let mut buf = Buffer::new();
        buf.write_gchar(SVO_PLYRADD)
            .write_gshort(player.id())
            .write_gchar(player.player_type() as u8);
        for prop_id in [
            PLPROP_ACCOUNTNAME,
            PLPROP_NICKNAME,
            PLPROP_CURLEVEL,
            PLPROP_X,
            PLPROP_Y,
            PLPROP_ALIGNMENT,
            PLPROP_IPADDR,
        ] {
            buf.write_gchar(prop_id).write(&player.get_prop(prop_id));
        }
        self.send_packet(&buf.data);
    }

    pub fn refresh_server_settings(&self) {
        let Some(server) = self.server.upgrade() else {
            return;
        };
        if !self.is_connected() {
            return;
        }
        let name = nonempty(&server.settings.get("name"))
            .unwrap_or_else(|| server.name.read().unwrap().clone());
        let description = nonempty(&server.settings.get("description"))
            .unwrap_or_else(|| server.name.read().unwrap().clone());
        let language =
            nonempty(&server.settings.get("language")).unwrap_or_else(|| "English".to_string());
        let url = server.settings.get("url");
        let ip = nonempty(&server.settings.get("serverip")).unwrap_or_else(|| "AUTO".to_string());
        let port =
            nonempty(&server.settings.get("serverport")).unwrap_or_else(|| "14802".to_string());
        self.set_name(&name);
        self.set_desc(&description);
        self.set_lang(&language);
        self.set_vers(APP_VERSION);
        self.set_url(&url);
        self.set_ip(&ip);
        self.set_port(&port);
        self.send_version_config();
    }

    pub fn refreshServerSettings(&self) {
        self.refresh_server_settings()
    }
    fn send_text(&self, packet_id: u8, value: &str) {
        let mut buf = Buffer::new();
        buf.write_gchar(packet_id).write(value.as_bytes());
        self.send_packet(&buf.data);
    }
    pub fn AddPlayer(&self, player: &Player) {
        if !is_listserver_player(player) {
            return;
        }
        let mut buf = Buffer::new();
        buf.write_gchar(SVO_PLYRADD)
            .write_gshort(player.id())
            .write_gchar(player.player_type() as u8);
        for prop_id in [
            PLPROP_ACCOUNTNAME,
            PLPROP_NICKNAME,
            PLPROP_CURLEVEL,
            PLPROP_X,
            PLPROP_Y,
            PLPROP_ALIGNMENT,
            PLPROP_IPADDR,
        ] {
            buf.write_gchar(prop_id).write(&player.get_prop(prop_id));
        }
        self.send_packet(&buf.data);
    }
    pub fn DeletePlayer(&self, player: &Player) {
        let mut buf = Buffer::new();
        buf.write_gchar(SVO_PLYRREM).write_gshort(player.id());
        self.send_packet(&buf.data);
    }
    pub fn SendLoginPacketForPlayer(&self, player: &Player, password: &str, identity: &str) {
        let mut buf = Buffer::new();
        buf.write_gchar(SVO_VERIACC2)
            .write_string8_encoded(&player.account_name())
            .write_string8_encoded(password)
            .write_gshort(player.id())
            .write_gchar(player.player_type() as u8)
            .write_gshort(identity.len() as u16)
            .write(identity.as_bytes());
        self.send_packet(&buf.data);
    }
    pub fn SendPlayerTextPacket(&self, packet_id: u8, player_id: u16, text: &str) {
        let mut buf = Buffer::new();
        buf.write_gchar(packet_id)
            .write_gshort(player_id)
            .write(text.as_bytes());
        self.send_packet(&buf.data);
    }
    pub fn SendTextPacket(&self, packet_id: u8, text: &str) {
        self.send_text(packet_id, text);
    }

    pub fn clear_send_queue(&self) {
        self.send_queue.lock().unwrap().clear();
    }
    pub fn clearSendQueue(&self) {
        self.clear_send_queue()
    }
    pub fn reset_send_queue(&self) {
        self.clear_send_queue()
    }
    pub fn resetSendQueue(&self) {
        self.reset_send_queue()
    }

    fn flush_send_queue(&self) -> io::Result<()> {
        if !self.is_connected() {
            return Ok(());
        }
        let key = server_list_key(self);
        let mut connection = server_list_connections().lock().unwrap();
        let Some(stream) = connection.get_mut(&key) else {
            return Ok(());
        };
        let mut queue = self.send_queue.lock().unwrap();
        let mut failure = None;
        while let Some(packet) = queue.first_mut() {
            match stream.write(packet) {
                Ok(0) => break,
                Ok(count) if count == packet.len() => {
                    queue.remove(0);
                }
                Ok(count) => {
                    packet.drain(..count);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
        drop(queue);
        drop(connection);
        if let Some(error) = failure {
            self.disconnect();
            return Err(error);
        }
        Ok(())
    }

    fn receive_available(&self) -> io::Result<()> {
        if !self.is_connected() {
            return Ok(());
        }
        let key = server_list_key(self);
        let mut incoming = Vec::new();
        let mut scratch = [0u8; 8192];
        let mut close_connection = false;
        let mut read_error = None;
        {
            let mut connections = server_list_connections().lock().unwrap();
            let Some(stream) = connections.get_mut(&key) else {
                return Ok(());
            };
            loop {
                match stream.read(&mut scratch) {
                    Ok(0) => {
                        close_connection = true;
                        break;
                    }
                    Ok(count) => incoming.extend_from_slice(&scratch[..count]),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => {
                        read_error = Some(error);
                        close_connection = true;
                        break;
                    }
                }
            }
        }
        if !close_connection && incoming.is_empty() {
            let now = SystemTime::now();
            let last_receive = *self.last_receive.lock().unwrap();
            let last_idle_log = *self.last_idle_log.lock().unwrap();
            if now.duration_since(last_receive).unwrap_or_default() >= Duration::from_secs(30)
                && now.duration_since(last_idle_log).unwrap_or_default() >= Duration::from_secs(30)
            {
                if let Some(server) = self.server.upgrade() {
                    server.logger.debug(&format!(
                        "[LISTSERVER] Idle waiting for listserver data for {:?}",
                        now.duration_since(last_receive).unwrap_or_default()
                    ));
                }
                *self.last_idle_log.lock().unwrap() = now;
            }
        }
        if close_connection {
            *self.last_disconnect.lock().unwrap() = SystemTime::now();
            self.disconnect();
            self.apply_short_lived_backoff();
        }
        if let Some(error) = read_error {
            return Err(error);
        }
        if !incoming.is_empty() {
            *self.last_receive.lock().unwrap() = SystemTime::now();
            let mut buffer = self.read_buffer.lock().unwrap();
            buffer.extend_from_slice(&incoming);
            drop(buffer);
            self.process_list_data();
        }
        Ok(())
    }

    pub fn connect(&self, address: &str) -> io::Result<()> {
        if !self.enabled.load(Ordering::Relaxed) {
            return Ok(());
        }
        let stream = TcpStream::connect(address)?;
        stream.set_nonblocking(true)?;
        server_list_connections()
            .lock()
            .unwrap()
            .insert(server_list_key(self), stream);
        self.connected.store(true, Ordering::Relaxed);
        *self.last_receive.lock().unwrap() = SystemTime::now();
        *self.last_idle_log.lock().unwrap() = UNIX_EPOCH;
        *self.last_keepalive.lock().unwrap() = SystemTime::now();
        Ok(())
    }
    pub fn Connect(&self, address: &str) -> io::Result<()> {
        self.connect(address)
    }

    pub fn disconnect(&self) {
        self.connected.store(false, Ordering::Relaxed);
        server_list_connections()
            .lock()
            .unwrap()
            .remove(&server_list_key(self));
    }
    pub fn Disconnect(&self) {
        self.disconnect()
    }

    fn apply_short_lived_backoff(&self) {
        let last_connect = *self.last_connect.lock().unwrap();
        if last_connect == UNIX_EPOCH {
            return;
        }
        let now = SystemTime::now();
        if now.duration_since(last_connect).unwrap_or_default() >= Duration::from_secs(30) {
            return;
        }
        let attempts = self
            .connection_attempts
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1).min(8))
            })
            .unwrap_or(8);
        let attempts = attempts.saturating_add(1).min(8);
        let wait = (1u64 << attempts).min(300) + u64::from(rand::random::<u8>() % 5);
        *self.next_connection_attempt.lock().unwrap() = now + Duration::from_secs(wait);
        if let Some(server) = self.server.upgrade() {
            server.logger.debug(&format!(
                "[LISTSERVER] Short-lived connection detected, backing off {:?} before reconnect",
                Duration::from_secs(wait)
            ));
        }
    }

    pub fn process_list_data(&self) {
        loop {
            let mut buffer = self.read_buffer.lock().unwrap();
            if buffer.is_empty() {
                return;
            }
            if buffer[0] >= 32 {
                let Some(newline) = buffer.iter().position(|value| *value == b'\n') else {
                    return;
                };
                let packet = buffer.drain(..=newline).collect::<Vec<_>>();
                drop(buffer);
                self.process_list_packets(&packet);
                continue;
            }
            if buffer.len() < 2 {
                return;
            }
            let length = (usize::from(buffer[0]) << 8) | usize::from(buffer[1]);
            if buffer.len() < length + 2 {
                return;
            }
            let compressed = buffer[2..length + 2].to_vec();
            let Ok(data) = zlib_decompress(&compressed) else {
                return;
            };
            buffer.drain(..length + 2);
            drop(buffer);
            self.process_list_packets(&data);
        }
    }
    pub fn processListData(&self) {
        self.process_list_data()
    }

    fn process_list_packets(&self, data: &[u8]) {
        let mut remaining = data;
        while let Some(newline) = remaining.iter().position(|value| *value == b'\n') {
            let packet = &remaining[..newline];
            remaining = &remaining[newline + 1..];
            if packet.is_empty() {
                continue;
            }
            let packet_id = if packet[0] >= 32 {
                packet[0] - 32
            } else {
                packet[0]
            };
            self.handle_list_packet(packet_id, &packet[1..]);
        }
    }

    pub fn process_packet(&self, data: &[u8]) {
        let Some((&packet_id, payload)) = data.split_first() else {
            return;
        };
        // This direct-packet helper intentionally handles only the narrow
        // switch; REQUESTTEXT and SENDTEXT use framed input.
        match packet_id {
            SVI_VERIACC => {
                if let Some(server) = self.server.upgrade() {
                    server
                        .logger
                        .debug("Deprecated account verification response");
                }
            }
            SVI_VERIACC2 => self.handle_verify_account2(payload),
            SVI_FILESTART | SVI_FILESTART2 | SVI_FILESTART3 => {
                if let Some(server) = self.server.upgrade() {
                    server.logger.debug("File transfer started");
                }
            }
            SVI_FILEDATA | SVI_FILEDATA2 | SVI_FILEDATA3 => {}
            SVI_FILEEND | SVI_FILEEND2 | SVI_FILEEND3 => {}
            SVI_SERVERINFO => self.handle_server_info(payload),
            SVI_ERRMSG => {
                if let Some(server) = self.server.upgrade() {
                    server.logger.error(&format!(
                        "List server error: {}",
                        String::from_utf8_lossy(payload)
                    ));
                }
            }
            SVI_PING => {
                let mut buf = Buffer::new();
                buf.write_gchar(SVO_PING);
                self.send_packet(&buf.data);
            }
            SVI_ASSIGNPCID => self.handle_assign_pcid(payload),
            _ => {}
        }
    }
    pub fn processPacket(&self, data: &[u8]) {
        self.process_packet(data)
    }

    fn handle_list_packet(&self, packet_id: u8, data: &[u8]) {
        match packet_id {
            SVI_VERIACC => {
                if let Some(server) = self.server.upgrade() {
                    server
                        .logger
                        .debug("Deprecated account verification response");
                }
            }
            SVI_FILESTART | SVI_FILESTART2 | SVI_FILESTART3 => {
                if let Some(server) = self.server.upgrade() {
                    server.logger.debug("File transfer started");
                }
            }
            SVI_FILEDATA | SVI_FILEDATA2 | SVI_FILEDATA3 => {}
            SVI_FILEEND | SVI_FILEEND2 | SVI_FILEEND3 => {}
            SVI_VERIACC2 => self.handle_verify_account2(data),
            SVI_ASSIGNPCID => self.handle_assign_pcid(data),
            SVI_REQUESTTEXT => self.handle_request_text(data),
            SVI_SERVERINFO => self.handle_server_info(data),
            SVI_SENDTEXT => {
                if let Some(server) = self.server.upgrade() {
                    server.cache_listserver_text(data);
                }
            }
            SVI_PING => {
                let mut buf = Buffer::new();
                buf.write_gchar(SVO_PING);
                self.send_packet(&buf.data);
            }
            SVI_ERRMSG => {
                if let Some(server) = self.server.upgrade() {
                    server.logger.error(&format!(
                        "List server error: {}",
                        String::from_utf8_lossy(data)
                    ));
                }
            }
            _ => {}
        }
    }

    fn handle_verify_account2(&self, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        let mut buf = Buffer::from_bytes(data);
        let account_name = buf.read_gchar_string();
        let player_id = buf.read_gshort();
        let player_type = i32::from(buf.read_gchar());
        let message = String::from_utf8_lossy(&buf.read_bytes(buf.remaining())).into_owned();
        let Some(server) = self.server.upgrade() else {
            return;
        };
        if let Some(request) = server.take_api_auth(player_id, player_type) {
            let _ = request.send(ApiAuthResult {
                account: account_name,
                message,
            });
            return;
        }
        let Some(player) = server
            .get_all_players()
            .into_iter()
            .find(|value| value.id() == player_id && value.player_type() & player_type != 0)
        else {
            return;
        };
        if !account_name.is_empty() {
            player.set_account_name(&account_name);
        }
        if !message.is_empty() && message != "SUCCESS" {
            player.account.lock().unwrap().is_load_only = true;
            player.send_plo_discmessage(&message);
            player.disconnect();
            return;
        }
        let awaiting = player.state.lock().unwrap().awaiting_listserver_verify;
        if awaiting {
            player.state.lock().unwrap().awaiting_listserver_verify = false;
            server.add_player_to_listservers(&player);
        }
    }

    fn handle_assign_pcid(&self, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        let mut buf = Buffer::from_bytes(data);
        let player_id = buf.read_gshort();
        let player_type = i32::from(buf.read_gchar());
        let pc_id = buf.read_gchar_string();
        if pc_id.is_empty() {
            return;
        }
        let Some(server) = self.server.upgrade() else {
            return;
        };
        let Some(player) = server
            .get_all_players()
            .into_iter()
            .find(|value| value.id() == player_id && value.player_type() & player_type != 0)
        else {
            return;
        };
        if let Some(value) = login_pc_id(&pc_id) {
            player.account.lock().unwrap().device_id = value;
        }
        let changed = player.account.lock().unwrap().apply_guest_pcid(&pc_id);
        if changed {
            if let Some(player) = server.get_player(player_id) {
                server.refresh_player_list_entry(&player);
            }
        }
    }

    fn handle_request_text(&self, data: &[u8]) {
        if data.len() < 2 {
            return;
        }
        let mut buf = Buffer::from_bytes(data);
        let player_id = buf.read_gshort();
        let mut message = buf.read_bytes(buf.remaining());
        if let Some(server) = self.server.upgrade() {
            if let Some(player) = server.get_player(player_id) {
                message = normalize_listserver_ban_text(&message);
                message = merge_local_ban_details(&player, &message);
                let mut out = Buffer::new();
                out.write_byte(PLO_SERVERTEXT).write(&message);
                player.send(&out);
                server.cache_listserver_text(&message);
            }
        }
    }

    fn handle_server_info(&self, data: &[u8]) {
        if data.len() < 2 {
            return;
        }
        let mut buf = Buffer::from_bytes(data);
        let player_id = buf.read_gshort();
        let packet = buf.read_bytes(buf.remaining());
        if let Some(server) = self.server.upgrade() {
            if let Some(player) = server.get_player(player_id) {
                if player.version_id() > 0 && player.version_id() < 210 {
                    return;
                }
                let mut out = Buffer::new();
                out.write_byte(PLO_SERVERWARP).write(&packet);
                player.send(&out);
            }
        }
    }
}

fn normalize_listserver_ban_text(message: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(message)
        .trim_end_matches('\n')
        .replace('\u{1}', "\n");
    let decoded = guntokenize_text(&text);
    let fields = decoded.split('\n').collect::<Vec<_>>();
    if fields.len() < 3 || fields[0] != IRC_BYTES || fields[1] != "lister" {
        return message.to_vec();
    }
    if fields[2] == "ban" {
        return gtokenize_text(&decoded).into_bytes();
    }
    message.to_vec()
}

fn merge_local_ban_details(player: &Arc<Player>, message: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(message)
        .trim_end_matches('\n')
        .replace('\u{1}', "\n");
    let decoded = guntokenize_text(&text);
    let mut fields = decoded.split('\n').map(str::to_string).collect::<Vec<_>>();
    if fields.len() < 4 || fields[0] != IRC_BYTES || fields[1] != "lister" || fields[2] != "ban" {
        return message.to_vec();
    }
    let account = fields[3].trim().to_string();
    if account.is_empty() {
        return message.to_vec();
    }
    let Some((_, details)) = player.local_ban_details(&account) else {
        return message.to_vec();
    };
    while fields.len() < 5 {
        fields.push(String::new());
    }
    if fields.len() == 5 {
        fields.push(details);
    } else if !fields[5].contains("world=local") {
        if fields[5].trim().is_empty() {
            fields[5] = details;
        } else {
            fields[5].push('\n');
            fields[5].push_str(&details);
        }
    }
    gtokenize_text(&fields.join("\n")).into_bytes()
}

fn is_listserver_player(player: &Player) -> bool {
    player.player_type() & (PLTYPE_ANYPLAYER | PLTYPE_NPCSERVER) != 0
}

fn is_player_list_player(player: &Player) -> bool {
    is_listserver_player(player)
}

fn is_rc_only_packet(packet_id: u8) -> bool {
    (PLI_RC_SERVEROPTIONSGET..=PLI_RC_FILEBROWSER_RENAME).contains(&packet_id)
        && packet_id != PLI_PROFILEGET
        && packet_id != PLI_PROFILESET
        || packet_id == PLI_RC_FOLDERDELETE
}

fn is_nc_only_packet(packet_id: u8) -> bool {
    packet_id == PLI_NC_LISTNPCS
        || (PLI_NC_NPCGET..=PLI_NC_CLASSDELETE).contains(&packet_id)
        || packet_id == PLI_NC_LEVELLISTGET
        || packet_id == PLI_NC_LEVELLISTSET
}

fn first_bracket_tag(message: &str) -> String {
    let Some(start) = message.find('[') else {
        return String::new();
    };
    let Some(relative_end) = message[start + 1..].find(']') else {
        return String::new();
    };
    message[start + 1..start + 1 + relative_end]
        .trim()
        .to_string()
}

fn rc_payload(packet: &[u8], packet_id: u8) -> &[u8] {
    if packet.first().copied() == Some(packet_id) {
        &packet[1..]
    } else {
        packet
    }
}

fn rc_encoded_bytes(buf: &mut Buffer, value: &[u8]) {
    let length = value.len().min(223);
    buf.write_gchar(length as u8).write(&value[..length]);
}

fn rc_read_encoded_bytes(buf: &mut Buffer) -> Vec<u8> {
    let length = usize::from(buf.read_gchar()).min(buf.remaining());
    buf.read_bytes(length)
}

fn rc_read_encoded_string(buf: &mut Buffer) -> String {
    String::from_utf8_lossy(&rc_read_encoded_bytes(buf)).into_owned()
}

fn rc_write_chat(buf: &mut Buffer, message: &str) {
    buf.write_byte(PLO_RC_CHAT).write(message.as_bytes());
}

fn rc_chat_packet(message: &str) -> Vec<u8> {
    let mut buf = Buffer::new();
    rc_write_chat(&mut buf, message);
    buf.data
}

fn rc_control_type(player_type: i32) -> bool {
    player_type & PLTYPE_ANYRC != 0
}

fn rc_sanitize_account(value: &str) -> String {
    let mut value = value.trim().to_string();
    if let Some(index) = value.find(['/', '\\']) {
        value.truncate(index);
    }
    value
}

fn rc_read_account(packet: &[u8], packet_id: u8) -> String {
    let payload = rc_payload(packet, packet_id);
    if payload.is_empty() {
        return String::new();
    }
    let mut encoded = Buffer::from_bytes(payload);
    let length = usize::from(encoded.read_gchar());
    if length <= encoded.remaining() && length > 0 {
        return rc_sanitize_account(&String::from_utf8_lossy(&encoded.read_bytes(length)));
    }
    let mut raw = Buffer::from_bytes(payload);
    let value = raw.read_gstring();
    if !value.is_empty() {
        rc_sanitize_account(&value)
    } else {
        rc_sanitize_account(&String::from_utf8_lossy(payload))
    }
}

fn rc_read_string8_or_encoded_account(packet: &[u8], packet_id: u8) -> String {
    let payload = rc_payload(packet, packet_id);
    if payload.is_empty() {
        return String::new();
    }
    let mut encoded = Buffer::from_bytes(payload);
    let length = usize::from(encoded.read_gchar());
    if length == encoded.remaining() && length > 0 {
        return rc_sanitize_account(&String::from_utf8_lossy(&encoded.read_bytes(length)));
    }
    if usize::from(payload[0]) <= payload.len().saturating_sub(1) {
        let length = usize::from(payload[0]);
        if length > 0 {
            return rc_sanitize_account(&String::from_utf8_lossy(&payload[1..1 + length]));
        }
    }
    let mut raw = Buffer::from_bytes(payload);
    let value = raw.read_gstring();
    if !value.is_empty() {
        rc_sanitize_account(&value)
    } else {
        rc_sanitize_account(&String::from_utf8_lossy(payload))
    }
}

const ADMIN_ONLY_SERVER_OPTIONS: &[&str] = &[
    "name",
    "description",
    "url",
    "serverip",
    "serverport",
    "localip",
    "listip",
    "listport",
    "maxplayers",
    "onlystaff",
    "nofoldersconfig",
    "oldcreated",
    "serverside",
    "triggerhack_weapons",
    "triggerhack_guilds",
    "triggerhack_groups",
    "triggerhack_files",
    "triggerhack_rc",
    "flaghack_movement",
    "flaghack_ip",
    "sharefolder",
    "language",
];

fn preserve_admin_only_server_options(options: &str, settings: &Settings) -> String {
    let normalized = options.replace("\r\n", "\n");
    let had_newline = normalized.ends_with('\n');
    let mut lines = normalized
        .split('\n')
        .map(str::to_string)
        .collect::<Vec<_>>();
    if had_newline && lines.last().map(String::is_empty).unwrap_or(false) {
        lines.pop();
    }
    for line in &mut lines {
        if let Some(index) = line.find('=') {
            let key = line[..index].trim();
            if ADMIN_ONLY_SERVER_OPTIONS
                .iter()
                .any(|item| item.eq_ignore_ascii_case(key))
            {
                *line = format!("{key} = {}", settings.get(key));
            }
        }
    }
    let mut result = lines.join("\n");
    if had_newline || !result.is_empty() {
        result.push('\n');
    }
    result
}

fn rc_account_field(account: &Account, field: &str) -> String {
    match field.trim().to_ascii_lowercase().as_str() {
        "account" | "name" => account.account_name.clone(),
        "nick" | "nickname" => account.character.nickname.clone(),
        "email" => account.email.clone(),
        "adminip" | "iprange" => account.admin_ip.clone(),
        "adminlevel" => ((account.admin_rights as u32).count_ones().min(4)).to_string(),
        "localrights" | "rights" => account.admin_rights.to_string(),
        "blocked" | "banned" => account.is_banned.to_string(),
        "loadonly" => account.is_load_only.to_string(),
        _ => String::new(),
    }
}

#[derive(Clone, Debug, Default)]
struct RcAccountListEntry {
    account: String,
    nick: String,
    email: String,
    admin_ip: String,
    banned: bool,
    load_only: bool,
    rights: i32,
    admin_level: i32,
}

fn load_rc_account_list_entry(
    config: &FileSystem,
    account_file: &str,
) -> Option<RcAccountListEntry> {
    let file_account = Path::new(account_file)
        .file_name()
        .and_then(|value| value.to_str())?
        .strip_suffix(".txt")?
        .to_string();
    let account_path = account_file.replace('\\', "/");
    let account_path = if account_path.to_ascii_lowercase().starts_with("accounts/") {
        account_path
    } else {
        format!("accounts/{account_path}")
    };
    let lines = config.load_file_as_lines(&account_path).ok()?;
    if lines.is_empty() || lines[0].trim() != "GRACC001" {
        return None;
    }
    let mut entry = RcAccountListEntry {
        account: file_account.clone(),
        ..RcAccountListEntry::default()
    };
    for raw in lines.iter().skip(1) {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(' ') else {
            continue;
        };
        match key.to_ascii_uppercase().as_str() {
            "NAME" => entry.account = value.to_string(),
            "NICK" => entry.nick = value.to_string(),
            "EMAIL" => entry.email = value.to_string(),
            "IPRANGE" => entry.admin_ip = value.to_string(),
            "BANNED" => entry.banned = parse_i32(value) != 0,
            "LOADONLY" => entry.load_only = parse_i32(value) != 0,
            "LOCALRIGHTS" => entry.rights = parse_i32(value),
            _ => {}
        }
    }
    entry.admin_level = (entry.rights as u32).count_ones().min(4) as i32;
    if entry.account.is_empty()
        || entry.account.starts_with('_')
        || !entry.account.eq_ignore_ascii_case(&file_account)
    {
        return None;
    }
    Some(entry)
}

fn rc_account_list_field(entry: &RcAccountListEntry, field: &str) -> String {
    match field.trim().to_ascii_lowercase().as_str() {
        "account" | "name" => entry.account.clone(),
        "nick" | "nickname" => entry.nick.clone(),
        "email" => entry.email.clone(),
        "adminip" | "iprange" => entry.admin_ip.clone(),
        "adminlevel" => entry.admin_level.to_string(),
        "localrights" | "rights" => entry.rights.to_string(),
        "blocked" | "banned" => entry.banned.to_string(),
        "loadonly" => entry.load_only.to_string(),
        _ => String::new(),
    }
}

fn rc_account_list_condition_matches(entry: &RcAccountListEntry, condition: &str) -> bool {
    let condition = condition.trim();
    if condition.is_empty() {
        return true;
    }
    let lower = condition.to_ascii_lowercase();
    if let Some(index) = lower.find(" like ") {
        let field = condition[..index].trim();
        let pattern = condition[index + 6..].trim().trim_matches(['"', '\'']);
        return glob_match(
            &pattern.replace('%', "*").to_ascii_lowercase(),
            &rc_account_list_field(entry, field).to_ascii_lowercase(),
        );
    }
    for operator in [">=", "<=", "!=", "=", ">", "<"] {
        if let Some(index) = condition.find(operator) {
            let field = condition[..index].trim();
            let wanted = condition[index + operator.len()..]
                .trim()
                .trim_matches(['"', '\'']);
            if field.is_empty() {
                return false;
            }
            let actual = rc_account_list_field(entry, field);
            let left = if actual == "true" || actual == "false" {
                i64::from(actual == "true")
            } else {
                actual.parse::<i64>().unwrap_or(0)
            };
            let right = if wanted == "true" || wanted == "false" {
                i64::from(wanted == "true")
            } else {
                wanted.parse::<i64>().unwrap_or(0)
            };
            return match operator {
                "=" => actual.eq_ignore_ascii_case(wanted),
                "!=" => !actual.eq_ignore_ascii_case(wanted),
                ">" => left > right,
                "<" => left < right,
                ">=" => left >= right,
                "<=" => left <= right,
                _ => false,
            };
        }
    }
    false
}

fn rc_account_list_matches(entry: &RcAccountListEntry, name_spec: &str, conditions: &str) -> bool {
    let pattern = if name_spec.is_empty() { "*" } else { name_spec };
    if !glob_match(
        &pattern.to_ascii_lowercase(),
        &entry.account.to_ascii_lowercase(),
    ) {
        return false;
    }
    conditions
        .split(',')
        .all(|condition| rc_account_list_condition_matches(entry, condition))
}

fn rc_account_list_candidate_score(account_file: &str, entry: &RcAccountListEntry) -> i64 {
    let mut score = i64::from(entry.rights);
    let path = account_file.replace('\\', "/").to_ascii_lowercase();
    let canonical = account_file_write_path(&entry.account).replace('\\', "/");
    if path == canonical.to_ascii_lowercase() {
        score += 1_i64 << 30;
    }
    if !entry.nick.is_empty() {
        score += 1_i64 << 20;
    }
    if !entry.email.is_empty() {
        score += 1_i64 << 19;
    }
    score
}

fn rc_account_condition_matches(account: &Account, condition: &str) -> bool {
    let condition = condition.trim();
    if condition.is_empty() {
        return true;
    }
    let lower = condition.to_ascii_lowercase();
    if let Some(index) = lower.find(" like ") {
        let field = condition[..index].trim();
        let pattern = condition[index + 6..].trim().trim_matches(['\"', '\'']);
        return glob_match(
            &pattern.replace('%', "*").to_ascii_lowercase(),
            &rc_account_field(account, field).to_ascii_lowercase(),
        );
    }
    for operator in [">=", "<=", "!=", "=", ">", "<"] {
        if let Some(index) = condition.find(operator) {
            let field = condition[..index].trim();
            let wanted = condition[index + operator.len()..]
                .trim()
                .trim_matches(['\"', '\'']);
            let actual = rc_account_field(account, field);
            if operator == "=" {
                return actual.eq_ignore_ascii_case(wanted);
            }
            if operator == "!=" {
                return !actual.eq_ignore_ascii_case(wanted);
            }
            let left = if actual == "true" || actual == "false" {
                if actual == "true" {
                    1
                } else {
                    0
                }
            } else {
                actual.parse::<i64>().unwrap_or(0)
            };
            let right = if wanted == "true" || wanted == "false" {
                if wanted == "true" {
                    1
                } else {
                    0
                }
            } else {
                wanted.parse::<i64>().unwrap_or(0)
            };
            return match operator {
                ">" => left > right,
                "<" => left < right,
                ">=" => left >= right,
                "<=" => left <= right,
                _ => false,
            };
        }
    }
    false
}

fn rc_account_matches(account: &Account, name_spec: &str, conditions: &str) -> bool {
    let pattern = if name_spec.is_empty() { "*" } else { name_spec };
    if !glob_match(
        &pattern.to_ascii_lowercase(),
        &account.account_name.to_ascii_lowercase(),
    ) {
        return false;
    }
    conditions
        .split(',')
        .all(|condition| rc_account_condition_matches(account, condition))
}

fn load_offline_rc_player(server: &Arc<Server>, account_name: &str) -> Option<Arc<Player>> {
    let account_name = rc_sanitize_account(account_name);
    if account_name.is_empty() || !server.account_exists(&account_name) {
        return None;
    }
    let player = Player::NewPlayer(None, server);
    if player
        .account
        .lock()
        .unwrap()
        .load_account(&account_name, false)
    {
        Some(player)
    } else {
        None
    }
}

fn list_account_files(config: &FileSystem) -> io::Result<Vec<String>> {
    fn walk(root: &Path, current: &Path, output: &mut Vec<String>) -> io::Result<()> {
        for entry in std::fs::read_dir(current)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                walk(root, &path, output)?;
            } else if let Ok(relative) = path.strip_prefix(root) {
                output.push(relative.to_string_lossy().replace('\\', "/"));
            }
        }
        Ok(())
    }
    let root = config.resolve_existing_path("accounts");
    let mut files = Vec::new();
    if !root.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{}: no such file or directory", root.display()),
        ));
    }
    walk(&root, &root, &mut files)?;
    Ok(files)
}

fn load_rc_account_list_ban(config: &FileSystem, account_file: &str) -> Option<(String, bool)> {
    let file_name = Path::new(account_file).file_name()?.to_string_lossy();
    let file_account = file_name.strip_suffix(".txt")?.to_string();
    let account_path = if account_file
        .replace('\\', "/")
        .to_ascii_lowercase()
        .starts_with("accounts/")
    {
        account_file.replace('\\', "/")
    } else {
        format!("accounts/{}", account_file.replace('\\', "/"))
    };
    let lines = config.load_file_as_lines(&account_path).ok()?;
    if lines.first().map(String::as_str) != Some("GRACC001") {
        return None;
    }
    let mut account = file_account.clone();
    let mut banned = false;
    for raw in lines.iter().skip(1) {
        let line = raw.trim();
        let Some((key, value)) = line.split_once(' ') else {
            continue;
        };
        match key.to_ascii_uppercase().as_str() {
            "NAME" => account = value.to_string(),
            "BANNED" => banned = parse_i32(value) != 0,
            _ => {}
        }
    }
    if account.is_empty()
        || account.starts_with('_')
        || !account.eq_ignore_ascii_case(&file_account)
    {
        return None;
    }
    Some((account, banned))
}

fn should_send_client_player_list_entry(player: &Player) -> bool {
    if !is_player_list_player(player) {
        return false;
    }
    if player.player_type() & PLTYPE_NPCSERVER != 0 {
        return true;
    }
    let Some(server) = player.server() else {
        return true;
    };
    if !server.settings.get_bool("hidestaff", false) {
        return true;
    }
    !player.account.lock().unwrap().is_staff
}

pub struct NPCServer {
    server: Weak<Server>,
    enabled: AtomicBool,
    player: Mutex<Option<Arc<Player>>>,
    runtime: npc_runtime::Runtime,
}

pub const NPC_SERVER_ACCOUNT_NAME: &str = "(npcserver)";
pub const NPC_SERVER_PLAYER_ID: u16 = 2;
pub const NPC_SERVER_DEFAULT_PM_REPLY: &str =
    "I am the npcserver for\nthis game server. Almost\nall npc actions are controlled\nby me.";

impl NPCServer {
    fn new_internal(server: &Weak<Server>) -> Self {
        Self {
            server: server.clone(),
            enabled: AtomicBool::new(false),
            player: Mutex::new(None),
            runtime: npc_runtime::Runtime::new(),
        }
    }
    pub fn new_for_server(server: &Arc<Server>) -> Arc<Self> {
        Arc::new(Self::new_internal(&Arc::downgrade(server)))
    }
    pub fn NewNPCServer(server: &Arc<Server>) -> Arc<Self> {
        Self::new_for_server(server)
    }
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
    pub fn Enabled(&self) -> bool {
        self.enabled()
    }
    pub fn start(&self) -> Option<Arc<Player>> {
        let server = self.server.upgrade()?;
        if server.npc_server_mode() != "embedded" || !server.settings.get_bool("serverside", false)
        {
            self.enabled.store(false, Ordering::Relaxed);
            return None;
        }

        self.runtime.set_stopped(false);

        // The reference start path removes an existing pseudo-player from the
        // live map before constructing the replacement, without sending the
        // normal player logout broadcasts.
        if let Some(existing) = self.player() {
            server.players.write().unwrap().remove(&existing.id());
            self.player.lock().unwrap().take();
        }

        self.enabled.store(true, Ordering::Relaxed);
        let player = self.build_npc_player(&server);
        if !server.add_player(player.clone(), NPC_SERVER_PLAYER_ID) {
            self.enabled.store(false, Ordering::Relaxed);
            return None;
        }
        *self.player.lock().unwrap() = Some(player.clone());

        for list in server.listserver_targets() {
            list.AddPlayer(&player);
        }
        server.refresh_player_list_entry(&player);
        self.send_address_to_rcs(&server);

        server.update_all_weapons_for_players();
        server.run_server_side_event_for_active_scripts("onInitialized", Some(&player), &[]);
        server.logger.info(&format!(
            "NPC-Server initialized (id={} account={} nickname={} type={} x={} y={})",
            player.id(),
            player.account_name(),
            player.nickname(),
            player.player_type(),
            player.position().0,
            player.position().1
        ));
        Some(player)
    }
    pub fn Start(&self) -> Option<Arc<Player>> {
        self.start()
    }
    pub fn shutdown(&self) {
        self.runtime.set_stopped(true);
        self.stop_watching();
        self.enabled.store(false, Ordering::Relaxed);
        if let Some(server) = self.server.upgrade() {
            if let Some(player) = self.player() {
                server.delete_player(&player);
            }
            self.player.lock().unwrap().take();
            server.update_all_weapons_for_players();
        } else {
            self.player.lock().unwrap().take();
        }
    }
    pub fn Shutdown(&self) {
        self.shutdown()
    }
    pub fn kill(&self) {
        self.shutdown()
    }
    pub fn Kill(&self) {
        self.kill()
    }
    pub fn player(&self) -> Option<Arc<Player>> {
        if let Some(server) = self.server.upgrade() {
            if let Some(player) = server
                .get_all_players()
                .into_iter()
                .find(|player| player.player_type() & PLTYPE_NPCSERVER != 0)
            {
                *self.player.lock().unwrap() = Some(player.clone());
                return Some(player);
            }
        }
        self.player.lock().unwrap().take()
    }
    pub fn Player(&self) -> Option<Arc<Player>> {
        self.player()
    }
    pub fn sync(&self) {
        let Some(server) = self.server.upgrade() else {
            return;
        };
        let should_run =
            server.npc_server_mode() == "embedded" && server.settings.get_bool("serverside", false);
        if should_run {
            self.runtime.set_stopped(false);
            if let Some(player) = self.player() {
                let old_nickname = player.nickname();
                let old_head = player.account.lock().unwrap().character.head_image.clone();
                self.apply_player_settings(&player, &server);
                let new_head = player.account.lock().unwrap().character.head_image.clone();
                if old_nickname != player.nickname() || old_head != new_head {
                    server.refresh_player_list_entry(&player);
                }
            } else {
                self.start();
            }
            self.start_watching();
        } else {
            self.shutdown();
        }
    }
    pub fn Sync(&self) {
        self.sync()
    }

    // Synchronize quietly immediately before sending a complete list-server
    // player snapshot. This updates NPC settings but only broadcasts changed
    // properties to connected clients.
    fn sync_quiet(&self) {
        let Some(server) = self.server.upgrade() else {
            return;
        };
        let should_run =
            server.npc_server_mode() == "embedded" && server.settings.get_bool("serverside", false);
        if should_run {
            self.runtime.set_stopped(false);
            if let Some(player) = self.player() {
                let old_nickname = player.nickname();
                let old_head = player.account.lock().unwrap().character.head_image.clone();
                self.apply_player_settings(&player, &server);
                let new_head = player.account.lock().unwrap().character.head_image.clone();
                if old_nickname != player.nickname() || old_head != new_head {
                    server.broadcast_player_list_entry_to_clients(&player);
                }
            } else {
                self.start();
            }
            self.start_watching();
        } else {
            self.shutdown();
        }
    }
    pub fn SyncQuiet(&self) {
        self.sync_quiet()
    }

    fn start_watching(&self) {
        let Some(server) = self.server.upgrade() else {
            return;
        };
        let warning_logger = server.logger.clone();
        let info_logger = server.logger.clone();
        let server_for_events = self.server.clone();
        self.runtime.start_watching(
            server.config.get_base_path(),
            Some(Arc::new(move |message| warning_logger.warning(&message))),
            Some(Arc::new(move |message| info_logger.info(&message))),
            Some(Arc::new(move |relative, file_name| {
                if let Some(server) = server_for_events.upgrade() {
                    server.npc_server.handle_file_event(&relative, &file_name);
                }
            })),
        );
    }

    pub fn startWatching(&self) {
        self.start_watching()
    }

    fn stop_watching(&self) {
        self.runtime.stop_watching();
    }

    pub fn stopWatching(&self) {
        self.stop_watching()
    }

    fn handle_file_event(&self, relative: &str, file_name: &str) {
        if relative.starts_with("weapons/") && file_name.to_ascii_lowercase().ends_with(".txt") {
            self.reload_weapon_from_disk(relative);
        } else if relative.starts_with("scripts/")
            && file_name.to_ascii_lowercase().ends_with(".txt")
        {
            self.reload_class_from_disk(relative, file_name);
        }
    }

    fn reload_weapon_from_disk(&self, relative: &str) {
        let Some(server) = self.server.upgrade() else {
            return;
        };
        let Ok(data) = server.config.load_file(relative) else {
            return;
        };
        let Some(mut weapon) = parse_weapon(&String::from_utf8_lossy(&data)) else {
            return;
        };
        if !weapon.bytecode_file.is_empty() {
            weapon.bytecode = server
                .config
                .load_file(format!("weapon_bytecode/{}", weapon.bytecode_file))
                .unwrap_or_default();
        }
        let added = server.get_weapon(&weapon.name).is_none();
        if let Some(existing) = server.get_weapon(&weapon.name) {
            if existing.image == weapon.image
                && existing.script == weapon.script
                && existing.bytecode_file == weapon.bytecode_file
            {
                return;
            }
        }
        let name = weapon.name.clone();
        server.delete_weapon(&name);
        server.add_weapon(Arc::new(weapon));
        let _ = server.ensure_weapon_bytecode(&name);
        if let Some(updated) = server.get_weapon(&name) {
            server.update_weapon_for_players(&updated);
        }
        server
            .logger
            .info(&format!("Reloaded weapon {name} from disk"));
        let action = if added { "added" } else { "updated" };
        server.send_rc_chat(&format!("Weapon/GUI-script {name} {action} by Server"));
    }

    fn reload_class_from_disk(&self, relative: &str, file_name: &str) {
        let Some(server) = self.server.upgrade() else {
            return;
        };
        let Ok(data) = server.config.load_file(relative) else {
            return;
        };
        let Some(name) = Path::new(file_name)
            .file_stem()
            .map(|value| value.to_string_lossy().into_owned())
        else {
            return;
        };
        let script = String::from_utf8_lossy(&data).replace("\r\n", "\n");
        let existed = self
            .server
            .upgrade()
            .and_then(|server| server.get_class(&name))
            .is_some();
        let class = Arc::new(ScriptClass {
            name: name.clone(),
            script,
        });
        server.add_class(class.clone());
        server.update_class_for_players(&class);
        server
            .logger
            .info(&format!("Reloaded class {name} from disk"));
        let action = if existed { "updated" } else { "added" };
        server.send_rc_chat(&format!("Script {name} {action} by Server"));
    }

    pub fn new_npc_player(&self) -> Option<Arc<Player>> {
        let server = self.server.upgrade()?;
        Some(self.build_npc_player(&server))
    }
    pub fn newNPCPlayer(&self) -> Option<Arc<Player>> {
        self.new_npc_player()
    }

    fn build_npc_player(&self, server: &Arc<Server>) -> Arc<Player> {
        let player = Player::NewPlayer(None, server);
        {
            let mut account = player.account.lock().unwrap();
            account.account_name = NPC_SERVER_ACCOUNT_NAME.to_string();
        }
        {
            let mut account = player.account.lock().unwrap();
            let _ = account.load_account(NPC_SERVER_ACCOUNT_NAME, false);
        }
        self.apply_player_settings(&player, server);
        {
            let mut state = player.state.lock().unwrap();
            state.loaded = true;
            state.last_data = Instant::now();
            state.last_movement = Instant::now();
            state.last_save = Instant::now();
            state.last_one_minute = Instant::now();
        }
        player
    }

    fn configured_nickname(&self, server: &Server) -> String {
        let configured = if server
            .settings
            .get("npcservermode")
            .trim()
            .eq_ignore_ascii_case("external")
        {
            String::new()
        } else {
            server.settings.get("nickname")
        };
        npc_runtime::configured_nickname(&configured)
    }

    fn apply_player_settings(&self, player: &Arc<Player>, server: &Arc<Server>) {
        player.set_id(NPC_SERVER_PLAYER_ID);
        player.set_player_type(PLTYPE_NPCSERVER);
        player.set_current_level(None);
        {
            let mut account = player.account.lock().unwrap();
            account.account_name = NPC_SERVER_ACCOUNT_NAME.to_string();
            account.community_name = NPC_SERVER_ACCOUNT_NAME.to_string();
            account.is_load_only = true;
            account.is_staff = true;
            account.admin_rights = all_local_rights();
            account.admin_ip = "*.*.*.*".to_string();
            if account.folder_list.is_empty() {
                account.folder_list = server.default_rc_folder_rights();
            }
            account.level_name.clear();
            account.account_ip = 0;
            account.account_ip_str = "0".to_string();
            account.character.head_image = nonempty(&server.settings.get("staffhead"))
                .unwrap_or_else(|| "head25.png".to_string());
        }
        self.apply_player_display_identity(player, server);
    }

    fn apply_player_display_identity(&self, player: &Player, server: &Arc<Server>) {
        {
            let mut account = player.account.lock().unwrap();
            account.level_name.clear();
        }
        player.set_current_level(None);
        player.set_nickname(&self.configured_nickname(server));
    }

    fn send_address_to_rcs(&self, server: &Arc<Server>) {
        let targets = server
            .get_all_players()
            .into_iter()
            .filter(|player| player.is_logged_in() && player.player_type() & PLTYPE_ANYRC != 0)
            .collect::<Vec<_>>();
        for player in targets {
            let _ = self.send_nc_address(&player, None);
        }
    }

    pub fn send_nc_address(&self, to: &Arc<Player>, query_packet: Option<&[u8]>) -> bool {
        let Some(server) = self.server.upgrade() else {
            return false;
        };
        if to.player_type() & PLTYPE_ANYRC == 0 {
            return false;
        }
        let broadcast = query_packet.is_none();
        if !broadcast && !to.has_right(PLPERM_NPCCONTROL) {
            return false;
        }
        if let Some(query) = query_packet {
            if !npc_runtime::is_location_query(query, PLI_NPCSERVERQUERY) {
                return false;
            }
        }
        if server.npc_server_mode() == "external" {
            if self.player().is_none() {
                return false;
            }
        } else if !self.enabled() {
            return false;
        }
        let Some(npc_player) = self.player().or_else(|| self.start()) else {
            return false;
        };
        let address = self.address_for(&to);
        let mut packet = Buffer::new();
        packet
            .write_byte(PLO_NPCSERVERADDR)
            .write_gshort(npc_player.id().wrapping_add(0x1020))
            .write(address.as_bytes());
        to.send(&packet);
        true
    }
    pub fn sendNCAddress(&self, to: &Arc<Player>, query_packet: Option<&[u8]>) -> bool {
        self.send_nc_address(to, query_packet)
    }
    pub fn SendNCAddress(&self, to: &Arc<Player>, query_packet: Option<&[u8]>) -> bool {
        self.send_nc_address(to, query_packet)
    }

    pub fn send_npc_list(&self, to: &Arc<Player>) {
        let Some(server) = self.server.upgrade() else {
            return;
        };
        let npcs = server
            .npcs
            .read()
            .unwrap()
            .values()
            .filter(|npc| npc.npc_type() == NPCType::DBNPC)
            .cloned()
            .collect::<Vec<_>>();
        for npc in npcs {
            self.send_npc_add(to, &npc);
        }
    }
    pub fn sendNPCList(&self, to: &Arc<Player>) {
        self.send_npc_list(to)
    }
    pub fn SendNPCList(&self, to: &Arc<Player>) {
        self.send_npc_list(to)
    }

    pub fn send_npc_add(&self, to: &Arc<Player>, npc: &Arc<NPC>) {
        let mut packet = Buffer::new();
        let name = npc.npc_name();
        let script_type = npc.script_type();
        let level_name = npc.level_name();
        packet
            .write_byte(PLO_NC_NPCADD)
            .write_gint(npc.id())
            .write_gchar(NPCPROP_NAME)
            .write_gchar(name.len() as u8)
            .write(name.as_bytes())
            .write_gchar(NPCPROP_TYPE)
            .write_gchar(script_type.len() as u8)
            .write(script_type.as_bytes())
            .write_gchar(NPCPROP_CURLEVEL)
            .write_gchar(level_name.len() as u8)
            .write(level_name.as_bytes());
        to.send(&packet);
    }
    pub fn sendNPCAdd(&self, to: &Arc<Player>, npc: &Arc<NPC>) {
        self.send_npc_add(to, npc)
    }
    pub fn SendNPCAdd(&self, to: &Arc<Player>, npc: &Arc<NPC>) {
        self.send_npc_add(to, npc)
    }

    pub fn send_pm_fallback(&self, to: &Arc<Player>, npc_server: &Arc<Player>) -> bool {
        let mut packet = Buffer::new();
        packet
            .write_byte(PLO_PRIVATEMESSAGE)
            .write_gshort(npc_server.id())
            .write(b"\"\",")
            .write(gtokenize_text(NPC_SERVER_DEFAULT_PM_REPLY).as_bytes());
        to.send(&packet);
        true
    }
    pub fn sendPMFallback(&self, to: &Arc<Player>, npc_server: &Arc<Player>) -> bool {
        self.send_pm_fallback(to, npc_server)
    }
    pub fn SendPMFallback(&self, to: &Arc<Player>, npc_server: &Arc<Player>) -> bool {
        self.send_pm_fallback(to, npc_server)
    }

    pub fn address_for(&self, requester: &Arc<Player>) -> String {
        let Some(server) = self.server.upgrade() else {
            return String::new();
        };
        let requester_ip = requester.account.lock().unwrap().account_ip_str.clone();
        let admin_setting = |key: &str| server.admin_settings.get(key);
        let setting = |key: &str| server.settings.get(key);
        let mut address =
            npc_runtime::address_for(Some(&admin_setting), Some(&setting), &requester_ip);
        if server.npc_server_mode() == "external" {
            if let Some(port) = self.player().and_then(|player| {
                let value = player.state.lock().unwrap().npcserver_port.clone();
                nonempty(&value)
            }) {
                if let Some(index) = address.rfind(',') {
                    address.replace_range(index + 1.., &port);
                }
            }
        }
        address
    }
    pub fn AddressFor(&self, requester: &Arc<Player>) -> String {
        self.address_for(requester)
    }
}

pub struct GS2SocketManager {
    inner: npc_runtime::SocketManager,
    callback: Arc<dyn Fn(npc_runtime::SocketEvent) + Send + Sync>,
}
impl GS2SocketManager {
    fn new(server: &Weak<Server>) -> Self {
        let callback_server = server.clone();
        let callback: Arc<dyn Fn(npc_runtime::SocketEvent) + Send + Sync> =
            Arc::new(move |event: npc_runtime::SocketEvent| {
                let Some(server) = callback_server.upgrade() else {
                    return;
                };
                let mut event_name = event.event.clone();
                if !event.name.trim().is_empty() {
                    event_name = format!("{}.{}", event.name, event_name);
                }
                let mut result = server.run_server_side_gs2_with_context(
                    &event.base.script_type,
                    &event.base.script_name,
                    &event_name,
                    &event.base.script,
                    event.base.this.clone(),
                    event.base.player_context.clone(),
                    event.base.npc_id,
                    Some(event.socket.clone()),
                    event.argument.clone(),
                    &event.params,
                );
                result.vm_revision = event.base.revision;
                if !result.error.is_empty() {
                    server.send_gs2_vm_error_to_nc(
                        &format!("{} {}", event.base.script_type, event.base.script_name),
                        &result.error,
                    );
                    return;
                }
                server.apply_gs2_vm_result(result.clone());
                server.commit_gs2_npc_state(&result);
                server.emit_gs2_vm_output(&result);
            });
        let inner_callback = callback.clone();
        let inner =
            npc_runtime::SocketManager::new(Some(move |event: npc_runtime::SocketEvent| {
                inner_callback(event);
            }));
        Self { inner, callback }
    }

    pub fn new_for_server(server: &Arc<Server>) -> Arc<Self> {
        Arc::new(Self::new(&Arc::downgrade(server)))
    }

    pub fn NewGS2SocketManager(server: &Arc<Server>) -> Arc<Self> {
        Self::new_for_server(server)
    }

    pub fn apply(&self, result: &GS2VMResult) {
        let updates = result
            .socket_updates
            .iter()
            .map(|update| npc_runtime::SocketUpdate {
                name: update.name.clone(),
                id: update.id.clone(),
                address: update.address.clone(),
                port: update.port,
                ip_address: update.ip_address.clone(),
                data: update.data.clone(),
                buffer: update.buffer.clone(),
                package_delimiter: update.package_delimiter.clone(),
                is_connected: update.is_connected,
                state: update.state.clone(),
                joined_classes: update.joined_classes.clone(),
                parent_name: update.parent_name.clone(),
                parent_id: update.parent_id.clone(),
            })
            .collect::<Vec<_>>();
        self.inner
            .apply(socket_script(result), &updates, &result.socket_actions);
    }

    pub fn Apply(&self, result: GS2VMResult) {
        self.apply(&result)
    }

    pub fn prepare_bind(
        &self,
        result: &GS2VMResult,
        action: &npc_runtime::SocketAction,
    ) -> Result<npc_runtime::SocketContext, String> {
        self.inner.prepare_bind(&socket_script(result), action)
    }

    pub fn PrepareBind(
        &self,
        result: GS2VMResult,
        action: &npc_runtime::SocketAction,
    ) -> Result<npc_runtime::SocketContext, String> {
        self.prepare_bind(&result, action)
    }

    pub fn fire(
        &self,
        result: &GS2VMResult,
        name: &str,
        id: &str,
        event: &str,
        socket: npc_runtime::SocketContext,
        argument: Option<npc_runtime::SocketContext>,
        params: &[String],
    ) {
        (self.callback)(npc_runtime::SocketEvent {
            base: socket_script(result),
            name: name.to_string(),
            id: id.to_string(),
            event: event.to_string(),
            socket,
            argument,
            params: params.to_vec(),
        });
    }

    pub fn Fire(
        &self,
        result: &GS2VMResult,
        name: &str,
        id: &str,
        event: &str,
        socket: npc_runtime::SocketContext,
        argument: Option<npc_runtime::SocketContext>,
        params: &[String],
    ) {
        self.fire(result, name, id, event, socket, argument, params)
    }

    pub fn close_all(&self) {
        self.inner.close_all();
    }
    pub fn CloseAll(&self) {
        self.close_all()
    }
}

fn socket_script(result: &GS2VMResult) -> npc_runtime::SocketScript {
    npc_runtime::SocketScript {
        script_type: result.script_type.clone(),
        script_name: result.script_name.clone(),
        event_name: result.event_name.clone(),
        script: result.script.clone(),
        player_context: result.player_context.clone(),
        npc_id: result.npc_id,
        revision: result.vm_revision,
        this: result.this.clone(),
    }
}

pub fn socket_state(
    name: &str,
    id: &str,
    address: &str,
    ip_address: &str,
    port: i32,
    package_delimiter: &str,
    data: &str,
    buffer: &str,
    is_connected: bool,
    state: npc_runtime::AnyMap,
    joined_classes: Vec<String>,
    parent_name: &str,
    parent_id: &str,
) -> npc_runtime::SocketContext {
    npc_runtime::SocketContext {
        name: name.to_string(),
        id: id.to_string(),
        address: address.to_string(),
        ip_address: ip_address.to_string(),
        port,
        package_delimiter: package_delimiter.to_string(),
        data: data.to_string(),
        buffer: buffer.to_string(),
        is_connected,
        state,
        joined_classes,
        parent_name: parent_name.to_string(),
        parent_id: parent_id.to_string(),
    }
}

pub struct WordFilter {
    server: Weak<Server>,
    rules: RwLock<Vec<WordFilterRule>>,
    show_words_to_rc: AtomicBool,
    default_warn_message: RwLock<String>,
}
#[derive(Clone, Debug, Default)]
pub struct WordFilterRule {
    pub check: i32,
    pub word_position: i32,
    pub action: i32,
    pub precision: i32,
    pub precision_percentage: bool,
    pub matching: String,
    pub warn_message: String,
}
pub const FILTER_CHECK_CHAT: i32 = 1;
pub const FILTER_CHECK_PM: i32 = 2;
pub const FILTER_CHECK_NICK: i32 = 4;
pub const FILTER_CHECK_TOALL: i32 = 8;
pub const FILTER_POSITION_FULL: i32 = 1;
pub const FILTER_POSITION_START: i32 = 2;
pub const FILTER_POSITION_PART: i32 = 3;
pub const FILTER_ACTION_LOG: i32 = 1;
pub const FILTER_ACTION_TELLRC: i32 = 2;
pub const FILTER_ACTION_REPLACE: i32 = 4;
pub const FILTER_ACTION_WARN: i32 = 8;
pub const FILTER_ACTION_JAIL: i32 = 16;
pub const FILTER_ACTION_BAN: i32 = 32;
impl WordFilter {
    fn new(server: &Weak<Server>) -> Self {
        Self {
            server: server.clone(),
            rules: RwLock::new(Vec::new()),
            show_words_to_rc: AtomicBool::new(false),
            default_warn_message: RwLock::new(String::new()),
        }
    }
    pub fn load(&self, file_name: &str) {
        let Some(server) = self.server.upgrade() else {
            return;
        };
        let Ok(lines) = server.config.load_file_as_lines(file_name) else {
            self.rules.write().unwrap().clear();
            return;
        };
        let mut rules = Vec::new();
        let mut default_warn_message = String::new();
        let mut show_words_to_rc = false;
        let mut index = 0usize;
        while index < lines.len() {
            let line = lines[index].trim();
            if line.is_empty() {
                index += 1;
                continue;
            }
            let parts = line.split_whitespace().collect::<Vec<_>>();
            if parts.is_empty() {
                index += 1;
                continue;
            }
            if parts[0] == "RULE" {
                let mut rule = WordFilterRule {
                    precision: 100,
                    precision_percentage: true,
                    ..WordFilterRule::default()
                };
                index += 1;
                while index < lines.len() && lines[index].trim() != "RULEEND" {
                    let line = lines[index].trim();
                    let parts = line.split_whitespace().collect::<Vec<_>>();
                    if !parts.is_empty() {
                        match parts[0] {
                            "CHECK" => {
                                for value in parts.iter().skip(1) {
                                    match *value {
                                        "chat" => rule.check |= FILTER_CHECK_CHAT,
                                        "pm" => rule.check |= FILTER_CHECK_PM,
                                        "nick" => rule.check |= FILTER_CHECK_NICK,
                                        "toall" => rule.check |= FILTER_CHECK_TOALL,
                                        _ => {}
                                    }
                                }
                            }
                            "MATCH" if parts.len() == 2 => {
                                rule.matching = parts[1].to_string();
                            }
                            "PRECISION" if parts.len() == 2 => {
                                let mut value = parts[1].to_string();
                                if value.contains('%') {
                                    rule.precision_percentage = true;
                                    value = value.trim_end_matches('%').to_string();
                                } else {
                                    rule.precision_percentage = false;
                                }
                                if let Ok(value) = value.parse::<i32>() {
                                    rule.precision = value;
                                }
                            }
                            "WORDPOSITION" => {
                                for value in parts.iter().skip(1) {
                                    match *value {
                                        "full" => rule.word_position |= FILTER_POSITION_FULL,
                                        "start" => rule.word_position |= FILTER_POSITION_START,
                                        "part" => rule.word_position |= FILTER_POSITION_PART,
                                        _ => {}
                                    }
                                }
                            }
                            "ACTION" => {
                                for value in parts.iter().skip(1) {
                                    match *value {
                                        "log" => rule.action |= FILTER_ACTION_LOG,
                                        "tellrc" => rule.action |= FILTER_ACTION_TELLRC,
                                        "replace" => rule.action |= FILTER_ACTION_REPLACE,
                                        "warn" => rule.action |= FILTER_ACTION_WARN,
                                        "jail" => rule.action |= FILTER_ACTION_JAIL,
                                        "ban" => rule.action |= FILTER_ACTION_BAN,
                                        _ => {}
                                    }
                                }
                            }
                            "WARNMESSAGE" if line.len() > 12 => {
                                rule.warn_message = line[12..].trim().to_string();
                            }
                            _ => {}
                        }
                    }
                    index += 1;
                }
                if rule.check != 0 && rule.action != 0 && rule.word_position != 0 {
                    rules.push(rule);
                }
            } else if parts[0] == "WARNMESSAGE" && line.len() > 12 {
                default_warn_message = line[12..].trim().to_string();
            } else if parts[0] == "SHOWWORDSTORC" && parts.get(1) == Some(&"true") {
                show_words_to_rc = true;
            }
            index += 1;
        }
        *self.rules.write().unwrap() = rules;
        *self.default_warn_message.write().unwrap() = default_warn_message;
        self.show_words_to_rc
            .store(show_words_to_rc, Ordering::Relaxed);
    }
    pub fn Load(&self, file_name: &str) {
        self.load(file_name)
    }
    pub fn apply(&self, player: &Player, chat: &str, check: i32) -> String {
        let rules = self.rules.read().unwrap().clone();
        if chat.is_empty() || rules.is_empty() || check == 0 {
            return chat.to_string();
        }
        let mut output = chat.to_string();
        let chat_bytes = chat.as_bytes();
        let mut warn_message = String::new();
        let mut words_found = Vec::new();
        let mut actions_found = 0i32;
        let mut warned = false;
        for rule in rules {
            if check & rule.check == 0 {
                continue;
            }
            if rule.word_position != FILTER_POSITION_PART {
                for word in chat.split_whitespace() {
                    if rule.word_position == FILTER_POSITION_FULL
                        && word.len() != rule.matching.len()
                    {
                        continue;
                    }
                    let word_bytes = word.as_bytes();
                    let match_bytes = rule.matching.as_bytes();
                    let mut words_matched = 0usize;
                    let mut failed = false;
                    for index in 0..match_bytes.len().min(word_bytes.len()) {
                        let letter = match_bytes[index];
                        let word_letter = word_bytes[index];
                        if letter == b'?' {
                            words_matched += 1;
                        } else if letter.is_ascii_lowercase()
                            && letter == word_letter.to_ascii_lowercase()
                        {
                            words_matched += 1;
                        } else if letter.is_ascii_uppercase() {
                            if letter.to_ascii_lowercase() == word_letter.to_ascii_lowercase() {
                                words_matched += 1;
                            } else {
                                failed = true;
                                break;
                            }
                        }
                    }
                    if failed || !word_filter_precision_matches(&rule, words_matched) {
                        continue;
                    }
                    words_found.push(word.to_string());
                    actions_found |= rule.action;
                    if rule.action & FILTER_ACTION_WARN != 0 {
                        warn_message = rule.warn_message.clone();
                        warned = true;
                        break;
                    }
                    if rule.action & FILTER_ACTION_REPLACE != 0 {
                        output = output.replace(word, &"*".repeat(word.len()));
                    }
                }
            } else {
                let bypass = [b' ', b'\r', b'\n'];
                let match_bytes = rule.matching.as_bytes();
                for word_start in 0..chat_bytes.len() {
                    let mut word_pos = word_start;
                    let mut words_matched = 0usize;
                    let mut failed = false;
                    let mut word = Vec::new();
                    for chat_pos in 0..match_bytes.len() {
                        if word_pos + chat_pos >= chat_bytes.len() {
                            break;
                        }
                        if word_pos + chat_pos == word_start
                            && bypass.contains(&chat_bytes[word_pos + chat_pos])
                        {
                            failed = true;
                            break;
                        }
                        for value in bypass {
                            if chat_bytes[word_pos + chat_pos] == value {
                                word.push(value);
                                word_pos += 1;
                            }
                        }
                        if word_pos + chat_pos >= chat_bytes.len() {
                            failed = true;
                            break;
                        }
                        let letter = match_bytes[chat_pos];
                        let word_letter = chat_bytes[word_pos + chat_pos];
                        if letter == b'?' {
                            word.push(word_letter);
                            words_matched += 1;
                        } else if letter.is_ascii_lowercase()
                            && letter == word_letter.to_ascii_lowercase()
                        {
                            word.push(word_letter);
                            words_matched += 1;
                        } else if letter.is_ascii_uppercase() {
                            if letter.to_ascii_lowercase() == word_letter.to_ascii_lowercase() {
                                words_matched += 1;
                            } else {
                                failed = true;
                                break;
                            }
                            word.push(word_letter);
                        } else {
                            word.push(word_letter);
                        }
                    }
                    if failed || !word_filter_precision_matches(&rule, words_matched) {
                        continue;
                    }
                    let matched = String::from_utf8_lossy(&word).trim().to_string();
                    words_found.push(matched.clone());
                    actions_found |= rule.action;
                    if rule.action & FILTER_ACTION_WARN != 0 {
                        warn_message = rule.warn_message.clone();
                        warned = true;
                        break;
                    }
                    if rule.action & FILTER_ACTION_REPLACE != 0 {
                        output = output.replace(&matched, &"*".repeat(matched.len()));
                    }
                }
            }
            if warned {
                break;
            }
        }
        if words_found.is_empty() {
            return chat.to_string();
        }
        let bad_words = words_found.join(", ");
        if actions_found & FILTER_ACTION_LOG != 0 {
            if let Some(server) = self.server.upgrade() {
                server.logger.info(&format!(
                    "[Word Filter] Player {} was caught using these words: {}",
                    player.account_name(),
                    bad_words
                ));
            }
        }
        if self.show_words_to_rc.load(Ordering::Relaxed)
            || actions_found & FILTER_ACTION_TELLRC != 0
        {
            if let Some(server) = self.server.upgrade() {
                server.send_rc_chat(&format!(
                    "Word Filter: Player {} was caught using these words: {}",
                    player.account_name(),
                    bad_words
                ));
            }
        }
        if actions_found & FILTER_ACTION_WARN != 0 {
            if warn_message.is_empty() {
                return self.default_warn_message.read().unwrap().clone();
            }
            return warn_message;
        }
        output
    }
}

fn word_filter_precision_matches(rule: &WordFilterRule, words_matched: usize) -> bool {
    if !rule.precision_percentage {
        return words_matched >= rule.precision.max(0) as usize;
    }
    if rule.matching.is_empty() {
        return false;
    }
    rule.precision <= ((words_matched as f64 / rule.matching.len() as f64) * 100.0) as i32
}

// ---------------------------------------------------------------------------
// Server lifecycle and global collections

pub struct Server {
    self_weak: Weak<Server>,
    pub name: RwLock<String>,
    running: AtomicBool,
    pub config: Arc<FileSystem>,
    pub settings: Arc<Settings>,
    pub admin_settings: Arc<Settings>,
    pub logger: Arc<Logger>,
    pub socket_mgr: Arc<SocketManager>,
    listener: Mutex<Option<TcpListener>>,
    pub players: RwLock<HashMap<u16, Arc<Player>>>,
    player_id_gen: Mutex<u16>,
    pub allowed_versions: RwLock<Vec<String>>,
    pub levels: RwLock<HashMap<String, Arc<Level>>>,
    pub maps: RwLock<Vec<Arc<Map>>>,
    pub npcs: RwLock<HashMap<u32, Arc<NPC>>>,
    npc_id_gen: Mutex<u32>,
    pub weapons: RwLock<HashMap<String, Arc<Weapon>>>,
    pub classes: RwLock<HashMap<String, Arc<ScriptClass>>>,
    pub flags: RwLock<HashMap<String, String>>,
    pub ip_bans: RwLock<Vec<String>>,
    pub translations: RwLock<HashMap<String, HashMap<String, String>>>,
    pub server_list: RwLock<Option<Arc<ServerList>>>,
    pub server_lists: RwLock<Vec<Arc<ServerList>>>,
    api_auth: Mutex<HashMap<u16, Sender<ApiAuthResult>>>,
    pub listserver_cache: RwLock<HashMap<String, CachedListserverServer>>,
    fake_player_count: Mutex<Option<i32>>,
    pub npc_server: Arc<NPCServer>,
    pub gs2_sockets: Arc<GS2SocketManager>,
    gs2_log_hook_active: AtomicBool,
    pub server_message: RwLock<String>,
    server_time: AtomicU32,
    pub start_time: SystemTime,
    shutdown: AtomicBool,
    restart_requested: AtomicBool,
    config_loading: AtomicBool,
    pub word_filter: Arc<WordFilter>,
    pub script_help: RwLock<Vec<ScriptHelpEntry>>,
    pub script_help_ready: AtomicBool,
    pub script_help_raw: RwLock<String>,
    pub script_help_check: Mutex<Instant>,
    pub script_help_busy: AtomicBool,
    last_timer: Mutex<Instant>,
    last_minute: Mutex<Instant>,
    last_five_minute: Mutex<Instant>,
}

struct ApiAuthResult {
    account: String,
    message: String,
}

impl Server {
    pub fn set_script_help_entries(&self, mut entries: Vec<ScriptHelpEntry>) {
        entries.sort_by_key(|entry| entry.name.to_ascii_lowercase());
        *self.script_help.write().unwrap() = entries;
        self.script_help_ready.store(true, Ordering::Relaxed);
        *self.script_help_check.lock().unwrap() = Instant::now();
    }

    pub fn setScriptHelpEntries(&self, entries: Vec<ScriptHelpEntry>) {
        self.set_script_help_entries(entries)
    }

    pub fn script_help_entries(&self) -> Vec<ScriptHelpEntry> {
        self.script_help.read().unwrap().clone()
    }

    pub fn scriptHelpEntries(&self) -> Vec<ScriptHelpEntry> {
        self.script_help_entries()
    }

    fn refresh_script_help_cache(&self) {
        if self
            .script_help_busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let result = (|| {
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .map_err(|error| error.to_string())?;
            let response = client
                .get("https://api.gscript.dev")
                .send()
                .map_err(|error| error.to_string())?;
            if !response.status().is_success() {
                return Err(format!("HTTP {}", response.status().as_u16()));
            }
            response.bytes().map_err(|error| error.to_string())
        })();

        match result {
            Ok(data) => {
                let raw_text = String::from_utf8_lossy(&data).into_owned();
                let unchanged = self.script_help_ready.load(Ordering::Acquire)
                    && *self.script_help_raw.read().unwrap() == raw_text;
                if !unchanged {
                    match serde_json::from_slice::<HashMap<String, ScriptHelpEntry>>(&data) {
                        Ok(raw) => {
                            let mut entries = raw
                                .into_iter()
                                .map(|(key, mut entry)| {
                                    if entry.name.is_empty() {
                                        entry.name = key;
                                    }
                                    entry
                                })
                                .collect::<Vec<_>>();
                            entries.sort_by_key(|entry| entry.name.to_ascii_lowercase());
                            *self.script_help.write().unwrap() = entries;
                            *self.script_help_raw.write().unwrap() = raw_text;
                            self.script_help_ready.store(true, Ordering::Release);
                        }
                        Err(error) => self
                            .logger
                            .warning(&format!("Script help cache decode failed: {error}")),
                    }
                }
            }
            Err(error) => self
                .logger
                .warning(&format!("Script help cache failed: {error}")),
        }

        self.script_help_busy.store(false, Ordering::Release);
        *self.script_help_check.lock().unwrap() = Instant::now();
    }

    fn spawn_script_help_refresh(&self) {
        let Some(server) = self.self_weak.upgrade() else {
            return;
        };
        thread::spawn(move || server.refresh_script_help_cache());
    }

    pub fn refresh_script_help_cache_if_stale(&self) {
        let stale = !self.script_help_ready.load(Ordering::Relaxed)
            || self.script_help_check.lock().unwrap().elapsed() >= SCRIPT_HELP_CACHE_TTL;
        if stale && !self.script_help_busy.load(Ordering::Acquire) {
            self.spawn_script_help_refresh();
        }
    }

    pub fn refreshScriptHelpCacheIfStale(&self) {
        self.refresh_script_help_cache_if_stale()
    }

    pub fn scan_script_files(
        &self,
        scope: &str,
        query: &str,
        limit: usize,
        can_read: Option<&dyn Fn(&str) -> bool>,
    ) -> (Vec<ScriptScanMatch>, bool) {
        if limit == 0 {
            return (Vec::new(), false);
        }
        let base_path = self.config.get_base_path();
        let mut matches = Vec::new();
        for root in script_scan_roots(scope) {
            let root_path = base_path.join(&root.path);
            let mut files = Vec::new();
            walk_script_scan_files(&root_path, &mut files);
            for file_path in files {
                if !is_script_scan_text_file(&file_path, root.level_only) {
                    continue;
                }
                let Ok(relative_path) = file_path.strip_prefix(&base_path) else {
                    continue;
                };
                let relative_path = relative_path.to_string_lossy().replace('\\', "/");
                if let Some(can_read) = can_read {
                    if !can_read(&relative_path) {
                        continue;
                    }
                }
                let Ok(data) = std::fs::read(&file_path) else {
                    continue;
                };
                let Some(lines) = script_scan_context(&data, query) else {
                    continue;
                };
                matches.push(ScriptScanMatch {
                    path: relative_path.clone(),
                    display: script_scan_display_name(&root, &relative_path, &data),
                    lines,
                });
                if matches.len() >= limit {
                    return (matches, true);
                }
            }
        }
        (matches, false)
    }

    pub fn scanScriptFiles(
        &self,
        scope: &str,
        query: &str,
        limit: usize,
        can_read: Option<&dyn Fn(&str) -> bool>,
    ) -> (Vec<ScriptScanMatch>, bool) {
        self.scan_script_files(scope, query, limit, can_read)
    }

    fn create(name: &str, base_path: &str, logger: Arc<Logger>) -> Arc<Self> {
        let config = Arc::new(FileSystem::new(base_path));
        let settings = Arc::new(Settings::new());
        let admin_settings = Arc::new(Settings::new());
        let socket_mgr = SocketManager::new();
        let start_time = SystemTime::now();
        Arc::new_cyclic(|weak| {
            let npc_server = Arc::new(NPCServer::new_internal(weak));
            let word_filter = Arc::new(WordFilter::new(weak));
            let list = Arc::new(ServerList::new_internal(weak, "", ""));
            Self {
                self_weak: weak.clone(),
                name: RwLock::new(name.to_string()),
                running: AtomicBool::new(false),
                config: config.clone(),
                settings: settings.clone(),
                admin_settings: admin_settings.clone(),
                logger: logger.clone(),
                socket_mgr: socket_mgr.clone(),
                listener: Mutex::new(None),
                players: RwLock::new(HashMap::new()),
                player_id_gen: Mutex::new(PLAYERID_INIT),
                allowed_versions: RwLock::new(Vec::new()),
                levels: RwLock::new(HashMap::new()),
                maps: RwLock::new(Vec::new()),
                npcs: RwLock::new(HashMap::new()),
                npc_id_gen: Mutex::new(NPCID_INIT),
                weapons: RwLock::new(HashMap::new()),
                classes: RwLock::new(HashMap::new()),
                flags: RwLock::new(HashMap::new()),
                ip_bans: RwLock::new(Vec::new()),
                translations: RwLock::new(HashMap::new()),
                server_list: RwLock::new(Some(list.clone())),
                server_lists: RwLock::new(vec![list]),
                api_auth: Mutex::new(HashMap::new()),
                listserver_cache: RwLock::new(HashMap::new()),
                fake_player_count: Mutex::new(None),
                npc_server,
                gs2_sockets: Arc::new(GS2SocketManager::new(weak)),
                gs2_log_hook_active: AtomicBool::new(false),
                server_message: RwLock::new(format!("Welcome to {name}")),
                server_time: AtomicU32::new(0),
                start_time,
                shutdown: AtomicBool::new(false),
                restart_requested: AtomicBool::new(false),
                config_loading: AtomicBool::new(false),
                word_filter,
                script_help: RwLock::new(Vec::new()),
                script_help_ready: AtomicBool::new(false),
                script_help_raw: RwLock::new(String::new()),
                script_help_check: Mutex::new(Instant::now() - SCRIPT_HELP_CACHE_TTL),
                script_help_busy: AtomicBool::new(false),
                last_timer: Mutex::new(Instant::now() - Duration::from_secs(1)),
                last_minute: Mutex::new(Instant::now() - Duration::from_secs(60)),
                last_five_minute: Mutex::new(Instant::now() - Duration::from_secs(300)),
            }
        })
    }

    pub fn new(name: &str) -> Arc<Self> {
        Self::create(name, ".", Arc::new(Logger::new("[SERVER] ", true)))
    }
    pub fn NewServer(name: &str) -> Arc<Self> {
        Self::new(name)
    }
    pub fn new_with_logger(
        name: &str,
        base_path: impl AsRef<Path>,
        logger: Arc<Logger>,
    ) -> Arc<Self> {
        Self::create(name, &base_path.as_ref().to_string_lossy(), logger)
    }
    pub fn NewServerWithLogger(
        name: &str,
        base_path: impl AsRef<Path>,
        logger: Arc<Logger>,
    ) -> Arc<Self> {
        Self::new_with_logger(name, base_path, logger)
    }
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
    pub fn running(&self) -> bool {
        self.is_running()
    }
    pub fn settings(&self) -> Arc<Settings> {
        self.settings.clone()
    }
    pub fn GetSettings(&self) -> Arc<Settings> {
        self.settings()
    }
    pub fn admin_settings(&self) -> Arc<Settings> {
        self.admin_settings.clone()
    }
    pub fn config(&self) -> Arc<FileSystem> {
        self.config.clone()
    }
    pub fn GetConfig(&self) -> Arc<FileSystem> {
        self.config()
    }
    pub fn logger(&self) -> Arc<Logger> {
        self.logger.clone()
    }
    pub fn GetLogger(&self) -> Arc<Logger> {
        self.logger()
    }
    pub fn get_server_time(&self) -> u32 {
        self.server_time.load(Ordering::Relaxed)
    }
    pub fn GetServerTime(&self) -> u32 {
        self.get_server_time()
    }
    pub fn get_server_start_time(&self) -> SystemTime {
        self.start_time
    }
    pub fn GetServerStartTime(&self) -> SystemTime {
        self.start_time
    }
    pub fn configured_name(&self) -> String {
        nonempty(&self.settings.get("name")).unwrap_or_else(|| {
            nonempty(&self.name.read().unwrap()).unwrap_or_else(|| "GServer".to_string())
        })
    }
    pub fn configuredName(&self) -> String {
        self.configured_name()
    }

    pub fn init(&self) -> io::Result<()> {
        self.init_with_args("", "", "", "")
    }
    pub fn init_with_args(
        &self,
        server_ip: &str,
        server_port: &str,
        local_ip: &str,
        server_interface: &str,
    ) -> io::Result<()> {
        self.logger.write(":: Initializing player listen socket.\n");
        if !server_ip.is_empty() {
            self.settings.set("serverip", server_ip);
        }
        if !server_port.is_empty() {
            self.settings.set("serverport", server_port);
        }
        if !local_ip.is_empty() {
            self.settings.set("localip", local_ip);
        }
        if !server_interface.is_empty() {
            self.settings.set("serverinterface", server_interface);
        }
        self.load_config_files();
        let port =
            nonempty(&self.settings.get("serverport")).unwrap_or_else(|| "14802".to_string());
        let address = format!(":{port}");
        // Bind the unspecified address. Rust's socket address parser does not
        // accept the shorthand ":port", so use an IPv4 wildcard first and
        // retain an IPv6 wildcard fallback
        // for hosts configured IPv6-only.
        let listener = TcpListener::bind(format!("0.0.0.0:{port}"))
            .or_else(|ipv4_error| {
                TcpListener::bind(format!("[::]:{port}")).map_err(|_| ipv4_error)
            })
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("failed to listen on {address}: {error}"),
                )
            })?;
        listener.set_nonblocking(true)?;
        *self.listener.lock().unwrap() = Some(listener);
        Ok(())
    }
    pub fn Init(&self) -> io::Result<()> {
        self.init()
    }
    pub fn InitWithArgs(
        &self,
        server_ip: &str,
        server_port: &str,
        local_ip: &str,
        server_interface: &str,
    ) -> io::Result<()> {
        self.init_with_args(server_ip, server_port, local_ip, server_interface)
    }

    pub fn run(self: &Arc<Self>) -> io::Result<()> {
        self.running.store(true, Ordering::Relaxed);
        self.logger.info("Server started");
        self.spawn_script_help_refresh();
        let listener = self
            .listener
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|value| value.try_clone().ok());
        let Some(listener) = listener else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "server listener is not initialized",
            ));
        };
        listener.set_nonblocking(true)?;
        while self.is_running() && !self.shutdown.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nodelay(true);
                    let server = self.clone();
                    thread::spawn(move || server.handle_accepted_connection(stream));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => {
                    if self.is_running() {
                        self.logger.error(&format!("Accept error: {error}"));
                    }
                }
            }
            let has_socket_entries = !self.socket_mgr.is_empty();
            self.socket_mgr.update(if has_socket_entries {
                Duration::ZERO
            } else {
                Duration::from_millis(20)
            });
            self.do_timed_events();
            if has_socket_entries {
                thread::sleep(Duration::from_millis(5));
            }
        }
        self.running.store(false, Ordering::Relaxed);
        self.socket_mgr.cleanup();
        Ok(())
    }
    pub fn Run(self: &Arc<Self>) -> io::Result<()> {
        self.run()
    }
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(listener) = self.listener.lock().unwrap().take() {
            let _ = listener.set_nonblocking(true);
            drop(listener);
        }
        self.socket_mgr.cleanup();
        self.gs2_sockets.close_all();
        self.npc_server.stop_watching();
        self.logger.info("Server stopped");
    }
    pub fn Stop(&self) {
        self.stop()
    }
    pub fn stop_soon(&self, restart: bool) {
        thread::sleep(Duration::from_millis(100));
        if restart {
            self.restart_requested.store(true, Ordering::Relaxed);
        }
        self.stop();
    }
    pub fn StopSoon(&self, restart: bool) {
        self.stop_soon(restart)
    }
    pub fn restart_requested(&self) -> bool {
        self.restart_requested.load(Ordering::Relaxed)
    }
    pub fn restartRequested(&self) -> bool {
        self.restart_requested()
    }

    fn handle_accepted_connection(self: Arc<Self>, stream: TcpStream) {
        let result = sniff_game_connection(stream);
        let Ok((stream, is_http)) = result else {
            return;
        };
        if is_http {
            crate::http_api::serve_connection(stream, self);
            return;
        }
        let player = Player::from_stream(stream, &self);
        player.set_async_write(true);
        self.socket_mgr.register(None, player);
    }

    fn do_timed_events(&self) {
        let now = Instant::now();
        self.server_time.fetch_add(1, Ordering::Relaxed);
        let mut last = self.last_timer.lock().unwrap();
        if now.duration_since(*last) >= Duration::from_secs(1) {
            *last = now;
            for list in self.server_lists.read().unwrap().iter() {
                list.do_timed_events();
            }
            for level in self
                .levels
                .read()
                .unwrap()
                .values()
                .cloned()
                .collect::<Vec<_>>()
            {
                level.process_board_respawns(self);
                level.process_item_timeouts(self);
                level.process_horse_timeouts(self);
                level.process_baddy_timeouts(self);
            }
            for npc in self.npcs.read().unwrap().values().cloned() {
                for _ in 0..20 {
                    let timeout = npc.timeout();
                    if timeout <= 0 {
                        break;
                    }
                    let next = timeout - 1;
                    npc.set_timeout(next);
                    if next == 0 {
                        if let Some(server) = self.self_weak.upgrade() {
                            let npc = npc.clone();
                            thread::spawn(move || npc.run_timeout(&server));
                        }
                        break;
                    }
                }
            }
            for player in self.get_all_players() {
                player.process_timeout();
                player.process_ap();
            }
        }
        let mut minute = self.last_minute.lock().unwrap();
        if now.duration_since(*minute) >= Duration::from_secs(60) {
            *minute = now;
            self.logger.debug("One minute timer");
            self.save_player_accounts();
        }
        let mut five = self.last_five_minute.lock().unwrap();
        if now.duration_since(*five) >= Duration::from_secs(300) {
            *five = now;
            self.logger.info("Five minute timer - saving data");
            self.save_data();
        }
    }
    pub fn doTimedEvents(&self) {
        self.do_timed_events()
    }
    pub fn should_use_login_server_mode(&self) -> bool {
        self.settings.get_bool("loginserver", false)
    }
    pub fn shouldUseLoginServerMode(&self) -> bool {
        self.should_use_login_server_mode()
    }

    pub fn next_player_id(&self) -> u16 {
        let mut id = self.player_id_gen.lock().unwrap();
        *id = id.wrapping_add(1);
        if *id < 2 {
            *id = 2;
        }
        *id
    }
    pub fn nextPlayerId(&self) -> u16 {
        self.next_player_id()
    }
    pub fn next_npc_id(&self) -> u32 {
        let mut id = self.npc_id_gen.lock().unwrap();
        *id = id.wrapping_add(1);
        if *id < NPCID_INIT {
            *id = NPCID_INIT;
        }
        *id
    }

    pub fn add_player(&self, player: Arc<Player>, id: u16) -> bool {
        self.remove_duplicate_control_sessions(&player);
        if id == 0 || id == 1 {
            return false;
        }
        let mut players = self.players.write().unwrap();
        if players.values().any(|value| Arc::ptr_eq(value, &player)) || players.contains_key(&id) {
            return false;
        }
        player.set_id(id);
        players.insert(id, player.clone());
        drop(players);
        self.logger.info(&format!(
            "Player {id} added (account: {})",
            player.account_name()
        ));
        if is_listserver_player(&player) && !player.state.lock().unwrap().awaiting_listserver_verify
        {
            self.add_player_to_listservers(&player);
        }
        true
    }
    pub fn AddPlayer(&self, player: Arc<Player>, id: u16) -> bool {
        self.add_player(player, id)
    }
    pub fn delete_player(&self, player: &Arc<Player>) {
        let id = player.id();
        let removed = self.players.write().unwrap().remove(&id);
        if removed.is_none() {
            return;
        }

        self.logger.info(&format!("Player {id} removed"));

        let remaining = self.get_all_players();
        if player.player_type() & PLTYPE_ANYCLIENT != 0 {
            self.run_server_side_event_for_active_scripts("onPlayerLogout", Some(player), &[]);
        }
        for list in self.listserver_targets() {
            list.DeletePlayer(player);
        }
        if player.player_type() & PLTYPE_NPCSERVER != 0 {
            self.handle_npc_server_player_removed(&remaining);
        }
        for other in remaining {
            let no_connection_or_queue = {
                let state = other.state.lock().unwrap();
                state.conn.is_none() && !state.queue_outgoing
            };
            if other.id() == id || !other.is_logged_in() || no_connection_or_queue {
                continue;
            }
            if other.player_type() & PLTYPE_ANYCLIENT != 0 {
                other.send_plo_otherplprops_disconnected(id);
            } else if other.player_type() & PLTYPE_ANYRC != 0 {
                other.send_plo_delplayer(id);
            }
        }
    }
    pub fn DeletePlayer(&self, player: &Arc<Player>) {
        self.delete_player(player)
    }
    pub fn get_player(&self, id: u16) -> Option<Arc<Player>> {
        self.players.read().unwrap().get(&id).cloned()
    }
    pub fn GetPlayer(&self, id: u16) -> Option<Arc<Player>> {
        self.get_player(id)
    }
    pub fn get_all_players(&self) -> Vec<Arc<Player>> {
        self.players.read().unwrap().values().cloned().collect()
    }
    pub fn GetAllPlayers(&self) -> Vec<Arc<Player>> {
        self.get_all_players()
    }
    pub fn get_player_count(&self) -> usize {
        self.players.read().unwrap().len()
    }
    pub fn GetPlayerCount(&self) -> usize {
        self.get_player_count()
    }
    pub fn get_player_by_account(&self, account: &str, player_type: i32) -> Option<Arc<Player>> {
        self.get_all_players().into_iter().find(|player| {
            player.account_name() == account
                && (player_type == 0
                    || player.player_type() == player_type
                    || player.player_type() & player_type != 0)
        })
    }
    pub fn account_exists(&self, account: &str) -> bool {
        account_file_read_paths(account)
            .iter()
            .any(|path| self.config.file_exists(path))
    }
    pub fn next_guest_pc_account_name(&self) -> String {
        for _ in 0..1000 {
            let value = format!("pc:{:06}", rand::random::<u32>() % 1_000_000);
            if self
                .get_player_by_account(&value, PLTYPE_ANYPLAYER)
                .is_none()
                && !self.account_exists(&value)
            {
                return value;
            }
        }
        format!("pc:{:06}", system_time_millis() % 1_000_000)
    }
    pub fn listserver_player_count(&self) -> i32 {
        self.fake_player_count.lock().unwrap().unwrap_or_else(|| {
            self.get_all_players()
                .into_iter()
                .filter(|player| is_listserver_player(player))
                .count() as i32
        })
    }
    pub fn set_fake_player_count(&self, value: Option<i32>) {
        *self.fake_player_count.lock().unwrap() = value;
        let count = self.listserver_player_count();
        for list in self.listserver_targets() {
            if list.is_connected() {
                list.set_plyr(count);
            }
        }
    }

    pub fn setFakePlayerCount(&self, value: Option<i32>) {
        self.set_fake_player_count(value)
    }

    fn remove_duplicate_control_sessions(&self, player: &Arc<Player>) {
        let player_type = player.player_type();
        if player_type & PLTYPE_ANYCONTROL == 0 {
            return;
        }
        let account = player.account_name().trim().to_string();
        if account.is_empty() {
            return;
        }
        let control_mask = if player_type & PLTYPE_ANYRC != 0 {
            PLTYPE_ANYRC
        } else if player_type & PLTYPE_ANYNC != 0 {
            PLTYPE_ANYNC
        } else {
            return;
        };
        let duplicates = self
            .get_all_players()
            .into_iter()
            .filter(|other| {
                !Arc::ptr_eq(other, player)
                    && other.player_type() & control_mask != 0
                    && other.account_name().trim().eq_ignore_ascii_case(&account)
            })
            .collect::<Vec<_>>();
        for other in duplicates {
            self.logger.info(&format!(
                "Removing stale control session for {account} (old id {}, new id {})",
                other.id(),
                player.id()
            ));
            other.disconnect();
        }
    }

    fn handle_npc_server_player_removed(&self, remaining: &[Arc<Player>]) {
        self.npc_server.runtime.set_stopped(true);
        self.npc_server.stop_watching();
        self.npc_server.enabled.store(false, Ordering::Relaxed);
        for other in remaining {
            if other.player_type() & PLTYPE_ANYNC != 0 {
                other.disconnect();
            }
        }
    }

    pub fn send_packet_to_all(&self, packet: &[u8], exclude: &HashMap<u16, bool>) {
        for player in self.get_all_players() {
            if !exclude.get(&player.id()).copied().unwrap_or(false) {
                player.send_packet(packet);
            }
        }
    }
    pub fn SendPacketToAll(&self, packet: &[u8], exclude: &HashMap<u16, bool>) {
        self.send_packet_to_all(packet, exclude)
    }
    pub fn send_packet_to_type(
        &self,
        player_type: i32,
        packet: &[u8],
        exclude: Option<&Arc<Player>>,
    ) {
        for player in self.get_all_players() {
            if player.player_type() & player_type != 0
                && exclude
                    .map(|value| !Arc::ptr_eq(value, &player))
                    .unwrap_or(true)
            {
                player.send_packet(packet);
            }
        }
    }
    pub fn SendPacketToType(&self, player_type: i32, packet: &[u8], exclude: Option<&Arc<Player>>) {
        // This exported helper intentionally uses exact type equality. Callers
        // that need bitmask behavior use the lowercase helper.
        for player in self.get_all_players() {
            if player.player_type() == player_type
                && exclude
                    .map(|value| !Arc::ptr_eq(value, &player))
                    .unwrap_or(true)
            {
                player.send_packet(packet);
            }
        }
    }

    pub fn allows_warp_to_all(&self) -> bool {
        self.settings.get_bool("warptoforall", false)
    }
    pub fn allowsWarpToAll(&self) -> bool {
        self.allows_warp_to_all()
    }

    pub fn find_player_by_account_or_nick(
        &self,
        name: &str,
        player_type: i32,
    ) -> Option<Arc<Player>> {
        self.get_all_players().into_iter().find(|player| {
            (player_type == 0
                || player.player_type() == player_type
                || player.player_type() & player_type != 0)
                && (player.account_name().eq_ignore_ascii_case(name)
                    || player.nickname().eq_ignore_ascii_case(name))
        })
    }
    pub fn findPlayerByAccountOrNick(&self, name: &str, player_type: i32) -> Option<Arc<Player>> {
        self.find_player_by_account_or_nick(name, player_type)
    }
    pub fn send_buffer_to_type(&self, player_type: i32, buffer: &Buffer) {
        for player in self.get_all_players() {
            if player.player_type() & player_type != 0 {
                player.send(buffer);
            }
        }
    }
    pub fn sendBufferToType(&self, player_type: i32, buffer: &Buffer) {
        self.send_buffer_to_type(player_type, buffer)
    }
    pub fn broadcast_server_flag_set(&self, name: &str, value: &str) {
        for player in self.get_all_players() {
            if matches!(
                player.player_type(),
                PLTYPE_CLIENT | PLTYPE_CLIENT2 | PLTYPE_CLIENT3
            ) {
                player.send_plo_flagset(name, value);
            }
        }
    }
    pub fn broadcast_server_flag_delete(&self, name: &str) {
        for player in self.get_all_players() {
            if matches!(
                player.player_type(),
                PLTYPE_CLIENT | PLTYPE_CLIENT2 | PLTYPE_CLIENT3
            ) {
                player.send_plo_flagdel(name);
            }
        }
    }

    pub fn broadcast_board_modify(
        &self,
        level: &Level,
        x: i16,
        y: i16,
        width: i16,
        height: i16,
        tiles: &[i16],
    ) {
        for player_id in level.get_players() {
            if let Some(player) = self.get_player(player_id) {
                if player.has_connection() {
                    player.send_plo_boardmodify(x, y, width, height, tiles);
                }
            }
        }
    }

    pub fn broadcastBoardModify(
        &self,
        level: &Level,
        x: i16,
        y: i16,
        width: i16,
        height: i16,
        tiles: &[i16],
    ) {
        self.broadcast_board_modify(level, x, y, width, height, tiles)
    }

    pub fn broadcast_item_add(&self, level: &Level, x: i16, y: i16, item: i32) {
        for player_id in level.get_players() {
            if let Some(player) = self.get_player(player_id) {
                if player.has_connection() {
                    player.send_plo_itemadd(x, y, item, "");
                }
            }
        }
    }

    pub fn broadcastItemAdd(&self, level: &Level, x: i16, y: i16, item: i32) {
        self.broadcast_item_add(level, x, y, item)
    }

    pub fn resend_level_data(&self, level: &Arc<Level>) {
        for id in level.get_players() {
            let Some(player) = self.get_player(id) else {
                continue;
            };
            if !player.has_connection() {
                continue;
            }
            let mut level_name = player.level_name();
            if level_name.is_empty() {
                level_name = level.get_name();
            }
            if level_name.contains('/') || level_name.contains('\\') {
                level_name = Path::new(&level_name)
                    .file_name()
                    .map(|value| value.to_string_lossy().into_owned())
                    .unwrap_or(level_name);
            }
            let (x, y) = player.position();
            player.warp(&level_name, f64::from(x) / 16.0, f64::from(y) / 16.0, 0);
        }
    }
    pub fn resendLevelData(&self, level: &Arc<Level>) {
        self.resend_level_data(level)
    }

    pub fn get_flag(&self, name: &str) -> String {
        self.flags
            .read()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or_default()
    }
    pub fn GetFlag(&self, name: &str) -> String {
        self.get_flag(name)
    }
    pub fn cache_listserver_text(&self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let text = String::from_utf8_lossy(data)
            .trim_end_matches('\0')
            .trim()
            .to_string();
        if text.is_empty() {
            return;
        }
        // List-server text is either a server record stream or a modify
        // notification. Keep case-insensitive keying while accepting the wire
        // format's CR/LF/SOH separators.
        if text
            .to_ascii_lowercase()
            .starts_with("listserver,modify,server,")
        {
            let fields = text.split(',').collect::<Vec<_>>();
            if fields.len() >= 4 && !fields[3].trim().is_empty() {
                let name = fields[3].trim().to_string();
                let key = name.to_ascii_lowercase();
                let mut cache = self.listserver_cache.write().unwrap();
                let entry = cache.entry(key).or_insert_with(|| CachedListserverServer {
                    name: name.clone(),
                    ..CachedListserverServer::default()
                });
                entry.name = name;
                entry.updated = SystemTime::now();
                for field in fields.iter().skip(4) {
                    if let Some((key, value)) = field.trim().split_once('=') {
                        match key.trim().to_ascii_lowercase().as_str() {
                            "type" => entry.server_type = value.to_string(),
                            "players" | "playercount" => {
                                entry.player_count = value.trim().parse().unwrap_or(0)
                            }
                            "language" => entry.language = value.to_string(),
                            "description" | "desc" => entry.description = value.to_string(),
                            "url" | "website" => entry.url = value.to_string(),
                            "version" | "serverversion" => entry.version = value.to_string(),
                            "gameversions" | "allowedversions" => {
                                entry.game_versions = value.to_string()
                            }
                            "latency" | "ping" => entry.latency = value.trim().parse().unwrap_or(0),
                            _ => {}
                        }
                    }
                }
            }
            return;
        }
        let normalized = text
            .replace("\r\n", "\n")
            .replace('\r', "\n")
            .replace('\u{1}', "\n");
        for record in normalized.split('\n') {
            let decoded_record = if record.contains(',') {
                guntokenize_text(record)
            } else {
                record.to_string()
            };
            let fields = decoded_record
                .split('\n')
                .map(str::trim)
                .collect::<Vec<_>>();
            if fields.len() < 3 || fields[0].is_empty() {
                continue;
            }
            if fields[0].eq_ignore_ascii_case("listserver")
                || fields[0].eq_ignore_ascii_case(IRC_BYTES)
            {
                continue;
            }
            let name = fields[0].to_string();
            self.listserver_cache.write().unwrap().insert(
                name.to_ascii_lowercase(),
                CachedListserverServer {
                    name,
                    server_type: fields.get(1).unwrap_or(&"").to_string(),
                    player_count: fields.get(2).and_then(|v| v.parse().ok()).unwrap_or(0),
                    language: fields.get(3).unwrap_or(&"").to_string(),
                    description: fields.get(4).unwrap_or(&"").to_string(),
                    url: fields.get(5).unwrap_or(&"").to_string(),
                    version: fields.get(6).unwrap_or(&"").to_string(),
                    game_versions: fields.get(7).unwrap_or(&"").to_string(),
                    latency: fields.get(8).and_then(|v| v.parse().ok()).unwrap_or(0),
                    updated: SystemTime::now(),
                },
            );
        }
    }
    pub fn cacheListserverText(&self, data: &[u8]) {
        self.cache_listserver_text(data)
    }
    pub fn set_flag(&self, name: &str, value: &str) {
        self.flags
            .write()
            .unwrap()
            .insert(name.to_string(), value.to_string());
    }
    pub fn SetFlag(&self, name: &str, value: &str) {
        self.set_flag(name, value)
    }
    pub fn delete_flag(&self, name: &str) {
        self.flags.write().unwrap().remove(name);
    }
    pub fn DeleteFlag(&self, name: &str) {
        self.delete_flag(name)
    }
    pub fn set_server_flag_live(&self, name: &str, value: &str) {
        if is_valid_server_flag(name, value) {
            self.set_flag(name, value);
            self.broadcast_server_flag_set(name, value);
        }
    }
    pub fn SetServerFlagLive(&self, name: &str, value: &str) {
        self.set_server_flag_live(name, value)
    }
    pub fn delete_server_flag_live(&self, name: &str) {
        if is_valid_server_flag(name, "") {
            self.delete_flag(name);
            self.broadcast_server_flag_delete(name);
        }
    }
    pub fn DeleteServerFlagLive(&self, name: &str) {
        self.delete_server_flag_live(name)
    }

    pub fn add_npc(&self, npc: Arc<NPC>) -> bool {
        let mut generator = self.npc_id_gen.lock().unwrap();
        let mut id = npc.id();
        if id == 0 {
            if *generator < NPCID_INIT {
                *generator = NPCID_INIT;
            }
            id = *generator;
            npc.set_id(id);
        }
        let mut npcs = self.npcs.write().unwrap();
        if npcs.contains_key(&id) {
            return false;
        }
        npcs.insert(id, npc);
        if id >= *generator {
            *generator = id.wrapping_add(1);
        }
        true
    }
    pub fn AddNPC(&self, npc: Arc<NPC>) -> bool {
        self.add_npc(npc)
    }
    pub fn delete_npc(&self, id: u32) -> bool {
        let removed = self.npcs.write().unwrap().remove(&id);
        if let Some(npc) = removed {
            for player in self.get_all_players() {
                if player.player_type() & PLTYPE_ANYCLIENT != 0 {
                    player.send_plo_npcdel(id);
                }
            }
            if let Some(level) = npc.level() {
                level.state.write().unwrap().npcs.remove(&id);
            }
            true
        } else {
            false
        }
    }
    pub fn DeleteNPC(&self, id: u32) -> bool {
        self.delete_npc(id)
    }
    pub fn get_npc(&self, id: u32) -> Option<Arc<NPC>> {
        self.npcs.read().unwrap().get(&id).cloned()
    }
    pub fn GetNPC(&self, id: u32) -> Option<Arc<NPC>> {
        self.get_npc(id)
    }
    pub fn add_level(&self, level: Arc<Level>) {
        let name = level.get_name();
        self.levels.write().unwrap().insert(name, level.clone());
        self.associate_level_map(&level);
    }
    pub fn AddLevel(&self, level: Arc<Level>) {
        self.add_level(level)
    }
    pub fn delete_level(&self, name: &str) {
        self.levels.write().unwrap().remove(name);
    }
    pub fn DeleteLevel(&self, name: &str) {
        self.delete_level(name)
    }
    fn associate_level_map(&self, level: &Arc<Level>) {
        let level_name = level.get_name().replace('\\', "/").to_ascii_lowercase();
        let maps = self.maps.read().unwrap().clone();
        let mut state = level.state.write().unwrap();
        state.map_ref = None;
        state.map_x = 0;
        state.map_y = 0;
        for map in maps {
            if let Some((x, y)) = map.is_level_on_map(&level_name) {
                state.map_ref = Some(map);
                state.map_x = x;
                state.map_y = y;
                break;
            }
        }
    }
    fn find_level(&self, name: &str) -> (Option<Arc<Level>>, bool) {
        let level = self.levels.read().unwrap().get(name).cloned();
        (level.clone(), level.is_some())
    }
    fn delete_level_if_same(&self, name: &str, target: &Arc<Level>) {
        let mut levels = self.levels.write().unwrap();
        if levels
            .get(name)
            .is_some_and(|level| Arc::ptr_eq(level, target))
        {
            levels.remove(name);
        }
    }
    pub fn get_level(&self, name: &str) -> Option<Arc<Level>> {
        let name = name.trim().replace('\\', "/");
        if name.is_empty() {
            return None;
        }
        let clean = clean_level_name(&name);
        if let Some(level) = self
            .levels
            .read()
            .unwrap()
            .get(&name)
            .cloned()
            .or_else(|| self.levels.read().unwrap().get(&clean).cloned())
        {
            return Some(level);
        }
        for candidate in level_file_candidates(&name) {
            let level = Arc::new(Level::new());
            if level.load_level_with_arc(self, &candidate, Some(level.clone())) {
                self.add_level(level.clone());
                level.attach_entity_levels(&level);
                return Some(level);
            }
        }
        None
    }
    pub fn GetLevel(&self, name: &str) -> Option<Arc<Level>> {
        self.get_level(name)
    }
    pub fn resolve_requested_file(&self, file_name: &str) -> io::Result<(String, Vec<u8>)> {
        if let Ok(data) = self.config.load_file(file_name) {
            return Ok((file_name.to_string(), data));
        }
        if Path::new(file_name)
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| value.eq_ignore_ascii_case("gupd"))
            .unwrap_or(false)
        {
            let base = Path::new(file_name)
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy();
            let package = format!("packages/{base}.gupd");
            if let Ok(data) = self.config.load_file(&package) {
                return Ok((package, data));
            }
            return self
                .config
                .load_file(file_name)
                .map(|data| (file_name.to_string(), data));
        }
        if file_name.contains('/') || file_name.contains(char::from(92)) {
            return self
                .config
                .load_file(file_name)
                .map(|data| (file_name.to_string(), data));
        }
        if let Ok(lines) = self.config.load_file_as_lines("config/foldersconfig.txt") {
            for line in lines {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                if fields.len() < 2 {
                    continue;
                }
                let pattern = fields[1].replace(char::from(92), "/");
                let base_pattern = Path::new(&pattern)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy();
                if !glob_match(
                    &base_pattern.to_ascii_lowercase(),
                    &file_name.to_ascii_lowercase(),
                ) {
                    continue;
                }
                let prefix = pattern
                    .strip_suffix(base_pattern.as_ref())
                    .unwrap_or_default();
                let candidate = format!("{prefix}{file_name}");
                if let Ok(data) = self.config.load_file(&candidate) {
                    return Ok((candidate, data));
                }
            }
        }
        self.config
            .load_file(file_name)
            .map(|data| (file_name.to_string(), data))
    }
    pub fn resolveRequestedFile(&self, file_name: &str) -> io::Result<(String, Vec<u8>)> {
        self.resolve_requested_file(file_name)
    }
    pub fn load_level(&self, name: &str) -> Option<Arc<Level>> {
        if let Some(level) = self.levels.read().unwrap().get(name).cloned() {
            return Some(level);
        }
        let level = Arc::new(Level::new());
        level.set_level_name(name);
        {
            let mut state = level.state.write().unwrap();
            state.file_name = name.to_string();
            state.actual_level_name = name.to_string();
        }
        self.add_level(level.clone());
        self.logger
            .debug(&format!("loadLevel: Created new level '{name}'"));
        Some(level)
    }
    pub fn add_weapon(&self, weapon: Arc<Weapon>) {
        self.weapons
            .write()
            .unwrap()
            .insert(weapon.name.clone(), weapon);
    }
    pub fn AddWeapon(&self, weapon: Arc<Weapon>) {
        self.add_weapon(weapon)
    }
    pub fn get_weapon(&self, name: &str) -> Option<Arc<Weapon>> {
        let weapons = self.weapons.read().unwrap();
        weapons
            .get(name)
            .cloned()
            .or_else(|| weapons.get(&name.to_ascii_lowercase()).cloned())
            .or_else(|| {
                weapons
                    .values()
                    .find(|value| value.name.eq_ignore_ascii_case(name))
                    .cloned()
            })
    }
    pub fn GetWeapon(&self, name: &str) -> Option<Arc<Weapon>> {
        self.get_weapon(name)
    }

    pub fn update_weapon_for_players(&self, weapon: &Arc<Weapon>) {
        if weapon.name.is_empty() {
            return;
        }
        let players = self
            .get_all_players()
            .into_iter()
            .filter(|player| {
                player.player_type() & PLTYPE_ANYCLIENT != 0
                    && player.has_account_weapon(&weapon.name)
            })
            .collect::<Vec<_>>();
        for player in players {
            player.send_plo_npcweapondel(&weapon.name);
            player.send_account_weapon(&weapon.name);
        }
    }

    pub fn updateWeaponForPlayers(&self, weapon: &Arc<Weapon>) {
        self.update_weapon_for_players(weapon)
    }

    pub fn update_all_weapons_for_players(&self) {
        let mut seen = HashSet::new();
        let weapons = self
            .weapons
            .read()
            .unwrap()
            .values()
            .filter(|weapon| seen.insert(Arc::as_ptr(weapon) as usize))
            .cloned()
            .collect::<Vec<_>>();
        for weapon in weapons {
            self.update_weapon_for_players(&weapon);
        }
    }

    pub fn updateAllWeaponsForPlayers(&self) {
        self.update_all_weapons_for_players()
    }

    pub fn update_class_for_players(&self, class_obj: &Arc<ScriptClass>) {
        if class_obj.script.is_empty() {
            return;
        }
        let players = self
            .get_all_players()
            .into_iter()
            .filter(|player| {
                player.player_type() & PLTYPE_ANYCLIENT != 0 && player.version_id() >= 300
            })
            .collect::<Vec<_>>();
        for player in players {
            player.send_raw_npc_weapon_script(class_obj.script.as_bytes());
        }
    }

    pub fn updateClassForPlayers(&self, class_obj: &Arc<ScriptClass>) {
        self.update_class_for_players(class_obj)
    }

    pub fn add_class(&self, class_obj: Arc<ScriptClass>) {
        self.classes
            .write()
            .unwrap()
            .insert(class_obj.name.clone(), class_obj);
    }
    pub fn get_class(&self, name: &str) -> Option<Arc<ScriptClass>> {
        let classes = self.classes.read().unwrap();
        classes.get(name).cloned().or_else(|| {
            classes
                .values()
                .find(|value| value.name.eq_ignore_ascii_case(name))
                .cloned()
        })
    }
    pub fn GetClass(&self, name: &str) -> Option<Arc<ScriptClass>> {
        self.get_class(name)
    }
    pub fn delete_weapon(&self, name: &str) {
        self.weapons
            .write()
            .unwrap()
            .retain(|key, value| key != name && !value.name.eq_ignore_ascii_case(name));
    }
    pub fn DeleteWeapon(&self, name: &str) {
        self.delete_weapon(name)
    }
    pub fn delete_class(&self, name: &str) -> bool {
        let mut classes = self.classes.write().unwrap();
        let keys = classes
            .iter()
            .filter(|(key, value)| {
                key.eq_ignore_ascii_case(name) || value.name.eq_ignore_ascii_case(name)
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let existed = !keys.is_empty();
        for key in keys {
            classes.remove(&key);
        }
        existed
    }
    pub fn DeleteClass(&self, name: &str) -> bool {
        self.delete_class(name)
    }
    pub fn save_weapon_file(&self, weapon: &mut Weapon) -> io::Result<()> {
        if weapon.name.is_empty() || weapon.def_player {
            return Ok(());
        }
        if !weapon.bytecode.is_empty() {
            weapon.bytecode_file = weapon_bytecode_file_name(&weapon.name);
            self.config.save_file(
                format!("weapon_bytecode/{}", weapon.bytecode_file),
                &weapon.bytecode,
            )?;
        }
        let mut out = String::from("GRAWP001\r\n");
        let _ = writeln!(out, "REALNAME {}\r", weapon.name);
        let _ = writeln!(out, "IMAGE {}\r", weapon.image);
        if !weapon.bytecode_file.is_empty() {
            let _ = writeln!(out, "BYTECODE {}\r", weapon.bytecode_file);
        }
        if !weapon.script.is_empty() {
            out.push_str("SCRIPT\r\n");
            let script = weapon.script.replace("\r\n", "\n");
            out.push_str(&script.replace('\n', "\r\n"));
            if !script.ends_with('\n') {
                out.push_str("\r\n");
            }
            out.push_str("SCRIPTEND\r\n");
        }
        self.config.save_file(
            format!(
                "weapons/weapon{}.txt",
                sanitize_weapon_file_name(&weapon.name)
            ),
            out.as_bytes(),
        )
    }
    pub fn saveWeaponFile(&self, weapon: &mut Weapon) -> io::Result<()> {
        self.save_weapon_file(weapon)
    }
    pub fn delete_weapon_file(&self, name: &str) -> io::Result<()> {
        for path in [
            format!("weapons/weapon{}.txt", sanitize_weapon_file_name(name)),
            format!("weapons/{}", legacy_weapon_file_name(name)),
        ] {
            match self.config.delete_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    pub fn deleteWeaponFile(&self, name: &str) -> io::Result<()> {
        self.delete_weapon_file(name)
    }
    pub fn save_class_file(&self, name: &str, script: &str) -> io::Result<()> {
        self.config
            .save_file(format!("scripts/{name}.txt"), script.as_bytes())
    }
    pub fn saveClassFile(&self, name: &str, script: &str) -> io::Result<()> {
        self.save_class_file(name, script)
    }
    pub fn delete_class_file(&self, name: &str) -> io::Result<()> {
        match self.config.delete_file(format!("scripts/{name}.txt")) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
    pub fn deleteClassFile(&self, name: &str) -> io::Result<()> {
        self.delete_class_file(name)
    }
    pub fn save_database_npc_file(&self, npc: &NPC) -> io::Result<()> {
        save_database_npc_file(self, npc)
    }
    pub fn saveDatabaseNPCFile(&self, npc: &NPC) -> io::Result<()> {
        self.save_database_npc_file(npc)
    }
    pub fn save_put_npcs(&self) -> io::Result<usize> {
        let levels = self
            .levels
            .read()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut count = 0usize;
        for level in levels {
            let npcs = level
                .get_npcs()
                .into_iter()
                .filter(|npc| npc.npc_type() == NPCType::PUTNPC)
                .collect::<Vec<_>>();
            for npc in npcs {
                let mut state = npc.state.lock().unwrap().clone();
                state.npc_type = NPCType::DBNPC;
                state.npc_name = saved_put_npc_name(&level.get_name(), state.id, count + 1);
                if state.script_type.trim().is_empty() {
                    state.script_type = "PUTNPC".to_string();
                }
                if state.scripter.trim().is_empty() {
                    state.scripter = "NPC-Server".to_string();
                }
                state.level = Some(level.clone());
                let saved = NPC {
                    state: Mutex::new(state),
                };
                save_npc_file(self, &saved, &format!("npcs/npc{}.txt", saved.npc_name()))?;
                count += 1;
            }
        }
        Ok(count)
    }
    pub fn savePutNPCs(&self) -> io::Result<usize> {
        self.save_put_npcs()
    }
    pub fn delete_database_npc_file(&self, name: &str) -> io::Result<()> {
        delete_database_npc_file(self, name)
    }
    pub fn deleteDatabaseNPCFile(&self, name: &str) -> io::Result<()> {
        self.delete_database_npc_file(name)
    }
    pub fn npc_server_mode(&self) -> String {
        let value = self.settings.get("npcservermode");
        if value.is_empty() {
            "embedded".to_string()
        } else {
            value.to_ascii_lowercase()
        }
    }
    pub fn npcServerMode(&self) -> String {
        self.npc_server_mode()
    }
    pub fn npc_server_available(&self) -> bool {
        if self.npc_server_running() {
            return true;
        }
        self.npc_server_mode() == "external" && self.npc_server.player().is_some()
    }
    pub fn npcServerAvailable(&self) -> bool {
        self.npc_server_available()
    }
    pub fn npc_server_running(&self) -> bool {
        self.npc_server.enabled()
            && self.npc_server_mode() == "embedded"
            && self.settings.get_bool("serverside", false)
    }
    pub fn npc_server_owns_npc_props(&self) -> bool {
        self.npc_server_mode() == "external" || self.npc_server_running()
    }
    pub fn npcServerOwnsNPCProps(&self) -> bool {
        self.npc_server_owns_npc_props()
    }
    pub fn default_rc_folder_rights(&self) -> Vec<String> {
        self.config
            .load_file_as_lines("config/foldersconfig.txt")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|line| {
                let parts: Vec<_> = line.split_whitespace().collect();
                if parts.len() >= 2
                    && !line.trim_start().starts_with('#')
                    && !line.trim_start().starts_with('/')
                {
                    Some(format!("rw {}", parts[1..].join(" ")))
                } else {
                    None
                }
            })
            .collect()
    }

    fn listserver_targets(&self) -> Vec<Arc<ServerList>> {
        let primary = self.server_list.read().unwrap().clone();
        let configured = self.server_lists.read().unwrap().clone();
        let mut result = Vec::with_capacity(configured.len() + usize::from(primary.is_some()));
        if let Some(primary) = primary {
            result.push(primary);
        }
        for list in configured {
            if !result.iter().any(|existing| Arc::ptr_eq(existing, &list)) {
                result.push(list);
            }
        }
        result
    }

    pub fn active_server_names(&self) -> Vec<String> {
        let mut names = self
            .listserver_cache
            .read()
            .unwrap()
            .values()
            .map(|server| server.name.trim().to_string())
            .filter(|name| !name.is_empty())
            .collect::<Vec<_>>();
        let configured = self.configured_name();
        if !configured.is_empty()
            && !names
                .iter()
                .any(|name| name.eq_ignore_ascii_case(&configured))
        {
            names.push(configured);
        }
        names.sort_by_key(|name| name.to_ascii_lowercase());
        names.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
        names
    }

    pub fn activeServerNames(&self) -> Vec<String> {
        self.active_server_names()
    }

    pub fn active_guild_names(&self) -> Vec<String> {
        let mut names = self
            .get_all_players()
            .into_iter()
            .filter(|player| player.player_type() & PLTYPE_ANYCLIENT != 0)
            .map(|player| player.guild())
            .map(|guild| guild.trim().to_string())
            .filter(|guild| !guild.is_empty())
            .collect::<Vec<_>>();
        names.sort_by_key(|name| name.to_ascii_lowercase());
        names.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
        names
    }

    pub fn activeGuildNames(&self) -> Vec<String> {
        self.active_guild_names()
    }

    pub fn local_banned_accounts(&self) -> Vec<String> {
        let mut names = HashSet::new();
        if let Ok(files) = list_account_files(&self.config) {
            for file in files {
                if let Some((account, banned)) = load_rc_account_list_ban(&self.config, &file) {
                    if banned {
                        names.insert(account.to_ascii_lowercase());
                    }
                }
            }
        }
        for player in self.get_all_players() {
            let account = player.account.lock().unwrap();
            if account.is_banned && !account.account_name.is_empty() {
                names.insert(account.account_name.to_ascii_lowercase());
            }
        }
        let mut names = names.into_iter().collect::<Vec<_>>();
        names.sort();
        names
    }

    pub fn localBannedAccounts(&self) -> Vec<String> {
        self.local_banned_accounts()
    }

    pub fn send_login_packet_to_listservers(
        &self,
        player: &Player,
        password: &str,
        identity: &str,
    ) -> bool {
        let mut sent = false;
        for list in self.listserver_targets() {
            if list.is_connected() {
                list.SendLoginPacketForPlayer(player, password, identity);
                sent = true;
            }
        }
        sent
    }

    /// Authenticate an API login through the configured list servers. The
    /// temporary CLIENT3 identity is correlated by player id rather than
    /// treating a live TCP connection as proof
    /// of the password.
    pub fn authenticate_api(&self, account: &str, password: &str) -> (bool, String) {
        let Some(server) = self.self_weak.upgrade() else {
            return (false, "listserver unavailable".to_string());
        };
        let id = self.next_player_id();
        let (sender, receiver) = channel();
        self.api_auth.lock().unwrap().insert(id, sender);

        let player = Player::NewPlayer(None, &server);
        player.set_id(id);
        player.set_player_type(PLTYPE_CLIENT3);
        player.set_account_name(account);

        let mut sent = false;
        for list in self.listserver_targets() {
            if list.is_connected() {
                list.SendLoginPacketForPlayer(&player, password, "");
                sent = true;
            }
        }
        if !sent {
            self.api_auth.lock().unwrap().remove(&id);
            return (false, "listserver unavailable".to_string());
        }

        match receiver.recv_timeout(Duration::from_secs(10)) {
            Ok(result) => {
                if !result.message.trim().is_empty()
                    && !result.message.trim().eq_ignore_ascii_case("SUCCESS")
                {
                    (false, result.message)
                } else {
                    (true, String::new())
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                self.api_auth.lock().unwrap().remove(&id);
                (false, "listserver authentication timed out".to_string())
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                self.api_auth.lock().unwrap().remove(&id);
                (false, "listserver unavailable".to_string())
            }
        }
    }

    pub fn authenticateAPI(&self, account: &str, password: &str) -> (bool, String) {
        self.authenticate_api(account, password)
    }

    fn take_api_auth(&self, player_id: u16, _player_type: i32) -> Option<Sender<ApiAuthResult>> {
        self.api_auth.lock().unwrap().remove(&player_id)
    }

    pub fn add_player_to_listservers(&self, player: &Player) {
        for list in self.listserver_targets() {
            list.AddPlayer(player);
        }
    }
    pub fn send_player_text_to_listservers(
        &self,
        packet_id: u8,
        player_id: u16,
        text: &str,
    ) -> bool {
        let mut sent = false;
        for list in self.listserver_targets() {
            if list.is_connected() {
                list.SendPlayerTextPacket(packet_id, player_id, text);
                sent = true;
            }
        }
        sent
    }
    pub fn sendPlayerTextToListservers(&self, packet_id: u8, player_id: u16, text: &str) -> bool {
        self.send_player_text_to_listservers(packet_id, player_id, text)
    }
    pub fn send_text_to_listservers(&self, packet_id: u8, text: &str) -> bool {
        let mut sent = false;
        for list in self.listserver_targets() {
            if list.is_connected() {
                list.SendTextPacket(packet_id, text);
                sent = true;
            }
        }
        sent
    }
    pub fn sendTextToListservers(&self, packet_id: u8, text: &str) -> bool {
        self.send_text_to_listservers(packet_id, text)
    }
    pub fn forward_global_ban(
        &self,
        target: &str,
        actor: &str,
        banned: bool,
        ban_length: &str,
        ban_type: &str,
        reason: &str,
    ) -> bool {
        fn clean(value: &str) -> String {
            value
                .replace("\r\n", " ")
                .replace('\n', " ")
                .replace('\r', " ")
        }
        let mut fields = vec![
            IRC_BYTES.to_string(),
            "lister".to_string(),
            "setban".to_string(),
            clean(target.trim()),
            "world=all".to_string(),
            format!("banned={}", if banned { 1 } else { 0 }),
            format!("bantype={}", clean(ban_type)),
        ];
        if !ban_length.is_empty() {
            fields.push(format!("releasetime={}", clean(ban_length)));
        }
        fields.push(format!("actor={}", clean(actor)));
        fields.push(format!("reason={}", clean(reason)));
        self.send_text_to_listservers(SVO_SENDTEXT, &gtokenize_text(&fields.join("\n")))
    }
    pub fn forwardGlobalBan(
        &self,
        target: &str,
        actor: &str,
        banned: bool,
        ban_length: &str,
        ban_type: &str,
        reason: &str,
    ) -> bool {
        self.forward_global_ban(target, actor, banned, ban_length, ban_type, reason)
    }
    pub fn report_local_ban_history(
        &self,
        account: &str,
        actor: &str,
        banned: bool,
        ban_type: &str,
        ban_length: &str,
        reason: &str,
    ) -> bool {
        let account = account.trim();
        if account.is_empty() {
            return false;
        }
        let actor = if actor.trim().is_empty() {
            self.configured_name()
        } else {
            actor.trim().to_string()
        };
        let reason = reason
            .replace("\r\n", " ")
            .replace('\n', " ")
            .replace('\r', " ");
        let action = if banned { "banned" } else { "unbanned" };
        let fields = [
            IRC_BYTES,
            "lister",
            "localban",
            account,
            actor.as_str(),
            action,
            ban_type,
            ban_length,
            reason.as_str(),
        ];
        self.send_text_to_listservers(SVO_SENDTEXT, &gtokenize_text(&fields.join("\n")))
    }
    pub fn reportLocalBanHistory(
        &self,
        account: &str,
        actor: &str,
        banned: bool,
        ban_type: &str,
        ban_length: &str,
        reason: &str,
    ) -> bool {
        self.report_local_ban_history(account, actor, banned, ban_type, ban_length, reason)
    }
    pub fn save_player_accounts(&self) {
        for player in self.get_all_players() {
            if player.is_logged_in() && player.player_type() & PLTYPE_ANYCLIENT != 0 {
                player.save_account();
                player.state.lock().unwrap().last_save = Instant::now();
            }
        }
    }
    pub fn save_flags(&self) {
        let lines = self
            .flags
            .read()
            .unwrap()
            .iter()
            .filter(|(name, value)| is_valid_server_flag(name, value))
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>();
        let data = if lines.is_empty() {
            String::new()
        } else {
            format!("{}\n", lines.join("\n"))
        };
        let _ = self
            .config
            .save_file("config/serverflags.txt", data.as_bytes());
    }
    pub fn saveFlags(&self) {
        self.save_flags()
    }
    pub fn save_data(&self) {
        self.save_flags()
    }
    pub fn saveData(&self) {
        self.save_data()
    }

    fn listserver_config_key(&self) -> String {
        let mut parts = vec![format!(
            "enabled={}",
            self.settings.get_bool("listserver", true)
        )];
        for (host, port) in self.listserver_endpoints() {
            parts.push(format!("{host}:{port}"));
        }
        parts.join("|")
    }

    fn listserver_endpoints(&self) -> Vec<(String, String)> {
        let hosts = split_comma_list(&self.settings.get("listip"));
        if hosts.is_empty() {
            return Vec::new();
        }
        let mut ports = split_comma_list(&self.settings.get("listport"));
        if ports.is_empty() {
            ports.push("14900".to_string());
        }
        hosts
            .into_iter()
            .enumerate()
            .map(|(index, host)| {
                let port = ports
                    .get(index)
                    .or_else(|| ports.first())
                    .cloned()
                    .unwrap_or_else(|| "14900".to_string());
                (host, port)
            })
            .collect()
    }

    fn refresh_online_player_settings(&self) {
        for player in self.get_all_players() {
            if !player.is_logged_in() {
                continue;
            }
            player.apply_server_options_staff_rights();
            if player.has_connection() && is_player_list_player(&player) {
                player.send_staff_guilds();
                player.send_status_list();
            }
        }
    }

    fn refresh_listserver_settings(&self) {
        for list in self.server_lists.read().unwrap().iter() {
            list.refresh_server_settings();
        }
    }

    fn reconfigure_server_lists(&self) {
        for list in self.server_lists.read().unwrap().iter() {
            list.disconnect();
        }
        self.configure_server_lists();
    }

    fn load_settings(&self) {
        let old_listserver_config = self.listserver_config_key();
        let path = self.config.resolve_path("config/serveroptions.txt");
        if let Err(error) = self.settings.load(path) {
            self.logger.error(&format!(
                "Could not open config/serveroptions.txt. Will use default config. ({error})"
            ));
        }
        if let Some(name) = nonempty(&self.settings.get("name")) {
            *self.name.write().unwrap() = name;
        }
        DEBUG_MODE.store(
            self.settings.get_bool("debugmode", false),
            Ordering::Relaxed,
        );
        PACKET_DEBUG_MODE.store(
            self.settings.get_bool("packetdebugmode", false),
            Ordering::Relaxed,
        );
        self.load_server_message();
        self.load_allowed_versions();
        if self.config_loading.load(Ordering::Acquire) {
            return;
        }
        self.npc_server.sync();
        self.refresh_online_player_settings();
        if !old_listserver_config.is_empty()
            && old_listserver_config != self.listserver_config_key()
        {
            self.reconfigure_server_lists();
            return;
        }
        self.refresh_listserver_settings();
    }
    pub fn reload_settings(&self) {
        self.load_settings();
    }
    pub fn loadSettings(&self) {
        self.reload_settings();
    }
    fn load_admin_settings(&self) {
        let _ = self
            .admin_settings
            .load(self.config.resolve_path("config/adminconfig.txt"));
    }
    fn load_allowed_versions(&self) {
        let values = self
            .config
            .load_file_as_lines("config/allowedversions.txt")
            .unwrap_or_default()
            .into_iter()
            .map(|mut v| {
                if let Some(index) = v.find("//") {
                    v.truncate(index);
                }
                v.replace(['\r', '\t', ' '], "").trim().to_string()
            })
            .filter(|v| !v.is_empty())
            .collect();
        *self.allowed_versions.write().unwrap() = values;
    }
    fn load_flags(&self) {
        let mut flags = self.flags.write().unwrap();
        for line in self
            .config
            .load_file_as_lines("config/serverflags.txt")
            .unwrap_or_default()
        {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('/') {
                continue;
            }
            if let Some((name, value)) = line.split_once('=') {
                let name = name.trim();
                if is_valid_server_flag(name, value) {
                    flags.insert(name.to_string(), value.to_string());
                }
            }
        }
    }
    fn load_server_message(&self) {
        if let Ok(data) = self.config.load_file("config/servermessage.html") {
            *self.server_message.write().unwrap() = String::from_utf8_lossy(&data)
                .replace('\r', "")
                .replace('\n', " ");
        }
    }
    fn load_ip_bans(&self) {
        let lines = self
            .config
            .load_file_as_lines("config/ipbans.txt")
            .unwrap_or_default();
        let bans = lines
            .into_iter()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect::<Vec<_>>();
        *self.ip_bans.write().unwrap() = bans;
    }
    fn is_ip_banned(&self, ip: &str) -> bool {
        let ip = ip.trim();
        if ip.is_empty() {
            return false;
        }
        self.ip_bans
            .read()
            .unwrap()
            .iter()
            .any(|pattern| glob_match(pattern, ip))
    }
    fn load_weapons(&self) {
        let files = self.config.list_files("weapons/").unwrap_or_default();
        for file_name in files {
            if !file_name.starts_with("weapon") || !file_name.ends_with(".txt") {
                continue;
            }
            let Ok(data) = self.config.load_file(format!("weapons/{file_name}")) else {
                continue;
            };
            if let Some(mut weapon) = parse_weapon(&String::from_utf8_lossy(&data)) {
                if !weapon.bytecode_file.is_empty() {
                    weapon.bytecode = self
                        .config
                        .load_file(format!("weapon_bytecode/{}", weapon.bytecode_file))
                        .unwrap_or_default();
                }
                self.weapons
                    .write()
                    .unwrap()
                    .insert(weapon.name.to_ascii_lowercase(), Arc::new(weapon));
            }
        }
    }
    fn load_classes(&self) {
        let files = self.config.list_files("scripts/").unwrap_or_default();
        for file_name in files {
            if !file_name.to_ascii_lowercase().ends_with(".txt") {
                continue;
            }
            let Some(name) = Path::new(&file_name).file_stem().and_then(|v| v.to_str()) else {
                continue;
            };
            if let Ok(data) = self.config.load_file(format!("scripts/{file_name}")) {
                let class = ScriptClass {
                    name: name.to_string(),
                    script: String::from_utf8_lossy(&data).replace("\r\n", "\n"),
                };
                self.add_class(Arc::new(class));
            }
        }
    }
    fn load_npcs(&self) {
        let files = self.config.list_files("npcs/").unwrap_or_default();
        for file in files {
            if !file.starts_with("npc") || !file.ends_with(".txt") {
                continue;
            }
            let Ok(data) = self.config.load_file(format!("npcs/{file}")) else {
                continue;
            };
            let Some(npc) = parse_database_npc(&String::from_utf8_lossy(&data)) else {
                continue;
            };
            let npc = Arc::new(npc);
            if !self.add_npc(npc.clone()) {
                self.logger.warning(&format!(
                    "Could not add database NPC {} (id={})",
                    npc.npc_name(),
                    npc.id()
                ));
                continue;
            }
            if let Some(level_name) = nonempty(&npc.level_name()) {
                if let Some(level) = self.get_level(&level_name) {
                    npc.set_level(Some(level.clone()));
                    level.add_npc(npc.clone());
                }
            }
        }
    }
    fn load_maps(&self, print: bool) {
        let Some(server) = self.self_weak.upgrade() else {
            return;
        };
        let map_entries = |value: String| {
            guntokenize(&value)
                .replace('\r', "")
                .split('\n')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        let mut loaded = Vec::new();
        let mut load = |name: String, map_type: MapType, group_map: bool| {
            let map = Arc::new(Map::new(map_type, group_map));
            map.set_server(&server);
            if let Err(error) = map.load(&name) {
                if print {
                    self.logger
                        .warning(&format!("Could not load map {name}: {error}"));
                }
                return;
            }
            if print {
                self.logger.info(&format!("Loaded map: {name}"));
            }
            loaded.push(map);
        };

        for mut name in map_entries(self.settings.get("gmaps")) {
            if !name.to_ascii_lowercase().ends_with(".gmap") {
                name.push_str(".gmap");
            }
            load(name, MapType::Gmap, false);
        }
        for name in map_entries(self.settings.get("maps")) {
            load(name, MapType::BigMap, false);
        }
        for name in map_entries(self.settings.get("groupmaps")) {
            match Path::new(&name)
                .extension()
                .and_then(|value| value.to_str())
                .map(|value| value.to_ascii_lowercase())
                .as_deref()
            {
                Some("gmap") => load(name, MapType::Gmap, true),
                Some("txt") => load(name, MapType::BigMap, true),
                _ => {}
            }
        }
        *self.maps.write().unwrap() = loaded.clone();
        for map in &loaded {
            map.load_map_levels();
        }
        let levels = self
            .levels
            .read()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for level in levels {
            self.associate_level_map(&level);
        }
    }
    fn load_translations(&self) {
        let mut translations = HashMap::new();
        for file in self.config.list_files("translations/").unwrap_or_default() {
            let Some(extension) = Path::new(&file)
                .extension()
                .and_then(|value| value.to_str())
            else {
                continue;
            };
            if !extension.eq_ignore_ascii_case("po") {
                continue;
            }
            let Some(stem) = Path::new(&file)
                .file_stem()
                .and_then(|value| value.to_str())
            else {
                continue;
            };
            let Ok(data) = self.config.load_file(format!("translations/{file}")) else {
                continue;
            };
            translations.insert(
                stem.to_ascii_lowercase(),
                parse_po_translations(&String::from_utf8_lossy(&data)),
            );
        }
        *self.translations.write().unwrap() = translations;
    }
    fn translate(&self, language: &str, key: &str) -> String {
        self.translations
            .read()
            .unwrap()
            .get(&language.trim().to_ascii_lowercase())
            .and_then(|values| values.get(key))
            .filter(|value| !value.is_empty())
            .cloned()
            .unwrap_or_else(|| key.to_string())
    }
    fn load_config_files(&self) {
        self.config_loading.store(true, Ordering::Release);
        self.load_settings();
        self.load_admin_settings();
        self.load_flags();
        self.load_ip_bans();
        self.load_weapons();
        self.load_classes();
        self.load_maps(false);
        self.load_npcs();
        self.load_translations();
        self.word_filter.load("config/rules.txt");
        self.configure_server_lists();
        self.config_loading.store(false, Ordering::Release);
        self.npc_server.sync();
    }
    fn configure_server_lists(&self) {
        let hosts = split_comma_list(&self.settings.get("listip"));
        let ports = split_comma_list(&self.settings.get("listport"));
        let mut lists = Vec::new();
        for (index, host) in hosts.iter().enumerate() {
            let port = ports
                .get(index)
                .or_else(|| ports.first())
                .cloned()
                .unwrap_or_else(|| "14900".to_string());
            lists.push(Arc::new(ServerList::new_internal(
                &self.self_weak,
                host,
                &port,
            )));
        }
        for list in &lists {
            list.enabled.store(
                self.settings.get_bool("listserver", true),
                Ordering::Relaxed,
            );
        }
        *self.server_lists.write().unwrap() = lists.clone();
        *self.server_list.write().unwrap() = lists.first().cloned();
    }

    fn expand_joined_classes(&self, script: &str, seen: &mut HashSet<String>) -> String {
        let mut joins = Vec::new();
        let mut cleaned = Vec::new();
        for line in script.lines() {
            if let Some(name) = parse_gs2_join_line(line) {
                joins.push(name);
            } else {
                cleaned.push(line);
            }
        }

        let mut runtime_joins = Vec::new();
        let mut class_scripts = String::new();
        let mut class_created = Vec::new();
        for name in joins {
            let key = name.to_ascii_lowercase();
            if !seen.insert(key) {
                continue;
            }
            runtime_joins.push(name.clone());
            let Some(class) = self.get_class(&name) else {
                continue;
            };
            if class.script.trim().is_empty() {
                continue;
            }
            let class_created_name =
                format!("__class_{}_onCreated", sanitize_gs2_identifier(&name));
            let renamed = npc_runtime::rename_on_created(&class.script, &class_created_name);
            if renamed != class.script {
                class_created.push(class_created_name);
            }
            class_scripts.push('\n');
            class_scripts.push_str(&self.expand_joined_classes(&renamed, seen));
        }

        let mut output = String::new();
        for name in runtime_joins {
            let quoted = serde_json::to_string(&name).unwrap_or_else(|_| "\"\"".to_string());
            output.push_str("join(");
            output.push_str(&quoted);
            output.push_str(");\n");
        }
        output.push_str(&cleaned.join("\n"));
        output.push_str(&class_scripts);
        if !class_created.is_empty() {
            output.push_str("\nfunction __runJoinedClassOnCreated() {");
            for name in class_created {
                output.push_str("\n  ");
                output.push_str(&name);
                // The bundled Rust VM keeps the current receiver for a
                // direct script-function call; this is the ownership-safe
                // equivalent of the Goja `function.call(this)` wrapper.
                output.push_str("();");
            }
            output.push_str("\n}");
            output.push_str(
                "\nfunction __joinedClassOnCreatedBootstrap() { __runJoinedClassOnCreated(); }",
            );
        }
        output
    }

    pub fn run_server_side_gs2(
        &self,
        script_type: &str,
        script_name: &str,
        event_name: &str,
        script: &str,
        args: &[String],
    ) -> GS2VMResult {
        self.run_server_side_gs2_with_context(
            script_type,
            script_name,
            event_name,
            script,
            HashMap::new(),
            HashMap::new(),
            0,
            None,
            None,
            args,
        )
    }
    pub fn runServerSideGS2(
        &self,
        script_type: &str,
        script_name: &str,
        event_name: &str,
        script: &str,
        args: &[String],
    ) -> GS2VMResult {
        self.run_server_side_gs2(script_type, script_name, event_name, script, args)
    }

    /// Execute a server-side GS2 script with the same host objects exposed by
    /// the runtime. The public wrapper above intentionally keeps its
    /// original small signature; event-specific callers use this method so
    /// that `player`, `npcs`, `weapons`, `servers`, signs, chests, file
    /// resolvers, and persistent `this` state all observe one consistent
    /// snapshot.
    #[allow(clippy::too_many_arguments)]
    pub fn run_server_side_gs2_with_context(
        &self,
        script_type: &str,
        script_name: &str,
        event_name: &str,
        script: &str,
        this_state: HashMap<String, serde_json::Value>,
        player_context: HashMap<String, String>,
        npc_id: u32,
        socket: Option<npc_runtime::SocketContext>,
        socket_argument: Option<npc_runtime::SocketContext>,
        args: &[String],
    ) -> GS2VMResult {
        let mut imports = HashMap::new();
        for class in self.classes.read().unwrap().values() {
            if !class.name.is_empty() {
                imports.insert(class.name.clone(), class.script.clone());
            }
        }

        let players = self.snapshot_gs2_players();
        let player_flags = player_context
            .get("account")
            .and_then(|account| self.find_gs2_player(account))
            .map(|player| player.account.lock().unwrap().flag_list.clone())
            .unwrap_or_default();
        let weak_server = self.self_weak.clone();
        let server_player_resolver: npc_runtime::vm::ServerPlayerResolver =
            Arc::new(move |account| {
                let server = weak_server.upgrade()?;
                server.resolve_gs2_player_context(account)
            });
        let weak_server = self.self_weak.clone();
        let import_resolver: npc_runtime::vm::ImportResolver = Arc::new(move |name| {
            let server = weak_server.upgrade()?;
            server.resolve_gs2_import(name)
        });
        let weak_server = self.self_weak.clone();
        let tile_type: npc_runtime::vm::TileTypeResolver = Arc::new(move |level_name, x, y| {
            let Some(server) = weak_server.upgrade() else {
                return 0;
            };
            let Some(level) = server.get_level(&clean_level_name(level_name)) else {
                return 0;
            };
            level.get_tile(0, x.max(0) as usize, y.max(0) as usize) as i32
        });
        let weak_server = self.self_weak.clone();
        let map_position: npc_runtime::vm::MapPositionResolver = Arc::new(move |level_name| {
            let server = weak_server.upgrade()?;
            let level = server.get_level(&clean_level_name(level_name))?;
            let state = level.state.read().unwrap();
            if state.map_ref.as_ref().is_some_and(|map| map.is_gmap()) {
                Some((state.map_x, state.map_y))
            } else {
                None
            }
        });

        // Socket class joins are part of the script source in the original
        // runtime.  Prefixing them here preserves the order and lets the
        // native VM install the joined class methods on the socket receiver.
        let mut effective_script = script.to_string();
        for context in [socket.as_ref(), socket_argument.as_ref()]
            .into_iter()
            .flatten()
        {
            for class in &context.joined_classes {
                let quoted = serde_json::to_string(class).unwrap_or_else(|_| "\"\"".to_string());
                effective_script = format!("join({quoted});\n{effective_script}");
            }
        }
        let mut joined_seen = HashSet::new();
        effective_script = self.expand_joined_classes(&effective_script, &mut joined_seen);
        let mut runtime_event_name = event_name.to_string();
        let lower_event_name = event_name.trim().to_ascii_lowercase();
        if lower_event_name.ends_with(".oncreated") {
            if gs2_script_has_exact_event(&effective_script, "__runJoinedClassOnCreated") {
                runtime_event_name = "__runJoinedClassOnCreated".to_string();
            } else if !gs2_script_has_exact_event(&effective_script, event_name) {
                return GS2VMResult::default();
            }
        } else if !runtime_event_name.eq_ignore_ascii_case("onCreated")
            && !gs2_script_has_event(&effective_script, &runtime_event_name)
        {
            return GS2VMResult::default();
        }
        if runtime_event_name.eq_ignore_ascii_case("onCreated")
            && effective_script.contains("__joinedClassOnCreatedBootstrap")
        {
            effective_script = npc_runtime::inject_joined_class_on_created(&effective_script);
        }
        let bind_server = self.self_weak.clone();
        let bind_script_type = script_type.to_string();
        let bind_script_name = script_name.to_string();
        let bind_event_name = runtime_event_name.clone();
        let bind_script = effective_script.clone();
        let bind_player_context = player_context.clone();
        let bind_this_state = this_state.clone();
        let socket_bind: npc_runtime::vm::SocketBindResolver = Arc::new(move |action| {
            let Some(server) = bind_server.upgrade() else {
                return Err("socket manager is unavailable".to_string());
            };
            let result = GS2VMResult {
                script_type: bind_script_type.clone(),
                script_name: bind_script_name.clone(),
                event_name: bind_event_name.clone(),
                script: bind_script.clone(),
                player_context: bind_player_context.clone(),
                this: bind_this_state.clone(),
                ..GS2VMResult::default()
            };
            server.gs2_sockets.prepare_bind(&result, &action)
        });

        let runtime = npc_runtime::run_script(
            script_type,
            script_name,
            &runtime_event_name,
            &effective_script,
            npc_runtime::VMConfig {
                imports,
                socket_class_resolver: Some(import_resolver.clone()),
                socket_bind: Some(socket_bind),
                import_resolver: Some(import_resolver),
                params: args.to_vec(),
                player: player_context,
                player_flags,
                players,
                server_player_resolver: Some(server_player_resolver),
                weapons: self.snapshot_gs2_weapons(),
                servers: self.snapshot_gs2_servers(),
                npcs: self.snapshot_gs2_npcs(),
                signs: self.snapshot_gs2_signs(),
                chests: self.snapshot_gs2_chests(),
                npc_id,
                this: this_state,
                server_flags: self.flags.read().unwrap().clone(),
                server_options: self.settings.get_all(),
                file_root: self.config.get_base_path().to_string_lossy().into_owned(),
                file_rights: self.snapshot_gs2_file_rights(),
                socket,
                socket_argument,
                tile_type: Some(tile_type),
                map_position: Some(map_position),
                skip_top_level: !event_name.eq_ignore_ascii_case("onCreated"),
                ..npc_runtime::VMConfig::default()
            },
        );
        let mut result = gs2_result_from_runtime(runtime);
        result.event_name = event_name.to_string();
        result.script = effective_script;
        result
    }

    pub fn runServerSideGS2NativeWithState(
        &self,
        script_type: &str,
        script_name: &str,
        event_name: &str,
        script: &str,
        this_state: HashMap<String, serde_json::Value>,
        player_context: HashMap<String, String>,
        args: &[String],
    ) -> GS2VMResult {
        self.run_server_side_gs2_with_context(
            script_type,
            script_name,
            event_name,
            script,
            this_state,
            player_context,
            0,
            None,
            None,
            args,
        )
    }

    pub fn run_server_side_gs2_for_player(
        &self,
        script_type: &str,
        script_name: &str,
        event_name: &str,
        script: &str,
        player: Option<&Arc<Player>>,
        args: &[String],
    ) -> GS2VMResult {
        self.run_server_side_gs2_with_context(
            script_type,
            script_name,
            event_name,
            script,
            HashMap::new(),
            player.map(snapshot_gs2_player_map).unwrap_or_default(),
            0,
            None,
            None,
            args,
        )
    }

    pub fn runServerSideGS2ForPlayer(
        &self,
        script_type: &str,
        script_name: &str,
        event_name: &str,
        script: &str,
        player: Option<&Arc<Player>>,
        args: &[String],
    ) -> GS2VMResult {
        self.run_server_side_gs2_for_player(
            script_type,
            script_name,
            event_name,
            script,
            player,
            args,
        )
    }

    fn snapshot_gs2_players(&self) -> Vec<npc_runtime::PlayerContext> {
        let players = self.get_all_players();
        let mut result = Vec::new();
        for player in &players {
            if player.player_type() & PLTYPE_ANYCLIENT != 0 {
                if let Some(context) = snapshot_gs2_player_context(player) {
                    result.push(context);
                }
            }
        }
        for player in &players {
            if player.player_type() & (PLTYPE_ANYRC | PLTYPE_ANYNC | PLTYPE_NPCSERVER) != 0 {
                if let Some(context) = snapshot_gs2_player_context(player) {
                    result.push(context);
                }
            }
        }
        result
    }

    fn snapshot_gs2_weapons(&self) -> Vec<npc_runtime::WeaponContext> {
        let mut weapons = self
            .weapons
            .read()
            .unwrap()
            .values()
            .map(|weapon| npc_runtime::WeaponContext {
                name: weapon.name.clone(),
                image: weapon.image.clone(),
            })
            .collect::<Vec<_>>();
        weapons.sort_by_key(|weapon| weapon.name.to_ascii_lowercase());
        weapons
    }

    fn snapshot_gs2_servers(&self) -> Vec<npc_runtime::ServerContext> {
        let mut servers = self
            .listserver_cache
            .read()
            .unwrap()
            .values()
            .map(|server| npc_runtime::ServerContext {
                name: server.name.clone(),
                r#type: server.server_type.clone(),
                player_count: server.player_count,
                language: server.language.clone(),
                description: server.description.clone(),
                url: server.url.clone(),
                version: server.version.clone(),
                game_versions: server.game_versions.clone(),
                latency: server.latency,
            })
            .collect::<Vec<_>>();
        servers.sort_by_key(|server| server.name.to_ascii_lowercase());
        servers
    }

    fn snapshot_gs2_npcs(&self) -> Vec<npc_runtime::NPCContext> {
        let mut npcs = Vec::new();
        for npc in self.npcs.read().unwrap().values() {
            let state = npc.state.lock().unwrap();
            if state.npc_name.is_empty() {
                continue;
            }
            npcs.push(npc_runtime::NPCContext {
                id: state.id,
                name: state.npc_name.clone(),
                script: state.script.clone(),
                level: state
                    .level
                    .as_ref()
                    .map(|level| level.get_name())
                    .unwrap_or_default(),
                x: f64::from(state.x) / 16.0,
                y: f64::from(state.y) / 16.0,
                width: f64::from(state.width) / 16.0,
                height: f64::from(state.height) / 16.0,
                this: merge_npc_vm_state(&state),
            });
        }
        npcs.sort_by_key(|npc| npc.id);
        npcs
    }

    fn snapshot_gs2_signs(&self) -> Vec<npc_runtime::SignContext> {
        let mut signs = Vec::new();
        for level in self.levels.read().unwrap().values() {
            let state = level.state.read().unwrap();
            for sign in &state.signs {
                signs.push(npc_runtime::SignContext {
                    level: state.level_name.clone(),
                    x: sign.x,
                    y: sign.y,
                    text: sign.text.clone(),
                });
            }
        }
        signs
    }

    fn snapshot_gs2_chests(&self) -> Vec<npc_runtime::ChestContext> {
        let mut chests = Vec::new();
        for level in self.levels.read().unwrap().values() {
            let state = level.state.read().unwrap();
            for chest in &state.chests {
                chests.push(npc_runtime::ChestContext {
                    level: state.level_name.clone(),
                    x: chest.x,
                    y: chest.y,
                    item_type: chest.item_type as i32,
                    is_open: false,
                });
            }
        }
        chests
    }

    fn snapshot_gs2_file_rights(&self) -> Vec<String> {
        self.npc_server
            .player()
            .map(|player| player.account.lock().unwrap().folder_list.clone())
            .unwrap_or_default()
    }

    fn resolve_gs2_import(&self, name: &str) -> Option<String> {
        self.get_class(name).map(|class| class.script.clone())
    }

    fn resolve_gs2_player_context(&self, account: &str) -> Option<npc_runtime::PlayerContext> {
        let account = account.trim();
        if account.is_empty() || account.contains('/') || account.contains('\\') {
            return None;
        }
        if let Some(player) = self.find_gs2_player(account) {
            return snapshot_gs2_player_context(&player);
        }
        if !self.account_exists(account) {
            return None;
        }
        let player = Player::NewPlayer(None, &self.self_weak.upgrade()?);
        if !player.account.lock().unwrap().load_account(account, false) {
            return None;
        }
        snapshot_gs2_player_context(&player)
    }

    fn find_gs2_player(&self, account: &str) -> Option<Arc<Player>> {
        if account.trim().is_empty() {
            return None;
        }
        let account = account.trim();
        let players = self.get_all_players();
        players
            .iter()
            .filter(|player| player.player_type() & PLTYPE_ANYCLIENT != 0)
            .chain(players.iter().filter(|player| {
                player.player_type() & (PLTYPE_ANYRC | PLTYPE_ANYNC | PLTYPE_NPCSERVER) != 0
            }))
            .find(|player| {
                player.account_name().eq_ignore_ascii_case(account)
                    || snapshot_gs2_account(player).eq_ignore_ascii_case(account)
                    || player.nickname().eq_ignore_ascii_case(account)
            })
            .cloned()
    }

    fn send_gs2_compiler_output_to_nc(&self, origin: &str, level: &str, text: &str) {
        self.send_to_nc(&format!("Script compiler output for {origin}:"));
        let mut wrote = false;
        for line in text.lines() {
            let line = normalize_gs2_compiler_line(line);
            if !line.is_empty() {
                self.send_to_nc(&format!("{level}: {line}"));
                wrote = true;
            }
        }
        if !wrote {
            self.send_to_nc(&format!("{level}: compiler failed"));
        }
    }

    fn send_gs2_vm_error_to_nc(&self, origin: &str, text: &str) {
        self.send_to_nc(&format!("Compiler error for {origin}:"));
        let mut wrote = false;
        for line in text.lines() {
            let line = normalize_gs2_vm_error_line(line);
            if !line.is_empty() {
                self.send_to_nc(&format!("error: {line}"));
                wrote = true;
            }
        }
        if !wrote {
            self.send_to_nc("error: runtime failed");
        }
    }

    pub fn apply_gs2_vm_result(&self, result: GS2VMResult) {
        for flag in &result.server_flags {
            if flag.deleted {
                self.delete_server_flag_live(&flag.name);
            } else {
                self.set_server_flag_live(&flag.name, &flag.value);
            }
        }
        for flag in &result.player_flags {
            if let Some(player) = self.find_gs2_player(&flag.account) {
                player
                    .account
                    .lock()
                    .unwrap()
                    .set_flag(&flag.name, &flag.value);
                player.send_plo_flagset(&flag.name, &flag.value);
            }
        }
        for prop in &result.player_props {
            if let Some(player) = self.find_gs2_player(&prop.account) {
                if prop.name.eq_ignore_ascii_case("guild") {
                    let current_nick = player.nickname();
                    let base = current_nick
                        .split('(')
                        .next()
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| player.account_name());
                    let nickname = if prop.value.trim().is_empty() {
                        base
                    } else {
                        format!("{} ({})", base, prop.value.trim())
                    };
                    player.set_nickname(&nickname);
                    player.set_guild(prop.value.trim());
                    self.refresh_player_list_entry(&player);
                }
            }
        }
        for message in &result.player_messages {
            if let Some(player) = self.find_gs2_player(&message.account) {
                self.send_gs2_player_pm(&player, &message.message);
            }
        }
        for message in &result.player_rc_messages {
            if let Some(player) = self.find_gs2_control_player(&message.account) {
                player.send_plo_rc_chat(&message.message);
            }
        }
        for message in &result.player_irc_messages {
            if let Some(player) = self.find_gs2_control_player(&message.account) {
                if !message.command.is_empty() {
                    let mut fields = vec![IRC_BYTES.to_string(), "irc".to_string()];
                    fields.push(message.command.clone());
                    fields.extend(message.params.clone());
                    player.send_server_text_fields(&fields);
                }
            }
        }
        for message in &result.rc_messages {
            self.send_rc_chat(message);
        }
        for message in &result.nc_messages {
            self.send_to_nc(message);
        }
        for weapon in &result.player_weapons {
            if let Some(player) = self.find_gs2_player(&weapon.account) {
                if player.player_type() & PLTYPE_ANYCLIENT == 0 {
                    continue;
                }
                if weapon.add {
                    if player.add_weapon(&weapon.name) {
                        player.send_account_weapon(&weapon.name);
                    }
                } else if player.has_account_weapon(&weapon.name) {
                    player.delete_weapon(&weapon.name);
                    player.send_plo_npcweapondel(&weapon.name);
                }
                player.save_account();
                self.refresh_player_list_entry(&player);
            }
        }
        for class in &result.player_classes {
            if let Some(player) = self.find_gs2_player(&class.account) {
                if player.player_type() & PLTYPE_ANYCLIENT != 0
                    && player.version_id() >= 300
                    && self.get_class(&class.name).is_some()
                {
                    if let Some(class_obj) = self.get_class(&class.name) {
                        player.send_raw_npc_weapon_script(class_obj.script.as_bytes());
                    }
                }
            }
        }
        for warp in &result.player_warps {
            if let Some(player) = self.find_gs2_player(&warp.account) {
                if !warp.level.is_empty() {
                    player.warp(&warp.level, warp.x, warp.y, 0);
                }
            }
        }
        for flag in &result.npc_flags {
            self.apply_gs2_npc_flag(flag);
        }
        for call in &result.npc_function_calls {
            self.apply_gs2_npc_function_call(&result, call);
        }
        for action in &result.npc_actions {
            self.apply_gs2_npc_action(action);
        }
        for action in &result.level_actions {
            self.apply_gs2_level_action(&result, action);
        }
        self.gs2_sockets.apply(&result);
        for event in &result.scheduled_events {
            self.schedule_gs2_event(&result, event);
        }
        self.emit_gs2_vm_output(&result);
    }

    pub fn applyGS2VMResult(&self, result: GS2VMResult) {
        self.apply_gs2_vm_result(result)
    }

    fn send_gs2_player_pm(&self, player: &Arc<Player>, message: &str) {
        if !self.npc_server_running() {
            return;
        }
        let sender_id = self
            .npc_server
            .player()
            .map(|player| player.id())
            .unwrap_or(1);
        let mut packet = Buffer::new();
        packet
            .write_byte(PLO_PRIVATEMESSAGE)
            .write_gshort(sender_id)
            .write(b"\",\"")
            .write(gtokenize_text(message).as_bytes());
        player.send(&packet);
    }

    fn find_gs2_control_player(&self, account: &str) -> Option<Arc<Player>> {
        let account = account.trim();
        if account.is_empty() {
            return None;
        }
        self.get_all_players().into_iter().find(|player| {
            player.player_type() & (PLTYPE_ANYRC | PLTYPE_ANYNC) != 0
                && (player.account_name().eq_ignore_ascii_case(account)
                    || snapshot_gs2_account(player).eq_ignore_ascii_case(account)
                    || player.nickname().eq_ignore_ascii_case(account))
        })
    }

    fn apply_gs2_npc_flag(&self, flag: &GS2VMNPCFlag) {
        let Some(npc) = self.get_npc(flag.id) else {
            return;
        };
        if flag.name.is_empty() {
            return;
        }
        let mut state = npc.state.lock().unwrap();
        state
            .flag_list
            .insert(flag.name.clone(), flag.value.clone());
        state.vm_this.insert(
            flag.name.clone(),
            serde_json::Value::String(flag.value.clone()),
        );
        let npc_type = state.npc_type;
        drop(state);
        if npc_type == NPCType::DBNPC {
            let _ = self.save_database_npc_file(&npc);
        }
    }

    fn apply_gs2_npc_function_call(&self, source: &GS2VMResult, call: &GS2VMNPCFunctionCall) {
        let Some(npc) = self.get_npc(call.id) else {
            return;
        };
        if call.function.is_empty() {
            return;
        }
        let (name, script, state, revision) = {
            let value = npc.state.lock().unwrap();
            (
                value.npc_name.clone(),
                value.script.clone(),
                merge_npc_vm_state(&value),
                value.vm_revision,
            )
        };
        let mut next = self.run_server_side_gs2_with_context(
            "npc",
            &name,
            &call.function,
            &script,
            state,
            source.player_context.clone(),
            call.id,
            None,
            None,
            &call.args,
        );
        next.vm_revision = revision;
        if next.error.is_empty() {
            self.apply_gs2_vm_result(next.clone());
            self.commit_gs2_npc_state(&next);
        } else {
            self.send_gs2_compiler_output_to_nc(&format!("NPC {name}"), "error", &next.error);
        }
    }

    fn apply_gs2_npc_action(&self, action: &GS2VMNPCAction) {
        let Some(npc) = self.get_npc(action.id) else {
            return;
        };
        let mut state = npc.state.lock().unwrap();
        let moved = action.move_dx != 0.0
            || action.move_dy != 0.0
            || action.move_time != 0.0
            || action.move_options != 0;
        let mut changed = moved;
        if action.shape_type > 0 && (state.width != action.width || state.height != action.height) {
            state.width = action.width;
            state.height = action.height;
            changed = true;
        }
        if action.has_chat && state.character.chat_message != action.chat {
            state.character.chat_message = action.chat.clone();
            changed = true;
        }
        if apply_gs2_npc_props_state(&mut state, &action.props) {
            changed = true;
        }
        if action.has_vis_flags && state.vis_flags != action.vis_flags as u8 {
            state.vis_flags = action.vis_flags as u8;
            changed = true;
        }
        if action.has_block_flags && state.block_flags != action.block_flags as u8 {
            state.block_flags = action.block_flags as u8;
            changed = true;
        }
        for (name, value) in &action.flags {
            state.flag_list.insert(name.clone(), value.clone());
            state
                .vm_this
                .insert(name.clone(), serde_json::Value::String(value.clone()));
        }
        if moved {
            state.x = state
                .x
                .saturating_add((action.move_dx * 16.0).round() as i16);
            state.y = state
                .y
                .saturating_add((action.move_dy * 16.0).round() as i16);
        }
        let id = state.id;
        let old_level = state.level.clone();
        drop(state);

        if action.destroy {
            self.delete_npc(id);
            return;
        }
        if !action.warp_level.trim().is_empty() {
            if let Some(level) = self.load_level(&clean_level_name(&action.warp_level)) {
                self.move_npc_to_level(
                    &npc,
                    &level,
                    action.warp_x.round() as i16,
                    action.warp_y.round() as i16,
                );
            }
            return;
        }
        if moved {
            self.send_npc_moved_to_level(&npc);
        }
        if changed {
            self.send_npc_props_to_level(&npc);
        }
        let _ = old_level;
    }

    pub fn applyGS2NPCAction(&self, action: GS2VMNPCAction) {
        self.apply_gs2_npc_action(&action)
    }

    fn apply_gs2_level_action(&self, result: &GS2VMResult, action: &GS2VMLevelAction) {
        let requested = if action.level.trim().is_empty() {
            result
                .player_context
                .get("level")
                .cloned()
                .unwrap_or_default()
        } else {
            action.level.clone()
        };
        let Some(level) = self.get_level(&requested) else {
            return;
        };
        let owner = result
            .player_context
            .get("account")
            .and_then(|account| self.find_gs2_player(account))
            .map(|player| player.id())
            .unwrap_or(0);
        match action.action.to_ascii_lowercase().as_str() {
            "settile" => {
                let x = action.x.floor() as i32;
                let y = action.y.floor() as i32;
                let tile = action.tile as i16;
                if level.alter_board(self, x, y, 1, 1, &[tile]) {
                    self.broadcast_board_modify(&level, x as i16, y as i16, 1, 1, &[tile]);
                }
            }
            "putbomb" | "putbomb2" => {
                let mut packet = Buffer::new();
                packet
                    .write_byte(PLO_BOMBADD)
                    .write_gshort(owner)
                    .write_gchar(action.x as i32 as u8)
                    .write_gchar(action.y as i32 as u8)
                    .write_gchar(action.power as u8)
                    .write_gchar(55);
                self.send_gs2_level_packet(&level, &packet.data);
            }
            "putexplosion" | "putexplosion2" => {
                let mut packet = Buffer::new();
                packet
                    .write_byte(PLO_EXPLOSION)
                    .write_gshort(owner)
                    .write_gchar(action.power as u8)
                    .write_gchar(action.x as i32 as u8)
                    .write_gchar(action.y as i32 as u8)
                    .write_gchar(action.power as u8);
                self.send_gs2_level_packet(&level, &packet.data);
            }
            "shoot" => {
                let mut packet = Buffer::new();
                let params = action.params.join(",");
                packet
                    .write_byte(PLO_SHOOT)
                    .write_gshort(owner)
                    .write_gint(0)
                    .write_gchar(action.x as i32 as u8)
                    .write_gchar(action.y as i32 as u8)
                    .write_gchar(action.z as i32 as u8)
                    .write_gchar(action.angle as i32 as u8)
                    .write_gchar(action.z_angle as i32 as u8)
                    .write_gchar(action.strength as i32 as u8)
                    .write_gchar(action.ani.len() as u8)
                    .write(action.ani.as_bytes())
                    .write_gchar(params.len() as u8)
                    .write(params.as_bytes());
                self.send_gs2_level_packet(&level, &packet.data);
            }
            "triggeraction" => {
                for call in &action.calls {
                    self.apply_gs2_npc_function_call(result, call);
                }
                let mut action_text = action.target.clone();
                if !action.params.is_empty() {
                    action_text.push(',');
                    action_text.push_str(&action.params.join(","));
                }
                let mut packet = Buffer::new();
                packet
                    .write_byte(PLO_TRIGGERACTION)
                    .write_gshort(owner)
                    .write_gint(0)
                    .write_gchar((action.x * 2.0) as i32 as u8)
                    .write_gchar((action.y * 2.0) as i32 as u8)
                    .write(action_text.as_bytes());
                self.send_gs2_level_packet(&level, &packet.data);
            }
            "setani" => {
                if let Some(npc) = self.get_npc(action.set_npc_id) {
                    npc.state.lock().unwrap().character.gani = action.ani.clone();
                    self.send_npc_props_to_level(&npc);
                }
            }
            "putnpc" | "putnpc2" => self.apply_gs2_put_npc_action(result, &level, action),
            _ => {}
        }
    }

    pub fn applyGS2LevelAction(&self, result: GS2VMResult, action: GS2VMLevelAction) {
        self.apply_gs2_level_action(&result, &action)
    }

    fn apply_gs2_put_npc_action(
        &self,
        result: &GS2VMResult,
        level: &Arc<Level>,
        action: &GS2VMLevelAction,
    ) {
        let mut script = action.script.clone();
        if action.action.eq_ignore_ascii_case("putnpc") {
            for candidate in [
                script.clone(),
                format!("scripts/{}", script.trim_start_matches("scripts/")),
                format!("scripts/{}.txt", script.trim_start_matches("scripts/")),
            ] {
                if let Ok(data) = self.config.load_file(&candidate) {
                    script = String::from_utf8_lossy(&data).into_owned();
                    break;
                }
            }
        }
        if !action.classes.is_empty() {
            let mut prefix = String::new();
            for class in &action.classes {
                if !class.trim().is_empty() {
                    prefix.push_str("join(\"");
                    prefix.push_str(&class.replace('"', "\\\""));
                    prefix.push_str("\");\n");
                }
            }
            script = format!("{prefix}{script}");
        }
        let npc = Arc::new(NPC::new(NPCType::PUTNPC));
        {
            let mut state = npc.state.lock().unwrap();
            state.image = action.image.clone();
            state.script = script;
            state.script_type = "PUTNPC".to_string();
            state.scripter = result
                .player_context
                .get("account")
                .cloned()
                .unwrap_or_default();
            state.level = Some(level.clone());
            state.x = (action.x * 16.0).round() as i16;
            state.y = (action.y * 16.0).round() as i16;
            apply_gs2_npc_props_state(&mut state, &action.props);
            for (name, value) in &action.props {
                state.flag_list.insert(name.clone(), value.clone());
                state
                    .vm_this
                    .insert(name.clone(), serde_json::Value::String(value.clone()));
            }
        }
        if !self.add_npc(npc.clone()) {
            return;
        }
        {
            let mut state = npc.state.lock().unwrap();
            if state.npc_name.is_empty() {
                state.npc_name = saved_put_npc_name(&level.get_name(), state.id, state.id as usize);
            }
        }
        level.add_npc(npc.clone());
        self.send_npc_props_to_level(&npc);
        self.run_server_side_npc_event_for_player(&npc, "onCreated", None, &[]);
        for call in &action.calls {
            if !call.function.is_empty() {
                self.run_server_side_npc_event_for_player(&npc, &call.function, None, &call.args);
            }
        }
        let name = npc.npc_name();
        let _ = save_npc_file(self, &npc, &format!("npcs/npc{name}.txt"));
    }

    fn send_gs2_level_packet(&self, level: &Level, packet: &[u8]) {
        for id in level.get_players() {
            if let Some(player) = self.get_player(id) {
                if player.has_connection() {
                    player.send(&Buffer::from_bytes(packet));
                }
            }
        }
    }

    fn move_npc_to_level(&self, npc: &Arc<NPC>, level: &Arc<Level>, x: i16, y: i16) {
        if let Some(old) = npc.level() {
            old.remove_npc(npc.id());
        }
        npc.set_level(Some(level.clone()));
        npc.set_position(x, y, npc.snapshot().z);
        level.add_npc(npc.clone());
        self.send_npc_props_to_level(npc);
    }

    fn send_npc_moved_to_level(&self, npc: &Arc<NPC>) {
        let Some(level) = npc.level() else { return };
        let (id, x, y) = {
            let state = npc.state.lock().unwrap();
            (state.id, state.x, state.y)
        };
        for player_id in level.get_players() {
            if let Some(player) = self.get_player(player_id) {
                if player.has_connection() {
                    player.send_plo_npcmoved(id, x, y);
                }
            }
        }
    }

    fn send_npc_props_to_level(&self, npc: &Arc<NPC>) {
        let Some(level) = npc.level() else { return };
        for player_id in level.get_players() {
            if let Some(player) = self.get_player(player_id) {
                if player.has_connection() {
                    player.send_plo_npcprops(npc);
                }
            }
        }
    }

    fn emit_gs2_vm_output(&self, result: &GS2VMResult) {
        for line in &result.output {
            self.logger
                .info(&format!("[GS2:{}] {line}", result.script_name));
            self.send_to_nc(line);
        }
    }

    fn commit_gs2_npc_state(&self, result: &GS2VMResult) {
        if !result.script_type.eq_ignore_ascii_case("npc") || result.npc_id == 0 {
            return;
        }
        let Some(npc) = self.get_npc(result.npc_id) else {
            return;
        };
        let mut state = npc.state.lock().unwrap();
        if state.vm_revision != result.vm_revision || state.script != result.script {
            return;
        }
        state.vm_this = result.this.clone();
        let npc_type = state.npc_type;
        drop(state);
        if npc_type == NPCType::DBNPC {
            let _ = self.save_database_npc_file(&npc);
        }
    }

    fn gs2_vm_revision_still_current(&self, result: &GS2VMResult) -> bool {
        if result.script_type.eq_ignore_ascii_case("weapon") {
            return self
                .get_weapon(&result.script_name)
                .is_some_and(|weapon| weapon.vm_revision == result.vm_revision);
        }
        if result.script_type.eq_ignore_ascii_case("npc") {
            return self
                .get_npc(result.npc_id)
                .is_some_and(|npc| npc.state.lock().unwrap().vm_revision == result.vm_revision);
        }
        true
    }

    fn schedule_gs2_event(&self, result: &GS2VMResult, event: &GS2VMScheduledEvent) {
        if event.event.is_empty() || event.canceled {
            return;
        }
        let Some(server) = self.self_weak.upgrade() else {
            return;
        };
        let result = result.clone();
        let event = event.clone();
        let run = move || {
            if !server.gs2_vm_revision_still_current(&result) {
                return;
            }
            let mut next = server.run_server_side_gs2_with_context(
                &result.script_type,
                &result.script_name,
                &event.event,
                &result.script,
                result.this.clone(),
                result.player_context.clone(),
                result.npc_id,
                None,
                None,
                &event.params,
            );
            next.vm_revision = result.vm_revision;
            if next.error.is_empty() {
                server.apply_gs2_vm_result(next.clone());
                server.commit_gs2_npc_state(&next);
            } else {
                server.send_gs2_compiler_output_to_nc(
                    &format!("{} {}", result.script_type, result.script_name),
                    "error",
                    &next.error,
                );
            }
        };
        if event.delay <= 0.0 {
            run();
        } else {
            thread::spawn(move || {
                thread::sleep(Duration::from_secs_f64(event.delay));
                run();
            });
        }
    }

    pub fn run_server_side_weapon_event(&self, weapon: &Weapon, event_name: &str) {
        self.run_server_side_weapon_event_for_player(weapon, event_name, None, &[]);
    }

    pub fn runServerSideWeaponEvent(&self, weapon: &Weapon, event_name: &str) {
        self.run_server_side_weapon_event(weapon, event_name)
    }

    pub fn run_server_side_weapon_event_for_player(
        &self,
        weapon: &Weapon,
        event_name: &str,
        player: Option<&Arc<Player>>,
        args: &[String],
    ) {
        if weapon.script.trim().is_empty() || !self.npc_server_running() {
            return;
        }
        let mut result = self.run_server_side_gs2_with_context(
            "weapon",
            &weapon.name,
            event_name,
            &weapon.script,
            weapon.vm_this.clone(),
            player.map(snapshot_gs2_player_map).unwrap_or_default(),
            0,
            None,
            None,
            args,
        );
        result.vm_revision = weapon.vm_revision;
        if !result.error.is_empty() {
            self.send_gs2_compiler_output_to_nc(
                &format!("Weapon {}", weapon.name),
                "error",
                &result.error,
            );
            return;
        }
        if !self.gs2_vm_revision_still_current(&result) {
            return;
        }
        self.commit_gs2_weapon_state(&result);
        self.apply_gs2_vm_result(result.clone());
        if let Some(player) = player {
            for trigger in &result.client_triggers {
                // Mirror the reference server: client-bound trigger actions
                // carry the "clientside," prefix so the client routes them
                // to the weapon's onActionClientside handler.
                let mut action = format!("clientside,{}", trigger.name);
                if !trigger.args.is_empty() {
                    action.push(',');
                    action.push_str(&trigger.args.join(","));
                }
                player.send_plo_triggeraction(0, 0, 0, 0, &action);
            }
        }
    }

    pub fn runServerSideWeaponEventForPlayer(
        &self,
        weapon: &Weapon,
        event_name: &str,
        player: Option<&Arc<Player>>,
        args: &[String],
    ) {
        self.run_server_side_weapon_event_for_player(weapon, event_name, player, args)
    }

    pub fn run_server_side_npc_event_for_player(
        &self,
        npc: &Arc<NPC>,
        event_name: &str,
        player: Option<&Arc<Player>>,
        args: &[String],
    ) {
        if !self.npc_server_running() {
            return;
        }
        let (name, script, state, revision, level_name) = {
            let value = npc.state.lock().unwrap();
            (
                value.npc_name.clone(),
                value.script.clone(),
                merge_npc_vm_state(&value),
                value.vm_revision,
                value
                    .level
                    .as_ref()
                    .map(|level| level.get_name())
                    .unwrap_or_default(),
            )
        };
        if script.trim().is_empty() {
            return;
        }
        let mut context = player.map(snapshot_gs2_player_map).unwrap_or_default();
        if context.get("level").is_none_or(|value| value.is_empty()) && !level_name.is_empty() {
            context.insert("level".to_string(), level_name);
        }
        let id = npc.id();
        let mut result = self.run_server_side_gs2_with_context(
            "npc", &name, event_name, &script, state, context, id, None, None, args,
        );
        result.vm_revision = revision;
        if !result.error.is_empty() {
            let current = self
                .get_npc(id)
                .is_some_and(|value| value.state.lock().unwrap().vm_revision == revision);
            if current {
                self.send_gs2_compiler_output_to_nc(&format!("NPC {name}"), "error", &result.error);
            }
            return;
        }
        if !self.gs2_vm_revision_still_current(&result) {
            return;
        }
        self.apply_gs2_vm_result(result.clone());
        self.commit_gs2_npc_state(&result);
        if let Some(player) = player {
            for trigger in &result.client_triggers {
                // Mirror the reference server: client-bound trigger actions
                // carry the "clientside," prefix so the client routes them
                // to the NPC script's onActionClientside handler.
                let mut action = format!("clientside,{}", trigger.name);
                if !trigger.args.is_empty() {
                    action.push(',');
                    action.push_str(&trigger.args.join(","));
                }
                player.send_plo_triggeraction(0, id, 0, 0, &action);
            }
        }
    }

    pub fn runServerSideNPCEventForPlayer(
        &self,
        npc: &Arc<NPC>,
        event_name: &str,
        player: Option<&Arc<Player>>,
        args: &[String],
    ) {
        self.run_server_side_npc_event_for_player(npc, event_name, player, args)
    }

    pub fn run_server_side_event_for_active_scripts(
        &self,
        event_name: &str,
        player: Option<&Arc<Player>>,
        args: &[String],
    ) {
        if !self.npc_server_running() {
            return;
        }
        let weapons = self
            .weapons
            .read()
            .unwrap()
            .values()
            .filter(|weapon| !weapon.def_player && !weapon.script.trim().is_empty())
            .cloned()
            .collect::<Vec<_>>();
        for weapon in weapons {
            self.run_server_side_weapon_event_for_player(&weapon, event_name, player, args);
        }
        let npcs = self
            .npcs
            .read()
            .unwrap()
            .values()
            .filter(|npc| {
                matches!(npc.npc_type(), NPCType::DBNPC | NPCType::LEVELNPC)
                    && !npc.state.lock().unwrap().script.trim().is_empty()
            })
            .cloned()
            .collect::<Vec<_>>();
        for npc in npcs {
            self.run_server_side_npc_event_for_player(&npc, event_name, player, args);
        }
    }

    pub fn runServerSideEventForActiveScripts(
        &self,
        event_name: &str,
        player: Option<&Arc<Player>>,
        args: &[String],
    ) {
        self.run_server_side_event_for_active_scripts(event_name, player, args)
    }

    pub fn run_level_npc_trigger_action(
        &self,
        player: &Arc<Player>,
        npc_id: u32,
        x: i32,
        y: i32,
        parts: &[String],
    ) {
        if !self.npc_server_running() || parts.is_empty() {
            return;
        }
        let level = player
            .current_level()
            .or_else(|| self.get_level(&player.level_name()));
        let Some(level) = level else {
            return;
        };
        let event_name = level_npc_trigger_event_name(&parts[0]);
        let args = parts.get(1..).unwrap_or_default().to_vec();
        let match_x = x.saturating_mul(8);
        let match_y = y.saturating_mul(8);
        for npc in level.get_npcs() {
            if !npc.has_script() {
                continue;
            }
            if npc_id != 0 && npc.id() != npc_id {
                continue;
            }
            if npc_id == 0 && !npc.matches_trigger_area(match_x, match_y, 8, 8) {
                continue;
            }
            self.run_server_side_npc_event_for_player(&npc, &event_name, Some(player), &args);
        }
    }
    pub fn runLevelNPCTriggerAction(
        &self,
        player: &Arc<Player>,
        npc_id: u32,
        x: i32,
        y: i32,
        parts: &[String],
    ) {
        self.run_level_npc_trigger_action(player, npc_id, x, y, parts)
    }

    pub fn handle_trigger_command(&self, player: &Player, command: &str, args: &[String]) -> bool {
        let command = command.trim().to_ascii_lowercase();
        match command.as_str() {
            "serverside" => {
                if args.len() < 2 {
                    return true;
                }
                if let Some(weapon) = self.get_weapon(args[1].trim()) {
                    let player_arc = player.self_arc();
                    self.run_server_side_weapon_event_for_player(
                        &weapon,
                        "onActionServerSide",
                        player_arc.as_ref(),
                        &args[2..],
                    );
                }
                true
            }
            "gr.addweapon" => {
                if !self.settings.get_bool("triggerhack_weapons", false) {
                    return true;
                }
                for weapon in args.iter().skip(1) {
                    player.add_weapon(weapon.trim());
                }
                true
            }
            "gr.deleteweapon" => {
                if !self.settings.get_bool("triggerhack_weapons", false) {
                    return true;
                }
                for weapon in args.iter().skip(1) {
                    player.delete_weapon(weapon.trim());
                }
                true
            }
            "gr.setgroup" => {
                if self.settings.get_bool("triggerhack_groups", true) && args.len() == 2 {
                    player.set_level_group(&args[1]);
                }
                true
            }
            "gr.setlevelgroup" => {
                if self.settings.get_bool("triggerhack_groups", true) && args.len() == 2 {
                    let level = player
                        .current_level()
                        .or_else(|| self.get_level(&clean_level_name(&player.level_name())));
                    if let Some(level) = level {
                        for id in level.get_players() {
                            if let Some(target) = self.get_player(id) {
                                target.set_level_group(&args[1]);
                            }
                        }
                    }
                }
                true
            }
            "gr.setplayergroup" => {
                if self.settings.get_bool("triggerhack_groups", true) && args.len() == 3 {
                    if let Some(target) = self.get_player_by_account(&args[1], PLTYPE_ANYCLIENT) {
                        target.set_level_group(&args[2]);
                    }
                }
                true
            }
            "gr.rcchat" => {
                if !self.settings.get_bool("triggerhack_rc", false) {
                    return true;
                }
                let message = args.iter().skip(1).cloned().collect::<Vec<_>>().join(",");
                let mut packet = Buffer::new();
                packet
                    .write_byte(PLO_PRIVATEMESSAGE)
                    .write_string8(&format!("[RC] {}: {}", player.account_name(), message));
                self.send_buffer_to_type(PLTYPE_RC, &packet);
                true
            }
            "gr.addguildmember" => {
                if !self.settings.get_bool("triggerhack_guilds", false) || args.len() < 3 {
                    return true;
                }
                let guild = args[1].trim();
                let account = args[2].trim();
                if !guild.is_empty() && !account.is_empty() {
                    let path = format!("guilds/guild{guild}.txt");
                    if let Ok(data) = self.config.load_file(&path) {
                        if !String::from_utf8_lossy(&data).contains(account) {
                            let mut line = account.to_string();
                            if let Some(nick) = args.get(3).filter(|value| !value.is_empty()) {
                                line.push(':');
                                line.push_str(nick);
                            }
                            let mut updated = data;
                            updated.extend_from_slice(format!("\n{line}").as_bytes());
                            let _ = self.config.save_file(&path, &updated);
                        }
                    } else {
                        let _ = self.config.save_file(&path, account.as_bytes());
                    }
                }
                true
            }
            "gr.removeguildmember" => {
                if !self.settings.get_bool("triggerhack_guilds", false) || args.len() < 3 {
                    return true;
                }
                let guild = args[1].trim();
                let account = args[2].trim();
                if !guild.is_empty() && !account.is_empty() {
                    let path = format!("guilds/guild{guild}.txt");
                    if let Ok(data) = self.config.load_file(&path) {
                        let text = String::from_utf8_lossy(&data);
                        if let Some(start) = text.find(account) {
                            let end = text[start..]
                                .find('\n')
                                .map(|offset| start + offset + 1)
                                .unwrap_or(text.len());
                            let mut updated = String::new();
                            updated.push_str(&text[..start]);
                            updated.push_str(&text[end..]);
                            let _ = self.config.save_file(&path, updated.as_bytes());
                        }
                    }
                }
                true
            }
            "gr.removeguild" => {
                if !self.settings.get_bool("triggerhack_guilds", false) || args.len() < 2 {
                    return true;
                }
                let guild = args[1].trim();
                if !guild.is_empty() {
                    let path = format!("guilds/guild{guild}.txt");
                    let _ = self.config.delete_file(&path);
                    for target in self.get_all_players() {
                        if target.guild() != guild {
                            continue;
                        }
                        target.set_guild("");
                        target.set_guild_nickname("");
                        let mut packet = Buffer::new();
                        packet
                            .write_byte(PLO_PLAYERPROPS)
                            .write_gchar(PLPROP_NICKNAME)
                            .write(&target.get_prop(PLPROP_NICKNAME));
                        target.send(&packet);
                    }
                }
                true
            }
            "gr.setguild" => {
                if !self.settings.get_bool("triggerhack_guilds", false) || args.len() < 2 {
                    return true;
                }
                let guild = args[1].trim();
                if !guild.is_empty() {
                    let target =
                        if let Some(account) = args.get(2).filter(|value| !value.is_empty()) {
                            self.get_player_by_account(account, PLTYPE_ANYCLIENT)
                        } else {
                            player.self_arc()
                        };
                    if let Some(target) = target {
                        target.set_guild(guild);
                        let base = target
                            .nickname()
                            .split('(')
                            .next()
                            .unwrap_or_default()
                            .trim()
                            .to_string();
                        let base = if base.is_empty() {
                            target.account_name()
                        } else {
                            base
                        };
                        target.set_nickname(&format!("{base} ({guild})"));
                        let mut packet = Buffer::new();
                        packet
                            .write_byte(PLO_PLAYERPROPS)
                            .write_gchar(PLPROP_NICKNAME)
                            .write(&target.get_prop(PLPROP_NICKNAME));
                        target.send(&packet);
                    }
                }
                true
            }
            _ => false,
        }
    }
    pub fn handleTriggerCommand(&self, player: &Player, command: &str, args: &[String]) -> bool {
        self.handle_trigger_command(player, command, args)
    }

    pub fn run_rc_npc_chat(&self, player: &Arc<Player>, payload: &str) {
        if payload.trim().is_empty() || !self.npc_server_running() {
            return;
        }
        let (command, data) = if let Some((command, data)) = payload.split_once(',') {
            (command.trim().to_string(), data.trim().to_string())
        } else {
            let mut parts = payload.split_whitespace();
            let command = parts.next().unwrap_or_default().to_string();
            let data = parts.collect::<Vec<_>>().join(" ");
            (command, data)
        };
        if command.is_empty() {
            return;
        }
        let npcs = self
            .npcs
            .read()
            .unwrap()
            .values()
            .filter(|npc| {
                npc.npc_type() == NPCType::DBNPC && !npc.snapshot().script.trim().is_empty()
            })
            .cloned()
            .collect::<Vec<_>>();
        for npc in npcs {
            let (name, script, state, revision) = {
                let value = npc.state.lock().unwrap();
                (
                    value.npc_name.clone(),
                    value.script.clone(),
                    merge_npc_vm_state(&value),
                    value.vm_revision,
                )
            };
            let mut result = self.run_server_side_gs2_with_context(
                "npc",
                &name,
                "onRCChat",
                &script,
                state,
                snapshot_gs2_player_map(player),
                npc.id(),
                None,
                None,
                &[command.clone(), data.clone()],
            );
            result.vm_revision = revision;
            if !result.error.is_empty() {
                self.send_gs2_compiler_output_to_nc(&format!("NPC {name}"), "error", &result.error);
                continue;
            }
            if !self.gs2_vm_revision_still_current(&result) {
                continue;
            }
            self.apply_gs2_vm_result(result.clone());
            self.commit_gs2_npc_state(&result);
            for line in &result.output {
                player.send_plo_rc_chat(line);
            }
            for line in &result.nc_messages {
                player.send_plo_rc_chat(line);
            }
        }
    }

    pub fn runRCNPCChat(&self, player: &Arc<Player>, payload: &str) {
        self.run_rc_npc_chat(player, payload)
    }

    pub fn run_server_side_level_event_for_player(
        &self,
        level: &Arc<Level>,
        event_name: &str,
        player: Option<&Arc<Player>>,
        args: &[String],
    ) {
        let npcs = level.get_npcs();
        for npc in npcs {
            self.run_server_side_npc_event_for_player(&npc, event_name, player, args);
        }
    }

    fn commit_gs2_weapon_state(&self, result: &GS2VMResult) {
        if !result.script_type.eq_ignore_ascii_case("weapon") {
            return;
        }
        let Some(weapon) = self.get_weapon(&result.script_name) else {
            return;
        };
        if weapon.vm_revision != result.vm_revision {
            return;
        }
        let mut updated = (*weapon).clone();
        updated.vm_this = result.this.clone();
        self.delete_weapon(&weapon.name);
        self.add_weapon(Arc::new(updated));
    }

    pub fn compile_gs2_for_feedback(
        &self,
        script_type: &str,
        script_name: &str,
        script: &str,
    ) -> GS2CompileResult {
        let result = npc_runtime::compile_for_feedback(script_type, script_name, script);
        GS2CompileResult {
            bytecode: result.bytecode,
            err_text: result.err_text,
            warning_text: result.warning_text,
        }
    }
    pub fn compileGS2ForFeedback(
        &self,
        script_type: &str,
        script_name: &str,
        script: &str,
    ) -> GS2CompileResult {
        self.compile_gs2_for_feedback(script_type, script_name, script)
    }

    pub fn ensure_weapon_bytecode(&self, weapon_name: &str) -> Option<Arc<Weapon>> {
        let weapon = self.get_weapon(weapon_name)?;
        if weapon.def_player
            || !self.npc_server_running()
            || npc_runtime::clientside_script_is_gs1(&weapon.script)
        {
            return Some(weapon);
        }
        if !npc_runtime::clientside_gs2(&weapon.script).is_some() {
            return Some(weapon);
        }
        if !weapon.bytecode.is_empty() && npc_runtime::bytecode_header(&weapon.bytecode).1 {
            return Some(weapon);
        }
        let compiled = self.compile_gs2_for_feedback("weapon", &weapon.name, &weapon.script);
        if !compiled.err_text.is_empty() || compiled.bytecode.is_empty() {
            if !compiled.err_text.is_empty() {
                self.logger.warning(&format!(
                    "Failed to compile weapon {} on send: {}",
                    weapon.name, compiled.err_text
                ));
            }
            return Some(weapon);
        }
        if !compiled.warning_text.is_empty() {
            self.logger.warning(&format!(
                "Could not compile weapon {} on send: {}",
                weapon.name, compiled.warning_text
            ));
            return Some(weapon);
        }
        let mut updated = (*weapon).clone();
        updated.bytecode = compiled.bytecode;
        updated.bytecode_file = weapon_bytecode_file_name(&updated.name);
        let _ = self.save_weapon_file(&mut updated);
        let updated = Arc::new(updated);
        self.delete_weapon(&weapon.name);
        self.add_weapon(updated.clone());
        Some(updated)
    }
    pub fn ensureWeaponBytecode(&self, weapon_name: &str) -> Option<Arc<Weapon>> {
        self.ensure_weapon_bytecode(weapon_name)
    }
}

fn system_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn split_comma_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .collect()
}
fn clean_level_name(value: &str) -> String {
    value
        .replace('\\', "/")
        .trim_end_matches(".nw")
        .trim_end_matches(".zelda")
        .trim_end_matches(".graal")
        .to_string()
}
fn level_file_candidates(value: &str) -> Vec<String> {
    let value = value.trim().replace('\\', "/");
    let clean = clean_level_name(&value);
    let mut names = Vec::new();
    let mut add = |candidate: String| {
        if !candidate.is_empty() && !names.contains(&candidate) {
            names.push(candidate);
        }
    };
    for name in [value.clone(), clean.clone()] {
        add(name.clone());
        if !name.starts_with("world/") {
            add(format!("world/{name}"));
            add(format!("world/levels/{name}"));
        }
        if !Path::new(&name).extension().is_some() {
            add(format!("{name}.nw"));
            if !name.starts_with("world/") {
                add(format!("world/{name}.nw"));
                add(format!("world/levels/{name}.nw"));
            }
        }
    }
    names
}

fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut table = vec![vec![false; value.len() + 1]; pattern.len() + 1];
    table[0][0] = true;
    for (i, token) in pattern.iter().enumerate() {
        for j in 0..=value.len() {
            table[i + 1][j] = match token {
                b'*' => table[i][j] || (j > 0 && table[i + 1][j - 1]),
                b'?' => j > 0 && table[i][j - 1],
                byte => j > 0 && table[i][j - 1] && *byte == value[j - 1],
            };
        }
    }
    table[pattern.len()][value.len()]
}

fn path_glob_match(pattern: &str, value: &str) -> bool {
    #[derive(Clone)]
    enum Token {
        Literal(u8),
        Any,
        Star,
        Class {
            negated: bool,
            ranges: Vec<(u8, u8)>,
        },
    }

    let pattern = pattern.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < pattern.len() {
        match pattern[index] {
            b'\\' => {
                index += 1;
                if index >= pattern.len() {
                    return false;
                }
                tokens.push(Token::Literal(pattern[index]));
            }
            b'*' => tokens.push(Token::Star),
            b'?' => tokens.push(Token::Any),
            b'[' => {
                let mut cursor = index + 1;
                let negated = if cursor < pattern.len() && pattern[cursor] == b'^' {
                    cursor += 1;
                    true
                } else {
                    false
                };
                let mut ranges = Vec::new();
                let mut closed = false;
                while cursor < pattern.len() {
                    if pattern[cursor] == b']' && !ranges.is_empty() {
                        closed = true;
                        break;
                    }
                    let start = if pattern[cursor] == b'\\' {
                        cursor += 1;
                        if cursor >= pattern.len() {
                            return false;
                        }
                        pattern[cursor]
                    } else {
                        pattern[cursor]
                    };
                    cursor += 1;
                    if cursor + 1 < pattern.len()
                        && pattern[cursor] == b'-'
                        && pattern[cursor + 1] != b']'
                    {
                        cursor += 1;
                        let end = if pattern[cursor] == b'\\' {
                            cursor += 1;
                            if cursor >= pattern.len() {
                                return false;
                            }
                            pattern[cursor]
                        } else {
                            pattern[cursor]
                        };
                        ranges.push((start.min(end), start.max(end)));
                        cursor += 1;
                    } else {
                        ranges.push((start, start));
                    }
                }
                if !closed {
                    return false;
                }
                tokens.push(Token::Class { negated, ranges });
                index = cursor;
            }
            byte => tokens.push(Token::Literal(byte)),
        }
        index += 1;
    }

    let value = value.as_bytes();
    let mut table = vec![vec![false; value.len() + 1]; tokens.len() + 1];
    table[0][0] = true;
    for (token_index, token) in tokens.iter().enumerate() {
        for value_index in 0..=value.len() {
            if !table[token_index][value_index] {
                continue;
            }
            match token {
                Token::Star => {
                    table[token_index + 1][value_index] = true;
                    if value_index < value.len() && value[value_index] != b'/' {
                        table[token_index][value_index + 1] = true;
                    }
                }
                Token::Any if value_index < value.len() && value[value_index] != b'/' => {
                    table[token_index + 1][value_index + 1] = true;
                }
                Token::Literal(expected)
                    if value_index < value.len() && value[value_index] == *expected =>
                {
                    table[token_index + 1][value_index + 1] = true;
                }
                Token::Class { negated, ranges }
                    if value_index < value.len() && value[value_index] != b'/' =>
                {
                    let matched = ranges
                        .iter()
                        .any(|(start, end)| (*start..=*end).contains(&value[value_index]));
                    if matched != *negated {
                        table[token_index + 1][value_index + 1] = true;
                    }
                }
                _ => {}
            }
        }
    }
    table[tokens.len()][value.len()]
}

fn is_default_player_asset(category: &str, file_name: &str) -> bool {
    let base = Path::new(file_name)
        .file_name()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let patterns: &[&str] = match category {
        "heads" => &["head*.png", "head*.gif"],
        "bodies" => &["body.png", "body2.png", "body3.png"],
        "swords" => &["sword?.png", "sword?.gif"],
        "shields" => &["shield?.png", "shield?.gif"],
        _ => &[],
    };
    patterns.iter().any(|pattern| glob_match(pattern, &base))
}

fn format_online_time(total: i32) -> String {
    let total = total.max(0);
    let seconds = total % 60;
    let minutes = (total / 60) % 60;
    let hours = total / 3600;
    if hours != 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes != 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

fn is_default_client_file(file_name: &str) -> bool {
    const PATTERNS: &[&str] = &[
        "carried.gani",
        "carry.gani",
        "carrystill.gani",
        "carrypeople.gani",
        "dead.gani",
        "def.gani",
        "ghostani.gani",
        "grab.gani",
        "gralats.gani",
        "hatoff.gani",
        "haton.gani",
        "hidden.gani",
        "hiddenstill.gani",
        "hurt.gani",
        "idle.gani",
        "kick.gani",
        "lava.gani",
        "lift.gani",
        "maps1.gani",
        "maps2.gani",
        "maps3.gani",
        "pull.gani",
        "push.gani",
        "ride.gani",
        "rideeat.gani",
        "ridefire.gani",
        "ridehurt.gani",
        "ridejump.gani",
        "ridestill.gani",
        "ridesword.gani",
        "shoot.gani",
        "sit.gani",
        "skip.gani",
        "sleep.gani",
        "spin.gani",
        "swim.gani",
        "sword.gani",
        "walk.gani",
        "walkslow.gani",
        "sword?.png",
        "sword?.gif",
        "shield?.png",
        "shield?.gif",
        "head*.png",
        "head*.gif",
        "body.png",
        "body2.png",
        "body3.png",
        "w*.png",
        "w*.gif",
        "plisticon*.png",
        "plisticon*.gif",
        "emoticon*.png",
        "emoticon*.gif",
        "emoticon*.mng",
        "-.gif",
        "arrow.wav",
        "arrowon.wav",
        "axe.wav",
        "bomb.wav",
        "chest.wav",
        "compudead.wav",
        "crush.wav",
        "dead.wav",
        "extra.wav",
        "fire.wav",
        "frog.wav",
        "frog2.wav",
        "goal.wav",
        "horse.wav",
        "horse2.wav",
        "item.wav",
        "item2.wav",
        "jump.wav",
        "lift.wav",
        "lift2.wav",
        "nextpage.wav",
        "put.wav",
        "sign.wav",
        "steps.wav",
        "steps2.wav",
        "stonemove.wav",
        "sword.wav",
        "swordon.wav",
        "thunder.wav",
        "water.wav",
        "pics1.png",
        "sprites.png",
        "basepackage.gupd",
        "tempsitcbd.ttf",
        "arial.ttf",
    ];
    let base = Path::new(&file_name.replace('\\', "/"))
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    PATTERNS.iter().any(|pattern| glob_match(pattern, &base))
}

fn valid_client_file_signature(file_name: &str, data: &[u8]) -> bool {
    match Path::new(file_name)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "png" => data.starts_with(b"\x89PNG\r\n\x1a\n"),
        "gif" => data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a"),
        "mng" => data.starts_with(b"\x8aMNG\r\n\x1a\n"),
        _ => true,
    }
}

fn calculate_crc32_checksum(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[derive(Clone, Debug, Default)]
pub struct UpdatePackageFileEntry {
    pub size: u32,
    pub checksum: u32,
}

pub struct UpdatePackage {
    package_name: String,
    file_list: Mutex<HashMap<String, UpdatePackageFileEntry>>,
    checksum: Mutex<u32>,
    package_size: Mutex<u32>,
}

impl UpdatePackage {
    pub fn new(package_name: &str) -> Self {
        Self {
            package_name: package_name.to_string(),
            file_list: Mutex::new(HashMap::new()),
            checksum: Mutex::new(0),
            package_size: Mutex::new(0),
        }
    }

    pub fn NewUpdatePackage(package_name: &str) -> Self {
        Self::new(package_name)
    }

    pub fn get_package_name(&self) -> String {
        self.package_name.clone()
    }

    pub fn GetPackageName(&self) -> String {
        self.get_package_name()
    }

    pub fn get_package_size(&self) -> u32 {
        *self.package_size.lock().unwrap()
    }

    pub fn GetPackageSize(&self) -> u32 {
        self.get_package_size()
    }

    pub fn get_file_list(&self) -> HashMap<String, UpdatePackageFileEntry> {
        self.file_list.lock().unwrap().clone()
    }

    pub fn GetFileList(&self) -> HashMap<String, UpdatePackageFileEntry> {
        self.get_file_list()
    }

    pub fn compare_checksum(&self, check: u32) -> bool {
        *self.checksum.lock().unwrap() == check
    }

    pub fn CompareChecksum(&self, check: u32) -> bool {
        self.compare_checksum(check)
    }

    pub fn reload(&self, server: &Server) {
        *self.checksum.lock().unwrap() = 0;
        *self.package_size.lock().unwrap() = 0;
        self.file_list.lock().unwrap().clear();

        let Ok(file_contents) = server.config.load_file(&self.package_name) else {
            return;
        };
        *self.checksum.lock().unwrap() = calculate_crc32_checksum(&file_contents);
        for line in String::from_utf8_lossy(&file_contents).split('\n') {
            let line = line.trim();
            if !line.starts_with("FILE") {
                continue;
            }
            let file_path = line[4..].trim();
            let Some(base_file_name) = Path::new(file_path)
                .file_name()
                .map(|value| value.to_string_lossy().into_owned())
            else {
                continue;
            };
            let Ok(update_file_data) = server.config.load_file(&base_file_name) else {
                let mut buffer = Buffer::new();
                buffer
                    .write_byte(PLO_PRIVATEMESSAGE)
                    .write_string8(&format!(
                        "[Server]: Unable to find file '{}' in package '{}'",
                        base_file_name, self.package_name
                    ));
                server.send_buffer_to_type(PLTYPE_RC, &buffer);
                continue;
            };
            let file_length = update_file_data.len() as u32;
            self.file_list.lock().unwrap().insert(
                base_file_name,
                UpdatePackageFileEntry {
                    size: file_length,
                    checksum: calculate_crc32_checksum(&update_file_data),
                },
            );
            let mut package_size = self.package_size.lock().unwrap();
            *package_size = package_size.saturating_add(file_length);
        }
    }

    pub fn Reload(&self, server: &Server) {
        self.reload(server)
    }
}

pub fn load_update_package(server: &Server, name: &str) -> (UpdatePackage, bool) {
    let package = UpdatePackage::new(name);
    package.reload(server);
    let valid = !package.compare_checksum(0);
    (package, valid)
}

pub fn LoadUpdatePackage(server: &Server, name: &str) -> (UpdatePackage, bool) {
    load_update_package(server, name)
}

fn is_valid_server_flag(name: &str, value: &str) -> bool {
    !name.is_empty()
        && !name
            .chars()
            .any(|v| v == '\0' || v == '\r' || v == '\n' || v == '=')
        && !value.chars().any(|v| v == '\0' || v == '\r' || v == '\n')
}
fn server_options_staff_contains(staff: &str, account: &str) -> bool {
    let account = account.trim();
    !account.is_empty()
        && staff.split(',').map(str::trim).any(|entry| {
            !entry.is_empty()
                && !(entry.starts_with('(') && entry.ends_with(')'))
                && entry.eq_ignore_ascii_case(account)
        })
}
fn is_hub_lister_option(option: &str) -> bool {
    matches!(
        option.trim().to_ascii_lowercase().as_str(),
        "getbanhistory" | "getbanbyid" | "getstaffactivity" | "staffactivity"
    )
}
fn local_ban_length(ban_type: &str) -> &'static str {
    match ban_type.trim().to_ascii_lowercase().as_str() {
        "event interruption" | "message code abuse" => "259200",
        "general scamming" | "advertising" | "general harassment" => "604800",
        "racism or severe vulgarity" | "sexual harassment" => "1209600",
        "cheating" => "2592000",
        "advertising money trade"
        | "ban evasion"
        | "speed hacking"
        | "bug abuse"
        | "multiple jailings" => "2592000",
        "server destruction" | "leaking information" => "3888000",
        "account scam" => "7776000",
        "account sharing" | "hacking" | "multiple bans" => "315360000",
        "other unlimited" => "315360001",
        _ => "",
    }
}
fn format_local_ban_time(value: &str) -> String {
    let Ok(seconds) = value.trim().parse::<i64>() else {
        return if value.trim().is_empty() {
            "-".to_string()
        } else {
            value.trim().to_string()
        };
    };
    if seconds < 0 {
        return value.trim().to_string();
    }
    let day = 24 * 60 * 60;
    let year = 365 * day;
    format!(
        "{} years, {} days and {} hours",
        seconds / year,
        (seconds % year) / day,
        (seconds % day) / (60 * 60)
    )
}
fn resolve_local_ban_length(
    banned: bool,
    ban_type: &str,
    requested: &str,
    current: &str,
) -> String {
    if !requested.trim().is_empty() {
        return requested.trim().to_string();
    }
    if !banned {
        return current.to_string();
    }
    let resolved = local_ban_length(ban_type);
    if resolved.is_empty() {
        current.to_string()
    } else {
        resolved.to_string()
    }
}
pub fn all_local_rights() -> i32 {
    (PLPERM_NPCCONTROL << 1) - 1
}
pub fn serverOptionsStaffContains(staff: &str, account: &str) -> bool {
    server_options_staff_contains(staff, account)
}
pub fn allLocalRights() -> i32 {
    all_local_rights()
}
fn external_npc_account_name(account: &str) -> String {
    let account = account.trim();
    if account.is_empty()
        || account.eq_ignore_ascii_case("npcserver")
        || account.eq_ignore_ascii_case("(npcserver)")
    {
        "(npcserver)".to_string()
    } else {
        account.to_string()
    }
}

fn parse_nickname_guild(nickname: &str) -> String {
    let Some(start) = nickname.find('(') else {
        return String::new();
    };
    let tail = &nickname[start + 1..];
    let end = tail.find(')').map(|offset| start + 1 + offset);
    let end = end.unwrap_or(nickname.len());
    nickname[start + 1..end].trim().to_string()
}

fn level_npc_trigger_event_name(action: &str) -> String {
    match action.trim().to_ascii_lowercase().as_str() {
        "leftmouse" => "onActionLeftMouse".to_string(),
        "rightmouse" => "onActionRightMouse".to_string(),
        "middlemouse" => "onActionMiddleMouse".to_string(),
        "doublemouse" => "onActionDoubleMouse".to_string(),
        _ => format!("onAction{}", action.trim()),
    }
}

fn parse_weapon(data: &str) -> Option<Weapon> {
    let mut lines = data.lines();
    if lines.next()?.trim() != "GRAWP001" {
        return None;
    }
    let mut weapon = Weapon::new("");
    let mut script = Vec::new();
    let mut in_script = false;
    for raw in lines {
        let raw = raw.trim_end_matches('\r');
        let line = raw.trim();
        if in_script {
            if line == "SCRIPTEND" {
                in_script = false;
                weapon.script = script.join("\n");
                script.clear();
            } else {
                script.push(raw.to_string());
            }
            continue;
        }
        if line.starts_with("REALNAME ") {
            weapon.name = line[9..].trim().to_string();
        } else if line.starts_with("IMAGE ") {
            weapon.image = line[6..].trim().to_string();
        } else if line.starts_with("BYTECODE ") {
            weapon.bytecode_file = line[9..].trim().to_string();
        } else if line == "SCRIPT" {
            in_script = true;
        }
    }
    if weapon.name.is_empty() {
        None
    } else {
        Some(weapon)
    }
}

fn sanitize_weapon_file_name(name: &str) -> String {
    let mut result = String::new();
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            result.push(byte as char);
        } else {
            let _ = write!(result, "%{byte:03}");
        }
    }
    result
}

fn legacy_weapon_file_name(name: &str) -> String {
    let value: String = name
        .chars()
        .map(|value| match value {
            '\\' | '/' => '_',
            '*' => '@',
            ':' => ';',
            '?' => '!',
            other => other,
        })
        .collect();
    format!("weapon{value}.txt")
}

fn weapon_bytecode_file_name(name: &str) -> String {
    format!("weapon{}.gs2bc", sanitize_weapon_file_name(name))
}

fn parse_database_npc(data: &str) -> Option<NPC> {
    let mut npc = NPC::new(NPCType::DBNPC);
    let normalized = data.replace("\r\n", "\n");
    let lines = normalized.split('\n').collect::<Vec<_>>();
    if lines.first().map(|line| line.trim()) != Some("GRNPC001") {
        return None;
    }
    let mut in_script = false;
    let mut script_lines = Vec::new();
    {
        let mut state = npc.state.lock().unwrap();
        for raw in lines.iter().skip(1) {
            let line = raw.trim_end_matches('\r');
            let trimmed = line.trim();
            if in_script {
                if trimmed == "NPCSCRIPTEND" {
                    in_script = false;
                    state.script = script_lines.join("\n");
                    script_lines.clear();
                } else {
                    script_lines.push(line.to_string());
                }
                continue;
            }
            if trimmed.is_empty() {
                continue;
            }
            if trimmed == "NPCSCRIPT" {
                in_script = true;
                continue;
            }
            let (key, value) = trimmed.split_once(' ').unwrap_or((trimmed, ""));
            let value = value.trim();
            match key.to_ascii_uppercase().as_str() {
                "NAME" => state.npc_name = value.to_string(),
                "ID" => state.id = value.parse().unwrap_or(0),
                "TYPE" => state.script_type = value.to_string(),
                "SCRIPTER" => state.scripter = value.to_string(),
                "IMAGE" => state.image = value.to_string(),
                "STARTLEVEL" if !value.is_empty() => {
                    let level = Arc::new(Level::new());
                    level.set_level_name(value);
                    state.level = Some(level);
                }
                "STARTX" => state.x = (value.parse::<f32>().unwrap_or(0.0) * 16.0) as i16,
                "STARTY" => state.y = (value.parse::<f32>().unwrap_or(0.0) * 16.0) as i16,
                "NICK" => state.character.nickname = value.to_string(),
                "ANI" => state.character.gani = value.to_string(),
                "HP" => state.character.hitpoints = parse_i32(value),
                "GRALATS" => state.character.gralats = parse_i32(value),
                "ARROWS" => state.character.arrows = parse_i32(value),
                "BOMBS" => state.character.bombs = parse_i32(value),
                "GLOVEP" => state.character.glove_power = parse_i32(value),
                "SWORDP" => state.character.sword_power = parse_i32(value),
                "SHIELDP" => state.character.shield_power = parse_i32(value),
                "HEAD" => state.character.head_image = value.to_string(),
                "BODY" => state.character.body_image = value.to_string(),
                "SWORD" => state.character.sword_image = value.to_string(),
                "SHIELD" => state.character.shield_image = value.to_string(),
                "HORSE" => state.character.horse_image = value.to_string(),
                "COLORS" => {
                    for (index, part) in value.split(',').take(5).enumerate() {
                        state.character.colors[index] = parse_i32(part.trim()) as u8;
                    }
                }
                "SPRITE" => {
                    let sprite = parse_i32(value) as u8;
                    state.sprite = sprite;
                    state.character.sprite = sprite;
                }
                "AP" => state.character.ap = parse_i32(value),
                "TIMEOUT" => state.timeout = parse_i32(value).saturating_mul(20),
                "SAVEARR" => {
                    for (index, part) in value.split(',').take(10).enumerate() {
                        state.saves[index] = parse_i32(part.trim()) as u8;
                    }
                }
                "FLAG" => {
                    let (name, value) = value.split_once('=').unwrap_or((value, ""));
                    if !name.trim().is_empty() {
                        state
                            .flag_list
                            .insert(name.trim().to_string(), value.to_string());
                    }
                }
                _ => {}
            }
        }
        if in_script && !script_lines.is_empty() {
            state.script = script_lines.join("\n");
        }
        if state.npc_name.is_empty() || state.id == 0 {
            return None;
        }
    }
    Some(npc)
}

fn save_npc_file(server: &Server, npc: &NPC, file_name: &str) -> io::Result<()> {
    let state = npc.state.lock().unwrap();
    let level_name = state
        .level
        .as_ref()
        .map(|level| level.get_name())
        .unwrap_or_default();
    let colors = state
        .character
        .colors
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let saves = state
        .saves
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mut out = String::new();
    out.push_str("GRNPC001\r\n");
    for (key, value) in [
        ("NAME", state.npc_name.clone()),
        ("ID", state.id.to_string()),
        ("TYPE", state.script_type.clone()),
        ("SCRIPTER", state.scripter.clone()),
        ("IMAGE", state.image.clone()),
        ("STARTLEVEL", level_name),
        ("STARTX", format!("{:.2}", f32::from(state.x) / 16.0)),
        ("STARTY", format!("{:.2}", f32::from(state.y) / 16.0)),
        ("NICK", state.character.nickname.clone()),
        ("ANI", state.character.gani.clone()),
        ("HP", state.character.hitpoints.to_string()),
        ("GRALATS", state.character.gralats.to_string()),
        ("ARROWS", state.character.arrows.to_string()),
        ("BOMBS", state.character.bombs.to_string()),
        ("GLOVEP", state.character.glove_power.to_string()),
        ("SWORDP", state.character.sword_power.to_string()),
        ("SHIELDP", state.character.shield_power.to_string()),
        ("HEAD", state.character.head_image.clone()),
        ("BODY", state.character.body_image.clone()),
        ("SWORD", state.character.sword_image.clone()),
        ("SHIELD", state.character.shield_image.clone()),
        ("HORSE", state.character.horse_image.clone()),
        ("COLORS", colors),
        ("SPRITE", state.character.sprite.to_string()),
        ("AP", state.character.ap.to_string()),
        ("TIMEOUT", (state.timeout / 20).to_string()),
    ] {
        let _ = writeln!(out, "{key} {value}\r");
    }
    out.push_str("LAYER 0\r\nSHAPETYPE 0\r\n");
    if state.width > 0 || state.height > 0 {
        let _ = writeln!(out, "SHAPE {} {}\r", state.width, state.height);
    } else {
        out.push_str("SHAPE 32 48\r\n");
    }
    let _ = writeln!(out, "SAVEARR {saves}\r");
    let mut flag_names = state.flag_list.keys().cloned().collect::<Vec<_>>();
    flag_names.sort();
    for name in flag_names {
        let _ = writeln!(out, "FLAG {name}={}\r", state.flag_list[&name]);
    }
    out.push_str("NPCSCRIPT\r\n");
    let script = state.script.replace("\r\n", "\n");
    out.push_str(&script.replace('\n', "\r\n"));
    if !script.ends_with('\n') {
        out.push_str("\r\n");
    }
    out.push_str("NPCSCRIPTEND\r\n");
    server.config.save_file(file_name, out.as_bytes())
}

fn save_database_npc_file(server: &Server, npc: &NPC) -> io::Result<()> {
    if npc.npc_type() != NPCType::DBNPC || npc.npc_name().is_empty() {
        return Ok(());
    }
    save_npc_file(server, npc, &format!("npcs/npc{}.txt", npc.npc_name()))
}

fn delete_database_npc_file(server: &Server, name: &str) -> io::Result<()> {
    if name.is_empty() {
        return Ok(());
    }
    match server.config.delete_file(format!("npcs/npc{name}.txt")) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub type GS2VMPlayerFlag = npc_runtime::PlayerFlag;
pub type GS2VMPlayerProp = npc_runtime::PlayerProp;
pub type GS2VMPlayerEffect = npc_runtime::PlayerEffect;
pub type GS2VMServerFlag = npc_runtime::ServerFlag;
pub type GS2VMPlayerMessage = npc_runtime::PlayerMessage;
pub type GS2VMPlayerIRCMessage = npc_runtime::IRCMessage;
pub type GS2VMPlayerWeapon = npc_runtime::PlayerWeapon;
pub type GS2VMPlayerClass = npc_runtime::PlayerClass;
pub type GS2VMPlayerWarp = npc_runtime::PlayerWarp;
pub type GS2VMPlayerAttachment = npc_runtime::PlayerAttachment;
pub type GS2VMFileAction = npc_runtime::FileAction;
pub type GS2VMNPCFlag = npc_runtime::NPCFlag;
pub type GS2VMNPCFunctionCall = npc_runtime::NPCFunctionCall;
pub type GS2VMNPCAction = npc_runtime::NPCAction;
pub type GS2VMLevelAction = npc_runtime::LevelAction;
pub type GS2VMSocketAction = npc_runtime::SocketAction;
pub type GS2VMScheduledEvent = npc_runtime::ScheduledEvent;
pub type GS2VMWaitEvent = npc_runtime::WaitEvent;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GS2VMSocketUpdate {
    pub name: String,
    pub id: String,
    pub address: String,
    pub port: i32,
    pub ip_address: String,
    pub data: String,
    pub buffer: String,
    pub package_delimiter: String,
    pub is_connected: bool,
    pub state: npc_runtime::AnyMap,
    pub joined_classes: Vec<String>,
    pub parent_name: String,
    pub parent_id: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GS2VMResult {
    pub output: Vec<String>,
    pub client_triggers: Vec<npc_runtime::ClientTrigger>,
    pub player_flags: Vec<GS2VMPlayerFlag>,
    pub player_props: Vec<GS2VMPlayerProp>,
    pub player_effects: Vec<GS2VMPlayerEffect>,
    pub server_flags: Vec<GS2VMServerFlag>,
    pub player_messages: Vec<GS2VMPlayerMessage>,
    pub player_rc_messages: Vec<GS2VMPlayerMessage>,
    pub player_irc_messages: Vec<GS2VMPlayerIRCMessage>,
    pub rc_messages: Vec<String>,
    pub nc_messages: Vec<String>,
    pub player_weapons: Vec<GS2VMPlayerWeapon>,
    pub player_classes: Vec<GS2VMPlayerClass>,
    pub player_warps: Vec<GS2VMPlayerWarp>,
    pub player_attachments: Vec<GS2VMPlayerAttachment>,
    pub file_actions: Vec<GS2VMFileAction>,
    pub npc_flags: Vec<GS2VMNPCFlag>,
    pub npc_function_calls: Vec<GS2VMNPCFunctionCall>,
    pub npc_actions: Vec<GS2VMNPCAction>,
    pub level_actions: Vec<GS2VMLevelAction>,
    pub socket_actions: Vec<GS2VMSocketAction>,
    pub socket_updates: Vec<GS2VMSocketUpdate>,
    pub scheduled_events: Vec<GS2VMScheduledEvent>,
    pub wait_events: Vec<GS2VMWaitEvent>,
    pub this: npc_runtime::AnyMap,
    pub error: String,
    pub warning: String,
    pub script_type: String,
    pub script_name: String,
    pub event_name: String,
    pub script: String,
    pub player_context: HashMap<String, String>,
    pub npc_id: u32,
    pub vm_revision: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GS2CompileResult {
    pub bytecode: Vec<u8>,
    pub err_text: String,
    pub warning_text: String,
}

fn gs2_result_from_runtime(result: npc_runtime::ScriptResult) -> GS2VMResult {
    GS2VMResult {
        output: result.output,
        client_triggers: result
            .client_triggers
            .into_iter()
            .map(|value| {
                let value = value.strip_prefix("clientside,").unwrap_or(&value);
                let mut parts = value.split(',');
                npc_runtime::ClientTrigger {
                    kind: "clientside".to_string(),
                    name: parts.next().unwrap_or_default().to_string(),
                    args: parts.map(str::to_string).collect(),
                }
            })
            .collect(),
        player_flags: result.player_flags,
        player_props: result.player_props,
        player_effects: result.player_effects,
        server_flags: result.server_flags,
        player_messages: result.player_messages,
        player_rc_messages: result.player_rc_messages,
        player_irc_messages: result.player_irc_messages,
        rc_messages: result.rc_messages,
        nc_messages: result.nc_messages,
        player_weapons: result.player_weapons,
        player_classes: result.player_classes,
        player_warps: result.player_warps,
        player_attachments: result.player_attachments,
        file_actions: result.file_actions,
        npc_flags: result.npc_flags,
        npc_function_calls: result.npc_function_calls,
        npc_actions: result.npc_actions,
        level_actions: result.level_actions,
        socket_actions: result.socket_actions,
        socket_updates: result
            .socket_updates
            .into_iter()
            .map(|value| GS2VMSocketUpdate {
                name: value.name,
                id: value.id,
                address: value.address,
                port: value.port,
                ip_address: value.ip_address,
                data: value.data,
                buffer: value.buffer,
                package_delimiter: value.package_delimiter,
                is_connected: value.is_connected,
                state: value.state,
                joined_classes: value.joined_classes,
                parent_name: value.parent_name,
                parent_id: value.parent_id,
            })
            .collect(),
        scheduled_events: result.scheduled_events,
        wait_events: result.wait_events,
        this: result.this,
        error: result.err,
        warning: String::new(),
        script_type: result.script_type,
        script_name: result.script_name,
        event_name: result.event_name,
        script: result.script,
        player_context: result.player_context,
        npc_id: result.npc_id,
        vm_revision: 0,
    }
}

fn snapshot_gs2_account(player: &Player) -> String {
    let account = player.account.lock().unwrap();
    if account.device_id > 0
        && (account.account_name.is_empty() || account.account_name.eq_ignore_ascii_case("guest"))
    {
        format!("pc:{}", account.device_id)
    } else {
        account.account_name.clone()
    }
}

fn snapshot_gs2_player_map(player: &Arc<Player>) -> HashMap<String, String> {
    let account = player.account.lock().unwrap();
    let state = player.state.lock().unwrap();
    let account_name = if account.device_id > 0
        && (account.account_name.is_empty() || account.account_name.eq_ignore_ascii_case("guest"))
    {
        format!("pc:{}", account.device_id)
    } else {
        account.account_name.clone()
    };
    let mut result = HashMap::new();
    result.insert("account".to_string(), account_name);
    result.insert("id".to_string(), state.id.to_string());
    result.insert("nick".to_string(), account.character.nickname.clone());
    result.insert("nickname".to_string(), account.character.nickname.clone());
    result.insert("guild".to_string(), state.guild.clone());
    result.insert("level".to_string(), account.level_name.clone());
    result.insert(
        "x".to_string(),
        format!("{:.6}", f64::from(account.x) / 16.0),
    );
    result.insert(
        "y".to_string(),
        format!("{:.6}", f64::from(account.y) / 16.0),
    );
    result.insert(
        "dir".to_string(),
        (account.character.sprite & 0x03).to_string(),
    );
    result.insert("onlinetime".to_string(), account.online_time.to_string());
    result.insert(
        "adminlevel".to_string(),
        admin_level_from_rights(account.admin_rights).to_string(),
    );
    result.insert(
        "rights".to_string(),
        gs2_right_names(account.admin_rights).join(","),
    );
    result.insert("folders".to_string(), account.folder_list.join("\n"));
    result
}

fn snapshot_gs2_player_context(player: &Arc<Player>) -> Option<npc_runtime::PlayerContext> {
    let account = player.account.lock().unwrap();
    let state = player.state.lock().unwrap();
    let account_name = if account.device_id > 0
        && (account.account_name.is_empty() || account.account_name.eq_ignore_ascii_case("guest"))
    {
        format!("pc:{}", account.device_id)
    } else {
        account.account_name.clone()
    };
    if account_name.is_empty() {
        return None;
    }
    Some(npc_runtime::PlayerContext {
        id: state.id,
        account: account_name,
        nick: account.character.nickname.clone(),
        nickname: account.character.nickname.clone(),
        guild: state.guild.clone(),
        level: account.level_name.clone(),
        dir: i32::from(account.character.sprite & 0x03),
        x: f64::from(account.x) / 16.0,
        y: f64::from(account.y) / 16.0,
        online_time: account.online_time,
        admin_level: admin_level_from_rights(account.admin_rights),
        flags: account.flag_list.clone(),
        rights: gs2_right_names(account.admin_rights),
        folders: account.folder_list.clone(),
    })
}

fn admin_level_from_rights(mut rights: i32) -> i32 {
    let mut level = 0;
    while rights != 0 {
        level += rights & 1;
        rights >>= 1;
    }
    level.min(4)
}

fn gs2_right_names(rights: i32) -> Vec<String> {
    [
        (PLPERM_WARPTO, "warptoxy"),
        (PLPERM_WARPTOPLAYER, "warptoplayer"),
        (PLPERM_SUMMON, "warpplayers"),
        (PLPERM_UPDATELEVEL, "updatelevel"),
        (PLPERM_DISCONNECT, "disconnectplayers"),
        (PLPERM_VIEWATTRIBUTES, "viewattributes"),
        (PLPERM_SETATTRIBUTES, "setattributes"),
        (PLPERM_SETSELFATTRIBUTES, "setownattributes"),
        (PLPERM_RESETATTRIBUTES, "resetattributes"),
        (PLPERM_ADMINMSG, "adminmessage"),
        (PLPERM_SETRIGHTS, "changerights"),
        (PLPERM_BAN, "banplayers"),
        (PLPERM_SETCOMMENTS, "changecomments"),
        (PLPERM_INVISIBLE, "invisible"),
        (PLPERM_MODIFYSTAFFACCOUNT, "changestaffaccounts"),
        (PLPERM_SETSERVERFLAGS, "setserverflags"),
        (PLPERM_SETSERVEROPTIONS, "changeoptions"),
        (PLPERM_SETFOLDEROPTIONS, "changefolderconfig"),
        (PLPERM_SETFOLDERRIGHTS, "changefolderrights"),
        (PLPERM_NPCCONTROL, "NPC-Control"),
    ]
    .into_iter()
    .filter(|(bit, _)| rights & *bit != 0)
    .map(|(_, name)| name.to_string())
    .collect()
}

fn merge_npc_vm_state(state: &NPCState) -> npc_runtime::AnyMap {
    let mut result = state.vm_this.clone();
    for (name, value) in &state.flag_list {
        set_npc_vm_state_path(&mut result, name, serde_json::Value::String(value.clone()));
    }
    result
}

fn set_npc_vm_state_path(state: &mut npc_runtime::AnyMap, path: &str, value: serde_json::Value) {
    let parts = path
        .split('.')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return;
    }
    if parts.len() == 1 {
        state.insert(parts[0].to_string(), value);
        return;
    }
    let entry = state
        .entry(parts[0].to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if !entry.is_object() {
        let previous = entry.take();
        let mut object = serde_json::Map::new();
        if !previous.is_null() {
            object.insert("__gs2value".to_string(), previous);
        }
        *entry = serde_json::Value::Object(object);
    }
    let current = entry.as_object_mut().expect("object inserted above");
    set_npc_vm_state_object_path(current, &parts[1..], value);
}

fn set_npc_vm_state_object_path(
    state: &mut serde_json::Map<String, serde_json::Value>,
    parts: &[&str],
    value: serde_json::Value,
) {
    if parts.len() == 1 {
        let name = parts[0].to_string();
        if let Some(existing) = state.get_mut(&name) {
            if let Some(object) = existing.as_object_mut() {
                object.insert("__gs2value".to_string(), value);
            } else {
                *existing = value;
            }
        } else {
            state.insert(name, value);
        }
        return;
    }
    let entry = state
        .entry(parts[0].to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if !entry.is_object() {
        let previous = entry.take();
        let mut object = serde_json::Map::new();
        if !previous.is_null() {
            object.insert("__gs2value".to_string(), previous);
        }
        *entry = serde_json::Value::Object(object);
    }
    let current = entry.as_object_mut().expect("object inserted above");
    set_npc_vm_state_object_path(current, &parts[1..], value);
}

fn normalize_gs2_compiler_line(line: &str) -> String {
    let mut line = line.trim().trim_start_matches("->").trim().to_string();
    loop {
        let lower = line.to_ascii_lowercase();
        let prefix = if lower.starts_with("[error]") {
            Some("[error]")
        } else if lower.starts_with("error:") {
            Some("error:")
        } else if lower.starts_with("[warning]") {
            Some("[warning]")
        } else if lower.starts_with("warning:") {
            Some("warning:")
        } else if lower.starts_with("[info]") {
            Some("[info]")
        } else if lower.starts_with("info:") {
            Some("info:")
        } else {
            None
        };
        let Some(prefix) = prefix else { break };
        line = line[prefix.len()..].trim().to_string();
    }
    line
}

fn normalize_gs2_vm_error_line(value: &str) -> String {
    let mut line = normalize_gs2_compiler_line(value);
    loop {
        let lower = line.to_ascii_lowercase();
        let prefix = if lower.starts_with("typeerror:") {
            Some("TypeError:")
        } else if lower.starts_with("syntaxerror:") {
            Some("SyntaxError:")
        } else if lower.starts_with("referenceerror:") {
            Some("ReferenceError:")
        } else {
            None
        };
        let Some(prefix) = prefix else {
            break;
        };
        line = line[prefix.len()..].trim().to_string();
    }
    if let Some(index) = line.find(" at ") {
        if let Some(relative) = line[index..].find("(<eval>:") {
            let start = index + relative + "(<eval>:".len();
            let end = line[start..]
                .bytes()
                .take_while(|byte| byte.is_ascii_digit())
                .count()
                + start;
            if end > start {
                return format!("{} at line {}", line[..index].trim(), &line[start..end]);
            }
        }
    }
    line.trim().to_string()
}

fn apply_gs2_npc_props_state(state: &mut NPCState, props: &HashMap<String, String>) -> bool {
    let mut changed = false;
    for (raw_name, value) in props {
        match raw_name.trim().to_ascii_lowercase().as_str() {
            "image" => {
                if state.image != *value {
                    state.image = value.clone();
                    changed = true;
                }
            }
            "chat" | "message" => {
                if state.character.chat_message != *value {
                    state.character.chat_message = value.clone();
                    changed = true;
                }
            }
            "nick" | "nickname" => {
                if state.character.nickname != *value {
                    state.character.nickname = value.clone();
                    changed = true;
                }
            }
            "ani" | "gani" => {
                if state.character.gani != *value {
                    state.character.gani = value.clone();
                    changed = true;
                }
            }
            "dir" => {
                let direction = parse_gs2_int(value) as u8;
                if state.character.sprite != direction || state.sprite != direction {
                    state.character.sprite = direction;
                    state.sprite = direction;
                    changed = true;
                }
            }
            "head" | "headimg" => {
                if state.character.head_image != *value {
                    state.character.head_image = value.clone();
                    changed = true;
                }
            }
            "body" | "bodyimg" => {
                if state.character.body_image != *value {
                    state.character.body_image = value.clone();
                    changed = true;
                }
            }
            "sword" | "swordimg" => {
                if state.character.sword_image != *value {
                    state.character.sword_image = value.clone();
                    changed = true;
                }
            }
            "shield" | "shieldimg" => {
                if state.character.shield_image != *value {
                    state.character.shield_image = value.clone();
                    changed = true;
                }
            }
            "horse" | "horseimg" => {
                if state.character.horse_image != *value {
                    state.character.horse_image = value.clone();
                    changed = true;
                }
            }
            "colors" => {
                for (index, part) in value
                    .split(|ch: char| ch == ',' || ch.is_ascii_whitespace())
                    .filter(|part| !part.is_empty())
                    .take(5)
                    .enumerate()
                {
                    let color = gs2_color_id(part) as u8;
                    if state.character.colors[index] != color {
                        state.character.colors[index] = color;
                        changed = true;
                    }
                }
            }
            "hearts" => {
                let value = parse_gs2_float(value) as i32;
                if state.character.hitpoints != value {
                    state.character.hitpoints = value;
                    changed = true;
                }
            }
            "gralats" => {
                let value = parse_gs2_int(value);
                if state.character.gralats != value {
                    state.character.gralats = value;
                    changed = true;
                }
            }
            "arrows" => {
                let value = parse_gs2_int(value);
                if state.character.arrows != value {
                    state.character.arrows = value;
                    changed = true;
                }
            }
            "bombs" => {
                let value = parse_gs2_int(value);
                if state.character.bombs != value {
                    state.character.bombs = value;
                    changed = true;
                }
            }
            "glovepower" => {
                let value = parse_gs2_int(value);
                if state.character.glove_power != value {
                    state.character.glove_power = value;
                    changed = true;
                }
            }
            "ap" => {
                let value = parse_gs2_int(value);
                if state.character.ap != value {
                    state.character.ap = value;
                    changed = true;
                }
            }
            "swordpower" => {
                let value = parse_gs2_int(value);
                if state.character.sword_power != value {
                    state.character.sword_power = value;
                    changed = true;
                }
            }
            "shieldpower" => {
                let value = parse_gs2_int(value);
                if state.character.shield_power != value {
                    state.character.shield_power = value;
                    changed = true;
                }
            }
            "width" => {
                let value = parse_gs2_int(value);
                if state.width != value {
                    state.width = value;
                    changed = true;
                }
            }
            "height" => {
                let value = parse_gs2_int(value);
                if state.height != value {
                    state.height = value;
                    changed = true;
                }
            }
            _ => {}
        }
    }
    changed
}

fn parse_gs2_int(value: &str) -> i32 {
    value.trim().parse::<i32>().unwrap_or(0)
}

fn parse_gs2_float(value: &str) -> f64 {
    value.trim().parse::<f64>().unwrap_or(0.0)
}

fn gs2_color_id(value: &str) -> i32 {
    match value.trim().to_ascii_lowercase().as_str() {
        "white" => 0,
        "yellow" => 1,
        "orange" => 2,
        "pink" => 3,
        "red" | "darkred" | "dark red" => 5,
        "green" => 6,
        "blue" => 8,
        "lightblue" | "light blue" => 9,
        "black" => 21,
        _ => parse_gs2_int(value),
    }
}

fn saved_put_npc_name(level_name: &str, id: u32, fallback: usize) -> String {
    let mut base = Path::new(level_name)
        .file_stem()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_default();
    if base.is_empty() || base == "." {
        base = "level".to_string();
    }
    let base = base
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if id == 0 {
        format!("{base}_putnpc_{fallback}")
    } else {
        format!("{base}_putnpc_{id}")
    }
}

// ---------------------------------------------------------------------------
// Player transport, login, and packet builders

const PLAYER_WRITE_QUEUE_LIMIT: usize = 8 << 20;
const ZLIB_FIX_SCRIPT: &str = concat!(
    "//#CLIENTSIDE§",
    "if(playerchats) {§",
    "  this.chr = {ascii(#e(0,1,#c)),0,0,0,0};§",
    "  for(this.c=0;this.c<strlen(#c)*(strlen(#c)>=11);this.c++) {§",
    "    this.chr[2] = ascii(#e(this.c,1,#c));§",
    "    this.chr[3] += 1*(this.chr[2]==this.chr[0]);§",
    "    if(!(this.chr[2] in {this.chr[0], this.chr[1]})) {§",
    "      if(this.chr[1]==0) {§",
    "        if(this.chr[2]!=this.chr[0]) this.chr[1]=this.chr[2];§",
    "      } else break; //[A][B][C]§",
    "    }§",
    "    this.chr[4] += 1*(this.chr[2]==this.chr[1]);§",
    "    if(this.chr[1]>0 && this.chr[3] in |2,10|) break; //[1<A<11][B]§",
    "    if(this.chr[3]>=11 && this.chr[4]>1) break; //[A>=11][B>1]§",
    "  }§",
    "  if(this.c>0 && this.c == strlen(#c)) setplayerprop #c,\u{00a0}#c\u{00a0}; //Pad§",
    "}§",
);

struct PlayerState {
    conn: Option<ReplayStream>,
    async_write: bool,
    websocket: bool,
    websocket_candidate: bool,
    websocket_buffer: Vec<u8>,
    websocket_fragment: Vec<u8>,
    websocket_fragmented: bool,
    recv_buffer: Vec<u8>,
    read_scratch: Vec<u8>,
    encryption: Encryption,
    out_encryption: Encryption,
    queue_outgoing: bool,
    out_queue: Vec<u8>,
    wire_queue: Vec<u8>,
    version: String,
    server_name: String,
    id: u16,
    player_type: i32,
    version_id: i32,
    map_ref: Option<Arc<Map>>,
    current_level: Option<Arc<Level>>,
    external_players: HashMap<u16, Arc<Player>>,
    loaded: bool,
    disconnected: bool,
    defer_client_login: bool,
    login_pending: bool,
    next_is_raw: bool,
    raw_packet_size: usize,
    is_ftp: bool,
    last_folder: String,
    rc_large_files: HashMap<String, Vec<u8>>,
    last_rc_download_notice: Instant,
    last_rc_download_notice_file: String,
    nc_post_login_sent: bool,
    gr_movement_updated: bool,
    awaiting_listserver_verify: bool,
    first_level: bool,
    gr_movement_packets: Vec<Vec<u8>>,
    npcserver_port: String,
    packet_count: i32,
    invalid_packets: i32,
    guild: String,
    level_group: String,
    gr_exec_parameter_list: String,
    last_data: Instant,
    last_movement: Instant,
    last_chat: Instant,
    last_nick: Instant,
    last_message: Instant,
    last_save: Instant,
    last_one_minute: Instant,
    last_serverside_trigger: Instant,
    last_serverside_trigger_action: String,
}

pub struct Player {
    pub account: Mutex<Account>,
    state: Mutex<PlayerState>,
    server: Weak<Server>,
    self_ref: Mutex<Weak<Player>>,
}

fn is_rc_protected_file(path: &str) -> bool {
    matches!(
        path,
        "config/adminconfig.txt"
            | "config/allowedversions.txt"
            | "config/foldersconfig.txt"
            | "config/ipbans.txt"
            | "config/rchelp.txt"
            | "config/rcmessage.txt"
            | "config/rules.txt"
            | "config/servermessage.html"
            | "config/serveroptions.txt"
    )
}

fn read_cstring_bytes(buffer: &mut Buffer) -> Vec<u8> {
    let start = buffer.read;
    while buffer.read < buffer.data.len() && buffer.data[buffer.read] != 0 {
        buffer.read += 1;
    }
    let result = buffer.data[start..buffer.read].to_vec();
    if buffer.read < buffer.data.len() {
        buffer.read += 1;
    }
    result
}

fn decode_nc_script_bytes(data: &[u8]) -> String {
    let decoded = if data.contains(&0xa7) {
        data.iter()
            .map(|byte| if *byte == 0xa7 { b'\n' } else { *byte })
            .collect::<Vec<_>>()
    } else {
        data.to_vec()
    };
    let text = String::from_utf8_lossy(&decoded).into_owned();
    if data.contains(&0xa7)
        || text.starts_with('\"')
        || text.contains("\",")
        || text.contains(",\"")
    {
        if data.contains(&0xa7) {
            text
        } else {
            guntokenize_text(&text)
        }
    } else {
        text
    }
}

fn write_nc_script_bytes(buffer: &mut Buffer, script: &str) {
    for byte in script.as_bytes() {
        if *byte == b'\n' {
            buffer.write_byte(0xa7);
        } else {
            buffer.write_byte(*byte);
        }
    }
}

fn npc_type_wire_value(npc_type: NPCType) -> u8 {
    npc_type as u8
}

impl Player {
    fn nc_file_rights(&self, file_path: &str) -> String {
        let file_path = file_path.trim().trim_start_matches('/').replace('\\', "/");
        if file_path.is_empty() || file_path.contains("..") || file_path.contains(':') {
            return String::new();
        }
        let entries = self.account.lock().unwrap().folder_list.clone();
        if entries.is_empty() {
            return "rw".to_string();
        }
        let mut read = false;
        let mut write = false;
        for entry in entries {
            let (mut rights, pattern) = entry
                .split_once(' ')
                .map(|(rights, pattern)| (rights.trim().to_ascii_lowercase(), pattern.trim()))
                .unwrap_or_else(|| ("r".to_string(), entry.trim()));
            let deny = rights.starts_with('-');
            rights = rights.trim_start_matches('-').to_string();
            let pattern = pattern.trim_start_matches('/').replace('\\', "/");
            if pattern.is_empty()
                || pattern.contains("..")
                || pattern.contains(':')
                || !path_glob_match(&pattern, &file_path)
            {
                continue;
            }
            if deny {
                if rights.contains('r') {
                    read = false;
                }
                if rights.contains('w') {
                    write = false;
                }
            } else {
                read |= rights.contains('r');
                write |= rights.contains('w');
            }
        }
        let mut result = String::new();
        if read {
            result.push('r');
        }
        if write {
            result.push('w');
        }
        result
    }

    fn nc_file_has_right(&self, file_path: &str, right: char) -> bool {
        self.account.lock().unwrap().folder_list.is_empty()
            || self.nc_file_rights(file_path).contains(right)
    }

    fn send_nc_npc_add(&self, npc: &NPC) {
        let mut packet = Buffer::new();
        let name = npc.npc_name();
        let script_type = npc.script_type();
        let level = npc.level_name();
        packet
            .write_byte(PLO_NC_NPCADD)
            .write_gint(npc.id())
            .write_gchar(NPCPROP_NAME)
            .write_gchar(name.len() as u8)
            .write(name.as_bytes())
            .write_gchar(NPCPROP_TYPE)
            .write_gchar(script_type.len() as u8)
            .write(script_type.as_bytes())
            .write_gchar(NPCPROP_CURLEVEL)
            .write_gchar(level.len() as u8)
            .write(level.as_bytes());
        self.send(&packet);
    }

    fn send_nc_npc_list(&self) {
        let Some(server) = self.server() else {
            return;
        };
        let mut npcs = server
            .npcs
            .read()
            .unwrap()
            .values()
            .filter(|npc| npc.npc_type() == NPCType::DBNPC)
            .cloned()
            .collect::<Vec<_>>();
        npcs.sort_by_key(|npc| (npc.id(), npc.npc_name().to_ascii_lowercase()));
        for npc in npcs {
            self.send_nc_npc_add(&npc);
        }
    }

    fn msg_pli_nc_list_npcs(&self, _packet: &[u8]) -> bool {
        if self.player_type() & PLTYPE_ANYNC == 0 {
            return true;
        }
        self.send_nc_npc_list();
        true
    }

    fn msg_pli_nc_npcget(&self, packet: &[u8]) -> bool {
        if self.player_type() & PLTYPE_ANYNC == 0 {
            return true;
        }
        let mut input = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        if input.remaining() == 0 {
            return true;
        }
        let id = input.read_gint();
        if let Some(npc) = self.server().and_then(|server| server.get_npc(id)) {
            let mut output = Buffer::new();
            output
                .write_byte(PLO_NC_NPCATTRIBUTES)
                .write(gtokenize_text(&npc.variable_dump()).as_bytes());
            self.send(&output);
        }
        true
    }

    fn msg_pli_nc_npcdelete(&self, packet: &[u8]) -> bool {
        if self.player_type() & PLTYPE_ANYNC == 0 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut input = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let id = input.read_gint();
        let Some(npc) = server.get_npc(id) else {
            return true;
        };
        if npc.npc_type() != NPCType::DBNPC {
            return true;
        }
        let name = npc.npc_name();
        if !self.nc_file_has_right(&format!("NPCS/{name}"), 'w') {
            server.send_to_nc(&format!(
                "{} prob: insufficient rights to delete npc {name}",
                self.account_name()
            ));
            return true;
        }
        if server.delete_npc(id) {
            let _ = server.delete_database_npc_file(&name);
            let mut notification = Buffer::new();
            notification.write_byte(PLO_NC_NPCDELETE).write_gint(id);
            server.send_buffer_to_type(PLTYPE_ANYNC, &notification);
            server.send_to_nc(&format!("NPC {name} deleted by {}", self.account_name()));
        }
        true
    }

    fn msg_pli_nc_npcreset(&self, packet: &[u8]) -> bool {
        if self.player_type() & PLTYPE_ANYNC == 0 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut input = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let id = input.read_gint();
        let Some(npc) = server.get_npc(id) else {
            return true;
        };
        if npc.npc_type() != NPCType::DBNPC {
            return true;
        }
        let name = npc.npc_name();
        if !self.nc_file_has_right(&format!("NPCS/{name}"), 'w') {
            server.send_to_nc(&format!(
                "{} prob: insufficient rights to reset npc {name}",
                self.account_name()
            ));
            return true;
        }
        npc.reset_script();
        let _ = server.save_database_npc_file(&npc);
        let message = format!("NPC script of {name} reset by {}", self.account_name());
        server.send_to_nc(&message);
        server.run_server_side_event_for_active_scripts(
            "onAllRCChat",
            self.self_arc().as_ref(),
            std::slice::from_ref(&message),
        );
        true
    }

    fn msg_pli_nc_npcscriptget(&self, packet: &[u8]) -> bool {
        if self.player_type() & PLTYPE_ANYNC == 0 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut input = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let id = input.read_gint();
        let Some(npc) = server.get_npc(id) else {
            return true;
        };
        let name = npc.npc_name();
        if npc.npc_type() == NPCType::DBNPC && !self.nc_file_has_right(&format!("NPCS/{name}"), 'r')
        {
            server.send_to_nc(&format!(
                "{} prob: insufficient rights to read npc {name}",
                self.account_name()
            ));
            return true;
        }
        let mut output = Buffer::new();
        output
            .write_byte(PLO_NC_NPCSCRIPT)
            .write_gint(id)
            .write(gtokenize_text(&npc.snapshot().script).as_bytes());
        self.send(&output);
        true
    }

    fn move_npc_to_level(&self, npc: &Arc<NPC>, level: &Arc<Level>, x: i16, y: i16) {
        if let Some(old) = npc.level() {
            old.remove_npc(npc.id());
        }
        npc.set_level(Some(level.clone()));
        npc.set_position(x, y, npc.snapshot().z);
        level.add_npc(npc.clone());
        if let Some(server) = self.server() {
            for id in level.get_players() {
                if let Some(player) = server.get_player(id) {
                    if player.player_type() & PLTYPE_ANYCLIENT != 0 {
                        player.send_plo_npcprops(npc);
                    }
                }
            }
            if !npc.npc_name().is_empty() {
                let mut packet = Buffer::new();
                packet
                    .write_byte(PLO_NC_NPCADD)
                    .write_gint(npc.id())
                    .write_gchar(NPCPROP_CURLEVEL)
                    .write_string8_encoded(&level.get_name());
                server.send_buffer_to_type(PLTYPE_ANYNC, &packet);
            }
        }
    }

    fn msg_pli_nc_npcwarp(&self, packet: &[u8]) -> bool {
        if self.player_type() & PLTYPE_ANYNC == 0 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut input = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let id = input.read_gint();
        let x = f32::from(input.read_gchar()) / 2.0;
        let y = f32::from(input.read_gchar()) / 2.0;
        let level_name = input.read_string();
        let Some(npc) = server.get_npc(id) else {
            return true;
        };
        let name = npc.npc_name();
        if npc.npc_type() == NPCType::DBNPC && !self.nc_file_has_right(&format!("NPCS/{name}"), 'w')
        {
            server.send_to_nc(&format!(
                "{} prob: insufficient rights to warp npc {name}",
                self.account_name()
            ));
            return true;
        }
        if let Some(level) = server.get_level(&level_name) {
            self.move_npc_to_level(&npc, &level, (x * 16.0) as i16, (y * 16.0) as i16);
            if npc.npc_type() == NPCType::DBNPC {
                let _ = server.save_database_npc_file(&npc);
            }
        }
        true
    }

    fn msg_pli_nc_npcflagsget(&self, packet: &[u8]) -> bool {
        if self.player_type() & PLTYPE_ANYNC == 0 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut input = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let id = input.read_gint();
        let Some(npc) = server.get_npc(id) else {
            return true;
        };
        let name = npc.npc_name();
        if npc.npc_type() == NPCType::DBNPC && !self.nc_file_has_right(&format!("NPCS/{name}"), 'r')
        {
            server.send_to_nc(&format!(
                "{} prob: insufficient rights to read npc {name}",
                self.account_name()
            ));
            return true;
        }
        let mut lines = String::new();
        let mut flags = npc.flags().into_iter().collect::<Vec<_>>();
        flags.sort_by_key(|(key, _)| key.clone());
        for (key, value) in flags {
            let _ = writeln!(lines, "{key}={value}");
        }
        let mut output = Buffer::new();
        output
            .write_byte(PLO_NC_NPCFLAGS)
            .write_gint(id)
            .write(gtokenize_text(&lines).as_bytes());
        self.send(&output);
        true
    }

    fn msg_pli_nc_npcscriptset(&self, packet: &[u8]) -> bool {
        if self.player_type() & PLTYPE_ANYNC == 0 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut input = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let id = input.read_gint();
        let script = guntokenize_text(&input.read_string());
        let Some(npc) = server.get_npc(id) else {
            return true;
        };
        let name = npc.npc_name();
        if npc.npc_type() == NPCType::DBNPC && !self.nc_file_has_right(&format!("NPCS/{name}"), 'w')
        {
            server.send_to_nc(&format!(
                "{} prob: insufficient rights to write npc {name}",
                self.account_name()
            ));
            return true;
        }
        npc.replace_script(&script);
        if npc.npc_type() == NPCType::DBNPC {
            let _ = server.save_database_npc_file(&npc);
        }
        let message = format!("NPC script of {name} updated by {}", self.account_name());
        server.send_to_nc(&message);
        server.run_server_side_event_for_active_scripts(
            "onAllRCChat",
            self.self_arc().as_ref(),
            std::slice::from_ref(&message),
        );
        let npc_for_event = npc.clone();
        let player = self.self_arc();
        let server_for_event = server.clone();
        thread::spawn(move || {
            server_for_event.run_server_side_npc_event_for_player(
                &npc_for_event,
                "onCreated",
                player.as_ref(),
                &[],
            );
        });
        true
    }

    fn msg_pli_nc_npcflagsset(&self, packet: &[u8]) -> bool {
        if self.player_type() & PLTYPE_ANYNC == 0 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut input = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let id = input.read_gint();
        let flags_text = guntokenize_text(&input.read_string());
        let Some(npc) = server.get_npc(id) else {
            return true;
        };
        let name = npc.npc_name();
        if npc.npc_type() == NPCType::DBNPC && !self.nc_file_has_right(&format!("NPCS/{name}"), 'w')
        {
            server.send_to_nc(&format!(
                "{} prob: insufficient rights to write npc {name}",
                self.account_name()
            ));
            return true;
        }
        let mut flags = HashMap::new();
        for line in flags_text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line.split_once('=').unwrap_or((line, ""));
            if !key.trim().is_empty() {
                flags.insert(key.trim().to_string(), value.to_string());
            }
        }
        npc.set_flags(flags);
        if npc.npc_type() == NPCType::DBNPC {
            let _ = server.save_database_npc_file(&npc);
        }
        server.send_to_nc(&format!(
            "NPC flags of {name} updated by {}",
            self.account_name()
        ));
        true
    }

    fn msg_pli_nc_npcadd(&self, packet: &[u8]) -> bool {
        if self.player_type() & PLTYPE_ANYNC == 0 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut input = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let parts = guntokenize_text(&input.read_string())
            .split('\n')
            .map(str::to_string)
            .collect::<Vec<_>>();
        if parts.len() < 7 {
            return true;
        }
        let name = parts[0].trim().to_string();
        if name.is_empty() {
            return true;
        }
        let level_name = parts[4].clone();
        let Some(level) = server.get_level(&level_name) else {
            server.send_to_nc("Error adding database npc: Level does not exist");
            return true;
        };
        let npc = Arc::new(NPC::new(NPCType::DBNPC));
        npc.set_name(&name);
        npc.set_script_type(&parts[2]);
        npc.set_scripter(&parts[3]);
        npc.set_position(
            (parts[5].parse::<f32>().unwrap_or(0.0) * 16.0) as i16,
            (parts[6].parse::<f32>().unwrap_or(0.0) * 16.0) as i16,
            0,
        );
        npc.set_level(Some(level.clone()));
        if let Ok(id) = parts[1].trim().parse::<u32>() {
            if id >= 1000 {
                npc.set_id(id);
            }
        }
        if !server.add_npc(npc.clone()) {
            server.send_to_nc("Error adding database npc: Id is in use");
            return true;
        }
        level.add_npc(npc.clone());
        for id in level.get_players() {
            if let Some(player) = server.get_player(id) {
                if player.player_type() & PLTYPE_ANYCLIENT != 0 {
                    player.send_plo_npcprops(&npc);
                }
            }
        }
        let _ = server.save_database_npc_file(&npc);
        let mut notice = Buffer::new();
        notice
            .write_byte(PLO_NC_NPCADD)
            .write_gint(npc.id())
            .write_gchar(NPCPROP_NAME)
            .write_string8_encoded(&name)
            .write_gchar(NPCPROP_TYPE)
            .write_string8_encoded(&parts[2])
            .write_gchar(NPCPROP_CURLEVEL)
            .write_string8_encoded(&level_name);
        server.send_buffer_to_type(PLTYPE_ANYNC, &notice);
        server.send_to_nc(&format!("NPC {name} added by {}", self.account_name()));
        true
    }

    fn msg_pli_nc_classedit(&self, packet: &[u8]) -> bool {
        if self.player_type() & PLTYPE_ANYNC == 0 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut input = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let name = input.read_string();
        if !self.nc_file_has_right(&format!("CLASSES/{name}"), 'r') {
            server.send_to_nc(&format!(
                "{} prob: insufficient rights to read class {name}",
                self.account_name()
            ));
            return true;
        }
        if let Some(class) = server.get_class(&name) {
            let mut output = Buffer::new();
            output
                .write_byte(PLO_NC_CLASSGET)
                .write_string8_encoded(&name)
                .write(gtokenize_text(&class.script).as_bytes());
            self.send(&output);
        }
        true
    }

    fn msg_pli_nc_classadd(&self, packet: &[u8]) -> bool {
        if self.player_type() & PLTYPE_ANYNC == 0 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut input = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let name = input.read_gchar_string();
        let script = guntokenize_text(&input.read_string());
        if !self.nc_file_has_right(&format!("CLASSES/{name}"), 'w') {
            server.send_to_nc(&format!(
                "{} prob: insufficient rights to write class {name}",
                self.account_name()
            ));
            return true;
        }
        let existed = server.get_class(&name).is_some();
        let class = Arc::new(ScriptClass {
            name: name.clone(),
            script: script.clone(),
        });
        server.classes.write().unwrap().insert(name.clone(), class);
        if let Some(class) = server.get_class(&name) {
            server.update_class_for_players(&class);
        }
        let _ = server.save_class_file(&name, &script);
        if !existed {
            let mut add = Buffer::new();
            add.write_byte(PLO_NC_CLASSADD).write(name.as_bytes());
            server.send_buffer_to_type(PLTYPE_ANYNC, &add);
        }
        server.send_to_nc(&format!(
            "Script {name} {} by {}",
            if existed { "updated" } else { "added" },
            self.account_name()
        ));
        true
    }

    fn msg_pli_nc_localnpcsget(&self, packet: &[u8]) -> bool {
        if self.player_type() & PLTYPE_ANYNC == 0 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut input = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let level_name = input.read_string();
        if level_name.is_empty() {
            return true;
        }
        let Some(level) = server.get_level(&level_name) else {
            return true;
        };
        let mut dump = format!("Variables dump from level {level_name}\n");
        for npc in level.get_npcs() {
            dump.push('\n');
            dump.push_str(&npc.variable_dump());
            dump.push('\n');
        }
        let mut output = Buffer::new();
        output
            .write_byte(PLO_NC_LEVELDUMP)
            .write(gtokenize_text(&dump).as_bytes());
        self.send(&output);
        true
    }

    fn msg_pli_nc_weaponlistget(&self, _packet: &[u8]) -> bool {
        if self.player_type() & PLTYPE_ANYNC == 0 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut names = server
            .weapons
            .read()
            .unwrap()
            .values()
            .filter(|weapon| !weapon.def_player && !weapon.name.is_empty())
            .map(|weapon| weapon.name.clone())
            .collect::<Vec<_>>();
        names.sort_by_key(|name| name.to_ascii_lowercase());
        names.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
        let mut output = Buffer::new();
        output.write_byte(PLO_NC_WEAPONLISTGET);
        for name in names {
            output.write_string8_encoded(&name);
        }
        self.send(&output);
        true
    }

    fn msg_pli_nc_weaponget(&self, packet: &[u8]) -> bool {
        if self.player_type() & PLTYPE_ANYNC == 0 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut input = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let name = input.read_string();
        if !self.nc_file_has_right(&format!("WEAPONS/{name}"), 'r') {
            server.send_to_nc(&format!(
                "{} prob: insufficient rights to read weapon {name}",
                self.account_name()
            ));
            return true;
        }
        let Some(weapon) = server.get_weapon(&name) else {
            server.send_to_nc(&format!(
                "{} prob: weapon {name} doesn't exist",
                self.account_name()
            ));
            return true;
        };
        if weapon.def_player {
            return true;
        }
        let mut output = Buffer::new();
        output
            .write_byte(PLO_NC_WEAPONGET)
            .write_string8_encoded(&name)
            .write_string8_encoded(&weapon.image);
        write_nc_script_bytes(&mut output, &weapon.script);
        self.send(&output);
        true
    }

    fn msg_pli_nc_weaponadd(&self, packet: &[u8]) -> bool {
        if self.player_type() & PLTYPE_ANYNC == 0 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut input = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let name = input.read_gchar_string();
        let image = input.read_gchar_string();
        let script = decode_nc_script_bytes(&read_cstring_bytes(&mut input));
        if !self.nc_file_has_right(&format!("WEAPONS/{name}"), 'w') {
            server.send_to_nc(&format!(
                "{} prob: insufficient rights to write weapon {name}",
                self.account_name()
            ));
            return true;
        }
        let compile_result =
            if server.npc_server_running() && !npc_runtime::clientside_script_is_gs1(&script) {
                server.compile_gs2_for_feedback("weapon", &name, &script)
            } else {
                GS2CompileResult::default()
            };
        if !compile_result.err_text.is_empty() {
            server.send_gs2_compiler_output_to_nc(
                &format!("Weapon {name}"),
                "error",
                &compile_result.err_text,
            );
            return true;
        }

        let existing = server.get_weapon(&name);
        if existing.as_ref().is_some_and(|weapon| weapon.def_player) {
            return true;
        }
        let action = if let Some(existing) = existing {
            let mut updated = (*existing).clone();
            updated.image = image;
            updated.script = script;
            updated.bytecode = compile_result.bytecode;
            updated.bytecode_file = if updated.bytecode.is_empty() {
                String::new()
            } else {
                weapon_bytecode_file_name(&updated.name)
            };
            updated.vm_this.clear();
            updated.vm_revision = updated.vm_revision.wrapping_add(1);
            server.delete_weapon(&name);
            let updated = Arc::new(updated);
            server.add_weapon(updated.clone());
            for player in server.get_all_players() {
                if player.player_type() & PLTYPE_ANYCLIENT != 0 && player.has_account_weapon(&name)
                {
                    player.send_plo_npcweapondel(&name);
                    player.send_weapon(&updated);
                }
            }
            let mut saved = (*updated).clone();
            let _ = server.save_weapon_file(&mut saved);
            ("updated", updated)
        } else {
            let mut new_weapon = Weapon::new(&name);
            new_weapon.image = image;
            new_weapon.script = script;
            new_weapon.bytecode = compile_result.bytecode;
            if !new_weapon.bytecode.is_empty() {
                new_weapon.bytecode_file = weapon_bytecode_file_name(&new_weapon.name);
            }
            new_weapon.modified = true;
            let new_weapon = Arc::new(new_weapon);
            server.add_weapon(new_weapon.clone());
            let mut saved = (*new_weapon).clone();
            let _ = server.save_weapon_file(&mut saved);
            ("added", new_weapon)
        };
        let log_msg = format!(
            "Weapon/GUI-script {} {} by {}",
            name,
            action.0,
            self.account_name()
        );
        server.send_to_nc(&log_msg);
        let me = self.self_arc();
        server.run_server_side_event_for_active_scripts("onAllRCChat", me.as_ref(), &[log_msg]);
        if !compile_result.warning_text.is_empty() {
            server.send_gs2_compiler_output_to_nc(
                &format!("Weapon {name}"),
                "warning",
                &compile_result.warning_text,
            );
        }
        server.run_server_side_weapon_event_for_player(&action.1, "onCreated", me.as_ref(), &[]);
        true
    }

    fn msg_pli_nc_weapondelete(&self, packet: &[u8]) -> bool {
        if self.player_type() & PLTYPE_ANYNC == 0 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut input = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let name = input.read_string();
        if !self.nc_file_has_right(&format!("WEAPONS/{name}"), 'w') {
            server.send_to_nc(&format!(
                "{} prob: insufficient rights to delete weapon {name}",
                self.account_name()
            ));
            return true;
        }
        if let Some(weapon) = server.get_weapon(&name) {
            if !weapon.def_player {
                server.delete_weapon(&name);
                let _ = server.delete_weapon_file(&name);
                for player in server.get_all_players() {
                    if player.player_type() & PLTYPE_ANYCLIENT != 0 {
                        player.send_plo_npcweapondel(&name);
                    }
                }
                server.send_to_nc(&format!("Weapon {name} deleted by {}", self.account_name()));
            }
        } else {
            server.send_to_nc(&format!(
                "{} prob: weapon {name} doesn't exist",
                self.account_name()
            ));
        }
        true
    }

    fn msg_pli_nc_classdelete(&self, packet: &[u8]) -> bool {
        if self.player_type() & PLTYPE_ANYNC == 0 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut input = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let name = input.read_string();
        if !self.nc_file_has_right(&format!("CLASSES/{name}"), 'w') {
            server.send_to_nc(&format!(
                "{} prob: insufficient rights to delete class {name}",
                self.account_name()
            ));
            return true;
        }
        if server.delete_class(&name) {
            let _ = server.delete_class_file(&name);
            let mut output = Buffer::new();
            output.write_byte(PLO_NC_CLASSDELETE).write(name.as_bytes());
            server.send_buffer_to_type(PLTYPE_ANYNC, &output);
            server.send_to_nc(&format!("{} has deleted class {name}", self.account_name()));
        } else {
            server.send_to_nc(&format!("error: {name} does not exist on this server!"));
        }
        true
    }

    fn msg_pli_nc_levellistget(&self, _packet: &[u8]) -> bool {
        if self.player_type() & PLTYPE_ANYNC == 0 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut names = server
            .levels
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        names.sort();
        let level_list = names
            .iter()
            .map(|name| format!("{name}\n"))
            .collect::<String>();
        let mut output = Buffer::new();
        output
            .write_byte(PLO_NC_LEVELLIST)
            .write(gtokenize_text(&level_list).as_bytes());
        self.send(&output);
        true
    }

    fn msg_pli_nc_levellistset(&self, _packet: &[u8]) -> bool {
        self.player_type() & PLTYPE_ANYNC != 0
    }

    pub fn msgPLI_NC_LISTNPCS(&self, packet: &[u8]) -> bool {
        self.msg_pli_nc_list_npcs(packet)
    }
    pub fn msgPLI_NC_NPCGET(&self, packet: &[u8]) -> bool {
        self.msg_pli_nc_npcget(packet)
    }
    pub fn msgPLI_NC_NPCDELETE(&self, packet: &[u8]) -> bool {
        self.msg_pli_nc_npcdelete(packet)
    }
    pub fn msgPLI_NC_NPCRESET(&self, packet: &[u8]) -> bool {
        self.msg_pli_nc_npcreset(packet)
    }
    pub fn msgPLI_NC_NPCSCRIPTGET(&self, packet: &[u8]) -> bool {
        self.msg_pli_nc_npcscriptget(packet)
    }
    pub fn msgPLI_NC_NPCWARP(&self, packet: &[u8]) -> bool {
        self.msg_pli_nc_npcwarp(packet)
    }
    pub fn msgPLI_NC_NPCFLAGSGET(&self, packet: &[u8]) -> bool {
        self.msg_pli_nc_npcflagsget(packet)
    }
    pub fn msgPLI_NC_NPCSCRIPTSET(&self, packet: &[u8]) -> bool {
        self.msg_pli_nc_npcscriptset(packet)
    }
    pub fn msgPLI_NC_NPCFLAGSSET(&self, packet: &[u8]) -> bool {
        self.msg_pli_nc_npcflagsset(packet)
    }
    pub fn msgPLI_NC_NPCADD(&self, packet: &[u8]) -> bool {
        self.msg_pli_nc_npcadd(packet)
    }
    pub fn msgPLI_NC_CLASSEDIT(&self, packet: &[u8]) -> bool {
        self.msg_pli_nc_classedit(packet)
    }
    pub fn msgPLI_NC_CLASSADD(&self, packet: &[u8]) -> bool {
        self.msg_pli_nc_classadd(packet)
    }
    pub fn msgPLI_NC_LOCALNPCSGET(&self, packet: &[u8]) -> bool {
        self.msg_pli_nc_localnpcsget(packet)
    }
    pub fn msgPLI_NC_WEAPONLISTGET(&self, packet: &[u8]) -> bool {
        self.msg_pli_nc_weaponlistget(packet)
    }
    pub fn msgPLI_NC_WEAPONGET(&self, packet: &[u8]) -> bool {
        self.msg_pli_nc_weaponget(packet)
    }
    pub fn msgPLI_NC_WEAPONADD(&self, packet: &[u8]) -> bool {
        self.msg_pli_nc_weaponadd(packet)
    }
    pub fn msgPLI_NC_WEAPONDELETE(&self, packet: &[u8]) -> bool {
        self.msg_pli_nc_weapondelete(packet)
    }
    pub fn msgPLI_NC_CLASSDELETE(&self, packet: &[u8]) -> bool {
        self.msg_pli_nc_classdelete(packet)
    }
    pub fn msgPLI_NC_LEVELLISTGET(&self, packet: &[u8]) -> bool {
        self.msg_pli_nc_levellistget(packet)
    }
    pub fn msgPLI_NC_LEVELLISTSET(&self, packet: &[u8]) -> bool {
        self.msg_pli_nc_levellistset(packet)
    }
}

impl Player {
    fn is_exact_rc_connection(&self) -> bool {
        matches!(self.player_type(), PLTYPE_RC | PLTYPE_RC2 | PLTYPE_ANYRC)
    }

    fn rc_folder_entries(&self) -> Vec<String> {
        self.account.lock().unwrap().folder_list.clone()
    }

    fn rc_file_browser_path(value: &str) -> String {
        let value = value.trim().trim_start_matches('/').replace('\\', "/");
        if value.is_empty() || value.contains("..") || value.contains(':') {
            return value;
        }
        let root = value.split('/').next().unwrap_or_default();
        if matches!(
            root,
            "accounts" | "config" | "logs" | "world" | "weapons" | "scripts" | "npcs"
        ) || root.contains('*')
            || root.contains('?')
        {
            value
        } else {
            format!("world/{value}")
        }
    }

    fn rc_file_browser_pattern(value: &str) -> String {
        let value = value.trim().trim_start_matches('/').replace('\\', "/");
        if value.is_empty() || value.contains("..") || value.contains(':') {
            return value;
        }
        let root = value.split('/').next().unwrap_or_default();
        let has_slash = value.contains('/');
        if matches!(
            root,
            "accounts" | "config" | "logs" | "world" | "weapons" | "scripts" | "npcs"
        ) || (has_slash && (root.contains('*') || root.contains('?')))
        {
            value
        } else {
            format!("world/{value}")
        }
    }

    fn rc_file_rights(&self, file_path: &str) -> String {
        let file_path = Self::rc_file_browser_path(file_path);
        if file_path.is_empty() || file_path.contains("..") || file_path.contains(':') {
            return String::new();
        }
        let mut read = false;
        let mut write = false;
        for entry in self.rc_folder_entries() {
            let (rights, pattern) = entry
                .split_once(' ')
                .map(|(rights, pattern)| (rights.trim().to_ascii_lowercase(), pattern.trim()))
                .unwrap_or_else(|| ("r".to_string(), entry.trim()));
            let pattern = Self::rc_file_browser_pattern(pattern);
            if pattern.is_empty()
                || pattern.contains("..")
                || pattern.contains(':')
                || !path_glob_match(&pattern, &file_path)
            {
                continue;
            }
            read |= rights.contains('r');
            write |= rights.contains('w');
        }
        let mut result = String::new();
        if read {
            result.push('r');
        }
        if write {
            result.push('w');
        }
        result
    }

    fn rc_file_has_right(&self, file_path: &str, right: char) -> bool {
        self.rc_file_rights(file_path).contains(right)
    }

    fn rc_folder_has_right(&self, folder_path: &str, right: char) -> bool {
        let folder = folder_path.trim().trim_matches('/');
        if folder.is_empty() {
            return self.rc_file_has_right("x", right);
        }
        self.rc_file_has_right(&format!("{folder}/x"), right)
    }

    fn rc_file_browser_list_dirs(&self, prefix: &str) -> Vec<String> {
        if prefix.is_empty() {
            let mut result = Vec::new();
            let base = self
                .server()
                .map(|server| server.config.get_base_path())
                .unwrap_or_else(|| PathBuf::from("."));
            if let Ok(entries) = std::fs::read_dir(base) {
                for entry in entries.flatten() {
                    if entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                        result.push(entry.file_name().to_string_lossy().into_owned());
                    }
                }
            }
            result.sort();
            return result;
        }
        let Some(server) = self.server() else {
            return Vec::new();
        };
        let mut result = server.config.list_dirs(prefix).unwrap_or_default();
        result.sort();
        result
    }

    fn expand_rc_folder_path(&self, folder_path: &str) -> Vec<String> {
        let folder_path = folder_path.trim().replace('\\', "/");
        if folder_path.is_empty() {
            return vec![String::new()];
        }
        if !folder_path.contains('*') && !folder_path.contains('?') {
            return vec![folder_path];
        }
        let parts = folder_path
            .trim_end_matches('/')
            .split('/')
            .collect::<Vec<_>>();
        let (start_prefix, start_index) = if parts.first().copied() == Some("world") {
            ("world/".to_string(), 1usize)
        } else {
            (String::new(), 0usize)
        };
        let mut result = Vec::new();
        fn walk(
            player: &Player,
            parts: &[&str],
            prefix: String,
            index: usize,
            out: &mut Vec<String>,
        ) {
            if index >= parts.len() {
                out.push(prefix);
                return;
            }
            for dir in player.rc_file_browser_list_dirs(&prefix) {
                if path_glob_match(parts[index], &dir) {
                    walk(player, parts, format!("{prefix}{dir}/"), index + 1, out);
                }
            }
        }
        walk(self, &parts, start_prefix, start_index, &mut result);
        result
    }

    fn rc_folder_map(&self) -> HashMap<String, String> {
        let mut result = HashMap::new();
        for entry in self.rc_folder_entries() {
            let (rights, mut folder_path) = entry
                .split_once(' ')
                .map(|(rights, path)| (rights.trim().to_ascii_lowercase(), path.trim().to_string()))
                .unwrap_or_else(|| ("r".to_string(), entry.trim().to_string()));
            if !rights.contains('r') {
                continue;
            }
            folder_path = folder_path.replace('\\', "/");
            let mut wildcard = "*".to_string();
            if !folder_path.ends_with('/') {
                if let Some(index) = folder_path.rfind('/') {
                    wildcard = folder_path[index + 1..].to_string();
                    folder_path.truncate(index + 1);
                } else if folder_path.contains('*') || folder_path.contains('?') {
                    wildcard = folder_path.clone();
                    folder_path.clear();
                }
            }
            if folder_path.is_empty() && (wildcard.contains('*') || wildcard.contains('?')) {
                folder_path = "world/".to_string();
            } else {
                folder_path = Self::rc_file_browser_path(&folder_path);
            }
            for real_folder in self.expand_rc_folder_path(&folder_path) {
                result
                    .entry(real_folder)
                    .or_insert_with(String::new)
                    .push_str(&format!("{rights}:{wildcard}\n"));
            }
        }
        result
    }

    fn rc_folder_list(&self, folder_map: &HashMap<String, String>) -> String {
        let mut folders = Vec::new();
        for (folder, entries) in folder_map {
            for entry in entries.lines() {
                let Some((rights, wildcard)) = entry.split_once(':') else {
                    continue;
                };
                folders.push(format!("{rights} {folder}{wildcard}"));
            }
        }
        folders.sort();
        folders.dedup();
        folders.join("\n")
    }

    fn file_browser_message(&self, message: &str) {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_RC_FILEBROWSER_MESSAGE)
            .write(message.as_bytes());
        self.send(&buf);
    }

    fn send_rc_file_browser_packet(&self, packet: &[u8]) {
        let mut data = packet.to_vec();
        data.push(b'\n');
        let running = self
            .server()
            .map(|server| server.is_running())
            .unwrap_or(false);
        let queued = self.state.lock().unwrap().queue_outgoing;
        if queued || !running {
            self.send_packet(&data);
        } else {
            self.send_immediate_packet(&data);
        }
    }

    fn send_rc_file_browser_dir(&self, _folder_map: &HashMap<String, String>) {
        let Some(server) = self.server() else {
            return;
        };
        let folder = self.state.lock().unwrap().last_folder.clone();
        let mut files = server.config.list_files(&folder).unwrap_or_default();
        files.sort();
        let mut header = Buffer::new();
        rc_encoded_bytes(&mut header, folder.as_bytes());
        let initial = {
            let mut packet = Buffer::new();
            packet
                .write_byte(PLO_RC_FILEBROWSER_DIR)
                .write(&header.data);
            packet.data
        };
        let mut packet = Buffer::from_bytes(&initial);
        for file in files {
            if file.starts_with('.') {
                continue;
            }
            let file_path = format!("{folder}{file}");
            let rights = self.rc_file_rights(&file_path);
            if !rights.contains('r') {
                continue;
            }
            let Ok(info) = server.config.file_info(&file_path) else {
                continue;
            };
            let mut entry = Buffer::new();
            rc_encoded_bytes(&mut entry, file.as_bytes());
            rc_encoded_bytes(&mut entry, rights.as_bytes());
            let modified = info
                .modified
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            entry.write_gint5(info.size).write_gint5(modified);
            if packet.len() > initial.len() && packet.len() + 2 + entry.len() > 0x6000 {
                self.send_rc_file_browser_packet(&packet.data);
                packet = Buffer::from_bytes(&initial);
            }
            packet
                .write_byte(b' ')
                .write_gchar(entry.len() as u8)
                .write(&entry.data);
        }
        self.send_rc_file_browser_packet(&packet.data);
    }

    fn msg_pli_rc_filebrowser_start(&self, _packet: &[u8]) -> bool {
        if !self.is_exact_rc_connection() {
            return true;
        }
        let mut folder_entries = self.rc_folder_entries();
        if folder_entries.is_empty()
            && (self.has_right(PLPERM_SETFOLDERRIGHTS) || self.has_right(PLPERM_SETFOLDEROPTIONS))
        {
            if let Some(server) = self.server() {
                folder_entries = server.default_rc_folder_rights();
                self.account.lock().unwrap().folder_list = folder_entries.clone();
            }
        }
        if folder_entries.is_empty() {
            return true;
        }
        let folder_map = self.rc_folder_map();
        let mut list = Buffer::new();
        list.write_byte(PLO_RC_FILEBROWSER_DIRLIST)
            .write(gtokenize_text(&self.rc_folder_list(&folder_map)).as_bytes());
        self.send(&list);
        if !self.state.lock().unwrap().is_ftp {
            let name = self
                .server()
                .map(|server| {
                    nonempty(&server.settings.get("name"))
                        .unwrap_or_else(|| "this server".to_string())
                })
                .unwrap_or_else(|| "this server".to_string());
            self.file_browser_message(&format!("Welcome to the File Browser for {name}."));
        }
        {
            let mut state = self.state.lock().unwrap();
            if !folder_map.contains_key(&state.last_folder) {
                state.last_folder = folder_map.keys().next().cloned().unwrap_or_default();
            }
            state.is_ftp = true;
        }
        self.send_rc_file_browser_dir(&folder_map);
        true
    }

    fn msg_pli_rc_filebrowser_cd(&self, packet: &[u8]) -> bool {
        if !self.is_exact_rc_connection() {
            return true;
        }
        let folder = String::from_utf8_lossy(packet.get(1..).unwrap_or_default()).into_owned();
        let folder_map = self.rc_folder_map();
        if !folder_map.contains_key(&folder) {
            return true;
        }
        self.state.lock().unwrap().last_folder = folder;
        self.send_rc_file_browser_dir(&folder_map);
        true
    }

    fn msg_pli_rc_filebrowser_end(&self, _packet: &[u8]) -> bool {
        if self.is_exact_rc_connection() {
            self.state.lock().unwrap().is_ftp = false;
        }
        true
    }

    fn msg_pli_rc_filebrowser_down(&self, packet: &[u8]) -> bool {
        if !self.is_exact_rc_connection() {
            return true;
        }
        let file_name = String::from_utf8_lossy(packet.get(1..).unwrap_or_default()).into_owned();
        let folder = self.state.lock().unwrap().last_folder.clone();
        let file_path = format!("{folder}{file_name}");
        if !self.rc_file_has_right(&file_path, 'r') {
            self.file_browser_message(&format!("Insufficient rights to download/view {file_path}"));
            return true;
        }
        if !self.has_right(PLPERM_MODIFYSTAFFACCOUNT)
            && matches!(
                file_path.as_str(),
                "config/adminconfig.txt" | "config/allowedversions.txt" | "config/rchelp.txt"
            )
        {
            self.file_browser_message(&format!("Insufficient rights to download/view {file_path}"));
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        match server.config.load_file(&file_path) {
            Ok(data) => {
                let modified = server
                    .config
                    .file_mod_time(&file_path)
                    .ok()
                    .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                    .map(|value| value.as_secs())
                    .unwrap_or(0);
                let mut file_packet = Buffer::new();
                file_packet
                    .write_gchar(PLO_FILE)
                    .write_gint5(modified)
                    .write_gchar(file_name.len() as u8)
                    .write(file_name.as_bytes())
                    .write(&data)
                    .write_byte(b'\n');
                let mut outer = Buffer::new();
                outer
                    .write_byte(PLO_RAWDATA)
                    .write_gint(file_packet.len() as u32)
                    .write_byte(b'\n')
                    .write(&file_packet.data);
                self.send_packet(&outer.data);
            }
            Err(_) => {
                server
                    .logger
                    .error(&format!("Failed to load file {}", file_path));
                self.send_plo_filesendfailed(&file_name);
            }
        }
        server.logger.info(&format!(
            "{} downloaded file {}",
            self.account_name(),
            file_name
        ));
        let (last_file, elapsed) = {
            let state = self.state.lock().unwrap();
            (
                state.last_rc_download_notice_file.clone(),
                state.last_rc_download_notice.elapsed(),
            )
        };
        if last_file != file_path || elapsed > Duration::from_secs(1) {
            self.file_browser_message(&format!("Downloaded file {file_name}"));
            let mut state = self.state.lock().unwrap();
            state.last_rc_download_notice_file = file_path;
            state.last_rc_download_notice = Instant::now();
        }
        true
    }

    fn msg_pli_rc_filebrowser_up(&self, packet: &[u8]) -> bool {
        if !self.is_exact_rc_connection() {
            return true;
        }
        let mut input = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let name_len = usize::from(input.read_gchar()).min(input.remaining());
        let file_name = String::from_utf8_lossy(&input.read_bytes(name_len)).into_owned();
        let folder = self.state.lock().unwrap().last_folder.clone();
        let file_path = format!("{folder}{file_name}");
        if !self.rc_file_has_right(&file_path, 'w') {
            self.file_browser_message(&format!("Insufficient rights to upload {file_path}"));
            return true;
        }
        let protected = [
            ("config/adminconfig.txt", PLPERM_MODIFYSTAFFACCOUNT),
            ("config/allowedversions.txt", PLPERM_MODIFYSTAFFACCOUNT),
            ("config/foldersconfig.txt", PLPERM_MODIFYSTAFFACCOUNT),
            ("config/ipbans.txt", PLPERM_SETFOLDEROPTIONS),
            ("config/rchelp.txt", PLPERM_MODIFYSTAFFACCOUNT),
            ("config/rcmessage.txt", PLPERM_MODIFYSTAFFACCOUNT),
            ("config/rules.txt", PLPERM_MODIFYSTAFFACCOUNT),
            ("config/servermessage.html", PLPERM_MODIFYSTAFFACCOUNT),
            ("config/serveroptions.txt", PLPERM_MODIFYSTAFFACCOUNT),
        ];
        if let Some((_, permission)) = protected.iter().find(|(name, _)| *name == file_path) {
            if !self.has_right(PLPERM_MODIFYSTAFFACCOUNT) && !self.has_right(*permission) {
                self.file_browser_message(&format!("Insufficient rights to upload {file_path}"));
                return true;
            }
        }
        let data = input.read_bytes(input.remaining());
        let large = self
            .state
            .lock()
            .unwrap()
            .rc_large_files
            .contains_key(&file_name);
        let Some(server) = self.server() else {
            return true;
        };
        if large {
            self.state
                .lock()
                .unwrap()
                .rc_large_files
                .entry(file_name.clone())
                .or_default()
                .extend_from_slice(&data);
            self.state
                .lock()
                .unwrap()
                .rc_large_files
                .entry(file_name.clone())
                .or_default()
                .extend_from_slice(&data);
        } else {
            if server.config.save_file(&file_path, &data).is_err() {
                server
                    .logger
                    .error(&format!("Failed to save file {}: upload failed", file_path));
                return true;
            }
            server.logger.info(&format!(
                "{} uploaded file {}",
                self.account_name(),
                file_name
            ));
            self.file_browser_message(&format!("Uploaded file {file_name}"));
            self.update_uploaded_file(&folder, &file_name);
        }
        true
    }

    fn msg_pli_rc_filebrowser_move(&self, packet: &[u8]) -> bool {
        if !self.is_exact_rc_connection() {
            return true;
        }
        let mut input = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let dir_len = usize::from(input.read_gbyte()).min(input.remaining());
        let dir = String::from_utf8_lossy(&input.read_bytes(dir_len)).into_owned();
        let mut file_name =
            String::from_utf8_lossy(&input.read_bytes(input.remaining())).into_owned();
        file_name = file_name.replace('"', "");
        let dir = if dir.ends_with('/') || dir.ends_with('\\') {
            dir
        } else {
            format!("{dir}/")
        };
        let folder = self.state.lock().unwrap().last_folder.clone();
        let source = format!("{folder}{file_name}");
        let destination = format!("{dir}{file_name}");
        if !self.rc_file_has_right(&source, 'w') || !self.rc_file_has_right(&destination, 'w') {
            self.file_browser_message(&format!("Not allowed to move file {source}"));
            return true;
        }
        if is_rc_protected_file(&source) {
            self.file_browser_message(&format!("Not allowed to move file {source}"));
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let Ok(data) = server.config.load_file(&source) else {
            server.logger.error("Failed to load file for move");
            return true;
        };
        if server.config.save_file(&destination, &data).is_err() {
            server.logger.error("Failed to save file for move");
            return true;
        }
        if server.config.delete_file(&source).is_err() {
            server
                .logger
                .error("Failed to delete source file after move");
            return true;
        }
        server.logger.info(&format!(
            "{} moved file {} to {}",
            self.account_name(),
            source,
            destination
        ));
        true
    }

    fn msg_pli_rc_filebrowser_delete(&self, packet: &[u8]) -> bool {
        if !self.is_exact_rc_connection() {
            return true;
        }
        let file_name = String::from_utf8_lossy(packet.get(1..).unwrap_or_default()).into_owned();
        let folder = self.state.lock().unwrap().last_folder.clone();
        let file_path = format!("{folder}{file_name}");
        if !self.rc_file_has_right(&file_path, 'w') || is_rc_protected_file(&file_path) {
            self.file_browser_message(&format!("Not allowed to delete file {file_path}"));
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        if server.config.delete_file(&file_path).is_err() {
            server
                .logger
                .error(&format!("Failed to delete file {}", file_path));
            self.file_browser_message(&format!(
                "Error removing {file_name}. File may not exist or may not be empty."
            ));
        } else {
            server.logger.info(&format!(
                "{} deleted file {}",
                self.account_name(),
                file_name
            ));
            self.file_browser_message(&format!("Deleted file {file_name}"));
        }
        true
    }

    fn msg_pli_rc_filebrowser_rename(&self, packet: &[u8]) -> bool {
        if !self.is_exact_rc_connection() {
            return true;
        }
        let mut input = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let old_len = usize::from(input.read_gbyte()).min(input.remaining());
        let old_name = String::from_utf8_lossy(&input.read_bytes(old_len)).into_owned();
        let new_len = usize::from(input.read_gbyte()).min(input.remaining());
        let new_name = String::from_utf8_lossy(&input.read_bytes(new_len)).into_owned();
        let folder = self.state.lock().unwrap().last_folder.clone();
        let old_path = format!("{folder}{old_name}");
        let new_path = format!("{folder}{new_name}");
        if !self.rc_file_has_right(&old_path, 'w')
            || !self.rc_file_has_right(&new_path, 'w')
            || is_rc_protected_file(&old_path)
            || is_rc_protected_file(&new_path)
        {
            self.file_browser_message(&format!(
                "Not allowed to rename/overwrite file {old_path} or {new_path}"
            ));
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let Ok(data) = server.config.load_file(&old_path) else {
            server.logger.error("Failed to load file for rename");
            return true;
        };
        if server.config.save_file(&new_path, &data).is_err() {
            server.logger.error("Failed to save renamed file");
            return true;
        }
        if server.config.delete_file(&old_path).is_err() {
            server
                .logger
                .error("Failed to delete old file after rename");
            return true;
        }
        server.logger.info(&format!(
            "{} renamed file {} to {}",
            self.account_name(),
            old_name,
            new_name
        ));
        self.file_browser_message(&format!("Renamed file {old_name} to {new_name}"));
        true
    }

    fn msg_pli_rc_large_file_start(&self, packet: &[u8]) -> bool {
        if !self.is_exact_rc_connection() {
            return true;
        }
        let file_name = String::from_utf8_lossy(packet.get(1..).unwrap_or_default()).into_owned();
        let folder = self.state.lock().unwrap().last_folder.clone();
        if !self.rc_file_has_right(&format!("{folder}{file_name}"), 'w') {
            self.file_browser_message(&format!(
                "Insufficient rights to upload {folder}{file_name}"
            ));
            return true;
        }
        self.state
            .lock()
            .unwrap()
            .rc_large_files
            .insert(file_name, Vec::new());
        true
    }

    fn msg_pli_rc_large_file_end(&self, packet: &[u8]) -> bool {
        if !self.is_exact_rc_connection() {
            return true;
        }
        let file_name = String::from_utf8_lossy(packet.get(1..).unwrap_or_default()).into_owned();
        let folder = self.state.lock().unwrap().last_folder.clone();
        let file_path = format!("{folder}{file_name}");
        if !self.rc_file_has_right(&file_path, 'w') {
            self.file_browser_message(&format!("Insufficient rights to upload {file_path}"));
            return true;
        }
        let data = self
            .state
            .lock()
            .unwrap()
            .rc_large_files
            .get(&file_name)
            .cloned();
        let Some(server) = self.server() else {
            return true;
        };
        if let Some(data) = data {
            if server.config.save_file(&file_path, &data).is_err() {
                server
                    .logger
                    .error(&format!("Failed to save large file {}", file_path));
            } else {
                self.state.lock().unwrap().rc_large_files.remove(&file_name);
                self.update_uploaded_file(&folder, &file_name);
                server.logger.info(&format!(
                    "{} uploaded large file {}",
                    self.account_name(),
                    file_name
                ));
                self.file_browser_message(&format!("Uploaded large file {file_name}"));
            }
        }
        true
    }

    fn msg_pli_rc_folder_delete(&self, packet: &[u8]) -> bool {
        if !self.is_exact_rc_connection() {
            return true;
        }
        let folder = String::from_utf8_lossy(packet.get(1..).unwrap_or_default()).into_owned();
        if !self.rc_folder_has_right(&folder, 'w') {
            self.file_browser_message(&format!("Not allowed to delete folder {folder}"));
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        if std::fs::remove_dir_all(server.config.resolve_path(&folder)).is_err() {
            self.file_browser_message(&format!(
                "Error removing {folder}. Folder may not exist or may not be empty."
            ));
        }
        true
    }

    fn update_uploaded_file(&self, dir: &str, file_name: &str) {
        let Some(server) = self.server() else {
            return;
        };
        let extension = Path::new(file_name)
            .extension()
            .map(|value| format!(".{}", value.to_string_lossy().to_ascii_lowercase()))
            .unwrap_or_default();
        if !matches!(extension.as_str(), ".nw" | ".graal" | ".zelda") {
            return;
        }
        let full = format!("{dir}{file_name}").replace('\\', "/");
        let base = Path::new(&full)
            .file_name()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_default();
        let candidates = [
            full.clone(),
            full.trim_start_matches("world/levels/").to_string(),
            base.clone(),
            clean_level_name(&full),
            clean_level_name(full.trim_start_matches("world/levels/")),
            clean_level_name(&base),
        ];
        let mut seen = Vec::new();
        for candidate in candidates {
            if candidate.is_empty() || seen.contains(&candidate) {
                continue;
            }
            seen.push(candidate.clone());
            if let Some(level) = server.get_level(&candidate) {
                if level.reload(&server) {
                    server.resend_level_data(&level);
                }
            }
        }
    }

    pub fn msgPLI_RC_FILEBROWSER_START(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_filebrowser_start(packet)
    }
    pub fn msgPLI_RC_FILEBROWSER_CD(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_filebrowser_cd(packet)
    }
    pub fn msgPLI_RC_FILEBROWSER_END(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_filebrowser_end(packet)
    }
    pub fn msgPLI_RC_FILEBROWSER_DOWN(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_filebrowser_down(packet)
    }
    pub fn msgPLI_RC_FILEBROWSER_UP(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_filebrowser_up(packet)
    }
    pub fn msgPLI_RC_FILEBROWSER_MOVE(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_filebrowser_move(packet)
    }
    pub fn msgPLI_RC_FILEBROWSER_DELETE(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_filebrowser_delete(packet)
    }
    pub fn msgPLI_RC_FILEBROWSER_RENAME(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_filebrowser_rename(packet)
    }
    pub fn msgPLI_RC_LARGEFILESTART(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_large_file_start(packet)
    }
    pub fn msgPLI_RC_LARGEFILEEND(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_large_file_end(packet)
    }
    pub fn msgPLI_RC_FOLDERDELETE(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_folder_delete(packet)
    }
    fn normalize_nickname(&self) {
        let mut account = self.account.lock().unwrap();
        let account_name = account.account_name.trim().to_string();
        if !account_name.is_empty()
            && account
                .character
                .nickname
                .trim()
                .eq_ignore_ascii_case(&account_name)
        {
            account.character.nickname = format!("*{account_name}");
        }
    }

    fn set_account_ip_from_remote(&self) {
        let ip = self
            .state
            .lock()
            .unwrap()
            .conn
            .as_ref()
            .and_then(|conn| conn.peer_addr().ok())
            .map(|addr| addr.ip().to_string());
        let Some(ip) = ip else { return };
        let Ok(parsed) = ip.parse::<std::net::Ipv4Addr>() else {
            return;
        };
        let mut account = self.account.lock().unwrap();
        account.account_ip = u32::from_be_bytes(parsed.octets());
        account.account_ip_str = account.account_ip.to_string();
    }

    fn admin_ip_matches_remote(&self, admin_ip: &str) -> bool {
        let remote = self
            .state
            .lock()
            .unwrap()
            .conn
            .as_ref()
            .and_then(|conn| conn.peer_addr().ok())
            .map(|addr| addr.ip().to_string())
            .or_else(|| {
                let value = self.account.lock().unwrap().account_ip;
                (value != 0).then(|| std::net::Ipv4Addr::from(value).to_string())
            });
        let Some(remote) = remote else { return false };
        admin_ip.split(',').map(str::trim).any(|mask| {
            !mask.is_empty()
                && (mask == "0.0.0.0"
                    || mask == "*.*.*.*"
                    || mask.eq_ignore_ascii_case(&remote)
                    || wildcard_match(mask, &remote))
        })
    }

    fn can_login_control(&self) -> bool {
        let (account_name, admin_ip) = {
            let account = self.account.lock().unwrap();
            (account.account_name.clone(), account.admin_ip.clone())
        };
        self.server()
            .map(|server| {
                server_options_staff_contains(&server.settings.get("staff"), &account_name)
                    && self.admin_ip_matches_remote(&admin_ip)
            })
            .unwrap_or(false)
    }

    fn apply_server_options_staff_rights(&self) {
        let Some(server) = self.server() else { return };
        let mut account = self.account.lock().unwrap();
        if !server_options_staff_contains(&server.settings.get("staff"), &account.account_name) {
            return;
        }
        account.admin_rights |= all_local_rights();
        account.is_staff = true;
        if account.admin_ip.trim().is_empty() || account.admin_ip == "0.0.0.0" {
            account.admin_ip = "*.*.*.*".to_string();
        }
        if account.folder_list.is_empty() {
            account.folder_list = server.default_rc_folder_rights();
        }
    }

    fn mark_movement(&self) {
        {
            let mut account = self.account.lock().unwrap();
            account.status &= !PLSTATUS_PAUSED;
        }
        self.state.lock().unwrap().last_movement = Instant::now();
    }

    pub fn run_server_side_npc_touch_test(&self) {
        let Some(server) = self.server() else {
            return;
        };
        if !server.npc_server_running() {
            return;
        }
        let level = self
            .current_level()
            .or_else(|| server.get_level(&self.level_name()));
        let Some(level) = level else {
            return;
        };
        let (x, y, sprite) = {
            let account = self.account.lock().unwrap();
            (
                i32::from(account.x),
                i32::from(account.y),
                account.character.sprite,
            )
        };
        let offsets = [(24, 16), (0, 32), (24, 56), (48, 32)];
        let direction = usize::from(sprite % 4);
        let x = x + offsets[direction].0;
        let y = y + offsets[direction].1;
        let player = self.self_arc();
        for npc in level.get_npcs() {
            if !npc.matches_trigger_point(x, y) {
                continue;
            }
            let script = npc.state.lock().unwrap().script.clone();
            let mut seen = HashSet::new();
            let expanded = server.expand_joined_classes(&script, &mut seen);
            if script.trim().is_empty() || !gs2_script_has_event(&expanded, "onPlayerTouchsMe") {
                continue;
            }
            server.run_server_side_npc_event_for_player(
                &npc,
                "onPlayerTouchsMe",
                player.as_ref(),
                &[],
            );
            let args = vec![npc.npc_name(), npc.id().to_string()];
            server.run_server_side_event_for_active_scripts(
                "onPlayerTouchsOther",
                player.as_ref(),
                &args,
            );
        }
    }
    pub fn runServerSideNPCTouchTest(&self) {
        self.run_server_side_npc_touch_test()
    }

    fn handle_movement_flag(&self, name: &str, value: &str) -> bool {
        if self.version_id() >= 230 || !name.starts_with("gr.") {
            return false;
        }
        if self
            .server()
            .map(|server| !server.settings.get_bool("flaghack_movement", true))
            .unwrap_or(false)
        {
            return false;
        }
        let position = match value.trim().parse::<f64>() {
            Ok(value) if value.is_finite() => value,
            _ => return false,
        };
        let (prop, same, encoded) = {
            let account = self.account.lock().unwrap();
            match name {
                "gr.x" => (
                    PLPROP_X,
                    account.x == (position * 16.0) as i16,
                    (position * 2.0) as u8,
                ),
                "gr.y" => (
                    PLPROP_Y,
                    account.y == (position * 16.0) as i16,
                    (position * 2.0) as u8,
                ),
                "gr.z" => (
                    PLPROP_Z,
                    account.z == (position * 16.0) as i16,
                    (position + 50.5) as u8,
                ),
                _ => return false,
            }
        };
        if same {
            return true;
        }
        let mut props = Buffer::new();
        props.write_gchar(prop).write_gchar(encoded);
        self.state
            .lock()
            .unwrap()
            .gr_movement_packets
            .push(props.data);
        true
    }

    fn flush_gr_movement_packets(&self) {
        let (packets, updated) = {
            let mut state = self.state.lock().unwrap();
            let packets = std::mem::take(&mut state.gr_movement_packets);
            let updated = state.gr_movement_updated;
            state.gr_movement_updated = false;
            (packets, updated)
        };
        if packets.is_empty() || updated {
            return;
        }
        for packet in packets {
            let mut value = vec![PLI_PLAYERPROPS];
            value.extend_from_slice(&packet);
            let _ = self.msg_pli_playerprops_exact(&value);
        }
    }

    fn player_supports_precise_movement(&self) -> bool {
        self.version_id() >= 230 || self.version().starts_with("G3D")
    }

    fn append_player_prop_delta(
        &self,
        prop_id: u8,
        common: &mut Buffer,
        legacy_move: &mut Buffer,
        precise_move: &mut Buffer,
        ordered_move: &mut Buffer,
    ) {
        let local = send_local_props();
        if !local.get(prop_id as usize).copied().unwrap_or(false) {
            return;
        }
        common.write_gchar(prop_id).write(&self.get_prop(prop_id));
        match prop_id {
            PLPROP_X => {
                precise_move
                    .write_gchar(PLPROP_X2)
                    .write(&self.get_prop(PLPROP_X2));
                ordered_move
                    .write_gchar(PLPROP_X2)
                    .write(&self.get_prop(PLPROP_X2));
            }
            PLPROP_Y => {
                precise_move
                    .write_gchar(PLPROP_Y2)
                    .write(&self.get_prop(PLPROP_Y2));
                ordered_move
                    .write_gchar(PLPROP_Y2)
                    .write(&self.get_prop(PLPROP_Y2));
            }
            PLPROP_Z => {
                precise_move
                    .write_gchar(PLPROP_Z2)
                    .write(&self.get_prop(PLPROP_Z2));
                ordered_move
                    .write_gchar(PLPROP_Z2)
                    .write(&self.get_prop(PLPROP_Z2));
            }
            PLPROP_X2 => {
                legacy_move
                    .write_gchar(PLPROP_X)
                    .write(&self.get_prop(PLPROP_X));
                ordered_move
                    .write_gchar(PLPROP_X)
                    .write(&self.get_prop(PLPROP_X));
            }
            PLPROP_Y2 => {
                legacy_move
                    .write_gchar(PLPROP_Y)
                    .write(&self.get_prop(PLPROP_Y));
                ordered_move
                    .write_gchar(PLPROP_Y)
                    .write(&self.get_prop(PLPROP_Y));
            }
            PLPROP_Z2 => {
                legacy_move
                    .write_gchar(PLPROP_Z)
                    .write(&self.get_prop(PLPROP_Z));
                ordered_move
                    .write_gchar(PLPROP_Z)
                    .write(&self.get_prop(PLPROP_Z));
            }
            _ => {}
        }
    }

    fn send_player_prop_deltas_to_current_level(
        &self,
        common: &[u8],
        legacy_move: &[u8],
        precise_move: &[u8],
        ordered_move: &[u8],
        _has_gani: bool,
        _has_movement: bool,
    ) {
        let Some(server) = self.server() else { return };
        let Some(level) = self.current_level().or_else(|| {
            let name = self.account.lock().unwrap().level_name.clone();
            server.get_level(&clean_level_name(&name))
        }) else {
            return;
        };
        if common.is_empty()
            && legacy_move.is_empty()
            && precise_move.is_empty()
            && ordered_move.is_empty()
        {
            return;
        }
        let mut packet = Buffer::new();
        packet.write_byte(PLO_OTHERPLPROPS).write_gshort(self.id());
        if self.player_supports_precise_movement() {
            packet.write(ordered_move).write(common);
        } else {
            packet.write(common).write(ordered_move);
        }
        for id in level.get_players() {
            if id == self.id() {
                continue;
            }
            if let Some(player) = server.get_player(id) {
                if player.player_type() & PLTYPE_ANYCLIENT != 0 && player.has_connection() {
                    player.SendPacket(&packet.data);
                }
            }
        }
        let _ = (legacy_move, precise_move);
    }

    fn send_player_prop_changes(&self, prop_ids: &[u8]) {
        let mut common = Buffer::new();
        let mut legacy = Buffer::new();
        let mut precise = Buffer::new();
        let mut ordered = Buffer::new();
        for prop_id in prop_ids {
            match *prop_id {
                PLPROP_X | PLPROP_Y | PLPROP_Z | PLPROP_X2 | PLPROP_Y2 | PLPROP_Z2 => {
                    self.append_player_prop_delta(
                        *prop_id,
                        &mut common,
                        &mut legacy,
                        &mut precise,
                        &mut ordered,
                    );
                }
                _ => {
                    let local = send_local_props();
                    if local.get(*prop_id as usize).copied().unwrap_or(false) {
                        common.write_gchar(*prop_id).write(&self.get_prop(*prop_id));
                    }
                }
            }
        }
        let self_move = if self.player_supports_precise_movement() {
            &precise.data
        } else {
            &legacy.data
        };
        let mut self_props = common.data.clone();
        self_props.extend_from_slice(self_move);
        if !self_props.is_empty() {
            let mut packet = Buffer::new();
            packet.write_byte(PLO_PLAYERPROPS).write(&self_props);
            self.SendPacket(&packet.data);
        }
        self.send_player_prop_deltas_to_current_level(
            &common.data,
            &legacy.data,
            &precise.data,
            &ordered.data,
            false,
            false,
        );
    }

    fn clear_chat_with_props(&self, props: &[u8]) {
        self.account.lock().unwrap().character.chat_message.clear();
        let mut ids = props.to_vec();
        ids.push(PLPROP_CURCHAT);
        self.send_player_prop_changes(&ids);
    }

    fn set_chat(&self, message: &str) {
        let mut value = message.to_string();
        value.truncate(223);
        self.account.lock().unwrap().character.chat_message = value;
        self.send_player_prop_changes(&[PLPROP_CURCHAT]);
    }

    fn send_to_current_level_except_self(&self, packet: &[u8]) {
        let Some(server) = self.server() else { return };
        let Some(level) = self.current_level().or_else(|| {
            server.get_level(&clean_level_name(&self.account.lock().unwrap().level_name))
        }) else {
            return;
        };
        for id in level.get_players() {
            if id == self.id() {
                continue;
            }
            if let Some(player) = server.get_player(id) {
                if player.has_connection() {
                    let mut value = packet.to_vec();
                    value.push(b'\n');
                    player.send_packet(&value);
                }
            }
        }
    }

    fn msg_pli_levelwarp(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !server.is_running() || packet.len() < 4 {
            return true;
        }
        let mut buf = Buffer::from_bytes(&packet[1..]);
        // The dispatcher has already normalized packet[0] to the raw opcode;
        // do not GChar-decode it here. Decoding made normal LEVELWARP packets
        // look like LEVELWARPMOD and consumed five bytes of the level name.
        let raw_id = packet[0];
        let mod_time = if raw_id == PLI_LEVELWARPMOD {
            if buf.remaining() < 5 {
                return true;
            }
            buf.read_gint5() as i64
        } else {
            0
        };
        if buf.remaining() < 3 {
            return true;
        }
        let x = f64::from(buf.read_gchar()) / 2.0;
        let y = f64::from(buf.read_gchar()) / 2.0;
        let level = String::from_utf8_lossy(&buf.read_bytes(buf.remaining()))
            .trim()
            .to_string();
        if level.trim().is_empty()
            || level.len() < 3
            || level.chars().any(|v| v == '\0' || v == '\r' || v == '\n')
        {
            return true;
        }
        self.warp(&level, x, y, mod_time);
        true
    }

    fn msg_pli_boardmodify(&self, packet: &[u8]) -> bool {
        if packet.len() < 5 {
            return true;
        }
        let mut buf = Buffer::from_bytes(&packet[1..]);
        let x = i32::from(buf.read_gchar());
        let y = i32::from(buf.read_gchar());
        let width = i32::from(buf.read_gchar());
        let height = i32::from(buf.read_gchar());
        let count = width.max(0).saturating_mul(height.max(0)) as usize;
        let tiles = (0..count)
            .map(|_| buf.read_gshort() as i16)
            .collect::<Vec<_>>();
        let Some(server) = self.server() else {
            return true;
        };
        if width == 4
            && height == 4
            && server.settings.get_bool("clientsidepushpull", true)
            && Self::is_push_pull_block_tiles(&tiles)
        {
            self.send_plo_boardmodify(x as i16, y as i16, width as i16, height as i16, &tiles);
            return true;
        }
        let Some(level) = self.current_level() else {
            return true;
        };
        let old_tile = level.get_tile(0, x as usize, y as usize);
        if level.alter_board(&server, x, y, width, height, &tiles) {
            server.broadcast_board_modify(
                &level,
                x as i16,
                y as i16,
                width as i16,
                height as i16,
                &tiles,
            );
            self.maybe_drop_tile_item(&level, x, y, old_tile);
        }
        true
    }

    fn is_push_pull_block_tiles(tiles: &[i16]) -> bool {
        let mut index = 0usize;
        while index < 16
            && tiles
                .get(index)
                .is_some_and(|tile| *tile != 0x06e4 && *tile != 0x07ce)
        {
            index += 1;
        }
        if index >= 16 || index >= 11 {
            return false;
        }
        [0usize, 1, 4, 5]
            .iter()
            .filter(|offset| {
                tiles.get(index + **offset).is_some_and(|tile| {
                    matches!(
                        *tile,
                        0x06e4 | 0x06e5 | 0x06f4 | 0x06f5 | 0x07ce | 0x07cf | 0x07de | 0x07df
                    )
                })
            })
            .count()
            == 4
    }

    fn msg_pli_requestupdateboard(&self, packet: &[u8]) -> bool {
        if packet.len() < 2 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut buf = Buffer::from_bytes(&packet[1..]);
        let name = buf.read_gchar_string();
        let mod_time = buf.read_gint5() as i64;
        // The reference accepts the region fields for compatibility but
        // returns every change at or after the requested modification time.
        let _ = (
            buf.read_gshort(),
            buf.read_gshort(),
            buf.read_gshort(),
            buf.read_gshort(),
        );
        let Some(level) = server
            .get_level(&name)
            .or_else(|| server.get_level(&clean_level_name(&name)))
        else {
            return true;
        };
        let since = UNIX_EPOCH + Duration::from_secs(mod_time.max(0) as u64);
        for change in level.board_changes() {
            if change.time >= since {
                self.send_pboard_packet(
                    change.x as i16,
                    change.y as i16,
                    change.width as i16,
                    change.height as i16,
                    &bytes_to_shorts(&change.new_tiles),
                );
            }
        }
        true
    }

    fn msg_pli_broadcast(&self, packet_id: u8, payload: &[u8]) -> bool {
        let mut out = Buffer::new();
        out.write_byte(packet_id)
            .write_gshort(self.id())
            .write(payload);
        self.send_to_current_level_except_self(&out.data);
        true
    }

    fn msg_pli_bombdel(&self, packet: &[u8]) -> bool {
        // PLO_BOMBDEL is the one projectile update that does not carry the
        // originating player id. Forward the payload verbatim, because using
        // msg_pli_broadcast here shifts every field by two bytes for clients.
        if packet.len() > 1 {
            let mut out = Buffer::new();
            out.write_byte(PLO_BOMBDEL).write(&packet[1..]);
            self.send_to_current_level_except_self(&out.data);
        }
        true
    }

    fn msg_pli_npcprops(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if server.npc_server_owns_npc_props() || packet.len() < 4 {
            return true;
        }
        let mut buf = Buffer::from_bytes(&packet[1..]);
        let npc_id = buf.read_gint();
        let props = buf.read_bytes(buf.remaining());
        let Some(level) = self.current_level().or_else(|| {
            server.get_level(&clean_level_name(&self.account.lock().unwrap().level_name))
        }) else {
            return true;
        };
        let exists = level.state.read().unwrap().npcs.contains_key(&npc_id);
        if !exists {
            return true;
        }
        if let Some(npc) = level.state.read().unwrap().npcs.get(&npc_id).cloned() {
            npc.apply_props(&props);
        }
        let mut out = Buffer::new();
        out.write_byte(PLO_NPCPROPS)
            .write_gint(npc_id)
            .write(&props);
        for id in level.get_players() {
            if id == self.id() {
                continue;
            }
            if let Some(player) = server.get_player(id) {
                if player.has_connection() {
                    player.send(&out);
                }
            }
        }
        true
    }

    fn msg_pli_arrowadd(&self, packet: &[u8]) -> bool {
        self.msg_pli_broadcast(PLO_ARROWADD, packet.get(1..).unwrap_or_default())
    }

    fn msg_pli_firespy(&self, packet: &[u8]) -> bool {
        self.msg_pli_broadcast(PLO_FIRESPY, packet.get(1..).unwrap_or_default())
    }

    fn msg_pli_throwcarried(&self, packet: &[u8]) -> bool {
        self.msg_pli_broadcast(PLO_THROWCARRIED, packet.get(1..).unwrap_or_default())
    }

    fn msg_pli_claimpker(&self, packet: &[u8]) -> bool {
        if packet.len() < 3 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut buf = Buffer::from_bytes(&packet[1..]);
        let pker_id = buf.read_gshort();
        if let Some(player) = server.get_player(pker_id) {
            player
                .account
                .lock()
                .unwrap()
                .set_flag("killer", &self.account_name());
        }
        true
    }

    fn msg_pli_baddyprops(&self, packet: &[u8]) -> bool {
        if packet.len() < 3 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut buf = Buffer::from_bytes(&packet[1..]);
        let baddy_id = buf.read_gchar();
        let props = buf.read_bytes(buf.remaining());
        let Some(level) = self.current_level().or_else(|| {
            server.get_level(&clean_level_name(&self.account.lock().unwrap().level_name))
        }) else {
            return true;
        };
        let baddy = level.state.read().unwrap().baddies.get(&baddy_id).cloned();
        if let Some(baddy) = baddy {
            let mut updated = (*baddy).clone();
            updated.set_props(&props);
            if level.state.read().unwrap().baddies.contains_key(&baddy_id) {
                level
                    .state
                    .write()
                    .unwrap()
                    .baddies
                    .insert(baddy_id, Arc::new(updated));
            }
        } else {
            return true;
        }
        let mut out = Buffer::new();
        out.write_byte(PLO_BADDYPROPS)
            .write_gchar(baddy_id)
            .write(&props);
        for id in level.get_players() {
            if let Some(player) = server.get_player(id) {
                if player.has_connection() {
                    player.send(&out);
                }
            }
        }
        true
    }

    fn msg_pli_baddyhurt(&self, packet: &[u8]) -> bool {
        if packet.len() < 3 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut buf = Buffer::from_bytes(&packet[1..]);
        let baddy_id = buf.read_gchar();
        let power = buf.read_gchar();
        let Some(level) = self.current_level().or_else(|| {
            server.get_level(&clean_level_name(&self.account.lock().unwrap().level_name))
        }) else {
            return true;
        };
        for id in level.get_players() {
            if let Some(player) = server.get_player(id) {
                if player.has_connection() {
                    player.send_plo_baddyhurt(u32::from(baddy_id), i32::from(power));
                }
            }
        }
        true
    }

    fn msg_pli_baddyadd(&self, packet: &[u8]) -> bool {
        if packet.len() < 5 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut buf = Buffer::from_bytes(&packet[1..]);
        let x = f32::from(buf.read_gchar()) / 2.0;
        let y = f32::from(buf.read_gchar()) / 2.0;
        let baddy_type = buf.read_gchar();
        let power = buf.read_gchar();
        let image = String::from_utf8_lossy(&buf.read_bytes(buf.remaining())).into_owned();
        let Some(level) = self.current_level().or_else(|| {
            server.get_level(&clean_level_name(&self.account.lock().unwrap().level_name))
        }) else {
            return true;
        };
        let mut baddy = LevelBaddy::new(x, y, baddy_type, Some(level.clone()), &server);
        let baddy_id = {
            let state = level.state.read().unwrap();
            state.baddies.len() as u8
        };
        baddy.id = baddy_id;
        if power > 0 || !image.is_empty() {
            let mut props = Buffer::new();
            props
                .write_gchar(BDPROP_POWERIMAGE)
                .write_gchar(power)
                .write_gchar(image.len() as u8)
                .write(image.as_bytes());
            baddy.set_props(&props.data);
        }
        let baddy = Arc::new(baddy);
        level
            .state
            .write()
            .unwrap()
            .baddies
            .insert(baddy_id, baddy.clone());
        for id in level.get_players() {
            if let Some(player) = server.get_player(id) {
                if player.has_connection() {
                    player.send_plo_levelbaddyprops(&baddy);
                }
            }
        }
        true
    }

    fn msg_pli_putnpc(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        let mut buf = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let image = buf.read_gchar_string();
        let script = buf.read_gchar_string();
        let x = f32::from(buf.read_gchar()) / 2.0;
        let y = f32::from(buf.read_gchar()) / 2.0;
        let Some(level) = self.current_level().or_else(|| {
            server.get_level(&clean_level_name(&self.account.lock().unwrap().level_name))
        }) else {
            return true;
        };
        let npc = Arc::new(NPC::new(NPCType::PUTNPC));
        npc.set_position((x * 16.0) as i16, (y * 16.0) as i16, 0);
        npc.set_image(&image);
        npc.set_script(&script);
        npc.set_level(Some(level.clone()));
        let id = server.next_npc_id();
        npc.set_id(id);
        level.state.write().unwrap().npcs.insert(id, npc.clone());
        server.npcs.write().unwrap().insert(id, npc.clone());
        self.send_plo_npcprops(&npc);
        true
    }

    fn msg_pli_npcdel(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if server.npc_server_owns_npc_props() || packet.len() < 4 {
            return true;
        }
        let mut buf = Buffer::from_bytes(&packet[1..]);
        let id = buf.read_gint();
        let Some(level) = self.current_level().or_else(|| {
            server.get_level(&clean_level_name(&self.account.lock().unwrap().level_name))
        }) else {
            return true;
        };
        let removed = level.state.write().unwrap().npcs.remove(&id).is_some();
        if removed {
            self.send_plo_npcdel(id);
            server.npcs.write().unwrap().remove(&id);
        }
        true
    }

    fn msg_pli_showimg(&self, packet: &[u8]) -> bool {
        let mut out = Buffer::new();
        out.write_byte(PLO_SHOWIMG)
            .write_gshort(self.id())
            .write(packet.get(1..).unwrap_or_default());
        self.send_to_current_level_except_self(&out.data);
        true
    }

    fn msg_pli_hurtplayer(&self, packet: &[u8]) -> bool {
        if packet.len() < 9 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut buf = Buffer::from_bytes(&packet[1..]);
        let victim_id = buf.read_gshort();
        let hurt_dx = buf.read_gchar();
        let hurt_dy = buf.read_gchar();
        let power = buf.read_gchar();
        let npc_id = buf.read_gint();
        if let Some(victim) = server.get_player(victim_id) {
            if victim.has_connection() {
                let mut out = Buffer::new();
                out.write_byte(PLO_HURTPLAYER)
                    .write_gshort(self.id())
                    .write_gchar(hurt_dx)
                    .write_gchar(hurt_dy)
                    .write_gchar(power)
                    .write_gint(npc_id);
                victim.send(&out);
            }
        }
        true
    }

    fn msg_pli_explosion(&self, packet: &[u8]) -> bool {
        if packet.len() < 5 {
            return true;
        }
        let mut buf = Buffer::from_bytes(&packet[1..]);
        let radius = buf.read_gchar();
        let x = buf.read_gchar();
        let y = buf.read_gchar();
        let power = buf.read_gchar();
        let mut out = Buffer::new();
        out.write_byte(PLO_EXPLOSION)
            .write_gshort(self.id())
            .write_gchar(radius)
            .write_gchar(x)
            .write_gchar(y)
            .write_gchar(power);
        self.send(&out);
        true
    }

    fn msg_pli_privatemessage(&self, packet: &[u8]) -> bool {
        if packet.len() < 3 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut buf = Buffer::from_bytes(&packet[1..]);
        let count = buf.read_gshort() as usize;
        let mut targets = Vec::with_capacity(count);
        for _ in 0..count {
            targets.push(buf.read_gshort());
        }
        let message = buf.read_bytes(buf.remaining());
        let label = if count > 1 {
            b"\"Mass message:\",".as_slice()
        } else {
            b"\"Private message:\",".as_slice()
        };
        for target_id in targets {
            let Some(target) = server.get_player(target_id) else {
                continue;
            };
            if target.id() == self.id() {
                continue;
            }
            if target.player_type() & PLTYPE_NPCSERVER != 0 {
                if let Some(npc_server) = server.npc_server.player() {
                    if let Some(sender) = self.self_arc() {
                        let _ = server.npc_server.send_pm_fallback(&sender, &npc_server);
                    }
                }
                continue;
            }
            if !target.has_connection() {
                continue;
            }
            let mut out = Buffer::new();
            out.write_byte(PLO_PRIVATEMESSAGE)
                .write_gshort(self.id())
                .write(b"\"\",")
                .write(label)
                .write(&message);
            target.send(&out);
        }
        true
    }

    fn msg_pli_npcserverquery(&self, packet: &[u8]) -> bool {
        if let (Some(server), Some(this)) = (self.server(), self.self_arc()) {
            let _ = server.npc_server.send_nc_address(&this, Some(packet));
        }
        true
    }

    fn msg_pli_npcweapondel(&self, packet: &[u8]) -> bool {
        if packet.len() > 1 {
            self.delete_weapon(&String::from_utf8_lossy(&packet[1..]));
        }
        true
    }

    fn msg_pli_weaponadd(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        let mut buf = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let weapon_type = buf.read_gchar();
        if weapon_type == 0 {
            let item_type = i32::from(buf.read_gchar());
            if !item_name(item_type).is_empty() {
                self.add_weapon(item_name(item_type));
            }
        } else {
            let npc_id = buf.read_gint();
            if let Some(npc) = server.get_npc(npc_id) {
                let name = npc.weapon_name();
                if !name.is_empty() {
                    self.add_weapon(&name);
                }
            }
        }
        true
    }

    fn msg_pli_toall(&self, packet: &[u8]) -> bool {
        if packet.len() <= 1 {
            return true;
        }
        let mut buf = Buffer::from_bytes(&packet[1..]);
        let message = buf.read_gchar_string();
        self.state.lock().unwrap().last_chat = Instant::now();
        self.send_pto_all_chat(&message);
        true
    }

    fn maybe_drop_tile_item(&self, level: &Arc<Level>, x: i32, y: i32, old_tile: i16) {
        if x < 0 || x > 63 || y < 0 || y > 63 || (self.version_id() > 0 && self.version_id() < 210)
        {
            return;
        }
        let Some(server) = self.server() else { return };
        let item = match old_tile {
            2 | 0x1a4 | 0x1ff | 0x3ff => {
                if !server.settings.get_bool("bushitems", true)
                    || rand::random::<u8>() % 100
                        >= server.settings.get_int("tiledroprate", 50).max(0) as u8
                {
                    return;
                }
                i32::from(rand::random::<u8>() % 6)
            }
            0x2ac => {
                if !server.settings.get_bool("vasesdrop", true) {
                    return;
                }
                ITEM_HEART
            }
            _ => return,
        };
        if level.add_item_for_server(&server, x as f32, y as f32, item) {
            server.broadcast_item_add(level, (x * 2) as i16, (y * 2) as i16, item);
        }
    }

    fn remove_item_for_drop(&self, item_type: LevelItemType) -> bool {
        let mut account = self.account.lock().unwrap();
        match item_type {
            ITEM_GREEN_RUPEE | ITEM_BLUE_RUPEE | ITEM_RED_RUPEE | ITEM_GOLD_RUPEE => {
                let value = rupee_item_value(item_type);
                if account.character.gralats < value {
                    return false;
                }
                account.character.gralats -= value;
                account.rupees = account.character.gralats.max(0) as u32;
                true
            }
            ITEM_BOMBS => {
                if account.character.bombs < 5 {
                    return false;
                }
                account.character.bombs -= 5;
                true
            }
            ITEM_DARTS => {
                if account.character.arrows < 5 {
                    return false;
                }
                account.character.arrows -= 5;
                true
            }
            ITEM_HEART => {
                if account.character.hitpoints <= 1 {
                    return false;
                }
                account.character.hitpoints -= 1;
                true
            }
            _ => false,
        }
    }

    fn msg_pli_itemadd(&self, packet: &[u8]) -> bool {
        let mut normal_item = true;
        if packet.len() >= 4 {
            let mut buf = Buffer::from_bytes(&packet[1..]);
            let x = f32::from(buf.read_gchar()) / 2.0;
            let y = f32::from(buf.read_gchar()) / 2.0;
            let item = i32::from(buf.read_gchar());
            if !self.remove_item_for_drop(item) {
                return true;
            }
            let server = self.server();
            let level = self.current_level().or_else(|| {
                server.as_ref().and_then(|server| {
                    server
                        .get_level(&self.level_name())
                        .or_else(|| server.get_level(&clean_level_name(&self.level_name())))
                })
            });
            if let (Some(level), Some(server)) = (level, server) {
                normal_item = level.add_item_for_server(&server, x, y, item);
            }
        }
        let mut out = Buffer::new();
        if normal_item {
            out.write_byte(PLO_ITEMADD).write(&packet[1..]);
            self.send_to_current_level_except_self(&out.data);
        } else {
            out.write_byte(PLO_ITEMDEL).write(&packet[1..]);
            self.send(&out);
        }
        true
    }

    fn msg_pli_itemdel(&self, packet: &[u8]) -> bool {
        let mut item = -1;
        if packet.len() >= 3 {
            let mut buf = Buffer::from_bytes(&packet[1..]);
            let x = f32::from(buf.read_gchar()) / 2.0;
            let y = f32::from(buf.read_gchar()) / 2.0;
            let level = self.current_level().or_else(|| {
                self.server().and_then(|server| {
                    server
                        .get_level(&self.level_name())
                        .or_else(|| server.get_level(&clean_level_name(&self.level_name())))
                })
            });
            if let Some(level) = level {
                item = level.remove_item_at(x, y);
            }
        }
        let mut out = Buffer::new();
        out.write_byte(PLO_ITEMDEL).write(&packet[1..]);
        self.send_to_current_level_except_self(&out.data);
        if Buffer::from_bytes(&packet[..1]).read_gchar() == PLI_ITEMTAKE && item >= 0 {
            self.apply_level_item(item);
        }
        true
    }

    fn msg_pli_openchest(&self, packet: &[u8]) -> bool {
        if packet.len() < 3 {
            return true;
        }
        let mut buf = Buffer::from_bytes(&packet[1..]);
        let x = i32::from(buf.read_gchar());
        let y = i32::from(buf.read_gchar());
        let Some(level) = self.current_level() else {
            return true;
        };
        for chest in level.chests() {
            if chest.x == x && chest.y == y {
                let key = level.chest_key(&chest);
                if !self.has_chest(&key) {
                    self.apply_level_item(chest.item_type);
                    self.send_plo_levelchest(&chest, true);
                    self.add_chest(&key);
                    self.save_account();
                }
                break;
            }
        }
        true
    }

    fn msg_pli_horseadd(&self, packet: &[u8]) -> bool {
        if packet.len() < 4 {
            return true;
        }
        let mut buf = Buffer::from_bytes(&packet[1..]);
        let x = f32::from(buf.read_byte()) / 2.0;
        let y = f32::from(buf.read_byte()) / 2.0;
        let dir_bush = buf.read_byte();
        let image = String::from_utf8_lossy(&buf.read_bytes(buf.remaining())).into_owned();
        if let Some(level) = self.current_level() {
            let lifetime = self
                .server()
                .map(|server| server.settings.get_int("horselifetime", 30))
                .unwrap_or(30);
            level.state.write().unwrap().horses.push(LevelHorse {
                x,
                y,
                dir: dir_bush & 3,
                bushes: dir_bush >> 2,
                image,
                expires_at: if lifetime <= 0 {
                    UNIX_EPOCH
                } else {
                    SystemTime::now() + Duration::from_secs(lifetime as u64)
                },
            });
        }
        let mut out = Buffer::new();
        out.write_byte(PLO_HORSEADD).write(&packet[1..]);
        self.send_to_current_level_except_self(&out.data);
        true
    }

    fn msg_pli_horsedel(&self, packet: &[u8]) -> bool {
        if packet.len() < 3 {
            return true;
        }
        let mut buf = Buffer::from_bytes(&packet[1..]);
        let x = f32::from(buf.read_byte()) / 2.0;
        let y = f32::from(buf.read_byte()) / 2.0;
        if let Some(level) = self.current_level() {
            level
                .state
                .write()
                .unwrap()
                .horses
                .retain(|horse| horse.x != x || horse.y != y);
        }
        let mut out = Buffer::new();
        out.write_byte(PLO_HORSEDEL).write(&packet[1..]);
        self.send_to_current_level_except_self(&out.data);
        true
    }

    fn msg_pli_wantfile(&self, packet: &[u8]) -> bool {
        let file_name = String::from_utf8_lossy(packet.get(1..).unwrap_or_default())
            .trim_end_matches('\n')
            .to_string();
        if file_name.is_empty() {
            return true;
        }
        let is_gupd = Path::new(&file_name)
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| value.eq_ignore_ascii_case("gupd"))
            .unwrap_or(false);
        if is_gupd || is_default_client_file(&file_name) {
            if self
                .server()
                .and_then(|server| server.resolve_requested_file(&file_name).ok())
                .is_some()
            {
                self.send_file(&file_name);
            } else {
                self.send_plo_fileuptodate(&file_name);
            }
        } else {
            self.send_file(&file_name);
        }
        true
    }

    fn msg_pli_updatefile(&self, packet: &[u8]) -> bool {
        let mut buf = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let client_mod_time = buf.read_gint5() as i64;
        let mut file_name = String::from_utf8_lossy(&buf.read_bytes(buf.remaining())).into_owned();
        file_name = file_name.trim_end_matches('\n').to_string();
        if file_name.is_empty() {
            return true;
        }
        if self.version_id() > 0
            && self.version_id() < 210
            && Path::new(&file_name).extension().is_none()
        {
            file_name.push_str(".gif");
        }
        if is_default_client_file(&file_name) {
            if self.version_id() > 0 && self.version_id() < 210 {
                self.send_plo_filesendfailed(&file_name);
            } else {
                self.send_plo_fileuptodate(&file_name);
            }
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let server_mod_time = server
            .config
            .file_mod_time(&file_name)
            .ok()
            .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
            .map(|value| value.as_secs() as i64)
            .unwrap_or(0);
        if server_mod_time == 0 || server_mod_time != client_mod_time {
            self.send_file(&file_name);
        } else {
            self.send_plo_fileuptodate(&file_name);
        }
        true
    }

    fn msg_pli_hitobjects(&self, packet: &[u8]) -> bool {
        if packet.len() < 4 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut buf = Buffer::from_bytes(&packet[1..]);
        let power = buf.read_gchar();
        let x = buf.read_gchar();
        let y = buf.read_gchar();
        let from_npc = buf.remaining() > 0;
        let npc_id = if from_npc { buf.read_gint() } else { 0 };
        let mut out = Buffer::new();
        out.write_byte(PLO_HITOBJECTS)
            .write_gshort(if from_npc { 0 } else { self.id() })
            .write_gchar(power)
            .write_gchar(x)
            .write_gchar(y);
        if from_npc {
            out.write_gint(npc_id);
        }
        let Some(level) = self.current_level().or_else(|| {
            server.get_level(&clean_level_name(&self.account.lock().unwrap().level_name))
        }) else {
            return true;
        };
        for id in level.get_players() {
            if id == self.id() {
                continue;
            }
            if let Some(player) = server.get_player(id) {
                if player.has_connection() {
                    player.send(&out);
                }
            }
        }
        true
    }

    fn msg_pli_language(&self, packet: &[u8]) -> bool {
        if packet.len() > 1 {
            let language = String::from_utf8_lossy(&packet[1..])
                .trim_end_matches('\n')
                .to_string();
            self.account.lock().unwrap().language = language.clone();
            if let Some(server) = self.server() {
                let args = vec![language];
                server.run_server_side_event_for_active_scripts(
                    "onPlayerLanguageChanges",
                    self.self_arc().as_ref(),
                    &args,
                );
            }
        }
        true
    }

    fn msg_pli_triggeraction(&self, packet: &[u8]) -> bool {
        if packet.len() <= 1 {
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let mut input = Buffer::from_bytes(&packet[1..]);
        let npc_id = input.read_gint();
        let x = input.read_gchar();
        let y = input.read_gchar();
        let action = String::from_utf8_lossy(&input.read_bytes(input.remaining()))
            .trim()
            .to_string();
        server
            .logger
            .debug(&format!("TRIGGERACTION npc={npc_id} at {x},{y}: {action}"));
        if action.to_ascii_lowercase().starts_with("serverside,") {
            let mut state = self.state.lock().unwrap();
            if state.last_serverside_trigger_action == action
                && state.last_serverside_trigger.elapsed() < Duration::from_millis(500)
            {
                server.logger.debug(&format!(
                    "Ignoring duplicate serverside trigger from {}: {action}",
                    self.account_name()
                ));
                return true;
            }
            state.last_serverside_trigger_action = action.clone();
            state.last_serverside_trigger = Instant::now();
        }
        let parts = action
            .split(',')
            .map(|part| part.to_string())
            .collect::<Vec<_>>();
        if parts.is_empty() {
            return true;
        }
        if server.handle_trigger_command(self, &parts[0], &parts) {
            return true;
        }
        if let Some(player) = self.self_arc() {
            server.run_level_npc_trigger_action(
                &player,
                npc_id,
                i32::from(x),
                i32::from(y),
                &parts,
            );
        }
        let level = self
            .current_level()
            .or_else(|| server.get_level(&clean_level_name(&self.level_name())));
        if let Some(level) = level {
            for npc in level.get_npcs() {
                let snapshot = npc.snapshot();
                if snapshot.script == action {
                    npc.set_timeout(0);
                    break;
                }
            }
        }
        let mut out = Buffer::new();
        out.write_byte(PLO_TRIGGERACTION)
            .write_gshort(self.id())
            .write(&packet[1..]);
        self.send_to_current_level_except_self(&out.data);
        true
    }

    fn msg_pli_adjacentlevel(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        let mut buf = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let mod_time = buf.read_gint5() as i64;
        let level_name = String::from_utf8_lossy(&buf.read_bytes(buf.remaining()))
            .trim()
            .to_string();
        if level_name.is_empty() {
            return true;
        }
        let Some(level) = server.load_level(&clean_level_name(&level_name)) else {
            return true;
        };
        self.send_level_data(&level, &level_name, mod_time, true, false);
        let current_name = self.account.lock().unwrap().level_name.clone();
        if !current_name.is_empty() {
            self.send_plo_levelname(&current_name);
        }
        true
    }

    fn msg_pli_shoot(&self, packet: &[u8]) -> bool {
        let mut buf = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let _ = buf.read_gint();
        let x = buf.read_gchar();
        let y = buf.read_gchar();
        let z = buf.read_gchar();
        let angle = buf.read_gchar();
        let z_angle = buf.read_gchar();
        let speed = buf.read_gchar();
        let gani = buf.read_gchar_string();
        let params_len = usize::from(buf.read_gchar());
        let params = buf.read_bytes(buf.remaining());
        let params = &params[..params_len.min(params.len())];
        let params_text = String::from_utf8_lossy(params).into_owned();
        let mut out = Buffer::new();
        out.write_byte(PLO_SHOOT)
            .write_gshort(self.id())
            .write_gint(0)
            .write_gchar(x)
            .write_gchar(y)
            .write_gchar(z)
            .write_gchar(angle)
            .write_gchar(z_angle)
            .write_gchar(speed)
            .write_gchar(gani.len().min(223) as u8)
            .write(&gani.as_bytes()[..gani.len().min(223)])
            .write_gchar(params.len().min(223) as u8)
            .write(&params[..params.len().min(223)]);
        self.send_to_current_level_except_self(&out.data);
        if let Some(server) = self.server() {
            let args = vec![gani, params_text];
            server.run_server_side_event_for_active_scripts(
                "onWeaponFired",
                self.self_arc().as_ref(),
                &args,
            );
        }
        true
    }

    fn msg_pli_shoot2(&self, packet: &[u8]) -> bool {
        let mut out = Buffer::new();
        out.write_byte(PLO_SHOOT2)
            .write_gshort(self.id())
            .write(packet.get(1..).unwrap_or_default());
        self.send_to_current_level_except_self(&out.data);
        if let Some(server) = self.server() {
            server.run_server_side_event_for_active_scripts(
                "onWeaponFired",
                self.self_arc().as_ref(),
                &[],
            );
        }
        true
    }

    fn msg_pli_verifywantsend(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        let mut buf = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let checksum = buf.read_gint5() as u32;
        let file_name = buf.read_gstring();
        if file_name.is_empty() {
            return true;
        }
        if !file_name.to_ascii_lowercase().ends_with(".gupd") {
            if let Ok(data) = server.config.load_file(&file_name) {
                if calculate_crc32_checksum(&data) == checksum {
                    self.send_plo_fileuptodate(&file_name);
                    return true;
                }
            }
        }
        self.send_file(&file_name);
        true
    }

    fn msg_pli_updateclass(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        let mut buf = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let _ = buf.read_gint5();
        let class_name = String::from_utf8_lossy(&buf.read_bytes(buf.remaining()))
            .trim_end_matches('\n')
            .to_string();
        if let Some(class_obj) = server.get_class(&class_name) {
            self.send_raw_npc_weapon_script(class_obj.script.as_bytes());
        } else {
            let header = format!("class {class_name} 1 0 0 0");
            let mut out = Buffer::new();
            out.write_byte(PLO_NPCWEAPONSCRIPT)
                .write_short(header.len() as i16)
                .write(header.as_bytes());
            self.send(&out);
        }
        true
    }

    fn send_server_text_fields(&self, fields: &[String]) {
        let mut packet = Buffer::new();
        packet.write_byte(PLO_SERVERTEXT);
        packet.write(fields.join("\u{1}").as_bytes());
        packet.write_byte(1);
        self.send(&packet);
    }

    fn send_server_text_tokenized_fields(&self, fields: &[String]) {
        let value = fields.join("\n");
        let mut packet = Buffer::new();
        packet
            .write_byte(PLO_SERVERTEXT)
            .write(gtokenize_text(&value).as_bytes());
        self.send(&packet);
    }

    fn msg_pli_requesttext(&self, packet: &[u8]) -> bool {
        let Some((raw_text, weapon, type_name, option, _extra)) = parse_text_request(packet, false)
        else {
            return true;
        };
        let Some(server) = self.server() else {
            return true;
        };
        let args = vec![
            weapon.clone(),
            type_name.clone(),
            option.clone(),
            raw_text.clone(),
        ];
        server.run_server_side_event_for_active_scripts(
            "onReceiveText",
            self.self_arc().as_ref(),
            &args,
        );
        if type_name == "lister" {
            match option.as_str() {
                "simplelist" => {
                    let forwarded = server.send_player_text_to_listservers(
                        SVO_REQUESTLIST,
                        self.id(),
                        &format!("{weapon}\u{1}{type_name}\u{1}simpleserverlist\u{1}"),
                    );
                    if !forwarded {
                        self.send_server_text_fields(&vec![
                            weapon,
                            type_name,
                            "simpleserverlist".to_string(),
                        ]);
                    }
                }
                "rebornlist" => {
                    server.send_player_text_to_listservers(SVO_REQUESTLIST, self.id(), &raw_text);
                }
                "subscriptions" => self.send_server_text_fields(&vec![
                    weapon,
                    type_name,
                    option,
                    "unlimited".to_string(),
                    "Unlimited Subscription".to_string(),
                    "\"\"".to_string(),
                ]),
                "getglobalitems" => self.send_server_text_fields(&vec![
                    weapon,
                    type_name,
                    "globalitems".to_string(),
                    self.account_name(),
                    "autobill=1\u{1}autobillmine=1\u{1}bundle=1\u{1}creationtime=1212768763\u{1}currenttime=1353248504\u{1}description=Gives\u{1}duration=2629800\u{1}flags=subscription\u{1}icon=graalicon_big.png\u{1}itemid=1\u{1}lifetime=1\u{1}owner=global\u{1}ownertype=server\u{1}price=100\u{1}quantity=988506\u{1}status=available\u{1}title=Gold\u{1}tradable=1\u{1}typeid=62\u{1}world=global".to_string(),
                ]),
                "serverinfo" => {
                    if !server.send_player_text_to_listservers(
                        SVO_REQUESTSVRINFO,
                        self.id(),
                        &raw_text,
                    ) {
                        self.send_server_text_fields(&vec![
                            weapon,
                            type_name,
                            option,
                            server.name.read().unwrap().clone(),
                        ]);
                    }
                }
                "localbans" => {
                    let allowed = self.player_type() & PLTYPE_ANYRC != 0
                        && self.has_right(PLPERM_BAN);
                    if allowed {
                        self.send_server_text_fields(&vec![
                            weapon,
                            type_name,
                            option,
                            server.local_banned_accounts().join("\n"),
                        ]);
                    } else {
                        self.send_server_text_fields(&vec![weapon, type_name, option]);
                    }
                }
                option if is_hub_lister_option(option) || option == "bantypes" => {
                    let forwarded = server.send_player_text_to_listservers(
                        SVO_REQUESTLIST,
                        self.id(),
                        &raw_text,
                    );
                    if !forwarded {
                        self.send_server_text_fields(&vec![weapon, type_name, option.to_string()]);
                    }
                }
                _ => {}
            }
        } else if type_name == "pmservers" {
            let forwarded =
                server.send_player_text_to_listservers(SVO_REQUESTLIST, self.id(), &raw_text);
            if !forwarded {
                let mut fields = vec![weapon, type_name, option];
                fields.extend(server.active_server_names());
                self.send_server_text_fields(&fields);
            }
        } else if type_name == "pmguilds" {
            let mut fields = vec![weapon, type_name, option];
            fields.extend(server.active_guild_names());
            self.send_server_text_fields(&fields);
        } else if type_name == "pmserverplayers" {
            self.add_pm_server(&option);
            self.send_server_text_fields(&vec![weapon, type_name, option]);
        } else if type_name == "pmunmapserver" {
            self.remove_pm_server(&option);
            self.send_server_text_fields(&vec![weapon, type_name, option]);
        } else if type_name == "packageinfo" {
            self.send_server_text_fields(&vec![
                weapon,
                type_name,
                option,
                "0".to_string(),
                "0".to_string(),
            ]);
        } else if type_name == "irc" {
            self.send_server_text_fields(&vec![weapon, type_name, option]);
        }
        true
    }

    fn local_ban_details(&self, account_name: &str) -> Option<(String, String)> {
        let Some(server) = self.server() else {
            return None;
        };
        let mut normalized = account_name.trim().to_string();
        if normalized.eq_ignore_ascii_case("npcserver") {
            normalized = "(npcserver)".to_string();
        }
        if normalized.is_empty() {
            return None;
        }
        let target = server.get_player_by_account(&normalized, 0).or_else(|| {
            if !server.account_exists(&normalized) {
                return None;
            }
            let target = Player::NewPlayer(None, &server);
            if target
                .account
                .lock()
                .unwrap()
                .load_account(&normalized, false)
            {
                Some(target)
            } else {
                None
            }
        })?;
        let account = target.account.lock().unwrap();
        if !account.is_banned {
            return None;
        }
        let details = format!(
            "account={},world=local,banned=1,bantype={},releasetime={},reason={}",
            normalized, account.ban_type, account.ban_length, account.ban_reason
        );
        Some((normalized, details))
    }

    fn parse_lister_set_ban(
        &self,
        fields: &[String],
    ) -> Option<(String, String, bool, String, String, String)> {
        let target = fields.first()?.trim().to_string();
        if target.is_empty() {
            return None;
        }
        let mut banned = None;
        let mut world = "local".to_string();
        let mut length = String::new();
        let mut ban_type = String::new();
        let mut reason = String::new();
        for (index, field) in fields.iter().enumerate().skip(1) {
            let Some((key, value)) = field.split_once('=') else {
                continue;
            };
            let key = key.trim().to_ascii_lowercase();
            let value = if key == "reason" {
                let mut value = value.to_string();
                for rest in fields.iter().skip(index + 1) {
                    value.push(',');
                    value.push_str(rest);
                }
                value
            } else {
                value.to_string()
            };
            match key.as_str() {
                "world" => world = value.trim().to_ascii_lowercase(),
                "banned" => match value.trim().to_ascii_lowercase().as_str() {
                    "1" | "true" => banned = Some(true),
                    "0" | "false" => banned = Some(false),
                    _ => return None,
                },
                "releasetime" | "banlength" => length = value.trim().to_string(),
                "bantype" => ban_type = value.trim().to_string(),
                "reason" => reason = value,
                _ => {}
            }
        }
        if world != "local" && world != "all" {
            return None;
        }
        let banned = banned?;
        Some((target, world, banned, length, ban_type, reason))
    }

    fn set_local_ban_values(
        &self,
        target_name: &str,
        banned: bool,
        length: &str,
        ban_type: &str,
        reason: &str,
    ) -> bool {
        if self.player_type() & PLTYPE_ANYRC == 0 {
            if let Some(server) = self.server() {
                server.logger.warning(&format!(
                    "[Hack] {} attempted PLAYERBANSET (non-RC): {}",
                    self.account_name(),
                    target_name
                ));
            }
            return true;
        }
        if !self.has_right(PLPERM_BAN) {
            if let Some(server) = self.server() {
                server.logger.warning(&format!(
                    "{} attempted PLAYERBANSET without permission",
                    self.account_name()
                ));
            }
            self.send_plo_rc_chat("Server: You are not authorized to set player bans.");
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let target_name = rc_sanitize_account(target_name);
        let target_name = if target_name.eq_ignore_ascii_case("npcserver") {
            "(npcserver)".to_string()
        } else {
            target_name
        };
        let target = server.get_player_by_account(&target_name, 0).or_else(|| {
            if !server.account_exists(&target_name) {
                return None;
            }
            let target = Player::NewPlayer(None, &server);
            if target
                .account
                .lock()
                .unwrap()
                .load_account(&target_name, false)
            {
                Some(target)
            } else {
                None
            }
        });
        let Some(target) = target else {
            return true;
        };
        let (changed, ban_type_value, ban_length_value) = {
            let mut account = target.account.lock().unwrap();
            let old_banned = account.is_banned;
            let old_reason = account.ban_reason.clone();
            let old_type = account.ban_type.clone();
            let old_length = account.ban_length.clone();
            if !ban_type.trim().is_empty() {
                account.ban_type = ban_type.trim().to_string();
            }
            account.ban_length =
                resolve_local_ban_length(banned, &account.ban_type, length, &account.ban_length);
            account.is_banned = banned;
            account.ban_reason = reason.to_string();
            (
                old_banned != account.is_banned
                    || old_reason != account.ban_reason
                    || old_type != account.ban_type
                    || old_length != account.ban_length,
                account.ban_type.clone(),
                account.ban_length.clone(),
            )
        };
        let saved = target.save_account();
        if saved && changed {
            server.report_local_ban_history(
                &target_name,
                &self.account_name(),
                banned,
                &ban_type_value,
                &ban_length_value,
                reason,
            );
            let action = if banned { "banned" } else { "unbanned" };
            server.send_rc_chat(&format!(
                "{} has locally {} {}",
                self.account_name(),
                action,
                target_name
            ));
            server.send_rc_chat(&format!("Ban type: {ban_type_value}"));
            server.send_rc_chat(&format!(
                "Ban time: {}",
                format_local_ban_time(&ban_length_value)
            ));
            server.send_rc_chat(&format!("Reason: {reason}"));
        }
        let target_account_name = target.account_name();
        let target_ban = {
            let account = target.account.lock().unwrap();
            (
                account.is_banned,
                account.ban_reason.clone(),
                account.ban_length.clone(),
                account.ban_type.clone(),
            )
        };
        for live_player in server.get_all_players() {
            if live_player.account_name() == target_account_name
                && !Arc::ptr_eq(&live_player, &target)
            {
                let mut account = live_player.account.lock().unwrap();
                account.is_banned = target_ban.0;
                account.ban_reason = target_ban.1.clone();
                account.ban_length = target_ban.2.clone();
                account.ban_type = target_ban.3.clone();
            }
        }
        server.logger.info(&format!(
            "{} set ban for account: {} (banned={})",
            self.account_name(),
            target_name,
            banned
        ));
        if banned && target.id() != 0 && target.player_type() & PLTYPE_NPCSERVER == 0 {
            target.send_packet(&[PLO_DISCMESSAGE, 0]);
            target.write_string8_raw(&format!(
                "{} has banned you.  Reason: {}",
                self.account_name(),
                reason
            ));
            server.delete_player(&target);
        }
        true
    }

    fn set_local_ban_from_fields(&self, fields: &[String]) -> bool {
        let Some((target_name, world, banned, length, ban_type, reason)) =
            self.parse_lister_set_ban(fields)
        else {
            return true;
        };
        if world != "local" {
            return true;
        }
        self.set_local_ban_values(&target_name, banned, &length, &ban_type, &reason)
    }

    fn msg_pli_sendtext(&self, packet: &[u8]) -> bool {
        let Some((raw_text, weapon, type_name, option, extra)) = parse_text_request(packet, true)
        else {
            return true;
        };
        let Some(server) = self.server() else {
            return true;
        };
        if type_name == "lister" {
            let mut fields = vec![weapon.clone(), type_name.clone(), option.clone()];
            fields.extend(extra.clone());
            if option == "setban" {
                if let Some((target, world, banned, length, ban_type, reason)) =
                    self.parse_lister_set_ban(&extra)
                {
                    if world == "local" {
                        self.set_local_ban_values(&target, banned, &length, &ban_type, &reason);
                    } else if !server.forward_global_ban(
                        &target,
                        &self.account_name(),
                        banned,
                        &length,
                        &ban_type,
                        &reason,
                    ) {
                        server.logger.warning(&format!(
                            "{} global ban request could not reach the HubServer",
                            self.account_name()
                        ));
                        self.send_plo_rc_chat("Server: Global ban service is unavailable.");
                    } else {
                        let action = if banned { "banned" } else { "unbanned" };
                        let display_length = if banned && length.trim().is_empty() {
                            resolve_local_ban_length(true, &ban_type, "", "")
                        } else {
                            length.clone()
                        };
                        server.logger.info(&format!(
                            "{} set global ban for account: {} (banned={})",
                            self.account_name(),
                            target,
                            banned
                        ));
                        server.send_rc_chat(&format!(
                            "{} has globally {} {}",
                            self.account_name(),
                            action,
                            target
                        ));
                        server.send_rc_chat(&format!("Ban type: {ban_type}"));
                        server.send_rc_chat(&format!(
                            "Ban time: {}",
                            format_local_ban_time(&display_length)
                        ));
                        server.send_rc_chat(&format!("Reason: {reason}"));
                    }
                } else {
                    server.logger.warning(&format!(
                        "{} sent malformed lister setban request",
                        self.account_name()
                    ));
                }
            } else if (option == "getban" || option == "getbanbyid")
                && self.player_type() & PLTYPE_ANYRC != 0
            {
                let mut account_name = extra.first().cloned().unwrap_or_default();
                let forward_text = if option == "getbanbyid" {
                    if let Ok(id) = account_name.trim().parse::<u16>() {
                        account_name = server
                            .get_player(id)
                            .map(|player| player.account_name())
                            .unwrap_or_else(|| {
                                if id == 1 {
                                    "(npcserver)".to_string()
                                } else {
                                    String::new()
                                }
                            });
                    }
                    let rewrite = vec![
                        weapon.clone(),
                        type_name.clone(),
                        option.clone(),
                        account_name.clone(),
                    ];
                    gtokenize_text(&rewrite.join("\n"))
                } else {
                    raw_text.clone()
                };
                let forwarded = server.send_player_text_to_listservers(
                    SVO_REQUESTLIST,
                    self.id(),
                    &forward_text,
                );
                if !forwarded {
                    if let Some((account, details)) = self.local_ban_details(&account_name) {
                        self.send_server_text_tokenized_fields(&vec![
                            IRC_BYTES.to_string(),
                            "lister".to_string(),
                            "ban".to_string(),
                            account,
                            String::new(),
                            details,
                        ]);
                    } else {
                        self.send_server_text_fields(&vec![
                            IRC_BYTES.to_string(),
                            "lister".to_string(),
                            "ban".to_string(),
                            account_name,
                            String::new(),
                        ]);
                    }
                }
            } else if option == "serverinfo" {
                let forwarded = server.send_player_text_to_listservers(
                    SVO_REQUESTSVRINFO,
                    self.id(),
                    &raw_text,
                );
                if !forwarded {
                    let mut response = vec![weapon.clone(), type_name.clone(), option.clone()];
                    response.extend(extra);
                    if response.len() == 3 {
                        response.push(server.configured_name());
                    }
                    self.send_server_text_fields(&response);
                }
            } else if option == "localbans" {
                if self.player_type() & PLTYPE_ANYRC != 0 && self.has_right(PLPERM_BAN) {
                    fields.push(server.local_banned_accounts().join("\n"));
                }
                self.send_server_text_fields(&fields);
            } else {
                let forwarded =
                    server.send_player_text_to_listservers(SVO_REQUESTLIST, self.id(), &raw_text);
                if !forwarded {
                    self.send_server_text_fields(&fields);
                }
            }
        }
        let args = vec![weapon.clone(), type_name.clone(), option.clone(), raw_text];
        server.run_server_side_event_for_active_scripts(
            "onReceiveText",
            self.self_arc().as_ref(),
            &args,
        );
        true
    }

    fn msg_pli_updategani(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        let mut buf = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let checksum = buf.read_gint5() as u32;
        let gani_name = String::from_utf8_lossy(&buf.read_bytes(buf.remaining())).into_owned();
        if gani_name.is_empty() {
            return true;
        }
        let file_name = format!("{gani_name}.gani");
        let Ok(data) = server.config.load_file(&file_name) else {
            return true;
        };
        let gani = String::from_utf8_lossy(&data);
        let mut set_back_to = String::new();
        for line in gani.lines() {
            if line.starts_with("SETBACKTO") {
                if let Some(value) = line.split_whitespace().nth(1) {
                    set_back_to = value.to_string();
                }
                break;
            }
        }
        if checksum != calculate_crc32_checksum(&data) && gani.contains("SCRIPT") {
            if let (Some(start), Some(end)) = (gani.find("SCRIPT"), gani.find("SCRIPTEND")) {
                if start + 7 <= end {
                    let mut payload = Buffer::new();
                    payload
                        .write_gchar(PLO_GANISCRIPT)
                        .write_gchar(gani_name.len().min(223) as u8)
                        .write(&gani_name.as_bytes()[..gani_name.len().min(223)])
                        .write(&gani.as_bytes()[start + 7..end]);
                    self.send_raw_data_payload(&payload.data);
                }
            }
        }
        let mut result = Buffer::new();
        result
            .write_byte(PLO_UNKNOWN195)
            .write_gchar(gani_name.len().min(223) as u8)
            .write(&gani_name.as_bytes()[..gani_name.len().min(223)])
            .write(format!("\"SETBACKTO {set_back_to}\"").as_bytes());
        self.send(&result);
        true
    }

    fn msg_pli_updatescript(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        let mut buf = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let weapon_name = buf.read_string();
        if let Some(weapon) = server.get_weapon(&weapon_name) {
            if !weapon.bytecode.is_empty() {
                self.send_raw_npc_weapon_script(&weapon.bytecode);
            }
        }
        true
    }

    fn msg_pli_updatepackage_request_file(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        let mut buf = Buffer::from_bytes(packet.get(1..).unwrap_or_default());
        let package_name_len = buf.read_gbyte() as usize;
        let package_name = String::from_utf8_lossy(&buf.read_bytes(package_name_len)).into_owned();
        let install_type = buf.read_gbyte();
        let _ = buf.read_string();
        if install_type == 2 {
            // Rewind and read the request again for this client variant. The
            // second pass only validates framing;
            // no value from it changes the package enumeration.
            let _ = (package_name_len, install_type);
        }
        let package_path = format!("packages/{package_name}.gupd");
        let mut total_size = 0i64;
        let mut files = Vec::new();
        if let Ok(data) = server.config.load_file(&package_path) {
            for line in String::from_utf8_lossy(&data).lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let Some(file_name) = parts.next() else {
                    continue;
                };
                if parts.next().is_none() {
                    continue;
                }
                if let Ok(file_data) = server.config.load_file(file_name) {
                    total_size += file_data.len() as i64;
                    files.push(file_name.to_string());
                }
            }
        }
        let mut size = Buffer::new();
        size.write_byte(PLO_UPDATEPACKAGESIZE)
            .write_gchar(package_name.len().min(223) as u8)
            .write(&package_name.as_bytes()[..package_name.len().min(223)])
            .write_int64(total_size);
        self.send(&size);
        for file_name in files {
            self.send_file(&file_name);
        }
        let mut done = Buffer::new();
        done.write_byte(PLO_UPDATEPACKAGEDONE)
            .write_gchar(package_name.len().min(223) as u8)
            .write(&package_name.as_bytes()[..package_name.len().min(223)]);
        self.send(&done);
        true
    }

    fn msg_pli_flagset(&self, packet: &[u8]) -> bool {
        if packet.len() <= 1 {
            return true;
        }
        let text = String::from_utf8_lossy(&packet[1..])
            .trim_end_matches('\n')
            .to_string();
        if let Some((name, value)) = text.split_once('=') {
            if self.handle_movement_flag(name, value) {
                return true;
            }
            self.account.lock().unwrap().set_flag(name, value);
        } else {
            self.account.lock().unwrap().set_flag(&text, "");
        }
        true
    }
    fn msg_pli_flagdel(&self, packet: &[u8]) -> bool {
        if packet.len() > 1 {
            self.account
                .lock()
                .unwrap()
                .delete_flag(String::from_utf8_lossy(&packet[1..]).trim_end_matches('\n'));
        }
        true
    }
    fn msg_pli_packetcount(&self, packet: &[u8]) -> bool {
        if packet.len() >= 3 {
            let mut buf = Buffer::from_bytes(&packet[1..]);
            let _ = buf.read_gshort();
        }
        self.state.lock().unwrap().packet_count = 0;
        true
    }
    fn msg_pli_serverwarp(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        let name = String::from_utf8_lossy(packet.get(1..).unwrap_or_default()).to_string();
        server.logger.debug(&format!("SERVERWARP to {name}"));
        if !name.is_empty() {
            let forwarded =
                server.send_player_text_to_listservers(SVO_SERVERINFO, self.id(), &name);
            if !forwarded {
                server.logger.warning(&format!(
                    "SERVERWARP requested by {} but no listserver is connected",
                    self.account_name()
                ));
            }
            let args = vec![name];
            server.run_server_side_event_for_active_scripts(
                "onServerWarp",
                self.self_arc().as_ref(),
                &args,
            );
        }
        true
    }

    fn handle_player_chat_command(&self, chat: &str) -> bool {
        let trimmed = chat.trim();
        if trimmed.is_empty() {
            return false;
        }
        let words = trimmed.split_whitespace().collect::<Vec<_>>();
        let command = words[0].to_ascii_lowercase();
        match command.as_str() {
            "/reconnect" | "reconnect" => {
                let Some(server) = self.server() else {
                    return true;
                };
                let name = nonempty(&server.name.read().unwrap())
                    .unwrap_or_else(|| nonempty(&server.settings.get("name")).unwrap_or_default());
                if name.is_empty() {
                    self.set_chat("(server name is not set)");
                    return true;
                }
                if self.should_save_player_account() {
                    let _ = self.save_account();
                    self.state.lock().unwrap().last_save = Instant::now();
                }
                if !server.send_player_text_to_listservers(SVO_SERVERINFO, self.id(), &name) {
                    let ip = nonempty(&server.settings.get("serverip"))
                        .filter(|value| !value.eq_ignore_ascii_case("AUTO"))
                        .unwrap_or_else(|| "127.0.0.1".to_string());
                    let port = nonempty(&server.settings.get("serverport"))
                        .unwrap_or_else(|| "14802".to_string());
                    let mut packet = Buffer::new();
                    packet
                        .write_byte(PLO_SERVERWARP)
                        .write(format!("P {name} {ip}:{port}").as_bytes());
                    self.send(&packet);
                }
                self.clear_chat_with_props(&[]);
                true
            }
            "setnick" => {
                let allowed = {
                    let mut state = self.state.lock().unwrap();
                    if state.last_nick.elapsed() < Duration::from_secs(10) {
                        false
                    } else {
                        state.last_nick = Instant::now();
                        true
                    }
                };
                if !allowed {
                    self.set_chat("Wait 10 seconds before changing your nick again!");
                    return true;
                }
                let value = trimmed.get("setnick".len()..).unwrap_or_default().trim();
                self.set_nickname(value);
                self.clear_chat_with_props(&[PLPROP_NICKNAME]);
                true
            }
            "sethead" => self.handle_player_chat_set_asset(
                &words,
                "heads",
                &[".png", ".mng", ".gif"],
                PLPROP_HEADGIF,
            ),
            "setbody" => self.handle_player_chat_set_asset(
                &words,
                "bodies",
                &[".png", ".mng", ".gif"],
                PLPROP_BODYIMG,
            ),
            "setsword" => self.handle_player_chat_set_asset(
                &words,
                "swords",
                &[".png", ".mng", ".gif"],
                PLPROP_SWORDPOWER,
            ),
            "setshield" => self.handle_player_chat_set_asset(
                &words,
                "shields",
                &[".png", ".mng", ".gif"],
                PLPROP_SHIELDPOWER,
            ),
            "setskin" | "setcoat" | "setsleeves" | "setshoes" | "setbelt" | "setall" => {
                if !self
                    .server()
                    .map(|server| server.settings.get_bool("setcolorsallowed", true))
                    .unwrap_or(true)
                {
                    return false;
                }
                let Some(value) = words.get(1).map(|v| v.to_ascii_lowercase()) else {
                    return false;
                };
                let value = if value == "grey" {
                    "gray".to_string()
                } else {
                    value
                };
                let color: u8 = match value.as_str() {
                    "white" => 0,
                    "yellow" => 1,
                    "orange" => 2,
                    "pink" => 3,
                    "red" => 4,
                    "darkred" => 5,
                    "lightgreen" => 6,
                    "green" => 7,
                    "darkgreen" => 8,
                    "lightblue" => 9,
                    "blue" => 10,
                    "darkblue" => 11,
                    "brown" => 12,
                    "cynober" => 13,
                    "purple" => 14,
                    "darkpurple" => 15,
                    "lightgray" => 16,
                    "gray" => 17,
                    "black" => 18,
                    "transparent" => 19,
                    _ => return true,
                };
                {
                    let mut account = self.account.lock().unwrap();
                    if command == "setall" {
                        account.character.colors = [color; 5];
                    } else {
                        let index = match command.as_str() {
                            "setskin" => 0,
                            "setcoat" => 1,
                            "setsleeves" => 2,
                            "setshoes" => 3,
                            "setbelt" => 4,
                            _ => return true,
                        };
                        account.character.colors[index] = color;
                    }
                }
                self.clear_chat_with_props(&[PLPROP_COLORS]);
                true
            }
            "warpto" => self.handle_player_chat_warpto(&words),
            "summon" => self.handle_player_chat_summon(&words),
            "unstick" | "unstuck" => {
                if words.len() == 2 && words[1].eq_ignore_ascii_case("me") {
                    self.handle_player_chat_unstick_me(trimmed)
                } else {
                    false
                }
            }
            "update" => {
                if trimmed.eq_ignore_ascii_case("update level")
                    && self.has_right(PLPERM_UPDATELEVEL)
                {
                    let server = self.server();
                    let level = self.current_level().or_else(|| {
                        server.as_ref().and_then(|server| {
                            server.get_level(&clean_level_name(&self.level_name()))
                        })
                    });
                    if let (Some(server), Some(level)) = (server, level) {
                        if level.reload(&server) {
                            server.resend_level_data(&level);
                        }
                    }
                    self.clear_chat_with_props(&[]);
                    true
                } else {
                    false
                }
            }
            "showkills" => {
                self.set_chat(&format!("kills: {}", self.account.lock().unwrap().kills));
                true
            }
            "showdeaths" => {
                self.set_chat(&format!("deaths: {}", self.account.lock().unwrap().deaths));
                true
            }
            "showonlinetime" => {
                self.set_chat(&format!(
                    "onlinetime: {}",
                    format_online_time(self.account.lock().unwrap().online_time)
                ));
                true
            }
            "showadmins" => {
                let names = self
                    .server()
                    .map(|server| {
                        server
                            .get_all_players()
                            .into_iter()
                            .filter(|player| player.player_type() & PLTYPE_ANYRC != 0)
                            .map(|player| player.account_name())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let message = if names.is_empty() {
                    "admins: (no one)".to_string()
                } else {
                    format!("admins: {}", names.join(", "))
                };
                self.set_chat(&message);
                true
            }
            "showguild" => self.handle_player_chat_show_guild(&words),
            "toguild:" => self.handle_player_chat_to_guild(trimmed),
            _ => false,
        }
    }

    fn handle_player_chat_set_asset(
        &self,
        words: &[&str],
        category: &str,
        extensions: &[&str],
        property: u8,
    ) -> bool {
        let Some(server) = self.server() else {
            return false;
        };
        let setting = match category {
            "heads" => "setheadallowed",
            "bodies" => "setbodyallowed",
            "swords" => "setswordallowed",
            "shields" => "setshieldallowed",
            _ => return false,
        };
        if words.len() != 2 || !server.settings.get_bool(setting, true) {
            return false;
        }
        let Some(file_name) = self.resolve_player_asset(category, words[1], extensions, &server)
        else {
            return true;
        };
        let mut account = self.account.lock().unwrap();
        match category {
            "heads" => account.character.head_image = file_name,
            "bodies" => account.character.body_image = file_name,
            "swords" => account.character.sword_image = file_name,
            "shields" => account.character.shield_image = file_name,
            _ => return false,
        }
        drop(account);
        self.clear_chat_with_props(&[property]);
        true
    }

    fn resolve_player_asset(
        &self,
        category: &str,
        requested: &str,
        extensions: &[&str],
        server: &Arc<Server>,
    ) -> Option<String> {
        let file_name = requested.trim().replace('\\', "/");
        if file_name.is_empty() || file_name.contains('/') || file_name.contains("..") {
            return None;
        }
        if is_default_player_asset(category, &file_name)
            || server.config.file_exists(format!("{category}/{file_name}"))
        {
            return Some(file_name);
        }
        if Path::new(&file_name).extension().is_none() {
            for extension in extensions {
                let candidate = format!("{file_name}{extension}");
                if is_default_player_asset(category, &candidate)
                    || server.config.file_exists(format!("{category}/{candidate}"))
                {
                    return Some(candidate);
                }
            }
        }
        None
    }

    fn handle_player_chat_warpto(&self, words: &[&str]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if words.len() == 2 {
            if (!self.has_right(PLPERM_WARPTOPLAYER) || !self.admin_ip_matches_current_remote())
                && !server.allows_warp_to_all()
            {
                self.set_chat("(not authorized to warp)");
                return true;
            }
            if let Some(player) = server.find_player_by_account_or_nick(words[1], PLTYPE_ANYCLIENT)
            {
                let level_name = player.level_name();
                let (x, y) = player.position();
                if !level_name.is_empty() {
                    self.warp(&level_name, f64::from(x) / 16.0, f64::from(y) / 16.0, 0);
                    self.clear_chat_with_props(&[]);
                }
            }
            return true;
        }
        if words.len() == 3 || words.len() == 4 {
            if (!self.has_right(PLPERM_WARPTO) || !self.admin_ip_matches_current_remote())
                && !server.allows_warp_to_all()
            {
                self.set_chat("(not authorized to warp)");
                return true;
            }
            let (Ok(x), Ok(y)) = (words[1].parse::<f64>(), words[2].parse::<f64>()) else {
                return true;
            };
            if words.len() == 4 {
                self.warp(words[3], x, y, 0);
                self.clear_chat_with_props(&[]);
            } else {
                let mut account = self.account.lock().unwrap();
                account.set_x(x as f32);
                account.set_y(y as f32);
                drop(account);
                self.clear_chat_with_props(&[PLPROP_X, PLPROP_Y]);
            }
            return true;
        }
        true
    }

    fn handle_player_chat_summon(&self, words: &[&str]) -> bool {
        if words.len() != 2 {
            return false;
        }
        if !self.has_right(PLPERM_SUMMON) {
            self.set_chat("(not authorized to summon)");
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        let level_name = self.level_name();
        let (x, y) = self.position();
        if let Some(player) = server.find_player_by_account_or_nick(words[1], PLTYPE_ANYCLIENT) {
            player.warp(&level_name, f64::from(x) / 16.0, f64::from(y) / 16.0, 0);
        }
        self.clear_chat_with_props(&[]);
        true
    }

    fn handle_player_chat_unstick_me(&self, original_chat: &str) -> bool {
        let Some(server) = self.server() else {
            return false;
        };
        let level_name = self.level_name();
        if server
            .settings
            .get("jaillevels")
            .split(',')
            .map(str::trim)
            .any(|value| value == level_name)
        {
            return false;
        }
        let unstick_time = server.settings.get_int("unstickmetime", 30).max(0) as u64;
        let elapsed = self.state.lock().unwrap().last_movement.elapsed().as_secs();
        if elapsed < unstick_time {
            self.set_chat(&format!(
                "Don't move for {} seconds before doing '{}'!",
                unstick_time - elapsed,
                original_chat
            ));
            return true;
        }
        self.state.lock().unwrap().last_movement = Instant::now();
        let level = nonempty(&server.settings.get("unstickmelevel"))
            .unwrap_or_else(|| "onlinestartlocal.nw".to_string());
        let x = server
            .settings
            .get("unstickmex")
            .parse::<f64>()
            .unwrap_or(30.0);
        let y = server
            .settings
            .get("unstickmey")
            .parse::<f64>()
            .unwrap_or(30.5);
        self.warp(&level, x, y, 0);
        self.set_chat("Warped!");
        true
    }

    fn handle_player_chat_show_guild(&self, words: &[&str]) -> bool {
        let guild = if words.len() == 2 {
            words[1].to_string()
        } else {
            self.guild()
        };
        if guild.is_empty() || words.len() > 2 {
            return false;
        }
        let names = self
            .server()
            .map(|server| {
                server
                    .get_all_players()
                    .into_iter()
                    .filter(|player| player.guild() == guild)
                    .map(|player| {
                        player
                            .nickname()
                            .split('(')
                            .next()
                            .unwrap_or_default()
                            .trim()
                            .to_string()
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if names.is_empty() {
            self.set_chat(&format!("members of '{guild}': (no one)"));
        } else {
            self.set_chat(&format!("members of '{guild}': {}", names.join(", ")));
        }
        true
    }

    fn handle_player_chat_to_guild(&self, chat: &str) -> bool {
        let guild = self.guild();
        if guild.is_empty() {
            return false;
        }
        let message = chat.get(8..).unwrap_or_default().trim();
        if message.is_empty() {
            return false;
        }
        let Some(server) = self.server() else {
            return false;
        };
        let mut count = 0;
        for player in server.get_all_players() {
            if player.guild() != guild || !player.has_connection() {
                continue;
            }
            let mut output = Buffer::new();
            output
                .write_byte(PLO_PRIVATEMESSAGE)
                .write_gshort(self.id())
                .write(b"\"\",\"Guild message:\",\"")
                .write(message.as_bytes())
                .write_byte(b'\"');
            player.send(&output);
            count += 1;
        }
        let suffix = if count == 0 { "" } else { "s" };
        self.set_chat(&format!(
            "({count} guild member{suffix} received your message)"
        ));
        true
    }

    fn msg_pli_playerprops_exact(&self, packet: &[u8]) -> bool {
        if packet.len() <= 1 {
            return true;
        }
        let mut buf = Buffer::from_bytes(&packet[1..]);
        let mut common = Buffer::new();
        let mut legacy_move = Buffer::new();
        let mut precise_move = Buffer::new();
        let mut ordered_move = Buffer::new();
        let mut moved = false;
        let mut chatted = false;
        let mut has_gani = false;
        let mut has_movement = false;
        let mut changed_props = Vec::new();

        while buf.remaining() > 0 {
            let prop = buf.read_gchar();
            let mut consumed = false;
            let mut changed = true;
            match prop {
                PLPROP_NICKNAME => {
                    let value = buf.read_gchar_string();
                    changed = value != self.nickname();
                    if !value.is_empty() && value != "unknown" {
                        let old = self.nickname();
                        self.set_nickname(&value);
                        if old != self.nickname() && self.player_type() & PLTYPE_ANYRC != 0 {
                            if let Some(server) = self.server() {
                                server.send_rc_chat(&format!(
                                    "{} changed his/her nick to {}",
                                    self.account_name(),
                                    self.nickname()
                                ));
                            }
                        }
                    }
                }
                PLPROP_MAXPOWER => {
                    let value = buf.read_gchar();
                    let mut account = self.account.lock().unwrap();
                    account.max_hitpoints = value;
                    account.character.hitpoints = i32::from(value);
                }
                PLPROP_CURPOWER => {
                    let value = buf.read_gchar();
                    self.account.lock().unwrap().character.hitpoints = i32::from(value) / 2;
                }
                PLPROP_RUPEESCOUNT => {
                    let value = buf.read_gint();
                    let mut account = self.account.lock().unwrap();
                    account.rupees = value;
                    account.character.gralats = value as i32;
                }
                PLPROP_ARROWSCOUNT => {
                    self.account.lock().unwrap().character.arrows = i32::from(buf.read_gchar());
                }
                PLPROP_BOMBSCOUNT => {
                    self.account.lock().unwrap().character.bombs = i32::from(buf.read_gchar());
                }
                PLPROP_GLOVEPOWER => {
                    self.account.lock().unwrap().character.glove_power =
                        i32::from(buf.read_gchar()).min(3);
                }
                PLPROP_BOMBPOWER => {
                    let _ = buf.read_gchar();
                }
                PLPROP_SWORDPOWER | PLPROP_SHIELDPOWER => {
                    let power = i32::from(buf.read_gchar());
                    let image = if (prop == PLPROP_SWORDPOWER && power <= 4)
                        || (prop == PLPROP_SHIELDPOWER && power <= 3)
                    {
                        if prop == PLPROP_SWORDPOWER {
                            format!("sword{power}.png")
                        } else {
                            format!("shield{power}.png")
                        }
                    } else {
                        buf.read_gchar_string()
                    };
                    let mut account = self.account.lock().unwrap();
                    if prop == PLPROP_SWORDPOWER {
                        account.character.sword_power = if power <= 4 { power } else { power - 30 };
                        account.character.sword_image = image;
                    } else {
                        account.character.shield_power =
                            if power <= 3 { power } else { power - 10 };
                        account.character.shield_image = image;
                    }
                }
                PLPROP_GANI => {
                    let value = buf.read_gchar_string();
                    let mut account = self.account.lock().unwrap();
                    changed = value != account.character.gani;
                    account.character.gani = value;
                    has_gani = true;
                }
                PLPROP_BODYIMG => {
                    let value = buf.read_gchar_string();
                    let mut account = self.account.lock().unwrap();
                    changed = value != account.character.body_image;
                    account.character.body_image = value;
                }
                PLPROP_HEADGIF => {
                    let length = buf.read_gchar();
                    let mut account = self.account.lock().unwrap();
                    if length < 100 {
                        let extension = if self.version_id() > 0 && self.version_id() < 210 {
                            ".gif"
                        } else {
                            ".png"
                        };
                        account.character.head_image = format!("head{length}{extension}");
                    } else if length > 100 {
                        account.character.head_image = String::from_utf8_lossy(
                            &buf.read_bytes(usize::from(length - 100).min(buf.remaining())),
                        )
                        .into_owned();
                    }
                }
                PLPROP_COLORS => {
                    let mut account = self.account.lock().unwrap();
                    let old = account.character.colors;
                    for value in &mut account.character.colors {
                        *value = buf.read_gchar();
                    }
                    changed = account.character.colors != old;
                }
                PLPROP_ID => {
                    let _ = buf.read_gshort();
                }
                PLPROP_X => {
                    let value = i16::from(buf.read_gchar()) * 8;
                    self.account.lock().unwrap().x = value;
                    self.mark_movement();
                    moved = true;
                    has_movement = true;
                }
                PLPROP_Y => {
                    let value = i16::from(buf.read_gchar()) * 8;
                    self.account.lock().unwrap().y = value;
                    self.mark_movement();
                    moved = true;
                    has_movement = true;
                }
                PLPROP_Z => {
                    let value = (i16::from(buf.read_gchar()) - 50) * 8;
                    self.account.lock().unwrap().z = value;
                    self.mark_movement();
                    moved = true;
                    has_movement = true;
                }
                PLPROP_CURLEVEL => {
                    self.account.lock().unwrap().level_name = buf.read_gchar_string();
                }
                PLPROP_SPRITE => {
                    self.account.lock().unwrap().character.sprite = buf.read_gchar();
                }
                PLPROP_STATUS => {
                    let old_status = self.account.lock().unwrap().status;
                    let value = i32::from(buf.read_gchar());
                    self.account.lock().unwrap().status = value;
                    let was_dead = old_status & PLSTATUS_DEAD != 0;
                    let is_dead = value & PLSTATUS_DEAD != 0;
                    let level = self.current_level();
                    if !was_dead && is_dead {
                        if let Some(level) = &level {
                            if !level.state.read().unwrap().is_sparring_zone {
                                let mut account = self.account.lock().unwrap();
                                account.deaths = account.deaths.saturating_add(1);
                                drop(account);
                                self.drop_items_on_death(level);
                            }
                        }
                        if let Some(level) = &level {
                            let players = level.get_players();
                            if !level.state.read().unwrap().is_sparring_zone
                                && players.len() > 1
                                && players[0] == self.id()
                            {
                                level.remove_player(self);
                                level.add_player(self);
                                if let Some(leader_id) = level.get_players().first().copied() {
                                    if let Some(server) = self.server() {
                                        if let Some(leader) = server.get_player(leader_id) {
                                            leader.send_plo_isleader();
                                        }
                                    }
                                }
                            }
                        }
                    } else if was_dead && !is_dead {
                        let (ap, max_hitpoints) = {
                            let account = self.account.lock().unwrap();
                            (account.character.ap, account.max_hitpoints)
                        };
                        let mut power = if ap >= 40 {
                            i32::from(max_hitpoints)
                        } else if ap >= 20 {
                            5
                        } else {
                            3
                        };
                        if power > i32::from(max_hitpoints) {
                            power = i32::from(max_hitpoints);
                        }
                        if power < 1 && max_hitpoints > 0 {
                            power = 1;
                        }
                        self.account.lock().unwrap().character.hitpoints = power;
                        let mut props = Buffer::new();
                        props
                            .write_gchar(PLPROP_CURPOWER)
                            .write_gchar((power * 2).clamp(0, 255) as u8);
                        let mut packet = Buffer::new();
                        packet.write_byte(PLO_PLAYERPROPS).write(&props.data);
                        self.send(&packet);
                        self.send_player_prop_deltas_to_current_level(
                            &props.data,
                            &[],
                            &[],
                            &[],
                            false,
                            false,
                        );
                    }
                }
                PLPROP_CARRYSPRITE => {
                    self.account.lock().unwrap().carry_sprite = buf.read_byte();
                }
                PLPROP_HORSEGIF => {
                    let value = buf.read_gchar_string();
                    let mut account = self.account.lock().unwrap();
                    changed = value != account.character.horse_image;
                    account.character.horse_image = value;
                }
                PLPROP_HORSEBUSHES => {
                    self.account.lock().unwrap().horse_bomb_count = buf.read_gchar();
                }
                PLPROP_EFFECTCOLORS => {
                    if buf.read_gchar() > 0 {
                        let _ = buf.read_gint4();
                    }
                }
                PLPROP_CARRYNPC => {
                    let value = buf.read_gint();
                    let mut account = self.account.lock().unwrap();
                    changed = account.attach_npc != value;
                    account.attach_npc = value;
                }
                PLPROP_APCOUNTER => {
                    let value = (buf.read_gshort() & 0xff) as u8;
                    let mut account = self.account.lock().unwrap();
                    changed = account.ap_counter != value;
                    account.ap_counter = value;
                }
                PLPROP_MAGICPOINTS => {
                    let value = buf.read_gchar().min(100);
                    let mut account = self.account.lock().unwrap();
                    changed = account.mp != value;
                    account.mp = value;
                }
                PLPROP_KILLSCOUNT => {
                    let _ = buf.read_gint();
                }
                PLPROP_DEATHSCOUNT => {
                    let _ = buf.read_gint();
                }
                PLPROP_ONLINESECS => {
                    let _ = buf.read_gint();
                }
                PLPROP_IPADDR => {
                    let _ = buf.read_gint5();
                }
                PLPROP_UDPPORT => {
                    self.account.lock().unwrap().udp_port = buf.read_gint() as i32;
                }
                PLPROP_ALIGNMENT => {
                    let value = i32::from(buf.read_gchar()).min(100);
                    let mut account = self.account.lock().unwrap();
                    changed = account.alignment != value;
                    account.alignment = value;
                }
                PLPROP_ADDITFLAGS => {
                    let value = u32::from(buf.read_gchar());
                    let mut account = self.account.lock().unwrap();
                    changed = account.additional_flags != value;
                    account.additional_flags = value;
                }
                PLPROP_ACCOUNTNAME => {
                    let _ = buf.read_gchar_string();
                }
                PLPROP_RATING => {
                    let _ = buf.read_gint();
                }
                PLPROP_ATTACHNPC => {
                    let _ = buf.read_gchar();
                    self.account.lock().unwrap().attach_npc = buf.read_gint();
                }
                PLPROP_GMAPLEVELX | PLPROP_GMAPLEVELY | PLPROP_JOINLEAVELVL => {
                    let _ = buf.read_gchar();
                }
                PLPROP_PCONNECTED => {}
                PLPROP_CURCHAT => {
                    let value = buf.read_gchar_string();
                    if self.handle_player_chat_command(&value) {
                        consumed = true;
                    } else {
                        let mut account = self.account.lock().unwrap();
                        changed = value != account.character.chat_message;
                        account.character.chat_message = value;
                        chatted = true;
                    }
                }
                PLPROP_PLANGUAGE => {
                    let value = buf.read_gchar_string();
                    let mut account = self.account.lock().unwrap();
                    changed = value != account.language;
                    account.language = value;
                }
                PLPROP_PSTATUSMSG => {
                    let value = buf.read_gchar();
                    let mut account = self.account.lock().unwrap();
                    changed = account.status_msg != value;
                    account.status_msg = value;
                }
                PLPROP_GATTRIB1..=PLPROP_GATTRIB5 => {
                    let value = buf.read_gchar_string();
                    self.account.lock().unwrap().character.gani_attributes
                        [(prop - PLPROP_GATTRIB1) as usize] = value;
                }
                PLPROP_GATTRIB6..=PLPROP_GATTRIB9 => {
                    let value = buf.read_gchar_string();
                    self.account.lock().unwrap().character.gani_attributes
                        [(prop - PLPROP_GATTRIB6 + 5) as usize] = value;
                }
                PLPROP_GATTRIB10..=PLPROP_GATTRIB30 => {
                    let value = buf.read_gchar_string();
                    self.account.lock().unwrap().character.gani_attributes
                        [(prop - PLPROP_GATTRIB10 + 9) as usize] = value;
                }
                PLPROP_OSTYPE => {
                    let value = buf.read_gchar_string();
                    let mut account = self.account.lock().unwrap();
                    changed = value != account.os;
                    account.os = value;
                }
                PLPROP_TEXTCODEPAGE => {
                    let value = buf.read_gint() as i32;
                    let mut account = self.account.lock().unwrap();
                    changed = value != account.env_code_page;
                    account.env_code_page = value;
                }
                PLPROP_UNKNOWN77 => {
                    let _ = buf.read_gchar();
                }
                PLPROP_X2 => {
                    let value = decode_signed_gshort_coord(buf.read_gshort());
                    self.account.lock().unwrap().x = value;
                    self.mark_movement();
                    moved = true;
                    has_movement = true;
                }
                PLPROP_Y2 => {
                    let value = decode_signed_gshort_coord(buf.read_gshort());
                    self.account.lock().unwrap().y = value;
                    self.mark_movement();
                    moved = true;
                    has_movement = true;
                }
                PLPROP_Z2 => {
                    let value = decode_signed_gshort_coord(buf.read_gshort());
                    self.account.lock().unwrap().z = value;
                    self.mark_movement();
                    moved = true;
                    has_movement = true;
                }
                PLPROP_UNKNOWN81 => {
                    let _ = buf.read_gchar();
                }
                PLPROP_COMMUNITYNAME => {
                    let value = buf.read_gchar_string();
                    let mut account = self.account.lock().unwrap();
                    changed = value != account.community_name;
                    account.community_name = value;
                }
                _ => return true,
            }
            if consumed {
                continue;
            }
            if changed {
                changed_props.push(prop);
            }
            self.append_player_prop_delta(
                prop,
                &mut common,
                &mut legacy_move,
                &mut precise_move,
                &mut ordered_move,
            );
        }

        let loaded = self.state.lock().unwrap().loaded;
        if loaded && self.is_logged_in() {
            self.send_player_prop_deltas_to_current_level(
                &common.data,
                &legacy_move.data,
                &precise_move.data,
                &ordered_move.data,
                has_gani,
                has_movement,
            );
        }
        if moved {
            self.state.lock().unwrap().gr_movement_updated = true;
            self.run_server_side_npc_touch_test();
        }
        if chatted {
            if let Some(server) = self.server() {
                let chat = self.account.lock().unwrap().character.chat_message.clone();
                let args = vec![chat];
                let player = self.self_arc();
                server.run_server_side_event_for_active_scripts(
                    "onPlayerChats",
                    player.as_ref(),
                    &args,
                );
            }
        }
        if let Some(server) = self.server() {
            for prop in changed_props {
                let args = vec![prop.to_string()];
                server.run_server_side_event_for_active_scripts(
                    "onPlayerChanges",
                    self.self_arc().as_ref(),
                    &args,
                );
            }
        }
        true
    }

    fn msg_pli_playerprops(&self, packet: &[u8]) -> bool {
        if packet.len() <= 1 {
            return true;
        }
        let mut buf = Buffer::from_bytes(&packet[1..]);
        let mut changed = Vec::new();
        while buf.remaining() > 0 {
            let prop = buf.read_gchar();
            match prop {
                PLPROP_NICKNAME => {
                    let value = buf.read_gchar_string();
                    if !value.is_empty() && value != "unknown" {
                        self.set_nickname(&value);
                    }
                    changed.push(prop);
                }
                PLPROP_MAXPOWER => {
                    let mut a = self.account.lock().unwrap();
                    a.max_hitpoints = buf.read_gchar();
                    a.character.hitpoints = a.max_hitpoints as i32;
                    changed.push(prop);
                }
                PLPROP_CURPOWER => {
                    self.account.lock().unwrap().character.hitpoints =
                        i32::from(buf.read_gchar()) / 2;
                    changed.push(prop);
                }
                PLPROP_RUPEESCOUNT => {
                    let value = buf.read_gint();
                    let mut a = self.account.lock().unwrap();
                    a.character.gralats = value as i32;
                    a.rupees = value;
                    changed.push(prop);
                }
                PLPROP_ARROWSCOUNT => {
                    self.account.lock().unwrap().character.arrows = i32::from(buf.read_gchar());
                    changed.push(prop);
                }
                PLPROP_BOMBSCOUNT => {
                    self.account.lock().unwrap().character.bombs = i32::from(buf.read_gchar());
                    changed.push(prop);
                }
                PLPROP_GLOVEPOWER => {
                    self.account.lock().unwrap().character.glove_power =
                        i32::from(buf.read_gchar()).min(3);
                    changed.push(prop);
                }
                PLPROP_SWORDPOWER => {
                    let power = i32::from(buf.read_gchar());
                    let mut a = self.account.lock().unwrap();
                    if power <= 4 {
                        a.character.sword_power = power;
                        a.character.sword_image = format!("sword{power}.png");
                    } else {
                        a.character.sword_power = power - 30;
                        a.character.sword_image = buf.read_gchar_string();
                    }
                    changed.push(prop);
                }
                PLPROP_SHIELDPOWER => {
                    let power = i32::from(buf.read_gchar());
                    let mut a = self.account.lock().unwrap();
                    if power <= 3 {
                        a.character.shield_power = power;
                        a.character.shield_image = format!("shield{power}.png");
                    } else {
                        a.character.shield_power = power - 10;
                        a.character.shield_image = buf.read_gchar_string();
                    }
                    changed.push(prop);
                }
                PLPROP_GANI => {
                    self.account.lock().unwrap().character.gani = buf.read_gchar_string();
                    changed.push(prop);
                }
                PLPROP_BODYIMG => {
                    self.account.lock().unwrap().character.body_image = buf.read_gchar_string();
                    changed.push(prop);
                }
                PLPROP_HEADGIF => {
                    let len = buf.read_gchar();
                    let mut a = self.account.lock().unwrap();
                    if len < 100 {
                        a.character.head_image = format!(
                            "head{}{}",
                            len,
                            if self.version_id() > 0 && self.version_id() < 210 {
                                ".gif"
                            } else {
                                ".png"
                            }
                        );
                    } else {
                        a.character.head_image =
                            String::from_utf8_lossy(&buf.read_bytes(usize::from(len - 100)))
                                .into_owned();
                    }
                    changed.push(prop);
                }
                PLPROP_COLORS => {
                    let mut a = self.account.lock().unwrap();
                    for color in &mut a.character.colors {
                        *color = buf.read_gchar();
                    }
                    changed.push(prop);
                }
                PLPROP_X => {
                    self.account.lock().unwrap().x = i16::from(buf.read_gchar()) * 8;
                    changed.push(prop);
                }
                PLPROP_Y => {
                    self.account.lock().unwrap().y = i16::from(buf.read_gchar()) * 8;
                    changed.push(prop);
                }
                PLPROP_Z => {
                    self.account.lock().unwrap().z = (i16::from(buf.read_gchar()) - 50) * 8;
                    changed.push(prop);
                }
                PLPROP_X2 => {
                    let value = decode_signed_gshort_coord(buf.read_gshort());
                    self.account.lock().unwrap().x = value;
                    changed.push(prop);
                }
                PLPROP_Y2 => {
                    let value = decode_signed_gshort_coord(buf.read_gshort());
                    self.account.lock().unwrap().y = value;
                    changed.push(prop);
                }
                PLPROP_Z2 => {
                    let value = decode_signed_gshort_coord(buf.read_gshort());
                    self.account.lock().unwrap().z = value;
                    changed.push(prop);
                }
                PLPROP_CURLEVEL => {
                    self.account.lock().unwrap().level_name = buf.read_gchar_string();
                }
                PLPROP_SPRITE => {
                    self.account.lock().unwrap().character.sprite = buf.read_gchar();
                    changed.push(prop);
                }
                PLPROP_STATUS => {
                    self.account.lock().unwrap().status = i32::from(buf.read_gchar());
                    changed.push(prop);
                }
                PLPROP_CARRYSPRITE => {
                    self.account.lock().unwrap().carry_sprite = buf.read_byte();
                    changed.push(prop);
                }
                PLPROP_HORSEGIF => {
                    self.account.lock().unwrap().character.horse_image = buf.read_gchar_string();
                    changed.push(prop);
                }
                PLPROP_HORSEBUSHES => {
                    self.account.lock().unwrap().horse_bomb_count = buf.read_gchar();
                }
                PLPROP_EFFECTCOLORS => {
                    if buf.read_gchar() > 0 {
                        let _ = buf.read_gint4();
                    }
                }
                PLPROP_CARRYNPC => {
                    self.account.lock().unwrap().attach_npc = buf.read_gint();
                }
                PLPROP_APCOUNTER => {
                    self.account.lock().unwrap().ap_counter = (buf.read_gshort() & 0xff) as u8;
                }
                PLPROP_MAGICPOINTS => {
                    self.account.lock().unwrap().mp = buf.read_gchar().min(100);
                    changed.push(prop);
                }
                PLPROP_UDPPORT => {
                    self.account.lock().unwrap().udp_port = buf.read_gint() as i32;
                }
                PLPROP_ALIGNMENT => {
                    self.account.lock().unwrap().alignment = i32::from(buf.read_gchar()).min(100);
                    changed.push(prop);
                }
                PLPROP_ADDITFLAGS => {
                    self.account.lock().unwrap().additional_flags = u32::from(buf.read_gchar());
                    changed.push(prop);
                }
                PLPROP_PLANGUAGE => {
                    self.account.lock().unwrap().language = buf.read_gchar_string();
                }
                PLPROP_PSTATUSMSG => {
                    self.account.lock().unwrap().status_msg = buf.read_gchar();
                    changed.push(prop);
                }
                PLPROP_OSTYPE => {
                    self.account.lock().unwrap().os = buf.read_gchar_string();
                }
                PLPROP_TEXTCODEPAGE => {
                    self.account.lock().unwrap().env_code_page = buf.read_gint() as i32;
                }
                PLPROP_GATTRIB1..=PLPROP_GATTRIB5 => {
                    let value = buf.read_gchar_string();
                    self.account.lock().unwrap().g_attribs[(prop - PLPROP_GATTRIB1) as usize] =
                        value;
                    changed.push(prop);
                }
                PLPROP_GATTRIB6..=PLPROP_GATTRIB9 => {
                    let value = buf.read_gchar_string();
                    self.account.lock().unwrap().g_attribs[(prop - PLPROP_GATTRIB6 + 5) as usize] =
                        value;
                    changed.push(prop);
                }
                PLPROP_GATTRIB10..=PLPROP_GATTRIB30 => {
                    let value = buf.read_gchar_string();
                    self.account.lock().unwrap().g_attribs
                        [(prop - PLPROP_GATTRIB10 + 9) as usize] = value;
                    changed.push(prop);
                }
                PLPROP_COMMUNITYNAME => {
                    self.account.lock().unwrap().community_name = buf.read_gchar_string();
                    changed.push(prop);
                }
                PLPROP_UNKNOWN77 | PLPROP_UNKNOWN81 => {
                    let _ = buf.read_gchar();
                }
                PLPROP_ID => {
                    let _ = buf.read_gshort();
                }
                PLPROP_GMAPLEVELX | PLPROP_GMAPLEVELY | PLPROP_JOINLEAVELVL => {
                    let _ = buf.read_gchar();
                }
                PLPROP_PCONNECTED => {}
                _ => break,
            }
        }
        self.forward_player_prop_changes(&changed);
        true
    }

    fn forward_player_prop_changes(&self, props: &[u8]) {
        if props.is_empty() {
            return;
        }
        let Some(server) = self.server() else { return };
        let Some(level) = self.current_level() else {
            return;
        };
        let mut payload = Buffer::new();
        for prop in props {
            payload.write_gchar(*prop).write(&self.get_prop(*prop));
        }
        let mut packet = Buffer::new();
        packet
            .write_byte(PLO_OTHERPLPROPS)
            .write_gshort(self.id())
            .write(&payload.data);
        for id in level.get_players() {
            if id != self.id() {
                if let Some(player) = server.get_player(id) {
                    if player.player_type() & PLTYPE_ANYCLIENT != 0 {
                        player.send(&packet);
                    }
                }
            }
        }
    }

    pub fn msgPLI_PLAYERPROPS(&self, packet: &[u8]) -> bool {
        self.msg_pli_playerprops_exact(packet)
    }
    pub fn msgPLI_NPCPROPS(&self, packet: &[u8]) -> bool {
        self.msg_pli_npcprops(packet)
    }
    pub fn msgPLI_BOMBADD(&self, packet: &[u8]) -> bool {
        self.msg_pli_broadcast(PLO_BOMBADD, packet.get(1..).unwrap_or_default())
    }
    pub fn msgPLI_BOMBDEL(&self, packet: &[u8]) -> bool {
        self.msg_pli_bombdel(packet)
    }
    pub fn msgPLI_TOALL(&self, packet: &[u8]) -> bool {
        self.msg_pli_toall(packet)
    }
    pub fn msgPLI_HORSEADD(&self, packet: &[u8]) -> bool {
        self.msg_pli_horseadd(packet)
    }
    pub fn msgPLI_HORSEDEL(&self, packet: &[u8]) -> bool {
        self.msg_pli_horsedel(packet)
    }
    pub fn msgPLI_ARROWADD(&self, packet: &[u8]) -> bool {
        self.msg_pli_arrowadd(packet)
    }
    pub fn msgPLI_FIRESPY(&self, packet: &[u8]) -> bool {
        self.msg_pli_firespy(packet)
    }
    pub fn msgPLI_THROWCARRIED(&self, packet: &[u8]) -> bool {
        self.msg_pli_throwcarried(packet)
    }
    pub fn msgPLI_ITEMADD(&self, packet: &[u8]) -> bool {
        self.msg_pli_itemadd(packet)
    }
    pub fn msgPLI_ITEMDEL(&self, packet: &[u8]) -> bool {
        self.msg_pli_itemdel(packet)
    }
    pub fn msgPLI_ITEMTAKE(&self, packet: &[u8]) -> bool {
        self.msg_pli_itemdel(packet)
    }
    pub fn msgPLI_CLAIMPKER(&self, packet: &[u8]) -> bool {
        self.msg_pli_claimpker(packet)
    }
    pub fn msgPLI_BADDYPROPS(&self, packet: &[u8]) -> bool {
        self.msg_pli_baddyprops(packet)
    }
    pub fn msgPLI_BADDYHURT(&self, packet: &[u8]) -> bool {
        self.msg_pli_baddyhurt(packet)
    }
    pub fn msgPLI_BADDYADD(&self, packet: &[u8]) -> bool {
        self.msg_pli_baddyadd(packet)
    }
    pub fn msgPLI_FLAGSET(&self, packet: &[u8]) -> bool {
        self.msg_pli_flagset(packet)
    }
    pub fn msgPLI_FLAGDEL(&self, packet: &[u8]) -> bool {
        self.msg_pli_flagdel(packet)
    }
    pub fn msgPLI_OPENCHEST(&self, packet: &[u8]) -> bool {
        self.msg_pli_openchest(packet)
    }
    pub fn msgPLI_PUTNPC(&self, packet: &[u8]) -> bool {
        self.msg_pli_putnpc(packet)
    }
    pub fn msgPLI_NPCDEL(&self, packet: &[u8]) -> bool {
        self.msg_pli_npcdel(packet)
    }
    pub fn msgPLI_WANTFILE(&self, packet: &[u8]) -> bool {
        self.msg_pli_wantfile(packet)
    }
    pub fn msgPLI_SHOWIMG(&self, packet: &[u8]) -> bool {
        self.msg_pli_showimg(packet)
    }
    pub fn msgPLI_HURTPLAYER(&self, packet: &[u8]) -> bool {
        self.msg_pli_hurtplayer(packet)
    }
    pub fn msgPLI_EXPLOSION(&self, packet: &[u8]) -> bool {
        self.msg_pli_explosion(packet)
    }
    pub fn msgPLI_PRIVATEMESSAGE(&self, packet: &[u8]) -> bool {
        self.msg_pli_privatemessage(packet)
    }
    pub fn msgPLI_NPCWEAPONDEL(&self, packet: &[u8]) -> bool {
        self.msg_pli_npcweapondel(packet)
    }
    pub fn msgPLI_WEAPONADD(&self, packet: &[u8]) -> bool {
        self.msg_pli_weaponadd(packet)
    }
    pub fn msgPLI_UPDATEFILE(&self, packet: &[u8]) -> bool {
        self.msg_pli_updatefile(packet)
    }
    pub fn msgPLI_REQUESTTEXT(&self, packet: &[u8]) -> bool {
        self.msg_pli_requesttext(packet)
    }
    pub fn msgPLI_SENDTEXT(&self, packet: &[u8]) -> bool {
        self.msg_pli_sendtext(packet)
    }
    pub fn msgPLI_UPDATEGANI(&self, packet: &[u8]) -> bool {
        self.msg_pli_updategani(packet)
    }
    pub fn msgPLI_UPDATESCRIPT(&self, packet: &[u8]) -> bool {
        self.msg_pli_updatescript(packet)
    }
    pub fn msgPLI_UPDATEPACKAGEREQUESTFILE(&self, packet: &[u8]) -> bool {
        self.msg_pli_updatepackage_request_file(packet)
    }
    pub fn msgPLI_HITOBJECTS(&self, packet: &[u8]) -> bool {
        self.msg_pli_hitobjects(packet)
    }
    pub fn msgPLI_LANGUAGE(&self, packet: &[u8]) -> bool {
        self.msg_pli_language(packet)
    }
    pub fn msgPLI_TRIGGERACTION(&self, packet: &[u8]) -> bool {
        self.msg_pli_triggeraction(packet)
    }
    pub fn msgPLI_ADJACENTLEVEL(&self, packet: &[u8]) -> bool {
        self.msg_pli_adjacentlevel(packet)
    }
    pub fn msgPLI_SHOOT(&self, packet: &[u8]) -> bool {
        self.msg_pli_shoot(packet)
    }
    pub fn msgPLI_SHOOT2(&self, packet: &[u8]) -> bool {
        self.msg_pli_shoot2(packet)
    }
    pub fn msgPLI_VERIFYWANTSEND(&self, packet: &[u8]) -> bool {
        self.msg_pli_verifywantsend(packet)
    }
    pub fn msgPLI_UPDATECLASS(&self, packet: &[u8]) -> bool {
        self.msg_pli_updateclass(packet)
    }
    pub fn new(conn: Option<TcpStream>, server: &Arc<Server>) -> Self {
        let replay = conn.map(|stream| ReplayStream::new(stream, Vec::new()));
        Self::with_replay(replay, server)
    }
    pub fn NewPlayer(conn: Option<TcpStream>, server: &Arc<Server>) -> Arc<Self> {
        Self::new_arc(
            conn.map(|stream| ReplayStream::new(stream, Vec::new())),
            server,
        )
    }
    pub fn from_stream(stream: ReplayStream, server: &Arc<Server>) -> Arc<Self> {
        Self::new_arc(Some(stream), server)
    }
    fn new_arc(conn: Option<ReplayStream>, server: &Arc<Server>) -> Arc<Self> {
        Arc::new_cyclic(|weak| {
            let mut player = Self::with_replay(conn, server);
            *player.self_ref.lock().unwrap() = weak.clone();
            player
        })
    }
    fn with_replay(conn: Option<ReplayStream>, server: &Arc<Server>) -> Self {
        let mut account = Account::new();
        account.set_server(server);
        // These are the same pre-login defaults established by NewPlayer in
        // the reference server.  They are deliberately distinct from the
        // persistent-account defaults loaded during login.
        account.x = 60;
        account.y = 61;
        account.carry_sprite = 0xff;
        account.alignment = 50;
        Self {
            account: Mutex::new(account),
            state: Mutex::new(PlayerState {
                conn,
                async_write: false,
                websocket: false,
                websocket_candidate: false,
                websocket_buffer: Vec::new(),
                websocket_fragment: Vec::new(),
                websocket_fragmented: false,
                recv_buffer: Vec::with_capacity(8192),
                read_scratch: vec![0; 0x8000],
                encryption: Encryption::new(),
                out_encryption: Encryption::new(),
                queue_outgoing: false,
                out_queue: Vec::new(),
                wire_queue: Vec::new(),
                version: String::new(),
                server_name: String::new(),
                id: 0,
                player_type: PLTYPE_AWAIT,
                version_id: 0,
                map_ref: None,
                current_level: None,
                external_players: HashMap::new(),
                loaded: false,
                disconnected: false,
                defer_client_login: false,
                login_pending: false,
                next_is_raw: false,
                raw_packet_size: 0,
                is_ftp: false,
                last_folder: String::new(),
                rc_large_files: HashMap::new(),
                last_rc_download_notice: Instant::now() - Duration::from_secs(3600),
                last_rc_download_notice_file: String::new(),
                nc_post_login_sent: false,
                gr_movement_updated: false,
                awaiting_listserver_verify: false,
                first_level: true,
                gr_movement_packets: Vec::new(),
                npcserver_port: String::new(),
                packet_count: 0,
                invalid_packets: 0,
                guild: String::new(),
                level_group: String::new(),
                gr_exec_parameter_list: String::new(),
                last_data: Instant::now(),
                // The reference constructor initializes movement/save/one-
                // minute timestamps to time.Now(); only the remaining
                // zero-value timestamps are already expired.
                last_movement: Instant::now(),
                last_chat: Instant::now() - Duration::from_secs(3600),
                last_nick: Instant::now() - Duration::from_secs(3600),
                last_message: Instant::now() - Duration::from_secs(3600),
                last_save: Instant::now(),
                last_one_minute: Instant::now(),
                last_serverside_trigger: Instant::now() - Duration::from_secs(3600),
                last_serverside_trigger_action: String::new(),
            }),
            server: Arc::downgrade(server),
            self_ref: Mutex::new(Weak::new()),
        }
    }
    pub fn server(&self) -> Option<Arc<Server>> {
        self.server.upgrade()
    }
    fn self_arc(&self) -> Option<Arc<Player>> {
        self.self_ref.lock().unwrap().upgrade()
    }
    pub fn account(&self) -> std::sync::MutexGuard<'_, Account> {
        self.account.lock().unwrap()
    }
    pub fn id(&self) -> u16 {
        self.state.lock().unwrap().id
    }
    pub fn get_id(&self) -> u16 {
        self.id()
    }
    pub fn getId(&self) -> u16 {
        self.id()
    }
    pub fn set_id(&self, id: u16) {
        self.state.lock().unwrap().id = id;
    }
    pub fn setId(&self, id: u16) {
        self.set_id(id)
    }
    pub fn player_type(&self) -> i32 {
        self.state.lock().unwrap().player_type
    }
    pub fn get_type(&self) -> i32 {
        self.player_type()
    }
    pub fn getType(&self) -> i32 {
        self.player_type()
    }
    pub fn set_player_type(&self, value: i32) {
        self.state.lock().unwrap().player_type = value;
    }
    pub fn version(&self) -> String {
        self.state.lock().unwrap().version.clone()
    }
    pub fn version_id(&self) -> i32 {
        self.state.lock().unwrap().version_id
    }
    pub fn set_version(&self, value: &str) {
        let mut state = self.state.lock().unwrap();
        state.version = value.to_string();
        state.version_id = client_version_id(value);
    }
    pub fn set_async_write(&self, value: bool) {
        self.state.lock().unwrap().async_write = value;
    }
    pub fn set_websocket(&self, value: bool) {
        self.state.lock().unwrap().websocket = value;
    }
    pub fn web_socket_active(&self) -> bool {
        self.state.lock().unwrap().websocket
    }
    pub fn webSocketActive(&self) -> bool {
        self.web_socket_active()
    }
    pub fn account_name(&self) -> String {
        self.account.lock().unwrap().account_name.clone()
    }
    pub fn translate(&self, key: &str) -> String {
        self.server()
            .map(|server| {
                let language = self.account.lock().unwrap().language.clone();
                server.translate(&language, key)
            })
            .unwrap_or_else(|| key.to_string())
    }
    pub fn get_account_name(&self) -> String {
        self.account_name()
    }
    pub fn set_account_name(&self, value: &str) {
        self.account.lock().unwrap().account_name = value.to_string();
    }
    pub fn nickname(&self) -> String {
        self.account.lock().unwrap().character.nickname.clone()
    }
    pub fn guild(&self) -> String {
        self.state.lock().unwrap().guild.clone()
    }
    pub fn set_guild(&self, value: &str) {
        self.state.lock().unwrap().guild = value.to_string();
    }
    pub fn level_group(&self) -> String {
        self.state.lock().unwrap().level_group.clone()
    }
    pub fn set_level_group(&self, value: &str) {
        self.state.lock().unwrap().level_group = value.to_string();
    }
    pub fn setGroup(&self, value: &str) {
        self.set_level_group(value)
    }
    pub fn getGroup(&self) -> String {
        self.level_group()
    }
    pub fn getGuild(&self) -> String {
        self.guild()
    }
    pub fn setGuild(&self, value: &str) {
        self.set_guild(value)
    }
    fn add_pm_server(&self, server_name: &str) {
        let name = server_name.trim();
        if name.is_empty() {
            return;
        }
        let mut account = self.account.lock().unwrap();
        if !account
            .private_message_server_list
            .iter()
            .any(|value| value.eq_ignore_ascii_case(name))
        {
            account.private_message_server_list.push(name.to_string());
        }
    }
    fn remove_pm_server(&self, server_name: &str) {
        let name = server_name.trim();
        self.account
            .lock()
            .unwrap()
            .private_message_server_list
            .retain(|value| !value.eq_ignore_ascii_case(name));
    }
    pub fn set_nickname(&self, value: &str) {
        let mut account = self.account.lock().unwrap();
        account.character.nickname = value.chars().take(223).collect();
        if account
            .character
            .nickname
            .trim()
            .eq_ignore_ascii_case(account.account_name.trim())
        {
            account.character.nickname = format!("*{}", account.account_name.trim());
        }
        let guild = parse_nickname_guild(&account.character.nickname);
        drop(account);
        self.set_guild(&guild);
    }
    pub fn set_guild_nickname(&self, guild: &str) {
        let guild = guild.trim();
        let mut base = self
            .nickname()
            .split('(')
            .next()
            .map(str::trim)
            .unwrap_or_default()
            .to_string();
        if base.is_empty() {
            base = self.account_name();
        }
        if guild.is_empty() {
            self.set_nickname(&base);
        } else {
            self.set_nickname(&format!("{base} ({guild})"));
        }
    }
    pub fn setGuildNickname(&self, guild: &str) {
        self.set_guild_nickname(guild)
    }
    pub fn current_level(&self) -> Option<Arc<Level>> {
        self.state.lock().unwrap().current_level.clone()
    }
    pub fn level_name(&self) -> String {
        self.account.lock().unwrap().level_name.clone()
    }
    pub fn position(&self) -> (i16, i16) {
        let account = self.account.lock().unwrap();
        (account.x, account.y)
    }
    pub fn set_current_level(&self, level: Option<Arc<Level>>) {
        self.state.lock().unwrap().current_level = level;
    }
    pub fn out_queue(&self) -> Vec<u8> {
        self.state.lock().unwrap().out_queue.clone()
    }
    pub fn wire_queue(&self) -> Vec<u8> {
        self.state.lock().unwrap().wire_queue.clone()
    }
    pub fn set_queue_outgoing(&self, value: bool) {
        self.state.lock().unwrap().queue_outgoing = value;
    }
    pub fn set_encryption_gen(&self, gen: u32) {
        let mut state = self.state.lock().unwrap();
        state.encryption.set_gen(gen);
        state.out_encryption.set_gen(gen);
    }
    pub fn encryption_gen(&self) -> u32 {
        self.state.lock().unwrap().encryption.get_gen()
    }
    pub fn set_connection(&self, stream: TcpStream) {
        self.state.lock().unwrap().conn = Some(ReplayStream::new(stream, Vec::new()));
    }

    pub fn has_connection(&self) -> bool {
        self.state.lock().unwrap().conn.is_some()
    }

    fn has_output_or_connection(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.conn.is_some()
            || state.queue_outgoing
            || !state.out_queue.is_empty()
            || !state.wire_queue.is_empty()
    }

    pub fn is_logged_in(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.player_type != PLTYPE_AWAIT && state.id > 0 && !state.login_pending
    }
    pub fn isLoggedIn(&self) -> bool {
        self.is_logged_in()
    }
    pub fn should_save_player_account(&self) -> bool {
        self.is_logged_in() && self.player_type() & PLTYPE_ANYCLIENT != 0
    }
    pub fn SaveAccount(&self) -> bool {
        self.account.lock().unwrap().save_account()
    }
    pub fn save_account(&self) -> bool {
        self.SaveAccount()
    }

    pub fn append_incoming_bytes(&self, data: &[u8]) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.websocket
            || state.websocket_candidate
            || (state.recv_buffer.is_empty()
                && state.websocket_buffer.is_empty()
                && is_websocket_request_prefix(data))
        {
            if !state.websocket {
                state.websocket_candidate = true;
            }
            state.websocket_buffer.extend_from_slice(data);
            if !state.websocket {
                match websocket_handshake_locked(&mut state, &self.server) {
                    Ok(Some(true)) => {}
                    Ok(Some(false)) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid WebSocket handshake",
                        ))
                    }
                    Ok(None) => return Ok(()),
                    Err(error) => return Err(error),
                }
            }
            consume_websocket_frames_locked(&mut state)
        } else {
            state.recv_buffer.extend_from_slice(data);
            Ok(())
        }
    }
    pub fn appendIncomingBytes(&self, data: &[u8]) -> io::Result<()> {
        self.append_incoming_bytes(data)
    }

    pub fn on_recv(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.disconnected || state.conn.is_none() {
            return false;
        }
        let mut conn = state.conn.take().unwrap();
        let _ = conn.set_read_timeout(Some(Duration::from_millis(2)));
        let mut scratch = std::mem::take(&mut state.read_scratch);
        if scratch.is_empty() {
            scratch.resize(0x8000, 0);
        }
        let result = conn.read(&mut scratch);
        state.conn = Some(conn);
        state.read_scratch = scratch;
        match result {
            Ok(count) if count > 0 => {
                state.last_data = Instant::now();
                let data = state.read_scratch[..count].to_vec();
                drop(state);
                if self.append_incoming_bytes(&data).is_err() {
                    self.disconnect();
                    return false;
                }
                let websocket_candidate = {
                    let state = self.state.lock().unwrap();
                    state.websocket_candidate && !state.websocket
                };
                if websocket_candidate {
                    return true;
                }
                self.process_packets();
                true
            }
            Ok(0) => {
                drop(state);
                self.disconnect();
                false
            }
            Ok(_) => {
                drop(state);
                self.process_packets();
                true
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                drop(state);
                self.process_packets();
                true
            }
            Err(_) => {
                drop(state);
                self.disconnect();
                false
            }
        }
    }
    pub fn OnRecv(&self) -> bool {
        self.on_recv()
    }
    pub fn can_recv(&self) -> bool {
        // SocketStub.CanRecv is unconditional in the reference server; the
        // receive callback itself reports a closed/disconnected stream.
        true
    }
    pub fn CanRecv(&self) -> bool {
        self.can_recv()
    }
    pub fn can_send(&self) -> bool {
        let state = self.state.lock().unwrap();
        !state.queue_outgoing && (!state.out_queue.is_empty() || !state.wire_queue.is_empty())
    }
    pub fn CanSend(&self) -> bool {
        self.can_send()
    }
    pub fn on_register(&self) -> bool {
        true
    }
    pub fn OnRegister(&self) -> bool {
        true
    }
    pub fn on_unregister(&self) {
        self.disconnect();
    }
    pub fn OnUnregister(&self) {
        self.on_unregister()
    }

    pub fn process_packets(&self) {
        loop {
            let packet = {
                let mut state = self.state.lock().unwrap();
                if state.login_pending || state.recv_buffer.len() < 2 {
                    break;
                }
                let length =
                    (usize::from(state.recv_buffer[0]) << 8) | usize::from(state.recv_buffer[1]);
                if state.recv_buffer.len() < length + 2 {
                    break;
                }
                state.recv_buffer.drain(..2);
                state.recv_buffer.drain(..length).collect::<Vec<_>>()
            };
            if self.player_type() == PLTYPE_AWAIT {
                let deferred = self
                    .server()
                    .map(|server| server.is_running())
                    .unwrap_or(false);
                self.state.lock().unwrap().defer_client_login = deferred;
                if !self.handle_login(&packet) {
                    self.state.lock().unwrap().defer_client_login = false;
                    self.disconnect();
                    break;
                }
                // Keep the deferred decision only in the local value used
                // after handleLogin returns.
                self.state.lock().unwrap().defer_client_login = false;
                let id = self.id();
                // Scope the self_ref guard to this statement. Keeping it alive
                // for the if-let body would self-deadlock when the body
                // re-locks self_ref below (std::sync::Mutex is not
                // reentrant), freezing the polling thread and with it the
                // whole server on every client login.
                let upgraded = self.self_ref.lock().unwrap().upgrade();
                if let (Some(server), Some(player)) = (self.server(), upgraded) {
                    let added = server.add_player(player, id);
                    if !added {
                        continue;
                    }
                    let player = self.self_ref.lock().unwrap().upgrade();
                    if self.player_type() & PLTYPE_ANYCLIENT != 0 {
                        if deferred {
                            self.state.lock().unwrap().login_pending = true;
                            if let Some(player) = self.self_arc() {
                                thread::spawn(move || player.finish_deferred_client_login());
                            } else {
                                self.finish_deferred_client_login();
                            }
                        } else {
                            self.send_post_login_tail();
                            server.run_server_side_event_for_active_scripts(
                                "onPlayerLogin",
                                self.self_arc().as_ref(),
                                &[],
                            );
                        }
                    } else if self.player_type() & PLTYPE_ANYRC != 0 {
                        self.send_rc_post_login_tail();
                    } else if self.player_type() & PLTYPE_ANYNC != 0 {
                        self.send_nc_post_login_tail();
                    } else if self.player_type() & PLTYPE_NPCSERVER != 0 {
                        if let Some(player) = player {
                            server
                                .npc_server
                                .apply_player_display_identity(&player, &server);
                            server.refresh_player_list_entry(&player);
                            server.npc_server.send_address_to_rcs(&server);
                        }
                    }
                }
            } else {
                self.handle_raw_data(&packet);
            }
        }
        self.flush_gr_movement_packets();
    }

    fn handle_login(&self, packet: &[u8]) -> bool {
        let data = match zlib_decompress(packet) {
            Ok(value) => value,
            Err(_) => return false,
        };
        if data.len() < 10 {
            return false;
        }
        let mut buf = Buffer::from_bytes(&data);
        let client_type_byte = buf.read_gchar();
        let client_type = 1i32.checked_shl(u32::from(client_type_byte)).unwrap_or(0);
        if client_type == 0 {
            return false;
        }
        let encryption_key = if client_type == PLTYPE_CLIENT2
            || client_type == PLTYPE_CLIENT3
            || client_type == PLTYPE_RC2
        {
            buf.read_gchar()
        } else {
            0
        };
        if buf.remaining() < 8 {
            return false;
        }
        let version_bytes = buf.read_bytes(8);
        let version = String::from_utf8_lossy(&version_bytes).into_owned();
        if buf.remaining() < 1 {
            return false;
        }
        let account_length = usize::from(buf.read_gchar());
        if buf.remaining() < account_length {
            return false;
        }
        let account = String::from_utf8_lossy(&buf.read_bytes(account_length)).into_owned();
        if buf.remaining() < 1 {
            return false;
        }
        let password_length = usize::from(buf.read_gchar());
        if buf.remaining() < password_length {
            return false;
        }
        let password = String::from_utf8_lossy(&buf.read_bytes(password_length)).into_owned();
        let identity = buf.read_string();
        let direct_nc =
            client_type & PLTYPE_ANYNC != 0 && version.to_ascii_uppercase().starts_with("NCL");
        let external_npc = self
            .server()
            .map(|server| client_type == PLTYPE_NPCSERVER && server.npc_server_mode() == "external")
            .unwrap_or(false);
        if external_npc && buf.remaining() >= 2 {
            let port = buf.read_short();
            if port > 0 {
                self.state.lock().unwrap().npcserver_port = port.to_string();
            }
        }
        let account = if external_npc {
            external_npc_account_name(&account)
        } else {
            account
        };
        {
            let mut state = self.state.lock().unwrap();
            state.player_type = client_type;
            state.version = version.clone();
            state.version_id = client_version_id(&version);
            state.id = self
                .server()
                .map(|server| server.next_player_id())
                .unwrap_or(2);
            state.encryption.gen = match client_type {
                PLTYPE_CLIENT => ENCRYPT_GEN_2,
                PLTYPE_CLIENT2 => ENCRYPT_GEN_4,
                PLTYPE_CLIENT3 | PLTYPE_RC2 => ENCRYPT_GEN_5,
                _ => ENCRYPT_GEN_3,
            };
            let generation = state.encryption.gen;
            state.encryption.reset(encryption_key);
            state.out_encryption.set_gen(generation);
            state.out_encryption.reset(encryption_key);
            state.queue_outgoing = true;
            state.out_queue.clear();
        }
        {
            let mut acc = self.account.lock().unwrap();
            acc.character = Character::default();
            acc.account_name = account.clone();
            acc.character.nickname = account.clone();
            acc.level_name = "empty".to_string();
            acc.x = 512;
            acc.y = 512;
            acc.character.gani = "idle.gif".to_string();
            acc.community_name = "default".to_string();
            acc.language = "english".to_string();
            acc.max_hitpoints = 3;
            acc.character.hitpoints = 3;
            acc.os = "wind".to_string();
            acc.env_code_page = 1252;
            acc.device_id = if account.eq_ignore_ascii_case("guest") {
                login_pc_id(&identity).unwrap_or(0)
            } else {
                0
            };
            acc.account_ip = 0;
            acc.account_ip_str = "0".to_string();
            acc.is_banned = false;
            acc.is_guest = false;
            acc.is_external = external_npc;
            acc.is_load_only = false;
            acc.is_staff = false;
            acc.admin_rights = 0;
            acc.max_hitpoints = 3;
            acc.character.gralats = 0;
            acc.character.arrows = 0;
            acc.character.bombs = 0;
            acc.character.glove_power = 0;
            acc.character.shield_power = 0;
            acc.character.sword_power = 0;
            acc.character.bow_power = 0;
            acc.character.sprite = 0;
            acc.status = 0;
            acc.mp = 0;
            acc.ap_counter = 0;
            acc.kills = 0;
            acc.deaths = 0;
            acc.elo_rating = 1500.0;
            acc.elo_deviation = 350.0;
            acc.rupees = 50;
            acc.status_msg = 0;
            acc.online_time = 0;
            acc.g_attribs = std::array::from_fn(|_| String::new());
            acc.flag_list.clear();
            acc.weapon_list.clear();
            acc.chest_list.clear();
            acc.folder_list.clear();
        }
        let awaiting = if external_npc || direct_nc {
            false
        } else {
            self.server()
                .map(|server| server.send_login_packet_to_listservers(self, &password, &identity))
                .unwrap_or(false)
        };
        self.state.lock().unwrap().awaiting_listserver_verify = awaiting;

        // Initial client packets are queued before account loading.
        let signature = {
            let mut value = Buffer::new();
            value.write_byte(PLO_SIGNATURE).write_byte(73);
            value
        };
        self.send(&signature);
        if let Some(server) = self.server() {
            if server.should_use_login_server_mode() {
                self.send_plo_fullstop();
                let mut ghost = Buffer::new();
                ghost.write_byte(PLO_GHOSTICON).write_byte(1);
                self.send(&ghost);
            }
        }
        if client_type & PLTYPE_ANYCLIENT != 0 {
            if self
                .server()
                .map(|server| server.npc_server_available())
                .unwrap_or(false)
            {
                self.send_plo_hasnpcserver();
            }
            self.send_plo_unknown168();
        }

        if external_npc {
            let mut acc = self.account.lock().unwrap();
            acc.is_staff = true;
            acc.admin_rights = all_local_rights();
            acc.admin_ip = "*.*.*.*".to_string();
            acc.is_load_only = true;
            acc.folder_list = self
                .server()
                .map(|server| server.default_rc_folder_rights())
                .unwrap_or_default();
            drop(acc);
            if let Some(server) = self.server() {
                server
                    .npc_server
                    .apply_player_display_identity(self, &server);
                self.state.lock().unwrap().loaded = true;
            }
        } else if !self.account.lock().unwrap().load_account(&account, true) {
            return false;
        }
        self.normalize_nickname();
        self.apply_server_options_staff_rights();
        self.set_account_ip_from_remote();
        let remote_ip = self
            .state
            .lock()
            .unwrap()
            .conn
            .as_ref()
            .and_then(|conn| conn.peer_addr().ok())
            .map(|address| address.ip().to_string())
            .unwrap_or_default();
        if let Some(server) = self.server() {
            if server.is_ip_banned(&remote_ip) && !self.has_right(PLPERM_MODIFYSTAFFACCOUNT) {
                self.send_plo_discmessage("You have been banned from this server.");
                self.send_compress(true);
                return false;
            }
        }
        if client_type & PLTYPE_ANYCONTROL != 0 && !self.can_login_control() {
            self.send_plo_discmessage(
                "You do not have RC/NC rights or your IP range does not match.",
            );
            self.send_compress(true);
            return false;
        }
        if client_type & PLTYPE_ANYRC != 0 {
            {
                let mut acc = self.account.lock().unwrap();
                acc.level_name.clear();
                acc.x = 0;
                acc.y = 0;
                acc.z = 0;
            }
            self.state.lock().unwrap().current_level = None;
            self.send_rc_login_payload();
            self.send_compress(true);
            self.state.lock().unwrap().loaded = true;
            return true;
        }
        if client_type & PLTYPE_ANYNC != 0 {
            self.send_compress(true);
            self.state.lock().unwrap().loaded = true;
            return true;
        }
        let deferred = self.state.lock().unwrap().defer_client_login;
        if !deferred {
            self.finish_client_login();
            self.state.lock().unwrap().loaded = true;
        } else {
            return true;
        }
        true
    }

    pub fn send_rc_login_payload(&self) {
        let max_upload = self
            .server()
            .map(|server| {
                server
                    .settings
                    .get_int("maxuploadfilesize", 20 * 1024 * 1024)
            })
            .unwrap_or(20 * 1024 * 1024);
        let mut packet = Buffer::new();
        packet
            .write_byte(PLO_RC_MAXUPLOADFILESIZE)
            .write_gint5(max_upload as u64);
        self.send(&packet);
        let server_name = self
            .server()
            .map(|server| server.configured_name())
            .unwrap_or_else(|| "GServer".to_string());
        self.send_plo_rc_chat(&format!(
            "Welcome to the GServer for {server_name}, type /help for a list of available commands"
        ));
    }
    pub fn sendRCLoginPayload(&self) {
        self.send_rc_login_payload()
    }

    fn can_login_control_locked(&self, account: &Account) -> bool {
        let Some(server) = self.server() else {
            return false;
        };
        server_options_staff_contains(&server.settings.get("staff"), &account.account_name)
            && (account.admin_ip == "0.0.0.0"
                || account.admin_ip == "*.*.*.*"
                || account.admin_rights != 0)
    }
    fn finish_client_login(&self) {
        self.send_props(&send_login_props());
        self.send_plo_clearweapons();
        let account = self.account.lock().unwrap();
        for (key, value) in [
            ("head", account.character.head_image.clone()),
            ("body", account.character.body_image.clone()),
            ("sword", account.character.sword_image.clone()),
            ("shield", account.character.shield_image.clone()),
        ] {
            self.send_plo_flagset(key, &value);
        }
        for (index, value) in account.character.colors.iter().enumerate() {
            self.send_plo_flagset(&format!("color{}", index + 1), &value.to_string());
        }
        self.send_plo_flagset("sprite", &account.character.sprite.to_string());
        drop(account);
        if let Some(server) = self.server() {
            for (name, value) in server.flags.read().unwrap().clone() {
                if is_valid_server_flag(&name, &value) {
                    self.send_plo_flagset(&name, &value);
                }
            }
        }
        self.send_missing_default_weapon_deletes();
        let weapons = self.account.lock().unwrap().weapon_list.clone();
        for weapon in weapons {
            self.send_account_weapon(&weapon);
        }
        self.send_plo_unknown190();
        let (level, x, y) = self.login_warp_target();
        self.warp(&level, x, y, 0);
        if let Some(server) = self.server() {
            if !server.settings.get("bigmap").is_empty() {
                self.send_plo_bigmap();
            }
            if !server.settings.get("minimap").is_empty() {
                self.send_plo_minimap();
            }
            self.send_plo_rpgwindow(&format!(
                "\"Welcome to {}.\",\"Go Code GServer.\"",
                server.name.read().unwrap()
            ));
            self.send_plo_startmessage(&server.server_message.read().unwrap());
        }
        self.send_plo_servertext("");
        self.send_compress(true);
        if let Some(server) = self.server() {
            let args = vec![self.account_name(), self.player_type().to_string()];
            server.run_server_side_event_for_active_scripts(
                "onServerLogin",
                self.self_arc().as_ref(),
                &args,
            );
        }
    }
    fn handle_raw_data(&self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let decoded = {
            let mut state = self.state.lock().unwrap();
            let mut value = data.to_vec();
            if state.encryption.gen == ENCRYPT_GEN_4 {
                state.encryption.limit = 4;
                state.encryption.decrypt(&mut value);
                match crate::network::bz2_decompress(&value) {
                    Ok(value) => value,
                    Err(_) => return,
                }
            } else if state.encryption.gen >= ENCRYPT_GEN_5 {
                if value.is_empty() {
                    return;
                }
                let compression = value[0];
                value.remove(0);
                state.encryption.limit_from_type(compression);
                state.encryption.decrypt(&mut value);
                match compression {
                    COMPRESS_ZLIB => match zlib_decompress_with_fallback(&value) {
                        Ok((value, used_deflate)) => {
                            if used_deflate {
                                state.encryption.rollback_iterator();
                            }
                            value
                        }
                        Err(_) => return,
                    },
                    COMPRESS_BZ2 => match crate::network::bz2_decompress(&value) {
                        Ok(value) => value,
                        Err(_) => return,
                    },
                    COMPRESS_UNCOMPRESSED => value,
                    _ => return,
                }
            } else {
                if matches!(state.encryption.gen, ENCRYPT_GEN_2 | ENCRYPT_GEN_3) {
                    match zlib_decompress(&value) {
                        Ok(value) => value,
                        Err(_) => return,
                    }
                } else {
                    value
                }
            }
        };
        self.handle_decompressed_packets(&decoded);
    }
    fn handle_decompressed_packets(&self, data: &[u8]) {
        let mut remaining = data;
        while !remaining.is_empty() {
            let packet_id = Buffer::from_bytes(&remaining[..1]).read_gchar();
            if packet_id == PLI_RC_FILEBROWSER_UP {
                let packet = remaining.strip_suffix(b"\n").unwrap_or(remaining);
                if !packet.is_empty() {
                    let _ = self.handle_packet(packet);
                }
                return;
            }
            let Some(newline) = remaining.iter().position(|byte| *byte == b'\n') else {
                let _ = self.handle_packet(remaining);
                return;
            };
            let packet = &remaining[..newline];
            remaining = &remaining[newline + 1..];
            if !packet.is_empty() {
                let _ = self.handle_packet(packet);
            }
        }
    }

    fn msg_pli_rc_chat(&self, packet: &[u8]) -> bool {
        if packet.len() <= 1 || self.player_type() & PLTYPE_ANYNC != 0 {
            return true;
        }
        if self.player_type() & PLTYPE_ANYCLIENT != 0 && !self.can_login_control() {
            return true;
        }
        let message = String::from_utf8_lossy(&packet[1..]).trim().to_string();
        if message.is_empty() {
            return true;
        }
        if message.starts_with('/') {
            return self.handle_rc_command(&message);
        }
        let chat = format!("{}: {message}", self.rc_chat_name());
        if let Some(server) = self.server() {
            server.run_server_side_event_for_active_scripts(
                "onAllRCChat",
                self.self_arc().as_ref(),
                &[chat.clone()],
            );
            server.send_rc_chat(&chat);
        }
        true
    }

    fn handle_rc_command(&self, message: &str) -> bool {
        let mut words = message.split_whitespace();
        let Some(command) = words.next() else {
            return true;
        };
        let command_lower = command.to_ascii_lowercase();
        let rest = message[command.len()..].trim();
        match command_lower.as_str() {
            "/help" if rest.is_empty() => {
                if let Some(server) = self.server() {
                    if let Ok(data) = server.config.load_file("config/rchelp.txt") {
                        for line in String::from_utf8_lossy(&data).lines() {
                            if !line.is_empty() {
                                self.send_plo_rc_chat(line.trim_end_matches('\r'));
                            }
                        }
                    } else {
                        self.send_plo_rc_chat("No RC help is available.");
                    }
                }
            }
            "/global" => self.handle_rc_global(rest),
            "/rps" => self.handle_rc_rps(words.collect()),
            "/roll" => self.handle_rc_roll(words.collect()),
            "/scripthelp" => {
                self.handle_rc_script_help(rest);
            }
            "/scriptscan" => {
                self.handle_rc_script_scan(rest);
            }
            "/npc" => {
                if let (Some(server), Some(player)) = (self.server(), self.self_arc()) {
                    server.run_rc_npc_chat(&player, rest);
                }
            }
            "/open" | "/openacc" | "/opencomments" | "/openban" | "/openrights" => {
                let account = if rest.is_empty() {
                    self.account_name()
                } else {
                    rest.to_string()
                };
                if account.is_empty() {
                    return true;
                }
                let mut packet = Buffer::new();
                packet.write_byte(match command_lower.as_str() {
                    "/open" => PLI_RC_PLAYERPROPSGET3,
                    "/openacc" => PLI_RC_ACCOUNTGET,
                    "/opencomments" => PLI_RC_PLAYERCOMMENTSGET,
                    "/openban" => PLI_RC_PLAYERBANGET,
                    _ => PLI_RC_PLAYERRIGHTSGET,
                });
                packet.write_string8_encoded(&account);
                match command_lower.as_str() {
                    "/open" => {
                        self.msg_pli_rc_player_props_get3(&packet.data);
                    }
                    "/openacc" => {
                        self.msg_pli_rc_account_get(&packet.data);
                    }
                    "/opencomments" => {
                        self.msg_pli_rc_player_comments_get(&packet.data);
                    }
                    "/openban" => {
                        self.msg_pli_rc_player_ban_get(&packet.data);
                    }
                    _ => {
                        self.msg_pli_rc_player_rights_get(&packet.data);
                    }
                }
            }
            "/openaccess" => {
                if !rest.is_empty() {
                    if let Some(server) = self.server() {
                        if let Some(target) = server.get_player_by_account(rest, PLTYPE_ANYPLAYER) {
                            let device_id = target.account.lock().unwrap().device_id;
                            self.send_plo_servertext(&format!(
                                "{IRC_BYTES},lister,ban,{},{}",
                                target.account_name(),
                                device_id
                            ));
                        }
                    }
                }
            }
            "/reset" => {
                let account = if rest.is_empty() {
                    self.account_name()
                } else {
                    rest.to_string()
                };
                let mut packet = Buffer::new();
                packet
                    .write_byte(PLI_RC_PLAYERPROPSRESET)
                    .write_string8_encoded(&account);
                self.msg_pli_rc_player_props_reset(&packet.data);
            }
            "/npcshutdown" => {
                if self.require_npc_control_command("/npcshutdown") {
                    if let Some(server) = self.server() {
                        match server.save_put_npcs() {
                            Ok(count) => {
                                server.npc_server.shutdown();
                                server.send_rc_chat(&format!(
                                    "{} shut down the NPC-Server. Saved {} map NPC(s).",
                                    self.account_name(),
                                    count
                                ));
                            }
                            Err(error) => {
                                self.send_plo_rc_chat(&format!(
                                    "Server: Failed to save map NPCs: {error}"
                                ));
                            }
                        }
                    }
                }
            }
            "/savenpcs" => {
                if self.require_npc_control_command("/savenpcs") {
                    if let Some(server) = self.server() {
                        match server.save_put_npcs() {
                            Ok(count) => server.send_rc_chat(&format!(
                                "{} saved {} map NPC(s).",
                                self.account_name(),
                                count
                            )),
                            Err(error) => {
                                self.send_plo_rc_chat(&format!(
                                    "Server: Failed to save map NPCs: {error}"
                                ));
                            }
                        }
                    }
                }
            }
            "/npckill" => {
                if self.require_npc_control_command("/npckill") {
                    if let Some(server) = self.server() {
                        server.npc_server.kill();
                        server.send_rc_chat(&format!(
                            "{} killed the NPC-Server.",
                            self.account_name()
                        ));
                    }
                }
            }
            "/npcstart" => {
                if self.require_npc_control_command("/npcstart") {
                    if let Some(server) = self.server() {
                        server.settings.set("serverside", "true");
                        if server.npc_server_mode() != "embedded" {
                            server.send_rc_chat("NPC-Server is configured for external mode.");
                        } else {
                            server.npc_server.start();
                            server.npc_server.start_watching();
                            server.send_rc_chat(&format!(
                                "{} started the NPC-Server.",
                                self.account_name()
                            ));
                        }
                    }
                }
            }
            "/shutdown" | "/restart" => {
                if self.has_right(all_local_rights()) && self.admin_ip_matches_current_remote() {
                    if let Some(server) = self.server() {
                        let action = if command_lower == "/shutdown" {
                            "shut down"
                        } else {
                            "restarted"
                        };
                        server.send_rc_chat(&format!(
                            "{} {} the server.",
                            self.account_name(),
                            action
                        ));
                        if command_lower == "/restart" {
                            server.restart_requested.store(true, Ordering::Relaxed);
                        }
                        server.stop_soon(command_lower == "/restart");
                    }
                } else {
                    self.send_plo_rc_chat(&format!(
                        "Server: You are not authorized to use {command_lower}."
                    ));
                }
            }
            _ => {}
        }
        true
    }

    fn require_npc_control_command(&self, command: &str) -> bool {
        if self.has_right(PLPERM_NPCCONTROL) && self.admin_ip_matches_current_remote() {
            return true;
        }
        self.send_plo_rc_chat(&format!("Server: You are not authorized to use {command}."));
        false
    }

    fn handle_rc_script_scan(&self, arg: &str) -> bool {
        let Some((scope, query)) = parse_script_scan_args(arg) else {
            self.send_plo_rc_chat("Usage: /scriptscan <scope> <query>");
            return true;
        };
        let Some(server) = self.server() else {
            return true;
        };
        let configured = server.settings.get_int(
            "scriptscanmaxresults",
            DEFAULT_SCRIPT_SCAN_MAX_RESULTS as i32,
        );
        let limit = if configured > 0 {
            configured as usize
        } else {
            DEFAULT_SCRIPT_SCAN_MAX_RESULTS
        };
        self.send_plo_rc_chat(&format!("Scanning for '{query}' in {scope}:"));
        let can_read = |file_path: &str| self.rc_file_has_right(file_path, 'r');
        let (matches, truncated) = server.scan_script_files(&scope, &query, limit, Some(&can_read));
        for (index, matching) in matches.iter().enumerate() {
            if index > 0 {
                self.send_plo_rc_chat("---");
            }
            self.send_plo_rc_chat(&format!("{}:", matching.display));
            for line in &matching.lines {
                self.send_plo_rc_chat(line);
            }
        }
        if truncated {
            self.send_plo_rc_chat(&format!(
                "Found more than {limit} matching scripts, try to do a more exact search."
            ));
        } else if matches.is_empty() {
            self.send_plo_rc_chat("No matching scripts found.");
        }
        true
    }

    fn handle_rc_script_help(&self, arg: &str) -> bool {
        let query = arg.trim();
        if query.is_empty() {
            self.send_plo_rc_chat("Usage: /scripthelp <name or wildcard>");
            return true;
        }
        let Some(server) = self.server() else {
            return true;
        };
        server.refresh_script_help_cache_if_stale();
        if !server.script_help_ready.load(Ordering::Relaxed) {
            self.send_plo_rc_chat("Script help cache is not loaded yet.");
            return true;
        }
        let entries = server.script_help_entries();
        let mut serverside = Vec::new();
        let mut clientside = Vec::new();
        for entry in entries {
            if !script_help_wildcard_match(query, &entry.name) {
                continue;
            }
            let line = entry.script_help_line();
            if line.is_empty() {
                continue;
            }
            if entry.scope.eq_ignore_ascii_case("clientside") {
                clientside.push(line);
            } else {
                serverside.push(line);
            }
        }
        self.send_plo_rc_chat(&format!("Script help for '{query}':"));
        if serverside.is_empty() && clientside.is_empty() {
            self.send_plo_rc_chat("No script help found.");
            return true;
        }
        const LIMIT: usize = 40;
        let mut count = 0;
        for line in serverside {
            if count >= LIMIT {
                self.send_plo_rc_chat("More results omitted.");
                return true;
            }
            self.send_plo_rc_chat(&line);
            count += 1;
        }
        if !clientside.is_empty() {
            self.send_plo_rc_chat("Clientside:");
        }
        for line in clientside {
            if count >= LIMIT {
                self.send_plo_rc_chat("More results omitted.");
                return true;
            }
            self.send_plo_rc_chat(&line);
            count += 1;
        }
        true
    }

    fn handle_rc_global(&self, rest: &str) {
        let words = rest.split_whitespace().collect::<Vec<_>>();
        if words
            .first()
            .map(|value| value.eq_ignore_ascii_case("setplayers"))
            != Some(true)
        {
            return;
        }
        if !self.has_right(PLPERM_MODIFYSTAFFACCOUNT) || !self.admin_ip_matches_current_remote() {
            self.send_plo_rc_chat("Server: You are not authorized to use /global.");
            return;
        }
        let Some(server) = self.server() else { return };
        match words.get(1).copied() {
            None => {
                server.set_fake_player_count(None);
                server.send_rc_chat(&format!(
                    "{} disabled fake listserver playercount.",
                    self.account_name()
                ));
            }
            Some(value) if value.eq_ignore_ascii_case("off") => {
                server.set_fake_player_count(None);
                server.send_rc_chat(&format!(
                    "{} disabled fake listserver playercount.",
                    self.account_name()
                ));
            }
            Some(value) => match value.parse::<i32>() {
                Ok(count) if count >= 0 => {
                    server.set_fake_player_count(Some(count));
                    server.send_rc_chat(&format!(
                        "{} set fake listserver playercount to {count}.",
                        self.account_name()
                    ));
                }
                _ => {
                    self.send_plo_rc_chat("Server: Usage: /global setplayers #|off");
                }
            },
        }
    }

    fn handle_rc_rps(&self, words: Vec<&str>) {
        let choices = ["rock", "paper", "scissors"];
        let pick = words
            .first()
            .map(|value| value.to_ascii_lowercase())
            .unwrap_or_else(|| choices[rand::random::<usize>() % choices.len()].to_string());
        if !choices.contains(&pick.as_str()) {
            self.send_plo_rc_chat("Server: Usage: /rps rock|paper|scissors");
            return;
        }
        let bot = choices[rand::random::<usize>() % choices.len()];
        let result = if pick == bot {
            "tie"
        } else if (pick == "rock" && bot == "scissors")
            || (pick == "paper" && bot == "rock")
            || (pick == "scissors" && bot == "paper")
        {
            "win"
        } else {
            "lose"
        };
        if let Some(server) = self.server() {
            server.send_rc_chat(&format!(
                "{} played RPS: {pick} vs {bot}, {result}.",
                self.rc_display_name()
            ));
        }
    }

    fn handle_rc_roll(&self, words: Vec<&str>) {
        let max = match words.first().copied() {
            None => 100,
            Some(value) => match value.parse::<i32>() {
                Ok(value) if (1..=200).contains(&value) => value,
                _ => {
                    self.send_plo_rc_chat("Server: Usage: /roll [1-200]");
                    return;
                }
            },
        };
        let roll = (rand::random::<u32>() % max as u32 + 1) as i32;
        let verb = if roll == max {
            "crit rolls"
        } else if roll == 1 {
            "tragically rolls"
        } else if max >= 100 && roll >= max - 4 {
            "high rolls"
        } else if max >= 20 && roll <= 3 {
            "low rolls"
        } else {
            "rolls"
        };
        if let Some(server) = self.server() {
            server.send_rc_chat(&format!(
                "{} {verb} {roll} (1-{max}).",
                self.rc_display_name()
            ));
        }
    }

    fn admin_ip_matches_current_remote(&self) -> bool {
        let admin_ip = self.account.lock().unwrap().admin_ip.clone();
        self.admin_ip_matches_remote(&admin_ip)
    }

    fn handle_packet(&self, packet: &[u8]) -> bool {
        if packet.is_empty() {
            return true;
        }
        let packet_id = Buffer::from_bytes(&packet[..1]).read_gchar();
        // Decode the GChar command byte and replace packet[0] before
        // dispatching. Keep that invariant so every handler sees the
        // raw PLI byte, including handlers that parse packet[1..] directly.
        let mut normalized = packet.to_vec();
        normalized[0] = packet_id;
        {
            self.state.lock().unwrap().packet_count += 1;
        }
        if is_rc_only_packet(packet_id)
            && self.player_type() & PLTYPE_ANYRC == 0
            && !(packet_id == PLI_RC_CHAT && self.can_login_control())
        {
            return true;
        }
        if is_nc_only_packet(packet_id) && self.player_type() & PLTYPE_ANYNC == 0 {
            return true;
        }
        if (is_rc_only_packet(packet_id) && self.player_type() & PLTYPE_ANYRC != 0
            || is_nc_only_packet(packet_id) && self.player_type() & PLTYPE_ANYNC != 0)
            && !self.can_login_control()
        {
            return false;
        }
        if packet_id == PLI_RC_CHAT
            && (self.player_type() & PLTYPE_ANYRC != 0 || self.can_login_control())
        {
            return self.msg_pli_rc_chat(&normalized);
        }
        match packet_id {
            PLI_TOALL => self.msg_pli_toall(&normalized),
            PLI_FLAGSET => self.msg_pli_flagset(&normalized),
            PLI_FLAGDEL => self.msg_pli_flagdel(&normalized),
            PLI_PACKETCOUNT => self.msg_pli_packetcount(&normalized),
            PLI_LEVELWARP | PLI_LEVELWARPMOD => self.msg_pli_levelwarp(&normalized),
            PLI_BOARDMODIFY => self.msg_pli_boardmodify(&normalized),
            PLI_REQUESTUPDATEBOARD => self.msg_pli_requestupdateboard(&normalized),
            PLI_PLAYERPROPS => self.msg_pli_playerprops_exact(&normalized),
            PLI_NPCPROPS => self.msg_pli_npcprops(&normalized),
            PLI_BOMBADD => self.msg_pli_broadcast(PLO_BOMBADD, &normalized[1..]),
            PLI_BOMBDEL => self.msg_pli_bombdel(&normalized),
            PLI_ARROWADD => self.msg_pli_arrowadd(&normalized),
            PLI_FIRESPY => self.msg_pli_firespy(&normalized),
            PLI_THROWCARRIED => self.msg_pli_throwcarried(&normalized),
            PLI_ITEMADD => self.msg_pli_itemadd(&normalized),
            PLI_ITEMDEL | PLI_ITEMTAKE => self.msg_pli_itemdel(&normalized),
            PLI_CLAIMPKER => self.msg_pli_claimpker(&normalized),
            PLI_BADDYPROPS => self.msg_pli_baddyprops(&normalized),
            PLI_BADDYHURT => self.msg_pli_baddyhurt(&normalized),
            PLI_BADDYADD => self.msg_pli_baddyadd(&normalized),
            PLI_OPENCHEST => self.msg_pli_openchest(&normalized),
            PLI_PUTNPC => self.msg_pli_putnpc(&normalized),
            PLI_NPCDEL => self.msg_pli_npcdel(&normalized),
            PLI_WANTFILE => self.msg_pli_wantfile(&normalized),
            PLI_SHOWIMG => self.msg_pli_showimg(&normalized),
            PLI_HURTPLAYER => self.msg_pli_hurtplayer(&normalized),
            PLI_EXPLOSION => self.msg_pli_explosion(&normalized),
            PLI_PRIVATEMESSAGE => self.msg_pli_privatemessage(&normalized),
            PLI_NPCWEAPONDEL => self.msg_pli_npcweapondel(&normalized),
            PLI_WEAPONADD => self.msg_pli_weaponadd(&normalized),
            PLI_HORSEADD => self.msg_pli_horseadd(&normalized),
            PLI_HORSEDEL => self.msg_pli_horsedel(&normalized),
            PLI_UPDATEFILE => self.msg_pli_updatefile(&normalized),
            PLI_HITOBJECTS => self.msg_pli_hitobjects(&normalized),
            PLI_LANGUAGE => self.msg_pli_language(&normalized),
            PLI_TRIGGERACTION => self.msg_pli_triggeraction(&normalized),
            PLI_MAPINFO => true,
            PLI_ADJACENTLEVEL => self.msg_pli_adjacentlevel(&normalized),
            PLI_SHOOT => self.msg_pli_shoot(&normalized),
            PLI_SHOOT2 => self.msg_pli_shoot2(&normalized),
            PLI_SERVERWARP => self.msg_pli_serverwarp(&normalized),
            PLI_MUTEPLAYER | PLI_PROCESSLIST | PLI_UNKNOWN46 | PLI_RAWDATA => true,
            PLI_VERIFYWANTSEND => self.msg_pli_verifywantsend(&normalized),
            PLI_REQUESTTEXT => self.msg_pli_requesttext(&normalized),
            PLI_SENDTEXT => self.msg_pli_sendtext(&normalized),
            PLI_UPDATEGANI => self.msg_pli_updategani(&normalized),
            PLI_UPDATESCRIPT => self.msg_pli_updatescript(&normalized),
            PLI_UPDATEPACKAGEREQUESTFILE => self.msg_pli_updatepackage_request_file(&normalized),
            PLI_UPDATECLASS => self.msg_pli_updateclass(&normalized),
            PLI_RC_SERVEROPTIONSGET => self.msg_pli_rc_server_options_get(&normalized),
            PLI_RC_SERVEROPTIONSSET => self.msg_pli_rc_server_options_set(&normalized),
            PLI_RC_FOLDERCONFIGGET => self.msg_pli_rc_folder_config_get(&normalized),
            PLI_RC_FOLDERCONFIGSET => self.msg_pli_rc_folder_config_set(&normalized),
            PLI_RC_RESPAWNSET
            | PLI_RC_HORSELIFESET
            | PLI_RC_APINCREMENTSET
            | PLI_RC_BADDYRESPAWNSET
            | PLI_RC_LISTRCS
            | PLI_RC_DISCONNECTRC
            | PLI_RC_APPLYREASON
            | PLI_RC_UNKNOWN162 => self.msg_pli_rc_noop(&normalized),
            PLI_RC_PLAYERPROPSGET => self.msg_pli_rc_player_props_get(&normalized),
            PLI_RC_PLAYERPROPSSET => self.msg_pli_rc_player_props_set(&normalized),
            PLI_RC_DISCONNECTPLAYER => self.msg_pli_rc_disconnect_player(&normalized),
            PLI_RC_UPDATELEVELS => self.msg_pli_rc_update_levels(&normalized),
            PLI_RC_ADMINMESSAGE => self.msg_pli_rc_admin_message(&normalized),
            PLI_RC_PRIVADMINMESSAGE => self.msg_pli_rc_priv_admin_message(&normalized),
            PLI_RC_SERVERFLAGSGET => self.msg_pli_rc_server_flags_get(&normalized),
            PLI_RC_SERVERFLAGSSET => self.msg_pli_rc_server_flags_set(&normalized),
            PLI_RC_ACCOUNTADD => self.msg_pli_rc_account_add(&normalized),
            PLI_RC_ACCOUNTDEL => self.msg_pli_rc_account_delete(&normalized),
            PLI_RC_ACCOUNTLISTGET => self.msg_pli_rc_account_list_get(&normalized),
            PLI_RC_PLAYERPROPSGET2 => self.msg_pli_rc_player_props_get2(&normalized),
            PLI_RC_PLAYERPROPSGET3 => self.msg_pli_rc_player_props_get3(&normalized),
            PLI_RC_PLAYERPROPSRESET => self.msg_pli_rc_player_props_reset(&normalized),
            PLI_RC_PLAYERPROPSSET2 => self.msg_pli_rc_player_props_set2(&normalized),
            PLI_RC_ACCOUNTGET => self.msg_pli_rc_account_get(&normalized),
            PLI_RC_ACCOUNTSET => self.msg_pli_rc_account_set(&normalized),
            PLI_PROFILEGET => self.msg_pli_profile_get(&normalized),
            PLI_PROFILESET => self.msg_pli_profile_set(&normalized),
            PLI_RC_WARPPLAYER => self.msg_pli_rc_warp_player(&normalized),
            PLI_RC_PLAYERRIGHTSGET => self.msg_pli_rc_player_rights_get(&normalized),
            PLI_RC_PLAYERRIGHTSSET => self.msg_pli_rc_player_rights_set(&normalized),
            PLI_RC_PLAYERCOMMENTSGET => self.msg_pli_rc_player_comments_get(&normalized),
            PLI_RC_PLAYERCOMMENTSSET => self.msg_pli_rc_player_comments_set(&normalized),
            PLI_RC_PLAYERBANGET => self.msg_pli_rc_player_ban_get(&normalized),
            PLI_RC_PLAYERBANSET => self.msg_pli_rc_player_ban_set(&normalized),
            PLI_RC_FILEBROWSER_START => self.msg_pli_rc_filebrowser_start(&normalized),
            PLI_RC_FILEBROWSER_CD => self.msg_pli_rc_filebrowser_cd(&normalized),
            PLI_RC_FILEBROWSER_END => self.msg_pli_rc_filebrowser_end(&normalized),
            PLI_RC_FILEBROWSER_DOWN => self.msg_pli_rc_filebrowser_down(&normalized),
            PLI_RC_FILEBROWSER_UP => self.msg_pli_rc_filebrowser_up(&normalized),
            PLI_RC_FILEBROWSER_MOVE => self.msg_pli_rc_filebrowser_move(&normalized),
            PLI_RC_FILEBROWSER_DELETE => self.msg_pli_rc_filebrowser_delete(&normalized),
            PLI_RC_FILEBROWSER_RENAME => self.msg_pli_rc_filebrowser_rename(&normalized),
            PLI_RC_LARGEFILESTART => self.msg_pli_rc_large_file_start(&normalized),
            PLI_RC_LARGEFILEEND => self.msg_pli_rc_large_file_end(&normalized),
            PLI_RC_FOLDERDELETE => self.msg_pli_rc_folder_delete(&normalized),
            PLI_NC_LISTNPCS => self.msg_pli_nc_list_npcs(&normalized),
            PLI_NC_NPCGET => self.msg_pli_nc_npcget(&normalized),
            PLI_NC_NPCDELETE => self.msg_pli_nc_npcdelete(&normalized),
            PLI_NC_NPCRESET => self.msg_pli_nc_npcreset(&normalized),
            PLI_NC_NPCSCRIPTGET => self.msg_pli_nc_npcscriptget(&normalized),
            PLI_NC_NPCWARP => self.msg_pli_nc_npcwarp(&normalized),
            PLI_NC_NPCFLAGSGET => self.msg_pli_nc_npcflagsget(&normalized),
            PLI_NC_NPCSCRIPTSET => self.msg_pli_nc_npcscriptset(&normalized),
            PLI_NC_NPCFLAGSSET => self.msg_pli_nc_npcflagsset(&normalized),
            PLI_NC_NPCADD => self.msg_pli_nc_npcadd(&normalized),
            PLI_NC_CLASSEDIT => self.msg_pli_nc_classedit(&normalized),
            PLI_NC_CLASSADD => self.msg_pli_nc_classadd(&normalized),
            PLI_NC_LOCALNPCSGET => self.msg_pli_nc_localnpcsget(&normalized),
            PLI_NC_WEAPONLISTGET => self.msg_pli_nc_weaponlistget(&normalized),
            PLI_NC_WEAPONGET => self.msg_pli_nc_weaponget(&normalized),
            PLI_NC_WEAPONADD => self.msg_pli_nc_weaponadd(&normalized),
            PLI_NC_WEAPONDELETE => self.msg_pli_nc_weapondelete(&normalized),
            PLI_NC_CLASSDELETE => self.msg_pli_nc_classdelete(&normalized),
            PLI_NC_LEVELLISTGET => self.msg_pli_nc_levellistget(&normalized),
            PLI_NC_LEVELLISTSET => self.msg_pli_nc_levellistset(&normalized),
            PLI_NPCSERVERQUERY => self.msg_pli_npcserverquery(&normalized),
            _ => {
                let invalid = {
                    let mut state = self.state.lock().unwrap();
                    state.invalid_packets = state.invalid_packets.saturating_add(1);
                    state.invalid_packets
                };
                invalid <= 5
            }
        }
    }

    pub fn send_packet(&self, packet: &[u8]) {
        if packet.is_empty() {
            return;
        }
        let encoded = encode_outgoing_packet(packet);
        let mut state = self.state.lock().unwrap();
        if state.queue_outgoing
            || self
                .server()
                .map(|server| server.is_running())
                .unwrap_or(false)
        {
            let overflow = state.out_queue.len() > 0
                && state.out_queue.len() + encoded.len() > PLAYER_WRITE_QUEUE_LIMIT;
            if overflow {
                drop(state);
                self.disconnect();
                return;
            }
            state.out_queue.extend_from_slice(&encoded);
        } else {
            let queued = std::mem::take(&mut state.out_queue);
            let queued_error = if queued.is_empty() {
                false
            } else {
                write_encoded_packet_locked(&mut state, &self.server, queued).is_err()
            };
            let packet_error =
                write_encoded_packet_locked(&mut state, &self.server, encoded).is_err();
            if queued_error || packet_error {
                drop(state);
                self.disconnect();
            }
        }
    }
    pub fn SendPacket(&self, packet: &[u8]) {
        let mut value = packet.to_vec();
        value.push(b'\n');
        self.send_packet(&value);
    }
    pub fn send(&self, buffer: &Buffer) {
        let mut value = buffer.data.clone();
        value.push(b'\n');
        self.send_packet(&value);
    }
    fn write_string8_raw(&self, value: &str) {
        let mut packet = Vec::with_capacity(value.len() + 1);
        packet.push(value.len() as u8);
        packet.extend_from_slice(value.as_bytes());
        self.send_packet(&packet);
    }
    pub fn send_compress(&self, _force_send: bool) {
        let mut state = self.state.lock().unwrap();
        if !state.queue_outgoing || state.out_queue.is_empty() {
            state.queue_outgoing = false;
            return;
        }
        state.queue_outgoing = false;
        let queued = std::mem::take(&mut state.out_queue);
        if write_encoded_packet_locked(&mut state, &self.server, queued).is_err() {
            drop(state);
            self.disconnect();
        }
    }
    pub fn sendCompress(&self, force_send: bool) {
        self.send_compress(force_send)
    }
    pub fn on_send(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        let async_runtime = state.async_write
            && self
                .server()
                .map(|server| server.is_running())
                .unwrap_or(false);
        if async_runtime {
            match flush_wire_queue_locked(&mut state) {
                Ok(true) => return true,
                Ok(false) => {}
                Err(_) => {
                    drop(state);
                    self.disconnect();
                    return false;
                }
            }
        }
        if state.queue_outgoing || state.out_queue.is_empty() {
            return true;
        }
        let queued = std::mem::take(&mut state.out_queue);
        if write_encoded_packet_locked(&mut state, &self.server, queued).is_err() {
            drop(state);
            self.disconnect();
            return false;
        }
        if async_runtime {
            if flush_wire_queue_locked(&mut state).is_err() {
                drop(state);
                self.disconnect();
                return false;
            }
        }
        true
    }
    pub fn OnSend(&self) -> bool {
        self.on_send()
    }
    pub fn send_immediate_packet(&self, packet: &[u8]) {
        if packet.is_empty() {
            return;
        }
        let mut state = self.state.lock().unwrap();
        let queued = std::mem::take(&mut state.out_queue);
        if !queued.is_empty() {
            if write_encoded_packet_locked(&mut state, &self.server, queued).is_err() {
                drop(state);
                self.disconnect();
                return;
            }
        }
        let encoded = encode_outgoing_packet(packet);
        if write_encoded_packet_locked(&mut state, &self.server, encoded).is_err() {
            drop(state);
            self.disconnect();
            return;
        }
        if state.async_write
            && self
                .server()
                .map(|server| server.is_running())
                .unwrap_or(false)
        {
            if flush_wire_queue_locked(&mut state).is_err() {
                drop(state);
                self.disconnect();
            }
        }
    }
    pub fn sendImmediatePacket(&self, packet: &[u8]) {
        self.send_immediate_packet(packet)
    }
    pub fn write_encoded_packet(&self, packet_name: &str, packet_id: u8, packet: &[u8]) {
        let mut state = self.state.lock().unwrap();
        let result = write_encoded_packet_named_locked(
            &mut state,
            &self.server,
            packet_name,
            packet_id,
            packet,
        );
        if result.is_err() {
            drop(state);
            self.disconnect();
        }
    }
    pub fn writeEncodedPacket(&self, packet_name: &str, packet_id: u8, packet: &[u8]) {
        self.write_encoded_packet(packet_name, packet_id, packet)
    }
    pub fn disconnect(&self) {
        let (conn, level, server, should_save) = {
            let mut state = self.state.lock().unwrap();
            if state.disconnected {
                return;
            }
            state.disconnected = true;
            let conn = state.conn.take();
            let level = state.current_level.take();
            let server = self.server();
            let should_save = state.loaded && state.player_type & PLTYPE_ANYCLIENT != 0;
            (conn, level, server, should_save)
        };
        if should_save {
            let _ = self.save_account();
        }
        if let Some(conn) = conn {
            let _ = conn.shutdown(Shutdown::Both);
        }
        if let Some(level) = level {
            level.remove_player(self);
        }
        if let Some(server) = server {
            if let Some(this) = server.get_player(self.id()) {
                server.delete_player(&this);
            }
        }
    }
    pub fn Disconnect(&self) {
        self.disconnect()
    }

    pub fn get_prop(&self, prop_id: u8) -> Vec<u8> {
        let account = self.account.lock().unwrap();
        let state = self.state.lock().unwrap();
        let mut buf = Buffer::new();
        match prop_id {
            PLPROP_NICKNAME => buf
                .write_gchar(account.character.nickname.len() as u8)
                .write(account.character.nickname.as_bytes()),
            PLPROP_MAXPOWER => {
                buf.write_gchar(account.max_hitpoints);
                &mut buf
            }
            PLPROP_CURPOWER => buf.write_gchar((account.character.hitpoints * 2) as u8),
            PLPROP_RUPEESCOUNT => buf.write_gint(account.character.gralats as u32),
            PLPROP_ARROWSCOUNT => buf.write_gchar(account.character.arrows as u8),
            PLPROP_BOMBSCOUNT => buf.write_gchar(account.character.bombs as u8),
            PLPROP_GLOVEPOWER => buf.write_gchar(account.character.glove_power as u8),
            PLPROP_SWORDPOWER => {
                buf.write_gchar((account.character.sword_power + 30) as u8)
                    .write_gchar(account.character.sword_image.len() as u8)
                    .write(account.character.sword_image.as_bytes());
                &mut buf
            }
            PLPROP_SHIELDPOWER => {
                buf.write_gchar((account.character.shield_power + 10) as u8)
                    .write_gchar(account.character.shield_image.len() as u8)
                    .write(account.character.shield_image.as_bytes());
                &mut buf
            }
            PLPROP_GANI => buf
                .write_gchar(account.character.gani.len() as u8)
                .write(account.character.gani.as_bytes()),
            PLPROP_HEADGIF => buf
                .write_gchar((account.character.head_image.len() + 100) as u8)
                .write(account.character.head_image.as_bytes()),
            PLPROP_CURCHAT => buf
                .write_gchar(account.character.chat_message.len() as u8)
                .write(account.character.chat_message.as_bytes()),
            PLPROP_COLORS => {
                for value in account.character.colors {
                    buf.write_gchar(value);
                }
                &mut buf
            }
            PLPROP_ID => buf.write_gshort(state.id),
            PLPROP_X => buf.write_gchar((account.x / 8) as u8),
            PLPROP_Y => buf.write_gchar((account.y / 8) as u8),
            PLPROP_SPRITE => buf.write_gchar(account.character.sprite),
            PLPROP_STATUS => buf.write_gchar(account.status as u8),
            PLPROP_CARRYSPRITE => buf.write_byte(account.carry_sprite),
            PLPROP_CURLEVEL => buf
                .write_gchar(account.level_name.len() as u8)
                .write(account.level_name.as_bytes()),
            PLPROP_HORSEGIF => buf
                .write_gchar(account.character.horse_image.len() as u8)
                .write(account.character.horse_image.as_bytes()),
            PLPROP_HORSEBUSHES | PLPROP_EFFECTCOLORS => buf.write_gchar(0),
            PLPROP_PCONNECTED | PLPROP_UNKNOWN81 => &mut buf,
            PLPROP_CARRYNPC => buf.write_gint(0),
            PLPROP_APCOUNTER => buf.write_gshort(u16::from(account.ap_counter) + 1),
            PLPROP_MAGICPOINTS => buf.write_gchar(account.mp),
            PLPROP_KILLSCOUNT => buf.write_gint(account.kills),
            PLPROP_DEATHSCOUNT => buf.write_gint(account.deaths),
            PLPROP_ONLINESECS => buf.write_gint(account.online_time as u32),
            PLPROP_IPADDR => buf.write_gint5(u64::from(rc_display_ip(account.account_ip))),
            PLPROP_UDPPORT => buf.write_gint(account.udp_port as u32),
            PLPROP_ALIGNMENT => buf.write_gchar(account.alignment as u8),
            PLPROP_ADDITFLAGS => buf.write_gchar(account.additional_flags as u8),
            PLPROP_ACCOUNTNAME => buf
                .write_gchar(account.account_name.len() as u8)
                .write(account.account_name.as_bytes()),
            PLPROP_BODYIMG => buf
                .write_gchar(account.character.body_image.len() as u8)
                .write(account.character.body_image.as_bytes()),
            PLPROP_RATING => buf.write_gint(
                ((account.elo_rating as u32 & 0xfff) << 9) | (account.elo_deviation as u32 & 0x1ff),
            ),
            PLPROP_JOINLEAVELVL => buf.write_gchar(1),
            PLPROP_PLANGUAGE => buf
                .write_gchar(account.language.len() as u8)
                .write(account.language.as_bytes()),
            PLPROP_PSTATUSMSG => buf.write_gchar(account.status_msg),
            PLPROP_Z => buf.write_gchar((account.z / 8 + 50).clamp(0, 223) as u8),
            PLPROP_COMMUNITYNAME => buf
                .write_gchar(account.community_name.len() as u8)
                .write(account.community_name.as_bytes()),
            PLPROP_OSTYPE => buf
                .write_gchar(account.os.len() as u8)
                .write(account.os.as_bytes()),
            PLPROP_TEXTCODEPAGE => buf.write_gint(account.env_code_page as u32),
            PLPROP_X2 => buf.write_gshort(encode_signed_gshort_coord(account.x)),
            PLPROP_Y2 => buf.write_gshort(encode_signed_gshort_coord(account.y)),
            PLPROP_Z2 => buf.write_gshort(encode_signed_gshort_coord(
                account.z.clamp(-25 * 16, 85 * 16),
            )),
            PLPROP_GATTRIB1..=PLPROP_GATTRIB5 => {
                let value = &account.g_attribs[(prop_id - PLPROP_GATTRIB1) as usize];
                buf.write_gchar(value.len() as u8).write(value.as_bytes());
                &mut buf
            }
            _ => buf.write_gchar(0),
        };
        buf.data
    }
    pub fn getProp(&self, prop_id: u8) -> Vec<u8> {
        self.get_prop(prop_id)
    }
    pub fn send_props(&self, props: &[bool; PROPCOUNT]) {
        let mut buf = Buffer::new();
        for (index, value) in props.iter().enumerate() {
            if *value {
                buf.write_gchar(index as u8)
                    .write(&self.get_prop(index as u8));
            }
        }
        if !buf.data.is_empty() {
            let mut packet = Buffer::new();
            packet.write_byte(PLO_PLAYERPROPS).write(&buf.data);
            self.send_packet(&packet.data);
        }
    }
    pub fn sendProps(&self, props: &[bool; PROPCOUNT]) {
        self.send_props(props)
    }
    pub fn send_props_with_array(&self, props: &[bool; PROPCOUNT]) -> Vec<u8> {
        let mut buf = Buffer::new();
        for (index, value) in props.iter().enumerate() {
            if *value {
                buf.write_gchar(index as u8)
                    .write(&self.get_prop(index as u8));
            }
        }
        buf.data
    }
    pub fn sendPropsWithArray(&self, props: &[bool; PROPCOUNT]) -> Vec<u8> {
        self.send_props_with_array(props)
    }
    pub fn process_ap(&self) {
        let Some(server) = self.server() else {
            return;
        };
        if self.player_type() & PLTYPE_ANYCLIENT == 0
            || !server.settings.get_bool("apsystem", false)
            || self.current_level().is_none()
        {
            return;
        }

        let (player_props, common_props) = {
            let mut account = self.account.lock().unwrap();
            if account.status & PLSTATUS_PAUSED != 0 {
                return;
            }
            if account.ap_counter > 0 {
                account.ap_counter -= 1;
            }
            if account.ap_counter > 0 {
                return;
            }

            let mut common = Buffer::new();
            if account.character.ap < 100 {
                account.character.ap += 1;
                account.alignment = account.character.ap;
                common
                    .write_gchar(PLPROP_ALIGNMENT)
                    .write_gchar(account.alignment as u8);
            }

            let ap = account.character.ap;
            let seconds = if ap < 20 {
                server.settings.get_int("aptime0", 30)
            } else if ap < 40 {
                server.settings.get_int("aptime1", 90)
            } else if ap < 60 {
                server.settings.get_int("aptime2", 300)
            } else if ap < 80 {
                server.settings.get_int("aptime3", 600)
            } else {
                server.settings.get_int("aptime4", 1200)
            };
            account.ap_counter = seconds.clamp(1, 255) as u8;

            if common.data.is_empty() {
                (None, None)
            } else {
                let mut packet = Buffer::new();
                packet.write_byte(PLO_PLAYERPROPS).write(&common.data);
                (Some(packet.data), Some(common.data))
            }
        };

        if let (Some(packet), Some(common)) = (player_props, common_props) {
            self.send_packet(&packet);
            self.send_player_prop_deltas_to_current_level(&common, &[], &[], &[], false, false);
        }
    }
    pub fn processAP(&self) {
        self.process_ap()
    }
}

impl Clone for PlayerState {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn.as_ref().and_then(|value| value.try_clone().ok()),
            async_write: self.async_write,
            websocket: self.websocket,
            websocket_candidate: self.websocket_candidate,
            websocket_buffer: self.websocket_buffer.clone(),
            websocket_fragment: self.websocket_fragment.clone(),
            websocket_fragmented: self.websocket_fragmented,
            recv_buffer: self.recv_buffer.clone(),
            read_scratch: self.read_scratch.clone(),
            encryption: self.encryption.clone(),
            out_encryption: self.out_encryption.clone(),
            queue_outgoing: self.queue_outgoing,
            out_queue: self.out_queue.clone(),
            wire_queue: self.wire_queue.clone(),
            version: self.version.clone(),
            server_name: self.server_name.clone(),
            id: self.id,
            player_type: self.player_type,
            version_id: self.version_id,
            map_ref: self.map_ref.clone(),
            current_level: self.current_level.clone(),
            external_players: self.external_players.clone(),
            loaded: self.loaded,
            disconnected: self.disconnected,
            defer_client_login: self.defer_client_login,
            login_pending: self.login_pending,
            next_is_raw: self.next_is_raw,
            raw_packet_size: self.raw_packet_size,
            is_ftp: self.is_ftp,
            last_folder: self.last_folder.clone(),
            rc_large_files: self.rc_large_files.clone(),
            last_rc_download_notice: self.last_rc_download_notice,
            last_rc_download_notice_file: self.last_rc_download_notice_file.clone(),
            nc_post_login_sent: self.nc_post_login_sent,
            gr_movement_updated: self.gr_movement_updated,
            awaiting_listserver_verify: self.awaiting_listserver_verify,
            first_level: self.first_level,
            gr_movement_packets: self.gr_movement_packets.clone(),
            npcserver_port: self.npcserver_port.clone(),
            packet_count: self.packet_count,
            invalid_packets: self.invalid_packets,
            guild: self.guild.clone(),
            level_group: self.level_group.clone(),
            gr_exec_parameter_list: self.gr_exec_parameter_list.clone(),
            last_data: self.last_data,
            last_movement: self.last_movement,
            last_chat: self.last_chat,
            last_nick: self.last_nick,
            last_message: self.last_message,
            last_save: self.last_save,
            last_one_minute: self.last_one_minute,
            last_serverside_trigger: self.last_serverside_trigger,
            last_serverside_trigger_action: self.last_serverside_trigger_action.clone(),
        }
    }
}
impl PlayerState {
    fn clone_state(&self) -> Self {
        self.clone()
    }
}

impl SocketStub for Player {
    fn on_recv(&self) -> bool {
        Player::on_recv(self)
    }
    fn on_send(&self) -> bool {
        Player::on_send(self)
    }
    fn on_register(&self) -> bool {
        true
    }
    fn on_unregister(&self) {
        self.disconnect();
    }
    fn can_recv(&self) -> bool {
        Player::can_recv(self)
    }
    fn can_send(&self) -> bool {
        Player::can_send(self)
    }
}

fn client_version_id(version: &str) -> i32 {
    match version {
        "GNW31101" => 210,
        "GNW01012" => 212,
        "GNW23012" => 213,
        "GNW30042" => 214,
        "GNW19052" => 215,
        "GNW12102" => 216,
        "GNW22122" => 217,
        "GNW21033" => 218,
        "GNW15053" => 219,
        "GNW28063" => 220,
        "GNW01113" => 221,
        "GNW03014" => 222,
        "GNW14015" => 230,
        "GNW28015" => 231,
        _ if version.starts_with("G3D") => 300,
        _ => 0,
    }
}
pub fn clientVersionID(version: &str) -> i32 {
    client_version_id(version)
}

fn encode_outgoing_packet(packet: &[u8]) -> Vec<u8> {
    let mut value = packet.to_vec();
    if let Some(first) = value.first_mut() {
        *first = (*first).min(223).wrapping_add(32);
    }
    value
}
pub fn encodeOutgoingPacket(packet: &[u8]) -> Vec<u8> {
    encode_outgoing_packet(packet)
}
fn rc_display_ip(ip: u32) -> u32 {
    ip.swap_bytes()
}
pub fn rcDisplayIP(ip: u32) -> u32 {
    rc_display_ip(ip)
}
pub fn encode_signed_gshort_coord(value: i16) -> u16 {
    let value = i32::from(value);
    if value < 0 {
        ((-value << 1) | 1) as u16
    } else {
        (value << 1) as u16
    }
}
pub fn encodeSignedGShortCoord(value: i16) -> u16 {
    encode_signed_gshort_coord(value)
}
pub fn decode_signed_gshort_coord(value: u16) -> i16 {
    let negative = value & 1 != 0;
    let magnitude = (value >> 1) as i16;
    if negative {
        -magnitude
    } else {
        magnitude
    }
}

fn props_from_indices(indices: &[usize]) -> [bool; PROPCOUNT] {
    let mut props = [false; PROPCOUNT];
    for index in indices {
        if *index < PROPCOUNT {
            props[*index] = true;
        }
    }
    props
}

// These four masks are the protocol's original sendLogin/getLogin/sendLocal/
// getRCLogin tables.  Keeping them as explicit masks is important: the
// client uses the presence of a property as a framing contract, so deriving
// one mask from another changes the wire stream for older clients.
fn send_login_props() -> [bool; PROPCOUNT] {
    props_from_indices(&[
        0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 13, 17, 18, 21, 22, 23, 25, 26, 32, 34, 35, 36, 37, 38,
        39, 40, 41, 46, 47, 48, 49, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69,
        70, 71, 72, 73, 74, 78, 79, 80, 82,
    ])
}

fn get_login_props() -> [bool; PROPCOUNT] {
    props_from_indices(&[
        0, 8, 9, 10, 11, 12, 13, 15, 16, 17, 18, 19, 20, 21, 24, 30, 31, 32, 34, 35, 36, 37, 38,
        39, 40, 41, 43, 44, 45, 46, 47, 48, 49, 50, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
        65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 78, 79, 80, 82,
    ])
}

fn send_local_props() -> [bool; PROPCOUNT] {
    props_from_indices(&[
        0, 2, 8, 9, 10, 11, 12, 13, 15, 16, 17, 18, 19, 20, 23, 24, 30, 31, 32, 34, 35, 36, 37, 38,
        39, 40, 41, 43, 44, 45, 46, 47, 48, 49, 50, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
        65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 78, 79, 80, 81, 82,
    ])
}

fn get_rc_login_props() -> [bool; PROPCOUNT] {
    props_from_indices(&[0, 11, 18, 20, 30, 31, 34, 53, 78, 82])
}

fn login_props() -> [bool; PROPCOUNT] {
    get_login_props()
}

fn websocket_handshake_locked(
    state: &mut PlayerState,
    server: &Weak<Server>,
) -> io::Result<Option<bool>> {
    let end = match state
        .websocket_buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
    {
        Some(value) => value + 4,
        None => {
            if state.websocket_buffer.len() > WEBSOCKET_MAX_HANDSHAKE_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("handshake exceeds {} bytes", WEBSOCKET_MAX_HANDSHAKE_SIZE),
                ));
            }
            return Ok(None);
        }
    };
    let header = state.websocket_buffer[..end].to_vec();
    let request_line = String::from_utf8_lossy(
        header
            .split(|value| *value == b'\n')
            .next()
            .unwrap_or_default(),
    )
    .trim()
    .to_string();
    let parts: Vec<_> = request_line.split_whitespace().collect();
    let key = crate::websocket::websocket_header_value(&header, "Sec-WebSocket-Key");
    let valid_key = general_purpose::STANDARD
        .decode(key.as_bytes())
        .map(|value| value.len() == 16)
        .unwrap_or(false);
    if parts.len() != 3
        || parts[0] != "GET"
        || parts[2] != "HTTP/1.1"
        || key.is_empty()
        || !valid_key
    {
        let name = server
            .upgrade()
            .map(|value| value.name.read().unwrap().clone())
            .unwrap_or_else(|| "GServer".to_string());
        let message = server
            .upgrade()
            .map(|value| value.server_message.read().unwrap().clone())
            .unwrap_or_else(|| "Welcome".to_string());
        let body = format!("<html><head><title>{name}</title></head><body><h1>Welcome to {name}!</h1><p>{message}</p></body></html>");
        let response = format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
        if let Some(conn) = state.conn.as_mut() {
            write_raw(conn, response.as_bytes())?;
        }
        return Ok(Some(false));
    }
    let accept = crate::websocket::websocket_accept(&key);
    let protocol = if crate::websocket::websocket_header_has_token(
        &header,
        "Sec-WebSocket-Protocol",
        "binary",
    ) {
        "Sec-WebSocket-Protocol: binary\r\n"
    } else {
        ""
    };
    let response = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n{protocol}Sec-WebSocket-Accept: {accept}\r\n\r\n");
    if let Some(conn) = state.conn.as_mut() {
        write_raw(conn, response.as_bytes())?;
    }
    state.websocket_buffer.drain(..end);
    state.websocket = true;
    state.websocket_candidate = false;
    Ok(Some(true))
}

fn consume_websocket_frames_locked(state: &mut PlayerState) -> io::Result<()> {
    while !state.websocket_buffer.is_empty() {
        let (frame, consumed, complete) = parse_websocket_frame(&state.websocket_buffer)?;
        if !complete {
            return Ok(());
        }
        state.websocket_buffer.drain(..consumed);
        match frame.opcode {
            WEBSOCKET_PING_OPCODE => {
                if let Some(conn) = state.conn.as_mut() {
                    let response = make_websocket_frame(WEBSOCKET_PONG_OPCODE, &frame.payload)?;
                    write_raw(conn, &response)?;
                }
            }
            WEBSOCKET_PONG_OPCODE => {}
            WEBSOCKET_CLOSE_OPCODE => {
                if let Some(conn) = state.conn.as_mut() {
                    let response = make_websocket_frame(WEBSOCKET_CLOSE_OPCODE, &frame.payload)?;
                    write_raw(conn, &response)?;
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed the WebSocket",
                ));
            }
            WEBSOCKET_BINARY_OPCODE => {
                if state.websocket_fragmented {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "new binary frame before fragmented frame completed",
                    ));
                }
                if frame.fin {
                    state.recv_buffer.extend_from_slice(&frame.payload);
                } else {
                    state.websocket_fragment = frame.payload;
                    state.websocket_fragmented = true;
                }
            }
            WEBSOCKET_CONTINUATION_OPCODE => {
                if !state.websocket_fragmented {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "continuation frame without binary frame",
                    ));
                }
                if state.websocket_fragment.len() + frame.payload.len()
                    > WEBSOCKET_MAX_FRAME_PAYLOAD
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "fragmented WebSocket payload exceeds {WEBSOCKET_MAX_FRAME_PAYLOAD} bytes"
                        ),
                    ));
                }
                state.websocket_fragment.extend_from_slice(&frame.payload);
                if frame.fin {
                    let fragment = std::mem::take(&mut state.websocket_fragment);
                    state.recv_buffer.extend_from_slice(&fragment);
                    state.websocket_fragmented = false;
                }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported WebSocket opcode 0x{:X}", frame.opcode),
                ))
            }
        }
    }
    Ok(())
}

fn flush_wire_queue_locked(state: &mut PlayerState) -> io::Result<bool> {
    if state.wire_queue.is_empty() {
        return Ok(false);
    }
    let Some(conn) = state.conn.as_mut() else {
        state.wire_queue.clear();
        return Ok(false);
    };
    let _ = conn.set_write_timeout(Some(Duration::from_millis(2)));
    let result = conn.write(&state.wire_queue);
    let _ = conn.set_write_timeout(None);
    match result {
        Ok(count) if count > 0 => {
            state.wire_queue.drain(..count);
            Ok(!state.wire_queue.is_empty())
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "zero-byte socket write",
        )),
        Err(error) if error.kind() == io::ErrorKind::TimedOut => Ok(!state.wire_queue.is_empty()),
        Err(error) => Err(error),
    }
}

fn write_encoded_packet_locked(
    state: &mut PlayerState,
    server: &Weak<Server>,
    packet: Vec<u8>,
) -> io::Result<()> {
    write_encoded_packet_named_locked(state, server, "QUEUED", 0, &packet)
}
fn write_encoded_packet_named_locked(
    state: &mut PlayerState,
    server: &Weak<Server>,
    packet_name: &str,
    packet_id: u8,
    packet: &[u8],
) -> io::Result<()> {
    let mut data = match state.encryption.gen {
        ENCRYPT_GEN_1 | ENCRYPT_GEN_6 => packet.to_vec(),
        ENCRYPT_GEN_2 | ENCRYPT_GEN_3 => {
            let compressed = match zlib_compress(packet) {
                Ok(value) => value,
                Err(error) => {
                    if let Some(server) = server.upgrade() {
                        server
                            .logger
                            .error(&format!("sendPacket: compression failed: {error}"));
                    }
                    return Ok(());
                }
            };
            if compressed.len() > 0xfffd {
                if let Some(server) = server.upgrade() {
                    server.logger.error(&format!(
                        "sendPacket: compressed packet too large ({})",
                        compressed.len()
                    ));
                }
                return Ok(());
            }
            let mut value = Vec::with_capacity(compressed.len() + 2);
            value.extend_from_slice(&(compressed.len() as u16).to_be_bytes());
            value.extend_from_slice(&compressed);
            value
        }
        ENCRYPT_GEN_5 => {
            let (compression, compressed) = if packet.len() > 0x2000 {
                let value = match crate::network::bz2_compress(packet) {
                    Ok(value) => value,
                    Err(error) => {
                        if let Some(server) = server.upgrade() {
                            server
                                .logger
                                .error(&format!("sendPacket: BZ2 compression failed: {error}"));
                        }
                        return Ok(());
                    }
                };
                (COMPRESS_BZ2, value)
            } else if packet.len() > 55 {
                let value = match zlib_compress(packet) {
                    Ok(value) => value,
                    Err(error) => {
                        if let Some(server) = server.upgrade() {
                            server
                                .logger
                                .error(&format!("sendPacket: Zlib compression failed: {error}"));
                        }
                        return Ok(());
                    }
                };
                (COMPRESS_ZLIB, value)
            } else {
                (COMPRESS_UNCOMPRESSED, packet.to_vec())
            };
            state.out_encryption.limit_from_type(compression);
            let encrypted = state.out_encryption.encrypt(&compressed);
            let frame_len = 1 + encrypted.len();
            if frame_len > 0xfffc {
                if let Some(server) = server.upgrade() {
                    server.logger.error(&format!(
                        "sendPacket: GEN_5 packet too large ({} ID {}, {} bytes)",
                        packet_name, packet_id, frame_len
                    ));
                }
                return Ok(());
            }
            let mut value = Vec::with_capacity(frame_len + 2);
            value.extend_from_slice(&(frame_len as u16).to_be_bytes());
            value.push(compression);
            value.extend_from_slice(&encrypted);
            value
        }
        _ => packet.to_vec(),
    };
    if state.websocket {
        data = match make_websocket_frame(WEBSOCKET_BINARY_OPCODE, &data) {
            Ok(value) => value,
            Err(error) => {
                if let Some(server) = server.upgrade() {
                    server
                        .logger
                        .error(&format!("sendPacket: WebSocket framing failed: {error}"));
                }
                return Ok(());
            }
        };
    }
    let async_runtime = state.async_write
        && server
            .upgrade()
            .map(|value| value.is_running())
            .unwrap_or(false);
    if async_runtime {
        if state.wire_queue.len() + data.len() > PLAYER_WRITE_QUEUE_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "player wire queue exceeded limit",
            ));
        }
        state.wire_queue.extend_from_slice(&data);
        return Ok(());
    }
    if let Some(conn) = state.conn.as_mut() {
        conn.set_write_timeout(Some(Duration::from_secs(2)))?;
        write_raw(conn, &data)?;
        let _ = conn.set_write_timeout(None);
    }
    Ok(())
}

// Small packet builders are kept separate from the receive dispatcher.  They
// intentionally encode fields in the same order as the original methods.
impl Player {
    pub fn send_plo_unknown168(&self) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_UNKNOWN168);
        self.send(&b);
        true
    }
    pub fn sendPLO_UNKNOWN168(&self) -> bool {
        self.send_plo_unknown168()
    }
    pub fn send_plo_clearweapons(&self) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_CLEARWEAPONS);
        self.send(&b);
        true
    }
    pub fn sendPLO_CLEARWEAPONS(&self) -> bool {
        self.send_plo_clearweapons()
    }
    pub fn send_plo_unknown190(&self) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_UNKNOWN190);
        self.send(&b);
        true
    }
    pub fn sendPLO_UNKNOWN190(&self) -> bool {
        self.send_plo_unknown190()
    }
    pub fn send_plo_hasnpcserver(&self) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_HASNPCSERVER);
        self.send(&b);
        true
    }
    pub fn sendPLO_HASNPCSERVER(&self) -> bool {
        self.send_plo_hasnpcserver()
    }
    pub fn send_plo_signature(&self, value: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_SIGNATURE).write_gstring(value);
        self.send(&b);
        true
    }
    pub fn sendPLO_SIGNATURE(&self, value: &str) -> bool {
        self.send_plo_signature(value)
    }
    pub fn send_plo_flagset(&self, flag: &str, value: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_FLAGSET).write(flag.as_bytes());
        if !value.is_empty() {
            b.write_byte(b'=').write(value.as_bytes());
        }
        self.send(&b);
        true
    }
    pub fn sendPLO_FLAGSET(&self, flag: &str, value: &str) -> bool {
        self.send_plo_flagset(flag, value)
    }
    pub fn send_plo_flagdel(&self, flag: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_FLAGDEL).write(flag.as_bytes());
        self.send(&b);
        true
    }
    pub fn sendPLO_FLAGDEL(&self, flag: &str) -> bool {
        self.send_plo_flagdel(flag)
    }
    pub fn send_plo_otherplprops_disconnected(&self, id: u16) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_OTHERPLPROPS)
            .write_gshort(id)
            .write_gchar(PLPROP_PCONNECTED);
        self.send(&b);
        true
    }
    pub fn sendPLO_OTHERPLPROPS_DISCONNECTED(&self, id: u16) -> bool {
        self.send_plo_otherplprops_disconnected(id)
    }
    pub fn send_plo_toall(&self, message: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_TOALL).write_gstring(message);
        self.send(&b);
        true
    }
    pub fn sendPLO_TOALL(&self, message: &str) -> bool {
        self.send_plo_toall(message)
    }
    pub fn send_plo_privatemessage(&self, from: &str, message: &str) -> bool {
        let _ = from;
        let mut b = Buffer::new();
        b.write_byte(PLO_PRIVATEMESSAGE)
            .write_gshort(self.id())
            .write(b"\"Private message:\",\"")
            .write(message.as_bytes())
            .write_byte(b'"');
        self.send(&b);
        true
    }
    pub fn sendPLO_PRIVATEMESSAGE(&self, from: &str, message: &str) -> bool {
        self.send_plo_privatemessage(from, message)
    }
    pub fn send_plo_discmessage(&self, message: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_DISCMESSAGE).write(message.as_bytes());
        self.send(&b);
        true
    }
    pub fn sendPLO_DISCMESSAGE(&self, message: &str) -> bool {
        self.send_plo_discmessage(message)
    }
    pub fn send_plo_warpfailed(&self, message: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_WARPFAILED).write(message.as_bytes());
        self.send(&b);
        true
    }
    pub fn sendPLO_WARPFAILED(&self, message: &str) -> bool {
        self.send_plo_warpfailed(message)
    }
    pub fn send_plo_levelname(&self, name: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_LEVELNAME).write(name.as_bytes());
        self.send(&b);
        true
    }
    pub fn sendPLO_LEVELNAME(&self, name: &str) -> bool {
        self.send_plo_levelname(name)
    }
    pub fn send_plo_levelsign(&self, x: i16, y: i16, text: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_LEVELSIGN).write(
            &LevelSign::new(i32::from(x), i32::from(y), text, false).get_sign_str(Some(self)),
        );
        self.send(&b);
        true
    }
    pub fn sendPLO_LEVELSIGN(&self, x: i16, y: i16, text: &str) -> bool {
        self.send_plo_levelsign(x, y, text)
    }
    pub fn send_plo_npcdel(&self, id: u32) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_NPCDEL).write_gint(id);
        self.send(&b);
        true
    }
    pub fn sendPLO_NPCDEL(&self, id: u32) -> bool {
        self.send_plo_npcdel(id)
    }
    pub fn send_plo_npcmoved(&self, id: u32, x: i16, y: i16) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_NPCMOVED)
            .write_gint(id)
            .write_gint(x as u32)
            .write_gint(y as u32);
        self.send(&b);
        true
    }
    pub fn sendPLO_NPCMOVED(&self, id: u32, x: i16, y: i16) -> bool {
        self.send_plo_npcmoved(id, x, y)
    }
    pub fn send_plo_npcaction(&self, id: u32, action: &str, params: &[&str]) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_NPCACTION)
            .write_gint(id)
            .write_gstring(action);
        for param in params {
            b.write_gstring(param);
        }
        self.send(&b);
        true
    }
    pub fn sendPLO_NPCACTION(&self, id: u32, action: &str, params: &[&str]) -> bool {
        self.send_plo_npcaction(id, action, params)
    }
    pub fn send_plo_triggeraction(
        &self,
        player_id: u16,
        npc_id: u32,
        x: u8,
        y: u8,
        action: &str,
    ) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_TRIGGERACTION)
            .write_gshort(player_id)
            .write_gint(npc_id)
            .write_gchar(x)
            .write_gchar(y)
            .write(action.as_bytes());
        self.send(&b);
        true
    }
    pub fn sendPLO_TRIGGERACTION(
        &self,
        player_id: u16,
        npc_id: u32,
        x: u8,
        y: u8,
        action: &str,
    ) -> bool {
        self.send_plo_triggeraction(player_id, npc_id, x, y, action)
    }
    pub fn send_plo_bombadd(&self, x: i16, y: i16, power: i32, _owner: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_BOMBADD)
            .write_gchar(x as u8)
            .write_gchar(y as u8)
            .write_gchar(power as u8);
        self.send(&b);
        true
    }
    pub fn sendPLO_BOMBADD(&self, x: i16, y: i16, power: i32, owner: &str) -> bool {
        self.send_plo_bombadd(x, y, power, owner)
    }
    pub fn send_plo_bombdel(&self, index: i32) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_BOMBDEL).write_gchar(index as u8);
        self.send(&b);
        true
    }
    pub fn sendPLO_BOMBDEL(&self, index: i32) -> bool {
        self.send_plo_bombdel(index)
    }
    pub fn send_plo_horseadd(&self, _id: u32, x: i16, y: i16, image: &str, _owner: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_HORSEADD)
            .write_byte(x as u8)
            .write_byte(y as u8)
            .write_byte(0)
            .write(image.as_bytes());
        self.send(&b);
        true
    }
    pub fn sendPLO_HORSEADD(&self, id: u32, x: i16, y: i16, image: &str, owner: &str) -> bool {
        self.send_plo_horseadd(id, x, y, image, owner)
    }
    pub fn send_plo_horsedel(&self, id: u32) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_HORSEDEL).write_gchar(id as u8);
        self.send(&b);
        true
    }
    pub fn sendPLO_HORSEDEL(&self, id: u32) -> bool {
        self.send_plo_horsedel(id)
    }
    pub fn send_plo_arrowadd(&self, x: i16, y: i16, angle: f32, _owner: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_ARROWADD)
            .write_gchar(x as u8)
            .write_gchar(y as u8)
            .write_gchar(angle as u8);
        self.send(&b);
        true
    }
    pub fn sendPLO_ARROWADD(&self, x: i16, y: i16, angle: f32, owner: &str) -> bool {
        self.send_plo_arrowadd(x, y, angle, owner)
    }
    pub fn send_plo_itemadd(&self, x: i16, y: i16, item: i32, _image: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_ITEMADD)
            .write_gchar(x as u8)
            .write_gchar(y as u8)
            .write_gchar(item as u8);
        self.send(&b);
        true
    }
    pub fn sendPLO_ITEMADD(&self, x: i16, y: i16, item: i32, image: &str) -> bool {
        self.send_plo_itemadd(x, y, item, image)
    }
    pub fn send_plo_itemdel(&self, item: i32) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_ITEMDEL).write_gchar(item as u8);
        self.send(&b);
        true
    }
    pub fn sendPLO_ITEMDEL(&self, item: i32) -> bool {
        self.send_plo_itemdel(item)
    }
    pub fn send_plo_showimg(&self, index: i32, image: &str, x: &str, y: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_SHOWIMG)
            .write_gint(index as u32)
            .write_gstring(image)
            .write_gstring(x)
            .write_gstring(y);
        self.send(&b);
        true
    }
    pub fn sendPLO_SHOWIMG(&self, index: i32, image: &str, x: &str, y: &str) -> bool {
        self.send_plo_showimg(index, image, x, y)
    }
    pub fn send_plo_hurtplayer(&self, hurter: i32, damage: i32) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_HURTPLAYER)
            .write_gint(hurter as u32)
            .write_gint(damage as u32);
        self.send(&b);
        true
    }
    pub fn sendPLO_HURTPLAYER(&self, hurter: i32, damage: i32) -> bool {
        self.send_plo_hurtplayer(hurter, damage)
    }
    pub fn send_plo_explosion(&self, x: i16, y: i16, power: i32) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_EXPLOSION)
            .write_short(x)
            .write_short(y)
            .write_gint(power as u32);
        self.send(&b);
        true
    }
    pub fn sendPLO_EXPLOSION(&self, x: i16, y: i16, power: i32) -> bool {
        self.send_plo_explosion(x, y, power)
    }
    pub fn send_plo_startmessage(&self, message: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_STARTMESSAGE).write(message.as_bytes());
        self.send(&b);
        true
    }
    pub fn sendPLO_STARTMESSAGE(&self, message: &str) -> bool {
        self.send_plo_startmessage(message)
    }
    pub fn send_plo_servertext(&self, message: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_SERVERTEXT).write(message.as_bytes());
        self.send(&b);
        true
    }
    pub fn sendPLO_SERVERTEXT(&self, message: &str) -> bool {
        self.send_plo_servertext(message)
    }
    pub fn send_plo_boardmodify(
        &self,
        x: i16,
        y: i16,
        width: i16,
        height: i16,
        tiles: &[i16],
    ) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_BOARDMODIFY)
            .write_gchar(x as u8)
            .write_gchar(y as u8)
            .write_gchar(width as u8)
            .write_gchar(height as u8);
        for tile in tiles {
            b.write_gshort(*tile as u16);
        }
        self.send(&b);
        true
    }
    pub fn sendPLO_BOARDMODIFY(
        &self,
        x: i16,
        y: i16,
        width: i16,
        height: i16,
        tiles: &[i16],
    ) -> bool {
        self.send_plo_boardmodify(x, y, width, height, tiles)
    }
    pub fn send_plo_to_all(&self, message: &str) -> bool {
        self.send_plo_toall(message)
    }
    pub fn send_plo_npcweaponadd(&self, id: u32, image: &str, owner: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_NPCWEAPONADD)
            .write_gint(id)
            .write_gstring(image)
            .write_gstring(owner);
        self.send(&b);
        true
    }
    pub fn sendPLO_NPCWEAPONADD(&self, id: u32, image: &str, owner: &str) -> bool {
        self.send_plo_npcweaponadd(id, image, owner)
    }
    pub fn send_plo_npcweapondel(&self, name: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_NPCWEAPONDEL).write(name.as_bytes());
        self.send(&b);
        true
    }
    pub fn sendPLO_NPCWEAPONDEL(&self, name: &str) -> bool {
        self.send_plo_npcweapondel(name)
    }
    pub fn send_plo_fullstop(&self) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_FULLSTOP);
        self.send(&b);
        true
    }
    pub fn sendPLO_FULLSTOP(&self) -> bool {
        self.send_plo_fullstop()
    }
    pub fn send_plo_baddyhurt(&self, id: u32, power: i32) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_BADDYHURT)
            .write_gchar(id as u8)
            .write_gchar(power as u8);
        self.send(&b);
        true
    }
    pub fn sendPLO_BADDYHURT(&self, id: u32, power: i32) -> bool {
        self.send_plo_baddyhurt(id, power)
    }
    pub fn send_plo_rc_chat(&self, message: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_RC_CHAT).write(message.as_bytes());
        self.send(&b);
        true
    }
    pub fn sendPLO_RC_CHAT(&self, message: &str) -> bool {
        self.send_plo_rc_chat(message)
    }
    pub fn send_plo_rc_adminmessage(&self, message: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_RC_ADMINMESSAGE).write(message.as_bytes());
        self.send(&b);
        true
    }
    pub fn sendPLO_RC_ADMINMESSAGE(&self, message: &str) -> bool {
        self.send_plo_rc_adminmessage(message)
    }
    pub fn send_plo_fileuptodate(&self, filename: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_FILEUPTODATE).write(filename.as_bytes());
        self.send(&b);
        true
    }
    pub fn send_plo_filesendfailed(&self, filename: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_FILESENDFAILED).write(filename.as_bytes());
        self.send(&b);
        true
    }
    pub fn send_plo_hitobjects(&self, objects: &[&str]) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_HITOBJECTS)
            .write_gint(objects.len() as u32);
        for object in objects {
            b.write_gstring(object);
        }
        self.send(&b);
        true
    }
    pub fn send_plo_bigmap(&self) -> bool {
        let value = self
            .server()
            .map(|s| s.settings.get("bigmap"))
            .unwrap_or_default();
        let mut b = Buffer::new();
        b.write_byte(PLO_BIGMAP)
            .write(normalized_map_setting(&value).as_bytes());
        self.send(&b);
        true
    }
    pub fn send_plo_minimap(&self) -> bool {
        let value = self
            .server()
            .map(|s| s.settings.get("minimap"))
            .unwrap_or_default();
        let mut b = Buffer::new();
        b.write_byte(PLO_MINIMAP)
            .write(normalized_map_setting(&value).as_bytes());
        self.send(&b);
        true
    }
    pub fn send_plo_isleader(&self) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_ISLEADER);
        self.send(&b);
        true
    }
    pub fn send_plo_listprocesses(&self) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_LISTPROCESSES);
        self.send(&b);
        true
    }
    pub fn send_plo_setactivelevel(&self, value: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_SETACTIVELEVEL).write(value.as_bytes());
        self.send(&b);
        true
    }
    pub fn send_plo_rpgwindow(&self, value: &str) -> bool {
        let mut b = Buffer::new();
        b.write_byte(PLO_RPGWINDOW).write(value.as_bytes());
        self.send(&b);
        true
    }
}

fn normalized_map_setting(value: &str) -> String {
    let mut parts = value.split(',').map(str::trim).collect::<Vec<_>>();
    if parts.len() == 4 {
        parts.join(",")
    } else {
        value.trim().to_string()
    }
}

fn npc_client_side_script(script: &str) -> String {
    let normalized = script.replace("\r\n", "\n").replace('\r', "\n");
    let marker = "//#CLIENTSIDE";
    let upper = normalized.to_ascii_uppercase();
    let Some(index) = upper.find(marker) else {
        return String::new();
    };
    let value = normalized[index + marker.len()..].trim();
    value.replace('\n', "§")
}

impl Player {
    pub fn send_plo_levelboardchanges(&self, level: Option<&Level>, since: SystemTime) -> bool {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_LEVELBOARD);
        if let Some(level) = level {
            for change in level.board_changes() {
                if change.time.duration_since(since).is_ok() {
                    buf.write(&change.get_board_str());
                }
            }
        }
        self.send(&buf);
        true
    }
    pub fn sendPLO_LEVELBOARDCHANGES(&self, level: Option<&Level>, since: SystemTime) -> bool {
        self.send_plo_levelboardchanges(level, since)
    }

    pub fn send_plo_levellink(&self, x: i16, y: i16, level_name: &str) -> bool {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_LEVELLINK)
            .write(format!("{level_name} {x} {y} 1 1 {x} {y}").as_bytes());
        self.send(&buf);
        true
    }
    pub fn sendPLO_LEVELLINK(&self, x: i16, y: i16, level_name: &str) -> bool {
        self.send_plo_levellink(x, y, level_name)
    }

    pub fn send_plo_levellink_full(&self, link: &LevelLink) -> bool {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_LEVELLINK)
            .write(link.get_link_str().as_bytes());
        self.send(&buf);
        true
    }
    pub fn sendPLO_LEVELLINK_FULL(&self, link: &LevelLink) -> bool {
        self.send_plo_levellink_full(link)
    }

    pub fn send_plo_sign(&self, sign: &LevelSign) -> bool {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_LEVELSIGN)
            .write(&sign.get_sign_str(Some(self)));
        self.send(&buf);
        true
    }
    pub fn sendPLO_SIGN(&self, sign: &LevelSign) -> bool {
        self.send_plo_sign(sign)
    }

    pub fn send_plo_otherplprops(&self, other: &Player) -> bool {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_OTHERPLPROPS).write_gshort(other.id());
        for prop_id in [
            PLPROP_NICKNAME,
            PLPROP_GANI,
            PLPROP_BODYIMG,
            PLPROP_HEADGIF,
            PLPROP_SWORDPOWER,
            PLPROP_SHIELDPOWER,
            PLPROP_HORSEGIF,
            PLPROP_SPRITE,
            PLPROP_COLORS,
            PLPROP_X,
            PLPROP_Y,
            PLPROP_Z,
            PLPROP_CURLEVEL,
        ] {
            buf.write_gchar(prop_id).write(&other.get_prop(prop_id));
        }
        self.send(&buf);
        true
    }
    pub fn sendPLO_OTHERPLPROPS(&self, other: &Player) -> bool {
        self.send_plo_otherplprops(other)
    }

    pub fn send_player_warp(&self, x: i16, y: i16, _z: i16, level_name: &str) -> bool {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_PLAYERWARP)
            .write_gchar((x / 8) as u8)
            .write_gchar((y / 8) as u8)
            .write(level_name.as_bytes());
        self.send(&buf);
        true
    }
    pub fn sendPlayerWarp(&self, x: i16, y: i16, z: i16, level_name: &str) -> bool {
        self.send_player_warp(x, y, z, level_name)
    }

    pub fn send_pto_all_chat(&self, message: &str) -> bool {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_TOALL)
            .write_gshort(self.id())
            .write_gchar(message.len() as u8)
            .write(message.as_bytes());
        if let Some(server) = self.server() {
            let level_name = self.level_name();
            for player in server.get_all_players() {
                if player.is_logged_in()
                    && player.level_name() == level_name
                    && player.has_connection()
                {
                    player.send(&buf);
                }
            }
        }
        true
    }
    pub fn sendPTO_ALL_CHAT(&self, message: &str) -> bool {
        self.send_pto_all_chat(message)
    }

    pub fn send_plo_levelchest(&self, chest: &LevelChest, open: bool) -> bool {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_LEVELCHEST)
            .write_gchar(if open { 1 } else { 0 });
        buf.write_gchar(chest.x as u8).write_gchar(chest.y as u8);
        if !open {
            buf.write_gchar(chest.item_type as u8);
            if chest.sign_index < 0 {
                buf.write_byte(0x1f);
            } else {
                buf.write_gchar(chest.sign_index as u8);
            }
        }
        self.send(&buf);
        true
    }
    pub fn sendPLO_LEVELCHEST(&self, chest: &LevelChest, open: bool) -> bool {
        self.send_plo_levelchest(chest, open)
    }

    pub fn send_plo_levelhorseadd(&self, horse: &LevelHorse) -> bool {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_HORSEADD)
            .write_byte((horse.x * 2.0) as u8)
            .write_byte((horse.y * 2.0) as u8)
            .write_byte((horse.bushes << 2) | (horse.dir & 0x03))
            .write(horse.image.as_bytes());
        self.send(&buf);
        true
    }
    pub fn sendPLO_LEVELHORSEADD(&self, horse: &LevelHorse) -> bool {
        self.send_plo_levelhorseadd(horse)
    }

    pub fn send_plo_shoot(&self, x: i16, y: i16, angle: f32, _owner: &str) -> bool {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_SHOOT)
            .write_gshort(self.id())
            .write_gint(0)
            .write_gchar(x as u8)
            .write_gchar(y as u8)
            .write_gchar(50)
            .write_gchar(angle as u8)
            .write_gchar(0)
            .write_gchar(0)
            .write_gchar(0)
            .write_gchar(0);
        self.send(&buf);
        true
    }
    pub fn sendPLO_SHOOT(&self, x: i16, y: i16, angle: f32, owner: &str) -> bool {
        self.send_plo_shoot(x, y, angle, owner)
    }

    pub fn send_pboard_packet(
        &self,
        x: i16,
        y: i16,
        width: i16,
        height: i16,
        tiles: &[i16],
    ) -> bool {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_BOARDPACKET)
            .write_short(x)
            .write_short(y)
            .write_short(width)
            .write_short(height);
        for tile in tiles {
            buf.write_short(*tile);
        }
        self.send(&buf);
        true
    }
    pub fn sendPBoardPacket(&self, x: i16, y: i16, width: i16, height: i16, tiles: &[i16]) -> bool {
        self.send_pboard_packet(x, y, width, height, tiles)
    }

    pub fn send_plo_baddyprops(&self, id: u32, x: i16, y: i16, image: &str, props: &[u8]) -> bool {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_BADDYPROPS).write_gchar(id as u8);
        if !image.is_empty() {
            buf.write_gchar(image.len() as u8).write(image.as_bytes());
        }
        let _ = (x, y);
        buf.write(props);
        self.send(&buf);
        true
    }
    pub fn sendPLO_BADDYPROPS(&self, id: u32, x: i16, y: i16, image: &str, props: &[u8]) -> bool {
        self.send_plo_baddyprops(id, x, y, image, props)
    }

    pub fn send_plo_levelbaddyprops(&self, baddy: &LevelBaddy) -> bool {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_BADDYPROPS)
            .write_gchar(baddy.id)
            .write(&baddy.get_props(self.version_id()));
        self.send(&buf);
        true
    }
    pub fn sendPLO_LEVELBADDYPROPS(&self, baddy: &LevelBaddy) -> bool {
        self.send_plo_levelbaddyprops(baddy)
    }

    pub fn send_plo_zlibfixweapon(&self) -> bool {
        let script = ZLIB_FIX_SCRIPT.as_bytes();
        let weapon_name = b"-gr_zlib_fix";
        let mut buf = Buffer::new();
        buf.write_byte(PLO_NPCWEAPONADD)
            .write_gchar(weapon_name.len() as u8)
            .write(weapon_name)
            .write_gchar(NPCPROP_IMAGE)
            .write_gchar(1)
            .write_byte(b'-')
            .write_gchar(NPCPROP_SCRIPT)
            .write_gshort(script.len() as u16)
            .write(script);
        self.send(&buf);
        true
    }
    pub fn sendPLO_ZLIBFIXWEAPON(&self) -> bool {
        self.send_plo_zlibfixweapon()
    }

    pub fn send_missing_default_weapon_deletes(&self) {
        self.send_plo_npcweapondel("Bomb");
        self.send_plo_npcweapondel("Bow");
    }
    pub fn sendMissingDefaultWeaponDeletes(&self) {
        self.send_missing_default_weapon_deletes()
    }

    pub fn send_plo_pushaway(&self, index: u16, x: f32, y: f32) -> bool {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_PUSHAWAY)
            .write_short(index as i16)
            .write_gstring(&format!("{x:.0},{y:.0}"));
        self.send(&buf);
        true
    }
    pub fn sendPLO_PUSHAWAY(&self, index: u16, x: f32, y: f32) -> bool {
        self.send_plo_pushaway(index, x, y)
    }

    pub fn send_plo_levelmodtime(&self, mod_time: i64) -> bool {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_LEVELMODTIME)
            .write_gint5(mod_time.max(0) as u64);
        self.send(&buf);
        true
    }
    pub fn sendPLO_LEVELMODTIME(&self, mod_time: i64) -> bool {
        self.send_plo_levelmodtime(mod_time)
    }

    pub fn send_plo_newworldtime(&self, world_time: u32) -> bool {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_NEWWORLDTIME).write_gint4(world_time);
        self.send(&buf);
        true
    }
    pub fn sendPLO_NEWWORLDTIME(&self, world_time: u32) -> bool {
        self.send_plo_newworldtime(world_time)
    }

    pub fn send_plo_ghosticon(&self, enabled: bool) -> bool {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_GHOSTICON).write_byte(enabled as u8);
        self.send(&buf);
        true
    }
    pub fn sendPLO_GHOSTICON(&self, enabled: bool) -> bool {
        self.send_plo_ghosticon(enabled)
    }

    pub fn send_plo_defaultweapon(&self, weapon_id: u8) -> bool {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_DEFAULTWEAPON).write_gchar(weapon_id);
        self.send(&buf);
        true
    }
    pub fn sendPLO_DEFAULTWEAPON(&self, weapon_id: u8) -> bool {
        self.send_plo_defaultweapon(weapon_id)
    }

    pub fn send_plo_npcprops(&self, npc: &NPC) -> bool {
        let snapshot = npc.snapshot();
        let mut buf = Buffer::new();
        buf.write_byte(PLO_NPCPROPS).write_gint(snapshot.id);
        buf.write_gchar(NPCPROP_IMAGE)
            .write_gchar(snapshot.image.len() as u8)
            .write(snapshot.image.as_bytes());
        let mut script = npc_client_side_script(&snapshot.script);
        if self.version_id() >= 300 {
            script.clear();
        }
        script.truncate(0x3fff);
        buf.write_gchar(NPCPROP_SCRIPT)
            .write_gshort(script.len() as u16)
            .write(script.as_bytes());
        buf.write_gchar(NPCPROP_X)
            .write_gchar((snapshot.x / 8) as u8)
            .write_gchar(NPCPROP_Y)
            .write_gchar((snapshot.y / 8) as u8);
        if snapshot.z != 0 {
            let z = (snapshot.z / 16).clamp(-50, 170);
            buf.write_gchar(NPCPROP_Z).write_gchar((z + 50) as u8);
        }
        let mut visible = snapshot.vis_flags;
        if visible == 0 && (!snapshot.image.is_empty() || !snapshot.script.is_empty()) {
            visible = NPCVISFLAG_VISIBLE;
        }
        buf.write_gchar(NPCPROP_VISFLAGS)
            .write_gchar(visible)
            .write_gchar(NPCPROP_ID)
            .write_gint(snapshot.id)
            .write_gchar(NPCPROP_SPRITE)
            .write_gchar(snapshot.sprite);
        let mut message = snapshot.character.chat_message.clone();
        message.truncate(255);
        buf.write_gchar(NPCPROP_MESSAGE)
            .write_gchar(message.len() as u8)
            .write(message.as_bytes());
        let nickname = if snapshot.character.nickname.is_empty() {
            snapshot.npc_name.clone()
        } else {
            snapshot.character.nickname.clone()
        };
        if !nickname.is_empty() {
            buf.write_gchar(NPCPROP_NICKNAME)
                .write_gchar(nickname.len() as u8)
                .write(nickname.as_bytes());
        }
        let mut gani = snapshot.character.gani.clone();
        if gani.is_empty()
            && snapshot.image == "#c#"
            && (self.version_id() == 0 || self.version_id() > 141)
        {
            gani = "idle".to_string();
        }
        if !gani.is_empty() {
            buf.write_gchar(NPCPROP_GANI)
                .write_gchar(gani.len() as u8)
                .write(gani.as_bytes());
        }
        if snapshot.character.arrows != 0 {
            buf.write_gchar(NPCPROP_ARROWS)
                .write_gchar(snapshot.character.arrows as u8);
        }
        if snapshot.character.bombs != 0 {
            buf.write_gchar(NPCPROP_BOMBS)
                .write_gchar(snapshot.character.bombs as u8);
        }
        if snapshot.character.glove_power != 0 {
            buf.write_gchar(NPCPROP_GLOVEPOWER)
                .write_gchar(snapshot.character.glove_power as u8);
        }
        if snapshot.character.gralats != 0 {
            buf.write_gchar(NPCPROP_RUPEES)
                .write_gint(snapshot.character.gralats as u32);
        }
        if snapshot.character.sword_power != 0 || !snapshot.character.sword_image.is_empty() {
            buf.write_gchar(NPCPROP_SWORDIMAGE)
                .write_gchar((snapshot.character.sword_power + 30) as u8)
                .write_gchar(snapshot.character.sword_image.len() as u8)
                .write(snapshot.character.sword_image.as_bytes());
        }
        if snapshot.character.shield_power != 0 || !snapshot.character.shield_image.is_empty() {
            buf.write_gchar(NPCPROP_SHIELDIMAGE)
                .write_gchar((snapshot.character.shield_power + 10) as u8)
                .write_gchar(snapshot.character.shield_image.len() as u8)
                .write(snapshot.character.shield_image.as_bytes());
        }
        if snapshot.character.colors != [0; 5] {
            buf.write_gchar(NPCPROP_COLORS);
            for color in snapshot.character.colors {
                buf.write_gchar(color);
            }
        }
        if snapshot.block_flags != 0 {
            buf.write_gchar(NPCPROP_BLOCKFLAGS)
                .write_gchar(snapshot.block_flags);
        }
        if !snapshot.character.horse_image.is_empty() {
            buf.write_gchar(NPCPROP_HORSEIMAGE)
                .write_gchar(snapshot.character.horse_image.len() as u8)
                .write(snapshot.character.horse_image.as_bytes());
        }
        if !snapshot.character.head_image.is_empty() {
            let head_len = snapshot.character.head_image.len().min(155);
            buf.write_gchar(NPCPROP_HEADIMAGE)
                .write_gchar((head_len + 100) as u8)
                .write(&snapshot.character.head_image.as_bytes()[..head_len]);
        }
        if !snapshot.character.body_image.is_empty() {
            buf.write_gchar(NPCPROP_BODYIMAGE)
                .write_gchar(snapshot.character.body_image.len() as u8)
                .write(snapshot.character.body_image.as_bytes());
        }
        if self.version_id() >= 230 {
            buf.write_gchar(NPCPROP_GMAPLEVELX)
                .write_gchar(0)
                .write_gchar(NPCPROP_GMAPLEVELY)
                .write_gchar(0)
                .write_gchar(NPCPROP_X2)
                .write_gshort(encode_signed_gshort_coord(snapshot.x))
                .write_gchar(NPCPROP_Y2)
                .write_gshort(encode_signed_gshort_coord(snapshot.y));
            if snapshot.z != 0 {
                buf.write_gchar(NPCPROP_Z2)
                    .write_gshort(encode_signed_gshort_coord(snapshot.z));
            }
        }
        self.send(&buf);
        if self.version_id() >= 300 {
            self.send_npc_bytecode(npc);
        }
        true
    }
    fn send_npc_bytecode(&self, npc: &NPC) {
        let snapshot = npc.snapshot();
        let Some(source) = npc_runtime::clientside_gs2(&snapshot.script) else {
            return;
        };
        if source.trim().is_empty() {
            return;
        }
        let compiled = npc_runtime::compile_gs2_script(&source);
        if !compiled.err_text.is_empty() || compiled.bytecode.is_empty() {
            if !compiled.err_text.is_empty() {
                if let Some(server) = self.server() {
                    server.logger.warning(&format!(
                        "Failed to compile NPC {} clientside: {}",
                        snapshot.id, compiled.err_text
                    ));
                }
            }
            return;
        }
        let mut payload = Buffer::new();
        payload
            .write_gchar(PLO_NPCBYTECODE)
            .write_gint(snapshot.id)
            .write(&compiled.bytecode);
        self.send_raw_data_payload(&payload.data);
    }
    pub fn sendPLO_NPCPROPS(&self, npc: &NPC) -> bool {
        self.send_plo_npcprops(npc)
    }
}

impl Server {
    pub fn send_rc_chat(&self, message: &str) {
        for player in self.get_all_players() {
            if player.player_type() & PLTYPE_ANYRC != 0 {
                player.send_plo_rc_chat(message);
            }
        }
    }
    pub fn sendRCChat(&self, message: &str) {
        self.send_rc_chat(message)
    }

    pub fn send_to_nc(&self, message: &str) {
        let message = message
            .split('\n')
            .next()
            .unwrap_or_default()
            .trim_end_matches('\r');
        if message.is_empty() {
            return;
        }
        if !self.gs2_log_hook_active.swap(true, Ordering::AcqRel) {
            let args = vec![message.to_string()];
            self.run_server_side_event_for_active_scripts("onLogMessage", None, &args);
            let tag = first_bracket_tag(message);
            if !tag.is_empty() {
                let args = vec![tag, message.to_string()];
                self.run_server_side_event_for_active_scripts("onFolderLog", None, &args);
            }
            self.gs2_log_hook_active.store(false, Ordering::Release);
        }
        for player in self.get_all_players() {
            if player.player_type() & PLTYPE_ANYNC != 0 {
                player.send_plo_rc_chat(message);
            }
        }
    }
    pub fn sendToNC(&self, message: &str) {
        self.send_to_nc(message)
    }
    pub fn send_nc_notice(&self, message: &str, exclude: Option<&Arc<Player>>) {
        let message = message
            .split('\n')
            .next()
            .unwrap_or_default()
            .trim_end_matches('\r');
        if message.is_empty() {
            return;
        }
        for player in self.get_all_players() {
            if exclude
                .map(|value| {
                    same_control_session_rust(value, &player)
                        || same_remote_control_session_rust(value, &player)
                })
                .unwrap_or(false)
            {
                continue;
            }
            if !player.is_logged_in()
                || (player.player_type() & PLTYPE_ANYNC == 0
                    && (player.player_type() & PLTYPE_ANYRC == 0
                        || !player.has_right(PLPERM_NPCCONTROL)))
            {
                continue;
            }
            player.send_plo_rc_chat(message);
        }
    }
    pub fn sendNCNotice(&self, message: &str, exclude: Option<&Arc<Player>>) {
        self.send_nc_notice(message, exclude)
    }

    pub fn allowed_versions_listserver_text(&self) -> String {
        self.allowed_versions.read().unwrap().join(",")
    }
    pub fn allowedVersionsListserverText(&self) -> String {
        self.allowed_versions_listserver_text()
    }

    pub fn refresh_player_list_entry(&self, player: &Arc<Player>) {
        if !is_player_list_player(player) {
            return;
        }
        self.broadcast_player_list_entry_to_clients(player);
        for other in self.get_all_players() {
            if other.id() == player.id() || !other.is_logged_in() {
                continue;
            }
            if other.player_type() & PLTYPE_ANYCONTROL != 0 {
                let entry = self.player_list_entry_for(player);
                other.send_plo_addplayer(&entry);
            }
        }
        self.add_player_to_listservers(player);
    }
    pub fn refreshPlayerListEntry(&self, player: &Arc<Player>) {
        self.refresh_player_list_entry(player)
    }

    fn broadcast_player_list_entry_to_clients(&self, player: &Arc<Player>) {
        if !should_send_client_player_list_entry(player) {
            return;
        }
        let props = if player.player_type() & PLTYPE_ANYCLIENT != 0 {
            player.send_props_with_array(&get_login_props())
        } else {
            player.send_props_with_array(&get_rc_login_props())
        };
        if props.is_empty() {
            return;
        }
        let mut packet = other_props_packet(player.id(), &props);
        packet.push(b'\n');
        for other in self.get_all_players() {
            if other.id() != player.id()
                && other.is_logged_in()
                && other.player_type() & PLTYPE_ANYCLIENT != 0
                && other.has_output_or_connection()
            {
                other.send_packet(&packet);
            }
        }
    }

    fn player_list_entry_for(&self, player: &Arc<Player>) -> Arc<Player> {
        if player.player_type() & PLTYPE_ANYCLIENT != 0 {
            return player.clone();
        }
        let account = player.account_name().trim().to_string();
        if account.is_empty() || player.player_type() & (PLTYPE_ANYRC | PLTYPE_ANYNC) == 0 {
            return player.clone();
        }
        self.get_all_players()
            .into_iter()
            .find(|other| {
                !Arc::ptr_eq(other, player)
                    && other.is_logged_in()
                    && other.player_type() & PLTYPE_ANYCLIENT != 0
                    && other.account_name().eq_ignore_ascii_case(&account)
            })
            .unwrap_or_else(|| player.clone())
    }

    fn playerListEntryFor(&self, player: &Arc<Player>) -> Arc<Player> {
        self.player_list_entry_for(player)
    }
}

fn same_control_session_rust(a: &Arc<Player>, b: &Arc<Player>) -> bool {
    if Arc::ptr_eq(a, b) || (a.id() != 0 && a.id() == b.id()) {
        return true;
    }
    a.player_type() & PLTYPE_ANYCONTROL != 0
        && b.player_type() & PLTYPE_ANYCONTROL != 0
        && !a.account_name().is_empty()
        && a.account_name().eq_ignore_ascii_case(&b.account_name())
}

fn same_remote_control_session_rust(a: &Arc<Player>, b: &Arc<Player>) -> bool {
    if a.player_type() & PLTYPE_ANYCONTROL == 0 || b.player_type() & PLTYPE_ANYCONTROL == 0 {
        return false;
    }
    let remote = |player: &Arc<Player>| {
        player
            .state
            .lock()
            .unwrap()
            .conn
            .as_ref()
            .and_then(|conn| conn.peer_addr().ok())
    };
    remote(a)
        .zip(remote(b))
        .map(|(left, right)| left == right)
        .unwrap_or(false)
}

fn other_props_packet(player_id: u16, props: &[u8]) -> Vec<u8> {
    let mut buf = Buffer::new();
    buf.write_byte(PLO_OTHERPLPROPS)
        .write_gshort(player_id)
        .write(props);
    buf.data
}

impl Player {
    pub fn finish_deferred_client_login(&self) {
        self.finish_client_login();
        self.state.lock().unwrap().loaded = true;
        self.send_post_login_tail();
        if let Some(server) = self.server() {
            server.run_server_side_event_for_active_scripts(
                "onPlayerLogin",
                self.self_arc().as_ref(),
                &[],
            );
        }
        self.state.lock().unwrap().login_pending = false;
    }
    pub fn finishDeferredClientLogin(&self) {
        self.finish_deferred_client_login()
    }

    pub fn send_staff_guilds(&self) {
        let Some(server) = self.server() else { return };
        let value = server.settings.get("staffguilds");
        if value.is_empty() {
            return;
        }
        let mut buf = Buffer::new();
        buf.write_byte(PLO_STAFFGUILDS);
        let mut first = true;
        for guild in value.split(',').map(str::trim).filter(|v| !v.is_empty()) {
            if !first {
                buf.write_byte(b',');
            }
            first = false;
            buf.write(format!("\"{guild}\"").as_bytes());
        }
        buf.write_byte(b'\n');
        self.send_packet(&buf.data);
    }
    pub fn sendStaffGuilds(&self) {
        self.send_staff_guilds()
    }

    pub fn send_status_list(&self) {
        let Some(server) = self.server() else { return };
        let value = nonempty(&server.settings.get("playerlisticons"))
            .or_else(|| nonempty(&server.settings.get("statuslist")))
            .unwrap_or_else(|| {
                "Online,Away,DND,Eating,Hiding,No PMs,RPing,Sparring,PKing".to_string()
            });
        let mut buf = Buffer::new();
        buf.write_byte(PLO_STATUSLIST);
        let mut first = true;
        for status in value.split(',').map(str::trim).filter(|v| !v.is_empty()) {
            if !first {
                buf.write_byte(b',');
            }
            first = false;
            buf.write(status.as_bytes());
        }
        buf.write_byte(b'\n');
        self.send_packet(&buf.data);
    }
    pub fn sendStatusList(&self) {
        self.send_status_list()
    }

    pub fn send_rc_post_login_tail(&self) {
        self.send_staff_guilds();
        self.send_plo_unknown190();
        if let Some(server) = self.server() {
            let Some(this) = self.self_ref.lock().unwrap().upgrade() else {
                return;
            };
            server.broadcast_player_list_entry_to_clients(&this);

            // Existing control sessions see the newly logged-in session.  A
            // control connection is represented by its matching client
            // session when one exists, exactly as in playerListEntryFor.
            let existing_controls = server
                .get_all_players()
                .into_iter()
                .filter(|other| {
                    other.id() != self.id()
                        && other.is_logged_in()
                        && other.player_type() & PLTYPE_ANYCONTROL != 0
                })
                .collect::<Vec<_>>();
            let entry = server.player_list_entry_for(&this);
            for other in existing_controls {
                other.send_plo_addplayer(&entry);
            }

            let mut existing_rc = Vec::new();
            let mut existing_nc = Vec::new();
            for other in server.get_all_players() {
                if other.id() == self.id() || !other.is_logged_in() {
                    continue;
                }
                if other.player_type() & PLTYPE_ANYNC != 0 {
                    if self.has_right(PLPERM_NPCCONTROL)
                        && !other
                            .account_name()
                            .eq_ignore_ascii_case(&self.account_name())
                    {
                        existing_nc.push(other.nc_display_name());
                    }
                    continue;
                }
                if other.player_type() & PLTYPE_ANYRC != 0 {
                    existing_rc.push(other.rc_display_name());
                }
                let other_entry = server.player_list_entry_for(&other);
                self.send_plo_addplayer(&other_entry);
            }
            for name in existing_rc {
                self.send_plo_rc_chat(&format!("New RC: {name}"));
            }
            for name in existing_nc {
                self.send_plo_rc_chat(&format!("New NC: {name}"));
            }
            server.send_rc_chat(&format!("New RC: {}", self.rc_display_name()));
        }
    }
    pub fn sendRCPostLoginTail(&self) {
        self.send_rc_post_login_tail()
    }

    pub fn send_nc_post_login_tail(&self) {
        if self.state.lock().unwrap().nc_post_login_sent {
            return;
        }
        self.state.lock().unwrap().nc_post_login_sent = true;
        self.send_nc_npc_list();
        self.send_nc_class_list();
        if let Some(server) = self.server() {
            self.send_plo_rc_chat(&format!(
                "Welcome to the NPC-Server for {}",
                server.configured_name()
            ));
            for other in server.get_all_players() {
                if other.id() != self.id()
                    && other.is_logged_in()
                    && other.player_type() & PLTYPE_ANYNC != 0
                    && !other
                        .account_name()
                        .eq_ignore_ascii_case(&self.account_name())
                {
                    self.send_plo_rc_chat(&format!("New NC: {}", other.nc_display_name()));
                }
            }
            let has_existing_same_account = server.get_all_players().into_iter().any(|other| {
                other.id() != self.id()
                    && other.is_logged_in()
                    && other.player_type() & PLTYPE_ANYNC != 0
                    && other
                        .account_name()
                        .eq_ignore_ascii_case(&self.account_name())
            });
            if !has_existing_same_account {
                if let Some(this) = self.self_ref.lock().unwrap().upgrade() {
                    server.send_nc_notice(
                        &format!("New NC: {}", self.nc_display_name()),
                        Some(&this),
                    );
                }
            }
        }
    }
    pub fn sendNCPostLoginTail(&self) {
        self.send_nc_post_login_tail()
    }

    fn rc_display_name(&self) -> String {
        let account = self.account_name().trim().to_string();
        let nick = self.nickname().trim().to_string();
        if nick.is_empty() {
            return account;
        }
        if nick.eq_ignore_ascii_case(&account) {
            return format!("*{account} ({account})");
        }
        if account.is_empty() {
            nick
        } else {
            format!("{nick} ({account})")
        }
    }

    fn rc_chat_name(&self) -> String {
        let nickname = self.nickname().trim().to_string();
        if nickname.is_empty() {
            self.account_name().trim().to_string()
        } else {
            nickname
        }
    }
    fn nc_display_name(&self) -> String {
        let account = self.account_name();
        if account.is_empty() {
            self.nickname()
        } else {
            account
        }
    }

    fn send_nc_class_list(&self) {
        let Some(server) = self.server() else { return };
        let mut names = server
            .classes
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        names.sort();
        for name in names {
            let mut buf = Buffer::new();
            buf.write_byte(PLO_NC_CLASSADD).write(name.as_bytes());
            self.send(&buf);
        }
    }

    pub fn send_post_login_tail(&self) {
        self.send_staff_guilds();
        self.send_status_list();
        let own_props = if self.player_type() & PLTYPE_ANYCLIENT != 0 {
            self.send_props_with_array(&get_login_props())
        } else {
            self.send_props_with_array(&get_rc_login_props())
        };
        if let Some(server) = self.server() {
            for other in server.get_all_players() {
                if other.id() == self.id() || !other.is_logged_in() {
                    continue;
                }
                if !is_player_list_player(&other) {
                    continue;
                }

                // Publish the newly logged-in player to the existing
                // player-list recipients.  Client recipients use the full
                // client mask; control recipients use the compact RC mask.
                if other.player_type() & PLTYPE_ANYCLIENT != 0 {
                    if should_send_client_player_list_entry(self) && !own_props.is_empty() {
                        let mut packet = other_props_packet(self.id(), &own_props);
                        packet.push(b'\n');
                        other.send_packet(&packet);
                    }
                } else if other.player_type() & PLTYPE_ANYCONTROL != 0 {
                    other.send_plo_addplayer(self);
                }

                // A client also receives each already connected player, with
                // the mask selected by the source player's protocol type.
                if self.player_type() & PLTYPE_ANYCLIENT != 0 {
                    let props = if other.player_type() & PLTYPE_ANYCLIENT != 0 {
                        other.send_props_with_array(&get_login_props())
                    } else if other.player_type() & PLTYPE_ANYCONTROL != 0 {
                        other.send_props_with_array(&get_rc_login_props())
                    } else {
                        Vec::new()
                    };
                    if should_send_client_player_list_entry(&other) && !props.is_empty() {
                        let mut packet = other_props_packet(other.id(), &props);
                        packet.push(b'\n');
                        self.send_packet(&packet);
                    }
                }
            }
        }
        if self.player_type() & PLTYPE_ANYCLIENT != 0
            && self.version_id() > 0
            && self.version_id() < 300
        {
            self.send_plo_listprocesses();
        }
    }
    pub fn sendPostLoginTail(&self) {
        self.send_post_login_tail()
    }

    pub fn login_warp_target(&self) -> (String, f64, f64) {
        let account = self.account.lock().unwrap();
        if !account.level_name.is_empty() {
            return (
                account.level_name.clone(),
                account.get_x() as f64,
                account.get_y() as f64,
            );
        }
        drop(account);
        let Some(server) = self.server() else {
            return ("onlinestartlocal.nw".to_string(), 32.0, 32.0);
        };
        let level = nonempty(&server.settings.get("startlevel"))
            .or_else(|| nonempty(&server.settings.get("unstickmelevel")))
            .unwrap_or_else(|| "onlinestartlocal.nw".to_string());
        (level, 32.0, 32.0)
    }
    pub fn loginWarpTarget(&self) -> (String, f64, f64) {
        self.login_warp_target()
    }

    pub fn warp(&self, level_name: &str, x: f64, y: f64, client_mod_time: i64) {
        let Some(server) = self.server() else { return };
        let was_loaded = self.state.lock().unwrap().loaded;
        let clean = clean_level_name(level_name);
        let (existing, level_exists) = server.find_level(&clean);
        let Some(level) = existing.or_else(|| server.load_level(&clean)) else {
            server
                .logger
                .error(&format!("warp: Failed to load level: {clean}"));
            self.send_plo_warpfailed(level_name);
            return;
        };

        let file_version_empty = level.state.read().unwrap().file_version.is_empty();
        if !level_exists && file_version_empty {
            let paths = [
                format!("world/{clean}.nw"),
                format!("world/levels/{clean}.nw"),
                format!("world/{clean}.zelda"),
                format!("world/levels/{clean}.zelda"),
                format!("world/{clean}.graal"),
                format!("world/levels/{clean}.graal"),
            ];
            let mut loaded = false;
            for path in paths {
                if level.load_level(&server, &path) {
                    loaded = true;
                    server
                        .logger
                        .debug(&format!("warp: Loaded level from {path}"));
                    break;
                }
            }
            if !loaded {
                server.delete_level_if_same(&clean, &level);
                server.logger.warning(&format!(
                    "warp: Could not load level file for {clean}, rejecting warp"
                ));
                self.send_plo_warpfailed(level_name);
                return;
            }
        }

        let old_level = self.current_level();
        let player_arc = self.self_arc();
        if let Some(old) = old_level {
            if was_loaded {
                server.run_server_side_level_event_for_player(
                    &old,
                    "onPlayerLeaves",
                    player_arc.as_ref(),
                    &[],
                );
            }
            old.remove_player(self);
        }
        let account_name = self.account_name();
        self.set_account_name(&account_name);
        {
            let mut account = self.account.lock().unwrap();
            account.set_x(x as f32);
            account.set_y(y as f32);
            account.level_name = level_name.to_string();
        }
        self.set_current_level(Some(level.clone()));
        level.add_player(self);
        if was_loaded {
            server.run_server_side_level_event_for_player(
                &level,
                "onPlayerEnters",
                player_arc.as_ref(),
                &[],
            );
        }
        let (player_x, player_y, player_z) = {
            let account = self.account.lock().unwrap();
            (account.x, account.y, account.z)
        };
        self.send_player_warp(player_x, player_y, player_z, level_name);
        self.send_level_data(
            &level,
            level_name,
            client_mod_time,
            false,
            client_mod_time == 0,
        );
        self.state.lock().unwrap().loaded = true;
        server.logger.debug(&format!(
            "warp: Player {} warped to {} at ({:.0}, {:.0})",
            self.account_name(),
            level_name,
            x,
            y
        ));
    }
    pub fn Warp(&self, level_name: &str, x: f64, y: f64, client_mod_time: i64) {
        self.warp(level_name, x, y, client_mod_time)
    }

    pub fn send_level_data(
        &self,
        level: &Arc<Level>,
        level_name: &str,
        client_mod_time: i64,
        from_adjacent: bool,
        force_board: bool,
    ) {
        self.send_plo_levelname(level_name);
        let level_mod_time = level
            .get_mod_time()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if force_board || client_mod_time != level_mod_time {
            let board = level.get_board_packet();
            let mut raw = Buffer::new();
            raw.write_byte(PLO_RAWDATA)
                .write_gint(board.len() as u32)
                .write_byte(b'\n')
                .write(&board);
            self.send_packet(&raw.data);
        }
        self.send_plo_levelmodtime(level_mod_time);
        for link in level.links() {
            self.send_plo_levellink_full(&link);
        }
        for sign in level.signs() {
            self.send_plo_sign(&sign);
        }
        if !from_adjacent {
            self.send_plo_levelboardchanges(Some(level), UNIX_EPOCH);
            for chest in level.chests() {
                self.send_plo_levelchest(&chest, self.has_chest(&level.chest_key(&chest)));
            }
            let state = level.state.read().unwrap();
            let horses = state.horses.clone();
            let baddies = state.baddies.values().cloned().collect::<Vec<_>>();
            drop(state);
            for horse in horses {
                self.send_plo_levelhorseadd(&horse);
            }
            for baddy in baddies {
                self.send_plo_levelbaddyprops(&baddy);
            }
        }
        self.send_plo_ghosticon(false);
        if !from_adjacent {
            self.send_plo_isleader();
        }
        if let Some(server) = self.server() {
            self.send_plo_newworldtime(server.get_server_time());
        }
        self.send_plo_setactivelevel(level_name);
        let npcs = level.get_npcs();
        for npc in npcs {
            self.send_plo_npcprops(&npc);
        }
    }
    pub fn sendLevelData(
        &self,
        level: &Arc<Level>,
        level_name: &str,
        client_mod_time: i64,
        from_adjacent: bool,
        force_board: bool,
    ) {
        self.send_level_data(
            level,
            level_name,
            client_mod_time,
            from_adjacent,
            force_board,
        )
    }

    pub fn process_timeout(&self) {
        let (player_type, last_data, last_movement, last_chat) = {
            let state = self.state.lock().unwrap();
            (
                state.player_type,
                state.last_data,
                state.last_movement,
                state.last_chat,
            )
        };
        if player_type & (PLTYPE_NPCSERVER | PLTYPE_ANYCONTROL) != 0
            || player_type & PLTYPE_ANYCLIENT == 0
        {
            return;
        }
        if let Some(server) = self.server() {
            let max_no_movement = server.settings.get_int("maxnomovement", 1200);
            if server.settings.get_bool("disconnectifnotmoved", false)
                && last_movement.elapsed().as_secs() as i32 > max_no_movement
                && last_chat.elapsed().as_secs() as i32 > max_no_movement
            {
                server.logger.info(&format!(
                    "Client {} has been disconnected due to inactivity.",
                    self.account_name()
                ));
                self.disconnect_with_message("You have been disconnected due to inactivity.");
                return;
            }
        }
        if last_data.elapsed() > Duration::from_secs(300) {
            self.disconnect();
        }
    }

    fn disconnect_with_message(&self, message: &str) {
        let mut packet = Vec::with_capacity(message.len() + 2);
        packet.push(PLO_DISCMESSAGE);
        packet.extend_from_slice(message.as_bytes());
        packet.push(b'\n');
        self.send_immediate_packet(&packet);
        self.disconnect();
    }

    fn drop_items_on_death(&self, level: &Arc<Level>) {
        let Some(server) = self.server() else {
            return;
        };
        if !server.settings.get_bool("dropitemsdead", true) {
            return;
        }
        let min_gralats = server.settings.get_int("mindeathgralats", 1);
        let max_gralats = server.settings.get_int("maxdeathgralats", 50);
        let (mut drop_gralats, mut drop_arrows, mut drop_bombs) = {
            let account = self.account.lock().unwrap();
            let mut gralats = if max_gralats > 0 {
                (rand::random::<u32>() % max_gralats as u32) as i32
            } else {
                0
            };
            if gralats < min_gralats {
                gralats = min_gralats;
            }
            if max_gralats > 0 {
                gralats = gralats.min(max_gralats).min(account.character.gralats);
            } else {
                gralats = 0;
            }
            let mut arrows = i32::from(rand::random::<u8>() % 4);
            let mut bombs = i32::from(rand::random::<u8>() % 4);
            arrows = arrows.min(account.character.arrows / 5);
            bombs = bombs.min(account.character.bombs / 5);
            (gralats, arrows, bombs)
        };
        {
            let mut account = self.account.lock().unwrap();
            account.character.gralats -= drop_gralats;
            account.character.arrows -= drop_arrows * 5;
            account.character.bombs -= drop_bombs * 5;
            account.rupees = account.character.gralats.max(0) as u32;
        }
        let (rupees, arrows, bombs) = {
            let account = self.account.lock().unwrap();
            (
                account.rupees,
                account.character.arrows,
                account.character.bombs,
            )
        };
        let mut props = Buffer::new();
        props
            .write_byte(PLO_PLAYERPROPS)
            .write_gchar(PLPROP_RUPEESCOUNT)
            .write_gint(rupees)
            .write_gchar(PLPROP_ARROWSCOUNT)
            .write_gchar(arrows.clamp(0, 255) as u8)
            .write_gchar(PLPROP_BOMBSCOUNT)
            .write_gchar(bombs.clamp(0, 255) as u8);
        self.send(&props);

        let (player_x, player_y) = self.position();
        let drop_position = || {
            (
                f32::from(player_x) / 16.0 + 1.5 + f32::from(rand::random::<u8>() % 8) - 2.0,
                f32::from(player_y) / 16.0 + 2.0 + f32::from(rand::random::<u8>() % 8) - 2.0,
            )
        };
        while drop_gralats > 0 {
            let (item_type, value) = if drop_gralats >= 100 {
                (ITEM_GOLD_RUPEE, 100)
            } else if drop_gralats >= 30 {
                (ITEM_RED_RUPEE, 30)
            } else if drop_gralats >= 5 {
                (ITEM_BLUE_RUPEE, 5)
            } else {
                (ITEM_GREEN_RUPEE, 1)
            };
            drop_gralats -= value;
            let (x, y) = drop_position();
            if level.add_item_for_server(&server, x, y, item_type) {
                let mut packet = Buffer::new();
                packet
                    .write_byte(PLO_ITEMADD)
                    .write_gchar((x * 2.0) as u8)
                    .write_gchar((y * 2.0) as u8)
                    .write_gchar(item_type as u8);
                self.send_to_current_level_except_self(&packet.data);
            }
        }
        for item_type in [ITEM_DARTS, ITEM_BOMBS] {
            let count = if item_type == ITEM_DARTS {
                drop_arrows
            } else {
                drop_bombs
            };
            for _ in 0..count {
                let (x, y) = drop_position();
                if level.add_item_for_server(&server, x, y, item_type) {
                    let mut packet = Buffer::new();
                    packet
                        .write_byte(PLO_ITEMADD)
                        .write_gchar((x * 2.0) as u8)
                        .write_gchar((y * 2.0) as u8)
                        .write_gchar(item_type as u8);
                    self.send_to_current_level_except_self(&packet.data);
                }
            }
        }
    }

    pub fn has_right(&self, permission: i32) -> bool {
        self.account.lock().unwrap().admin_rights & permission != 0
    }
    pub fn hasRight(&self, permission: i32) -> bool {
        self.has_right(permission)
    }

    pub fn add_weapon(&self, weapon_name: &str) -> bool {
        let name = weapon_name.trim();
        if name.is_empty() || !self.can_add_weapon(name) {
            return false;
        }
        let mut account = self.account.lock().unwrap();
        if account
            .weapon_list
            .iter()
            .any(|value| value.trim().eq_ignore_ascii_case(name))
        {
            return false;
        }
        account.weapon_list.push(name.to_string());
        true
    }
    pub fn addWeapon(&self, weapon_name: &str) -> bool {
        self.add_weapon(weapon_name)
    }
    pub fn can_add_weapon(&self, weapon_name: &str) -> bool {
        if weapon_name.trim().is_empty() {
            return false;
        }
        if default_weapon_item_id(weapon_name).is_some() {
            return true;
        }
        self.server()
            .and_then(|server| server.get_weapon(weapon_name))
            .is_some()
    }
    pub fn canAddWeapon(&self, weapon_name: &str) -> bool {
        self.can_add_weapon(weapon_name)
    }
    pub fn has_account_weapon(&self, weapon_name: &str) -> bool {
        self.account
            .lock()
            .unwrap()
            .weapon_list
            .iter()
            .any(|value| value.trim().eq_ignore_ascii_case(weapon_name.trim()))
    }
    pub fn hasAccountWeapon(&self, weapon_name: &str) -> bool {
        self.has_account_weapon(weapon_name)
    }
    pub fn has_chest(&self, chest_key: &str) -> bool {
        self.account
            .lock()
            .unwrap()
            .chest_list
            .iter()
            .any(|value| value == chest_key)
    }
    pub fn hasChest(&self, chest_key: &str) -> bool {
        self.has_chest(chest_key)
    }
    pub fn add_chest(&self, chest_key: &str) {
        if chest_key.is_empty() {
            return;
        }
        let mut account = self.account.lock().unwrap();
        if !account.chest_list.iter().any(|value| value == chest_key) {
            account.chest_list.push(chest_key.to_string());
        }
    }
    pub fn addChest(&self, chest_key: &str) {
        self.add_chest(chest_key)
    }
    pub fn delete_weapon(&self, weapon_name: &str) {
        self.account
            .lock()
            .unwrap()
            .weapon_list
            .retain(|value| value != weapon_name);
    }
    pub fn deleteWeapon(&self, weapon_name: &str) {
        self.delete_weapon(weapon_name)
    }
    pub fn apply_level_item(&self, item_type: LevelItemType) -> bool {
        if item_name(item_type).is_empty() {
            return false;
        }
        let (props, weapon) = self.item_reward(item_type);
        if !props.is_empty() {
            let mut packet = Buffer::new();
            packet.write_byte(PLO_PLAYERPROPS).write(&props);
            self.send(&packet);
        }
        if let Some(weapon) = weapon {
            self.send_account_weapon(&weapon);
        }
        self.save_account();
        true
    }
    pub fn applyLevelItem(&self, item_type: LevelItemType) -> bool {
        self.apply_level_item(item_type)
    }

    fn item_reward(&self, item_type: LevelItemType) -> (Vec<u8>, Option<String>) {
        let mut buf = Buffer::new();
        let mut account = self.account.lock().unwrap();
        match item_type {
            ITEM_GREEN_RUPEE | ITEM_BLUE_RUPEE | ITEM_RED_RUPEE | ITEM_GOLD_RUPEE => {
                let add = match item_type {
                    ITEM_BLUE_RUPEE => 5,
                    ITEM_RED_RUPEE => 30,
                    ITEM_GOLD_RUPEE => 100,
                    _ => 1,
                };
                account.character.gralats = (account.character.gralats + add).min(9_999_999);
                buf.write_gchar(PLPROP_RUPEESCOUNT)
                    .write_gint(account.character.gralats as u32);
            }
            ITEM_BOMBS => {
                account.character.bombs = (account.character.bombs + 5).min(99);
                buf.write_gchar(PLPROP_BOMBSCOUNT)
                    .write_gchar(account.character.bombs as u8);
            }
            ITEM_DARTS => {
                account.character.arrows = (account.character.arrows + 5).min(99);
                buf.write_gchar(PLPROP_ARROWSCOUNT)
                    .write_gchar(account.character.arrows as u8);
            }
            ITEM_HEART => {
                account.character.hitpoints =
                    (account.character.hitpoints + 1).min(account.max_hitpoints as i32);
                buf.write_gchar(PLPROP_CURPOWER)
                    .write_gchar((account.character.hitpoints * 2) as u8);
            }
            ITEM_GLOVE1 | ITEM_GLOVE2 => {
                account.character.glove_power = if item_type == ITEM_GLOVE2 {
                    3
                } else {
                    account.character.glove_power.max(2)
                };
                buf.write_gchar(PLPROP_GLOVEPOWER)
                    .write_gchar(account.character.glove_power as u8);
            }
            ITEM_BOW | ITEM_BOMB | ITEM_SUPER_BOMB | ITEM_FIREBALL | ITEM_FIREBLAST
            | ITEM_NUKESHOT | ITEM_JOLTBOMB => {
                let name = item_name(item_type).to_string();
                if account
                    .weapon_list
                    .iter()
                    .any(|value| value.eq_ignore_ascii_case(&name))
                {
                    return (Vec::new(), None);
                }
                account.weapon_list.push(name.clone());
                return (Vec::new(), Some(name));
            }
            ITEM_SHIELD | ITEM_MIRROR_SHIELD | ITEM_LIZARD_SHIELD => {
                let desired = match item_type {
                    ITEM_LIZARD_SHIELD => 3,
                    ITEM_MIRROR_SHIELD => 2,
                    _ => 1,
                };
                account.character.shield_power = account.character.shield_power.max(desired);
                buf.write_gchar(PLPROP_SHIELDPOWER)
                    .write_gchar((account.character.shield_power + 10) as u8);
            }
            ITEM_SWORD | ITEM_BATTLE_AXE | ITEM_LIZARD_SWORD | ITEM_GOLDEN_SWORD => {
                let desired = match item_type {
                    ITEM_GOLDEN_SWORD => 4,
                    ITEM_LIZARD_SWORD => 3,
                    ITEM_BATTLE_AXE => 2,
                    _ => 1,
                };
                account.character.sword_power = account.character.sword_power.max(desired);
                buf.write_gchar(PLPROP_SWORDPOWER)
                    .write_gchar((account.character.sword_power + 30) as u8);
            }
            ITEM_FULL_HEART => {
                account.max_hitpoints = (account.max_hitpoints + 1).min(20);
                account.character.hitpoints = account.max_hitpoints as i32;
                buf.write_gchar(PLPROP_MAXPOWER)
                    .write_gchar(account.max_hitpoints)
                    .write_gchar(PLPROP_CURPOWER)
                    .write_gchar(account.max_hitpoints * 2);
            }
            ITEM_SPINATTACK => {
                if account.status & PLSTATUS_HASSPIN != 0 {
                    return (Vec::new(), None);
                }
                account.status |= PLSTATUS_HASSPIN;
                buf.write_gchar(PLPROP_STATUS)
                    .write_gchar(account.status as u8);
            }
            _ => {}
        }
        (buf.data, None)
    }
}

fn default_weapon_item_id(name: &str) -> Option<LevelItemType> {
    match item_id(&name.to_ascii_lowercase()) {
        ITEM_BOW | ITEM_BOMB | ITEM_SUPER_BOMB | ITEM_FIREBALL | ITEM_FIREBLAST | ITEM_NUKESHOT
        | ITEM_JOLTBOMB => Some(item_id(&name.to_ascii_lowercase())),
        _ => None,
    }
}

impl Player {
    pub fn send_plo_addplayer(&self, other: &Player) -> bool {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_ADDPLAYER)
            .write_gshort(other.id())
            .write_string8_encoded(&other.account_name());
        let level_name = {
            let value = other.account.lock().unwrap().level_name.clone();
            if value.is_empty() {
                " ".to_string()
            } else {
                value
            }
        };
        buf.write_gchar(PLPROP_CURLEVEL)
            .write_gchar(level_name.len() as u8)
            .write(level_name.as_bytes())
            .write_gchar(PLPROP_PSTATUSMSG)
            .write(&other.get_prop(PLPROP_PSTATUSMSG))
            .write_gchar(PLPROP_NICKNAME)
            .write(&other.get_prop(PLPROP_NICKNAME))
            .write_gchar(PLPROP_COMMUNITYNAME)
            .write(&other.get_prop(PLPROP_COMMUNITYNAME));
        self.send(&buf);
        true
    }
    pub fn sendPLO_ADDPLAYER(&self, other: &Player) -> bool {
        self.send_plo_addplayer(other)
    }

    pub fn send_plo_delplayer(&self, id: u16) -> bool {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_DELPLAYER).write_gshort(id);
        self.send(&buf);
        true
    }
    pub fn sendPLO_DELPLAYER(&self, id: u16) -> bool {
        self.send_plo_delplayer(id)
    }

    pub fn send_raw_data_payload(&self, payload: &[u8]) {
        let mut buf = Buffer::new();
        buf.write_byte(PLO_RAWDATA)
            .write_gint(payload.len() as u32)
            .write_byte(b'\n')
            .write(payload);
        self.send_packet(&buf.data);
    }
    pub fn sendRawDataPayload(&self, payload: &[u8]) {
        self.send_raw_data_payload(payload)
    }

    pub fn send_raw_npc_weapon_script(&self, bytecode: &[u8]) {
        let mut payload = Buffer::new();
        payload.write_gchar(PLO_NPCWEAPONSCRIPT).write(bytecode);
        self.send_raw_data_payload(&payload.data);
    }
    pub fn sendRawNpcWeaponScript(&self, bytecode: &[u8]) {
        self.send_raw_npc_weapon_script(bytecode)
    }

    pub fn send_file(&self, file_name: &str) -> bool {
        let Some(server) = self.server() else {
            self.send_plo_filesendfailed(file_name);
            return false;
        };
        let (resolved_name, data) = match server.resolve_requested_file(file_name) {
            Ok(value) => value,
            Err(_) => {
                self.send_plo_filesendfailed(file_name);
                return false;
            }
        };
        if !valid_client_file_signature(file_name, &data) {
            self.send_plo_filesendfailed(file_name);
            return false;
        }
        let mod_unix = server
            .config
            .file_mod_time(&resolved_name)
            .ok()
            .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
            .map(|value| value.as_secs() as i64)
            .filter(|value| *value > 0)
            .unwrap_or(0);
        let mut file_packet = Buffer::new();
        file_packet
            .write_gchar(PLO_FILE)
            .write_gint5(mod_unix as u64)
            .write_gchar(file_name.len().min(223) as u8)
            .write(&file_name.as_bytes()[..file_name.len().min(223)])
            .write(&data)
            .write_byte(b'\n');
        let mut outer = Buffer::new();
        outer
            .write_byte(PLO_RAWDATA)
            .write_gint(file_packet.len() as u32)
            .write_byte(b'\n')
            .write(&file_packet.data);
        self.send_packet(&outer.data);
        true
    }
    pub fn sendFile(&self, file_name: &str) -> bool {
        self.send_file(file_name)
    }

    pub fn send_weapon(&self, weapon: &Weapon) -> bool {
        let Some(server) = self.server() else {
            return false;
        };
        let effective = server
            .ensure_weapon_bytecode(&weapon.name)
            .unwrap_or_else(|| Arc::new(weapon.clone()));
        let scripts_enabled = server.npc_server_running();
        let send_bytecode =
            scripts_enabled && !effective.bytecode.is_empty() && self.version_id() >= 300;
        let mut buf = Buffer::new();
        buf.write_byte(PLO_NPCWEAPONADD)
            .write_gchar(effective.name.len() as u8)
            .write(effective.name.as_bytes());
        if !effective.image.is_empty() {
            buf.write_gchar(NPCPROP_IMAGE)
                .write_gchar(effective.image.len() as u8)
                .write(effective.image.as_bytes());
        }
        if scripts_enabled && !send_bytecode {
            let (script, ok) = npc_runtime::format_clientside_weapon_script(&effective.script);
            if ok {
                buf.write_gchar(NPCPROP_SCRIPT)
                    .write_gshort(script.len() as u16)
                    .write(script.as_bytes());
            }
        }
        self.send(&buf);
        if send_bytecode {
            let bytecode = npc_runtime::bytecode_with_header(
                &effective.bytecode,
                "weapon",
                &effective.name,
                true,
            );
            self.send_raw_npc_weapon_script(&bytecode);
        }
        true
    }
    pub fn sendWeapon(&self, weapon: &Weapon) -> bool {
        self.send_weapon(weapon)
    }

    pub fn send_account_weapon(&self, weapon_name: &str) -> bool {
        let name = weapon_name.trim();
        if name.is_empty() {
            return false;
        }
        if let Some(item) = default_weapon_item_id(name) {
            let enabled = self
                .server()
                .map(|server| server.settings.get_bool("defaultweapons", true))
                .unwrap_or(true);
            if !enabled {
                return false;
            }
            return self.send_plo_defaultweapon(item as u8);
        }
        let Some(server) = self.server() else {
            return false;
        };
        let Some(weapon) = server.ensure_weapon_bytecode(name) else {
            return false;
        };
        self.send_weapon(&weapon)
    }
    pub fn sendAccountWeapon(&self, weapon_name: &str) -> bool {
        self.send_account_weapon(weapon_name)
    }
}

// ---------------------------------------------------------------------------
// RC/control protocol

impl Player {
    fn is_rc_connection(&self) -> bool {
        rc_control_type(self.player_type())
    }

    fn rc_require_right(&self, permission: i32, message: &str) -> bool {
        if self.has_right(permission) {
            true
        } else {
            self.send_plo_rc_chat(message);
            false
        }
    }

    pub fn get_props_rc(&self) -> Vec<u8> {
        const RC_PROPS: &[u8] = &[
            PLPROP_NICKNAME,
            PLPROP_MAXPOWER,
            PLPROP_CURPOWER,
            PLPROP_RUPEESCOUNT,
            PLPROP_ARROWSCOUNT,
            PLPROP_BOMBSCOUNT,
            PLPROP_GLOVEPOWER,
            PLPROP_SWORDPOWER,
            PLPROP_SHIELDPOWER,
            PLPROP_GANI,
            PLPROP_HEADGIF,
            PLPROP_COLORS,
            PLPROP_X,
            PLPROP_Y,
            PLPROP_STATUS,
            PLPROP_CURLEVEL,
            PLPROP_APCOUNTER,
            PLPROP_MAGICPOINTS,
            PLPROP_KILLSCOUNT,
            PLPROP_DEATHSCOUNT,
            PLPROP_ONLINESECS,
            PLPROP_IPADDR,
            PLPROP_ALIGNMENT,
            PLPROP_ACCOUNTNAME,
            PLPROP_BODYIMG,
            PLPROP_RATING,
        ];
        let account_name = self.account_name();
        let mut ret = Buffer::new();
        ret.write_string8_encoded(&account_name);
        ret.write_string8_encoded("main");

        let mut props = Buffer::new();
        for property in RC_PROPS {
            props
                .write_gchar(*property)
                .write(&self.get_prop(*property));
        }
        let property_length = props.len().min(255);
        ret.write_gchar(property_length as u8)
            .write(&props.data[..property_length]);

        let account = self.account.lock().unwrap();
        ret.write_gshort(account.flag_list.len().min(28_767) as u16);
        for (name, value) in &account.flag_list {
            let mut flag = name.clone();
            if !value.is_empty() {
                flag.push('=');
                flag.push_str(value);
            }
            rc_encoded_bytes(&mut ret, flag.as_bytes());
        }

        ret.write_gshort(account.chest_list.len().min(28_767) as u16);
        for chest in &account.chest_list {
            let parts = chest.splitn(3, ':').collect::<Vec<_>>();
            if parts.len() != 3 {
                continue;
            }
            let mut chest_data = Buffer::new();
            chest_data
                .write_gchar(parse_i32(parts[0]) as u8)
                .write_gchar(parse_i32(parts[1]) as u8)
                .write(parts[2].as_bytes());
            rc_encoded_bytes(&mut ret, &chest_data.data);
        }

        ret.write_gchar(account.weapon_list.len().min(223) as u8);
        for weapon in account.weapon_list.iter().take(223) {
            rc_encoded_bytes(&mut ret, weapon.as_bytes());
        }
        ret.data
    }
    pub fn getPropsRC(&self) -> Vec<u8> {
        self.get_props_rc()
    }

    fn rc_self_props_from_packet(&self, props: &[u8]) -> Vec<u8> {
        let mut input = Buffer::from_bytes(props);
        let mut ids = Vec::new();
        while input.remaining() > 0 {
            let property = input.read_gchar();
            let start = input.read;
            let recognized = match property {
                PLPROP_NICKNAME
                | PLPROP_GANI
                | PLPROP_BODYIMG
                | PLPROP_HORSEGIF
                | PLPROP_CURCHAT
                | PLPROP_PLANGUAGE
                | PLPROP_OSTYPE
                | PLPROP_COMMUNITYNAME
                | PLPROP_CURLEVEL
                | PLPROP_ACCOUNTNAME
                | PLPROP_GATTRIB1..=PLPROP_GATTRIB5
                | PLPROP_GATTRIB6..=PLPROP_GATTRIB9
                | PLPROP_GATTRIB10..=PLPROP_GATTRIB30 => {
                    let _ = input.read_gchar_string();
                    true
                }
                PLPROP_HEADGIF => {
                    let length = input.read_gchar();
                    if length >= 100 {
                        let _ = input.read_bytes(usize::from(length - 100));
                    }
                    true
                }
                PLPROP_SWORDPOWER | PLPROP_SHIELDPOWER => {
                    let power = input.read_gchar();
                    if (property == PLPROP_SWORDPOWER && power > 4)
                        || (property == PLPROP_SHIELDPOWER && power > 3)
                    {
                        let _ = input.read_gchar_string();
                    }
                    true
                }
                PLPROP_COLORS => {
                    let _ = input.read_bytes(5);
                    true
                }
                PLPROP_ID | PLPROP_APCOUNTER | PLPROP_X2 | PLPROP_Y2 | PLPROP_Z2 => {
                    let _ = input.read_bytes(2);
                    true
                }
                PLPROP_X | PLPROP_Y | PLPROP_Z | PLPROP_SPRITE | PLPROP_STATUS
                | PLPROP_CARRYSPRITE | PLPROP_HORSEBUSHES | PLPROP_MAGICPOINTS
                | PLPROP_ALIGNMENT | PLPROP_ADDITFLAGS | PLPROP_GMAPLEVELX | PLPROP_GMAPLEVELY
                | PLPROP_JOINLEAVELVL | PLPROP_PSTATUSMSG | PLPROP_UNKNOWN77 | PLPROP_UNKNOWN81 => {
                    let _ = input.read_bytes(1);
                    true
                }
                PLPROP_EFFECTCOLORS => {
                    if input.read_gchar() > 0 {
                        let _ = input.read_bytes(4);
                    }
                    true
                }
                PLPROP_CARRYNPC | PLPROP_ATTACHNPC => {
                    let _ = input.read_bytes(5);
                    true
                }
                PLPROP_UDPPORT | PLPROP_KILLSCOUNT | PLPROP_DEATHSCOUNT | PLPROP_ONLINESECS
                | PLPROP_RATING | PLPROP_TEXTCODEPAGE => {
                    let _ = input.read_bytes(4);
                    true
                }
                PLPROP_IPADDR => {
                    let _ = input.read_bytes(5);
                    true
                }
                PLPROP_PCONNECTED => true,
                _ => false,
            };
            if !recognized || input.read == start {
                break;
            }
            if !matches!(
                property,
                PLPROP_X
                    | PLPROP_Y
                    | PLPROP_Z
                    | PLPROP_X2
                    | PLPROP_Y2
                    | PLPROP_Z2
                    | PLPROP_CURLEVEL
            ) {
                ids.push(property);
            }
        }
        let mut output = Buffer::new();
        for property in ids {
            output.write_gchar(property).write(&self.get_prop(property));
        }
        output.data
    }

    fn set_props_from_rc(&self, input: &mut Buffer, _rc: &Player) {
        // RC attribute packets begin with the account/profile name followed
        // by a byte-sized property blob, then flags, chests, and weapons.
        let _ = rc_read_encoded_string(input);
        let property_length = usize::from(input.read_gchar()).min(input.remaining());
        let properties = input.read_bytes(property_length);
        if !properties.is_empty() {
            let mut packet = Vec::with_capacity(properties.len() + 1);
            packet.push(PLI_PLAYERPROPS);
            packet.extend_from_slice(&properties);
            let _ = self.msg_pli_playerprops(&packet);
            let self_properties = self.rc_self_props_from_packet(&properties);
            if self.id() != 0 && !self_properties.is_empty() {
                let mut output = Buffer::new();
                output.write_byte(PLO_PLAYERPROPS).write(&self_properties);
                self.send(&output);
            }
        }

        let old_flags = self.account.lock().unwrap().flag_list.clone();
        if self.id() != 0 {
            for (name, value) in old_flags {
                let mut packet = Buffer::new();
                packet.write_byte(PLO_FLAGDEL).write(name.as_bytes());
                if !value.is_empty() {
                    packet.write_byte(b'=').write(value.as_bytes());
                }
                self.send(&packet);
            }
        }
        let flag_count = usize::from(input.read_gshort());
        let mut flags = HashMap::new();
        for _ in 0..flag_count {
            let value = rc_read_encoded_string(input);
            let (name, flag_value) = value
                .split_once('=')
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .unwrap_or_else(|| (value, String::new()));
            if !name.is_empty() {
                flags.insert(name, flag_value);
            }
        }
        self.account.lock().unwrap().flag_list = flags;

        let chest_count = usize::from(input.read_gshort());
        let mut chests = Vec::new();
        for _ in 0..chest_count {
            let data = rc_read_encoded_bytes(input);
            if data.len() >= 2 {
                chests.push(format!(
                    "{}:{}:{}",
                    data[0],
                    data[1],
                    String::from_utf8_lossy(&data[2..])
                ));
            }
        }
        self.account.lock().unwrap().chest_list = chests;

        let weapon_count = usize::from(input.read_gchar());
        let old_weapons = self.account.lock().unwrap().weapon_list.clone();
        if self.id() != 0 {
            for weapon in &old_weapons {
                self.send_plo_npcweapondel(weapon);
            }
        }
        self.account.lock().unwrap().weapon_list.clear();
        let mut had_bomb = false;
        let mut had_bow = false;
        for _ in 0..weapon_count {
            let weapon = rc_read_encoded_string(input);
            if weapon.eq_ignore_ascii_case("bomb") {
                had_bomb = true;
            }
            if weapon.eq_ignore_ascii_case("bow") {
                had_bow = true;
            }
            if self.add_weapon(&weapon) && self.id() != 0 {
                self.send_account_weapon(&weapon);
            }
        }
        if self.id() != 0 {
            if !had_bomb {
                self.send_plo_npcweapondel("Bomb");
            }
            if !had_bow {
                self.send_plo_npcweapondel("Bow");
            }
        }
    }

    pub fn msg_pli_rc_server_options_get(&self, _packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() {
            return true;
        }
        let data = server
            .config
            .load_file("config/serveroptions.txt")
            .map(|value| String::from_utf8_lossy(&value).into_owned())
            .unwrap_or_else(|_| {
                server
                    .settings
                    .get_all()
                    .into_iter()
                    .map(|(key, value)| format!("{key}={value}\n"))
                    .collect()
            });
        let mut output = Buffer::new();
        output
            .write_byte(PLO_RC_SERVEROPTIONSGET)
            .write(gtokenize_text(&data).as_bytes());
        self.send(&output);
        true
    }

    pub fn msg_pli_rc_server_options_set(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() {
            return true;
        }
        if !self.rc_require_right(
            PLPERM_SETSERVEROPTIONS,
            &format!(
                "Server: {} is not authorized to change the server options.",
                self.account_name()
            ),
        ) {
            return true;
        }
        let mut options = if packet.len() > 1 {
            guntokenize_text(&String::from_utf8_lossy(&packet[1..]))
        } else {
            String::new()
        };
        if !self.has_right(PLPERM_MODIFYSTAFFACCOUNT) {
            options = preserve_admin_only_server_options(&options, &server.settings);
        }
        let _ = server.settings.load_from_string(&options);
        if !options.ends_with('\n') {
            options.push('\n');
        }
        if let Err(error) = server
            .config
            .save_file("config/serveroptions.txt", options.as_bytes())
        {
            server
                .logger
                .error(&format!("Failed to save serveroptions.txt: {error}"));
            return true;
        }
        server.load_settings();
        server.logger.info(&format!(
            "{} has updated the server options.",
            self.account_name()
        ));
        server.send_rc_chat(&format!(
            "{} has updated the server options.",
            self.account_name()
        ));
        true
    }

    pub fn msg_pli_rc_folder_config_get(&self, _packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() {
            return true;
        }
        let value = server
            .config
            .load_file("config/foldersconfig.txt")
            .map(|data| {
                String::from_utf8_lossy(&data)
                    .replace("\r\n", "\n")
                    .replace('\r', "\n")
            })
            .unwrap_or_default();
        let mut output = Buffer::new();
        output
            .write_byte(PLO_RC_FOLDERCONFIGGET)
            .write(gtokenize_text(&value).as_bytes());
        self.send(&output);
        true
    }

    pub fn msg_pli_rc_folder_config_set(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() {
            return true;
        }
        if !self.rc_require_right(
            PLPERM_SETFOLDEROPTIONS,
            &format!(
                "Server: {} is not authorized to change the folder config.",
                self.account_name()
            ),
        ) {
            return true;
        }
        let mut value = if packet.len() > 1 {
            guntokenize_text(&String::from_utf8_lossy(&packet[1..]))
        } else {
            String::new()
        };
        value = value.replace('\\', "").replace('\n', "\r\n");
        if server
            .config
            .save_file("config/foldersconfig.txt", value.as_bytes())
            .is_err()
        {
            server.logger.error("Failed to save foldersconfig.txt");
            return true;
        }
        server
            .logger
            .info(&format!("{} updated folder config", self.account_name()));
        server.send_rc_chat(&format!(
            "{} updated the folder config.",
            self.account_name()
        ));
        true
    }

    pub fn msg_pli_rc_noop(&self, _packet: &[u8]) -> bool {
        true
    }

    pub fn msg_pli_rc_player_props_get(&self, _packet: &[u8]) -> bool {
        true
    }

    pub fn msg_pli_rc_player_props_set(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() {
            return true;
        }
        let mut input = Buffer::from_bytes(rc_payload(packet, PLI_RC_PLAYERPROPSSET));
        let target_id = input.read_gshort();
        let Some(target) = server.get_player(target_id) else {
            return true;
        };
        let source = self.account_name();
        let target_name = target.account_name();
        let allowed = if target_name.eq_ignore_ascii_case(&source) {
            self.has_right(PLPERM_SETSELFATTRIBUTES)
        } else {
            self.has_right(PLPERM_SETATTRIBUTES)
        };
        if !allowed {
            self.send_plo_rc_chat(&format!(
                "Server: {source} is not authorized to set the properties of {target_name}"
            ));
            return true;
        }
        target.set_props_from_rc(&mut input, self);
        target.save_account();
        server.refresh_player_list_entry(&target);
        server.send_rc_chat(&format!(
            "{source} set the attributes of player {target_name}"
        ));
        true
    }

    pub fn msg_pli_rc_disconnect_player(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        let mut input = Buffer::from_bytes(rc_payload(packet, PLI_RC_DISCONNECTPLAYER));
        let target_id = input.read_gshort();
        let Some(target) = server.get_player(target_id) else {
            return true;
        };
        if !self.is_rc_connection() || !self.has_right(PLPERM_DISCONNECT) {
            return true;
        }
        let reason = input.read_gstring();
        let mut message = format!(
            "One of the server administrators, {}, has disconnected you",
            self.account_name()
        );
        if reason.is_empty() {
            message.push('.');
        } else {
            message.push_str(" for the following reason: ");
            message.push_str(&reason);
        }
        server.send_rc_chat(&format!(
            "{} disconnected {}",
            self.account_name(),
            target.account_name()
        ));
        target.send_packet(&[PLO_DISCMESSAGE, 0]);
        target.write_string8_raw(&message);
        target.disconnect();
        true
    }

    pub fn msg_pli_rc_update_levels(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() || !self.has_right(PLPERM_UPDATELEVEL) {
            return true;
        }
        let mut input = Buffer::from_bytes(rc_payload(packet, PLI_RC_UPDATELEVELS));
        let count = usize::from(input.read_gshort());
        for _ in 0..count {
            let name = input.read_gchar_string();
            if let Some(level) = server.get_level(&name) {
                level.reload(&server);
            }
        }
        true
    }

    pub fn msg_pli_rc_admin_message(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() || !self.has_right(PLPERM_ADMINMSG) {
            return true;
        }
        let mut input = Buffer::from_bytes(rc_payload(packet, PLI_RC_ADMINMESSAGE));
        let message = input.read_string();
        let mut output = Buffer::new();
        output
            .write_byte(PLO_RC_ADMINMESSAGE)
            .write_string8(&format!("Admin {}:§{}", self.account_name(), message));
        for player in server.get_all_players() {
            if player.id() != self.id() {
                player.send_packet(&output.data);
            }
        }
        true
    }

    pub fn msg_pli_rc_priv_admin_message(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() || !self.has_right(PLPERM_ADMINMSG) {
            return true;
        }
        let mut input = Buffer::from_bytes(rc_payload(packet, PLI_RC_PRIVADMINMESSAGE));
        let target_id = input.read_gshort();
        let message = input.read_string();
        let Some(target) = server.get_player(target_id) else {
            return true;
        };
        let mut output = Buffer::new();
        output
            .write_byte(PLO_RC_ADMINMESSAGE)
            .write_string8(&format!("Admin {}:§{}", self.account_name(), message));
        target.send_packet(&output.data);
        true
    }

    pub fn msg_pli_rc_server_flags_get(&self, _packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() {
            return true;
        }
        let flags = server.flags.read().unwrap().clone();
        let mut output = Buffer::new();
        output.write_byte(PLO_RC_SERVERFLAGSGET);
        let valid = flags
            .into_iter()
            .filter(|(name, value)| is_valid_server_flag(name, value))
            .collect::<Vec<_>>();
        output.write_gshort(valid.len().min(28_767) as u16);
        for (name, value) in valid {
            let text = format!("{name}={value}");
            rc_encoded_bytes(&mut output, text.as_bytes());
        }
        self.send(&output);
        true
    }

    pub fn msg_pli_rc_server_flags_set(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() || !self.has_right(PLPERM_SETSERVERFLAGS) {
            return true;
        }
        let mut input = Buffer::from_bytes(rc_payload(packet, PLI_RC_SERVERFLAGSSET));
        let count = usize::from(input.read_gshort());
        let old = server.flags.read().unwrap().clone();
        let mut next = HashMap::new();
        for _ in 0..count {
            let text = rc_read_encoded_string(&mut input);
            if let Some((name, value)) = text.split_once('=') {
                if is_valid_server_flag(name.trim(), value) {
                    next.insert(name.trim().to_string(), value.to_string());
                }
            } else if is_valid_server_flag(text.trim(), "") {
                next.insert(text.trim().to_string(), String::new());
            }
        }
        *server.flags.write().unwrap() = next.clone();
        for (name, value) in &next {
            if old.get(name) != Some(value) {
                server.broadcast_server_flag_set(name, value);
            }
        }
        for name in old.keys() {
            if !next.contains_key(name) {
                server.broadcast_server_flag_delete(name);
            }
        }
        server.save_flags();
        server.logger.info(&format!(
            "{} has updated the server flags.",
            self.account_name()
        ));
        server.send_rc_chat(&format!(
            "{} has updated the server flags.",
            self.account_name()
        ));
        true
    }

    pub fn msg_pli_rc_account_add(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() || !self.has_right(PLPERM_MODIFYSTAFFACCOUNT) {
            return true;
        }
        let mut input = Buffer::from_bytes(rc_payload(packet, PLI_RC_ACCOUNTADD));
        let account_name = rc_read_encoded_string(&mut input);
        let _nickname = rc_read_encoded_string(&mut input);
        let email = rc_read_encoded_string(&mut input);
        let banned = input.read_gchar() != 0;
        let load_only = input.read_gchar() != 0;
        let _ = input.read_gchar();
        let mut account = Account::new();
        account.set_server(&server);
        account.account_name = account_name.clone();
        account.email = email;
        account.is_banned = banned;
        account.is_load_only = load_only;
        let _ = account.save_account();
        if banned {
            server.report_local_ban_history(&account_name, &self.account_name(), true, "", "", "");
        }
        server.send_rc_chat(&format!(
            "{} has created a new account: {}",
            self.account_name(),
            account_name
        ));
        true
    }

    pub fn msg_pli_rc_account_delete(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() || !self.has_right(PLPERM_MODIFYSTAFFACCOUNT) {
            return true;
        }
        let account_name = rc_read_account(packet, PLI_RC_ACCOUNTDEL);
        if account_name.is_empty() || account_name.eq_ignore_ascii_case("defaultaccount") {
            return true;
        }
        if !server.account_exists(&account_name) {
            return true;
        }
        let mut deleted = false;
        for path in account_file_read_paths(&account_name) {
            if server.config.file_exists(&path) {
                if let Err(error) = server.config.delete_file(&path) {
                    server
                        .logger
                        .error(&format!("Failed to delete account file: {error}"));
                    return true;
                }
                deleted = true;
            }
        }
        if !deleted {
            return true;
        }
        server.logger.info(&format!(
            "{} has deleted the account: {}",
            self.account_name(),
            account_name
        ));
        server.send_rc_chat(&format!(
            "{} has deleted the account: {}",
            self.account_name(),
            account_name
        ));
        true
    }

    pub fn msg_pli_rc_account_list_get(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() {
            return true;
        }
        let mut input = Buffer::from_bytes(rc_payload(packet, PLI_RC_ACCOUNTLISTGET));
        let name = rc_read_encoded_string(&mut input).replace('%', "*");
        let conditions = rc_read_encoded_string(&mut input);
        let mut candidates: HashMap<String, (RcAccountListEntry, i64)> = HashMap::new();
        let Ok(files) = list_account_files(&server.config) else {
            server.logger.error("Failed to list accounts.");
            return true;
        };
        for relative in files {
            if !relative.ends_with(".txt") {
                continue;
            }
            let Some(entry) = load_rc_account_list_entry(&server.config, &relative) else {
                continue;
            };
            if !rc_account_list_matches(&entry, &name, &conditions) {
                continue;
            }
            let key = entry.account.to_ascii_lowercase();
            if key.is_empty() {
                continue;
            }
            let score = rc_account_list_candidate_score(&relative, &entry);
            if candidates
                .get(&key)
                .is_some_and(|(_, previous)| *previous >= score)
            {
                continue;
            }
            candidates.insert(key, (entry, score));
        }
        let mut keys = candidates.keys().cloned().collect::<Vec<_>>();
        keys.sort();
        let mut output = Buffer::new();
        output.write_byte(PLO_RC_ACCOUNTLISTGET);
        for key in keys {
            if let Some((entry, _)) = candidates.remove(&key) {
                rc_encoded_bytes(&mut output, entry.account.as_bytes());
            }
        }
        self.send(&output);
        true
    }

    pub fn msg_pli_rc_player_props_get2(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() || !self.has_right(PLPERM_VIEWATTRIBUTES) {
            return true;
        }
        let mut input = Buffer::from_bytes(rc_payload(packet, PLI_RC_PLAYERPROPSGET2));
        let Some(target) = server.get_player(input.read_gshort()) else {
            return true;
        };
        let mut output = Buffer::new();
        output
            .write_byte(PLO_RC_PLAYERPROPSGET)
            .write_gshort(target.id())
            .write(&target.get_props_rc());
        self.send(&output);
        server.send_rc_chat(&format!(
            "{} has opened the attributes of {}",
            self.account_name(),
            target.account_name()
        ));
        true
    }

    pub fn msg_pli_rc_player_props_get3(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() || !self.has_right(PLPERM_VIEWATTRIBUTES) {
            return true;
        }
        let account_name = rc_read_string8_or_encoded_account(packet, PLI_RC_PLAYERPROPSGET3);
        let target = server
            .get_player_by_account(&account_name, PLTYPE_ANYPLAYER | PLTYPE_NPCSERVER)
            .or_else(|| load_offline_rc_player(&server, &account_name));
        let Some(target) = target else {
            self.send_plo_rc_chat(&format!("Server: Account {account_name} does not exist."));
            return true;
        };
        let mut output = Buffer::new();
        output
            .write_byte(PLO_RC_PLAYERPROPSGET)
            .write_gshort(target.id())
            .write(&target.get_props_rc());
        self.send(&output);
        server.send_rc_chat(&format!(
            "{} has opened the attributes of {}",
            self.account_name(),
            account_name
        ));
        true
    }

    pub fn reset_account(&self) {
        let name = self.account_name();
        let mut account = Account::new();
        if let Some(server) = self.server() {
            account.set_server(&server);
        }
        account.account_name = name;
        account.x = 32 * 16;
        account.y = 32 * 16;
        account.level_name.clear();
        *self.account.lock().unwrap() = account;
    }
    pub fn resetAccount(&self) {
        self.reset_account()
    }

    pub fn msg_pli_rc_player_props_reset(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() || !self.has_right(PLPERM_RESETATTRIBUTES) {
            return true;
        }
        let account_name = rc_read_account(packet, PLI_RC_PLAYERPROPSRESET);
        if account_name.is_empty() {
            return true;
        }
        let targets = server
            .get_all_players()
            .into_iter()
            .filter(|player| {
                player.account_name().eq_ignore_ascii_case(&account_name)
                    && player.player_type() & PLTYPE_ANYCLIENT != 0
            })
            .collect::<Vec<_>>();
        let account_exists = server.account_exists(&account_name);
        if targets.is_empty() && !account_exists {
            return true;
        }
        for target in targets {
            target.send_plo_discmessage(&format!(
                "Your account was reset by {}",
                self.account_name()
            ));
            target.disconnect();
            target.reset_account();
        }
        if account_exists {
            for path in account_file_read_paths(&account_name) {
                let _ = server.config.delete_file(path);
            }
        }
        server.send_rc_chat(&format!(
            "{} has reset the attributes of account: {}",
            self.account_name(),
            account_name
        ));
        true
    }

    pub fn msg_pli_rc_player_props_set2(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() {
            return true;
        }
        let mut input = Buffer::from_bytes(rc_payload(packet, PLI_RC_PLAYERPROPSSET2));
        let account_name = rc_sanitize_account(&rc_read_encoded_string(&mut input));
        let target = server
            .get_player_by_account(&account_name, PLTYPE_ANYCLIENT)
            .or_else(|| load_offline_rc_player(&server, &account_name));
        let Some(target) = target else {
            self.send_plo_rc_chat(&format!("Server: Account {account_name} does not exist."));
            return true;
        };
        let source = self.account_name();
        let allowed = if target.account_name().eq_ignore_ascii_case(&source) {
            self.has_right(PLPERM_SETSELFATTRIBUTES)
        } else {
            self.has_right(PLPERM_SETATTRIBUTES)
        };
        if !allowed {
            self.send_plo_rc_chat(&format!(
                "Server: {source} is not authorized to set the properties of {}",
                target.account_name()
            ));
            return true;
        }
        if target.account.lock().unwrap().is_staff && !self.has_right(PLPERM_MODIFYSTAFFACCOUNT) {
            self.send_plo_rc_chat("Server: You are not authorized to modify staff accounts.");
            return true;
        }
        target.set_props_from_rc(&mut input, self);
        target.save_account();
        server.refresh_player_list_entry(&target);
        true
    }

    pub fn msg_pli_rc_account_get(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() {
            return true;
        }
        let account_name = rc_read_account(packet, PLI_RC_ACCOUNTGET);
        let target = server
            .get_player_by_account(&account_name, PLTYPE_ANYCLIENT)
            .or_else(|| load_offline_rc_player(&server, &account_name));
        let Some(target) = target else {
            self.send_plo_rc_chat(&format!("Server: Account {account_name} does not exist."));
            return true;
        };
        let account = target.account.lock().unwrap();
        let mut output = Buffer::new();
        output.write_byte(PLO_RC_ACCOUNTGET);
        rc_encoded_bytes(&mut output, account_name.as_bytes());
        output
            .write_gchar(0)
            .write_string8_encoded(&account.email)
            .write_gchar(account.is_banned as u8)
            .write_gchar(account.is_load_only as u8)
            .write_gchar(0)
            .write_string8_encoded("main")
            .write_string8_encoded(&account.ban_length)
            .write_string8_encoded(&account.ban_reason);
        drop(account);
        self.send(&output);
        true
    }

    pub fn msg_pli_rc_account_set(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() {
            server.logger.warning(&format!(
                "[Hack] {} attempted ACCOUNTSET (non-RC)",
                self.account_name()
            ));
            return true;
        }
        if !self.has_right(PLPERM_MODIFYSTAFFACCOUNT) {
            server.logger.warning(&format!(
                "{} attempted ACCOUNTSET without permission",
                self.account_name()
            ));
            self.send_plo_rc_chat("Server: You are not authorized to edit accounts.");
            return true;
        }
        let mut input = Buffer::from_bytes(rc_payload(packet, PLI_RC_ACCOUNTSET));
        let account_name = rc_sanitize_account(&rc_read_encoded_string(&mut input));
        if account_name.is_empty() {
            return true;
        }
        let _ = rc_read_encoded_string(&mut input);
        let email = rc_read_encoded_string(&mut input);
        let banned = input.read_gchar() != 0;
        let load_only = input.read_gchar() != 0;
        let _ = input.read_gchar();
        let _ = rc_read_encoded_string(&mut input);
        let ban_reason = rc_read_encoded_string(&mut input);
        let target = server
            .get_player_by_account(&account_name, PLTYPE_ANYCLIENT)
            .or_else(|| load_offline_rc_player(&server, &account_name));
        let Some(target) = target else { return true };
        let mut account = target.account.lock().unwrap();
        account.email = email;
        account.is_load_only = load_only;
        let mut ban_changed = false;
        if self.has_right(PLPERM_BAN) {
            ban_changed = account.is_banned != banned || account.ban_reason != ban_reason;
            account.is_banned = banned;
            account.ban_reason = ban_reason;
        }
        let saved = account.save_account();
        if saved && self.has_right(PLPERM_BAN) && ban_changed {
            server.report_local_ban_history(
                &account_name,
                &self.account_name(),
                banned,
                "",
                "",
                &account.ban_reason,
            );
        }
        drop(account);
        server.logger.info(&format!(
            "{} modified account: {}",
            self.account_name(),
            account_name
        ));
        server.send_rc_chat(&format!(
            "{} modified the account {}",
            self.account_name(),
            account_name
        ));
        true
    }

    pub fn msg_pli_profile_get(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        let text = String::from_utf8_lossy(packet.get(1..).unwrap_or_default()).into_owned();
        server.send_player_text_to_listservers(SVO_GETPROF, self.id(), &text);
        true
    }

    pub fn msg_pli_profile_set(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if packet.len() <= 1 {
            return true;
        }
        let mut input = Buffer::from_bytes(&packet[1..]);
        let length = usize::from(input.read_byte()).min(input.remaining());
        let account = String::from_utf8_lossy(&input.read_bytes(length)).into_owned();
        if !account.eq_ignore_ascii_case(&self.account_name()) {
            return true;
        }
        server.send_text_to_listservers(SVO_SETPROF, &String::from_utf8_lossy(&packet[1..]));
        true
    }

    pub fn msg_pli_rc_warp_player(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() || !self.has_right(PLPERM_WARPTOPLAYER) {
            return true;
        }
        let mut input = Buffer::from_bytes(rc_payload(packet, PLI_RC_WARPPLAYER));
        let target_id = input.read_gshort();
        let x = f64::from(input.read_gchar()) / 2.0;
        let y = f64::from(input.read_gchar()) / 2.0;
        let level = input.read_gstring();
        if let Some(target) = server.get_player(target_id) {
            target.warp(&level, x, y, 0);
        }
        true
    }

    pub fn msg_pli_rc_player_rights_get(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        let account_name = rc_read_account(packet, PLI_RC_PLAYERRIGHTSGET);
        if !self.is_rc_connection()
            || (!account_name.eq_ignore_ascii_case(&self.account_name())
                && !self.has_right(PLPERM_SETRIGHTS))
        {
            return true;
        }
        let target = server
            .get_player_by_account(&account_name, PLTYPE_ANYPLAYER | PLTYPE_NPCSERVER)
            .or_else(|| load_offline_rc_player(&server, &account_name));
        let Some(target) = target else { return true };
        let account = target.account.lock().unwrap();
        let folders = gtokenize_text(&account.folder_list.join("\n"));
        let rights = account.admin_rights;
        let admin_ip = account.admin_ip.clone();
        drop(account);
        let mut output = Buffer::new();
        output
            .write_byte(PLO_RC_PLAYERRIGHTSGET)
            .write_string8_encoded(&account_name)
            .write_gint5(rights as u64)
            .write_string8_encoded(&admin_ip)
            .write_gshort(folders.len().min(28_767) as u16)
            .write(folders.as_bytes());
        self.send(&output);
        true
    }

    pub fn msg_pli_rc_player_rights_set(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() || !self.has_right(PLPERM_SETRIGHTS) {
            return true;
        }
        let mut input = Buffer::from_bytes(rc_payload(packet, PLI_RC_PLAYERRIGHTSSET));
        let account_name = rc_sanitize_account(&rc_read_encoded_string(&mut input));
        let target = server
            .get_player_by_account(&account_name, PLTYPE_ANYCLIENT)
            .or_else(|| load_offline_rc_player(&server, &account_name));
        let Some(target) = target else { return true };
        let mut rights = input.read_gint5() as i32;
        if !self.has_right(PLPERM_MODIFYSTAFFACCOUNT) {
            rights &= self.account.lock().unwrap().admin_rights;
        }
        let target_is_self = target.id() == self.id()
            && target
                .account_name()
                .eq_ignore_ascii_case(&self.account_name());
        if target_is_self {
            rights |= PLPERM_MODIFYSTAFFACCOUNT | PLPERM_SETRIGHTS;
        }
        let admin_ip = rc_read_encoded_string(&mut input);
        let folder_len = usize::from(input.read_gshort()).min(input.remaining());
        let folder_text = guntokenize_text(&String::from_utf8_lossy(&input.read_bytes(folder_len)));
        let folders = folder_text
            .split('\n')
            .map(str::trim)
            .filter(|value| {
                !value.is_empty()
                    && !value.contains(':')
                    && !value.contains("..")
                    && !value.contains(" /*")
            })
            .map(str::to_string)
            .collect::<Vec<_>>();
        {
            let mut account = target.account.lock().unwrap();
            account.admin_rights = rights;
            account.admin_ip = admin_ip;
            account.folder_list = folders;
            let _ = account.save_account();
        }
        true
    }

    pub fn msg_pli_rc_player_comments_get(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() {
            return true;
        }
        let account_name = rc_read_account(packet, PLI_RC_PLAYERCOMMENTSGET);
        let target = server
            .get_player_by_account(&account_name, PLTYPE_ANYCLIENT)
            .or_else(|| load_offline_rc_player(&server, &account_name));
        let Some(target) = target else {
            self.send_plo_rc_chat(&format!("Server: Account {account_name} does not exist."));
            return true;
        };
        let comments = target.account.lock().unwrap().account_comments.clone();
        let mut output = Buffer::new();
        output
            .write_byte(PLO_RC_PLAYERCOMMENTSGET)
            .write_string8_encoded(&account_name)
            .write(comments.as_bytes());
        self.send(&output);
        server.send_rc_chat(&format!(
            "{} has opened the comments of {}",
            self.account_name(),
            account_name
        ));
        true
    }

    pub fn msg_pli_rc_player_comments_set(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() || !self.has_right(PLPERM_SETCOMMENTS) {
            return true;
        }
        let mut input = Buffer::from_bytes(rc_payload(packet, PLI_RC_PLAYERCOMMENTSSET));
        let account_name = rc_sanitize_account(&rc_read_encoded_string(&mut input));
        let comments = input.read_string();
        let target = server
            .get_player_by_account(&account_name, PLTYPE_ANYCLIENT)
            .or_else(|| load_offline_rc_player(&server, &account_name));
        let Some(target) = target else { return true };
        target.account.lock().unwrap().account_comments = comments;
        target.save_account();
        if let Some(rc_player) = server.get_player_by_account(&account_name, PLTYPE_ANYRC) {
            rc_player
                .account
                .lock()
                .unwrap()
                .load_account(&account_name, false);
        }
        server.logger.info(&format!(
            "{} has set the comments of {}",
            self.account_name(),
            account_name
        ));
        server.send_rc_chat(&format!(
            "{} has set the comments of {}",
            self.account_name(),
            account_name
        ));
        true
    }

    pub fn msg_pli_rc_player_ban_get(&self, packet: &[u8]) -> bool {
        let Some(server) = self.server() else {
            return true;
        };
        if !self.is_rc_connection() {
            return true;
        }
        let account_name = rc_read_account(packet, PLI_RC_PLAYERBANGET);
        let target = server
            .get_player_by_account(&account_name, PLTYPE_ANYCLIENT)
            .or_else(|| load_offline_rc_player(&server, &account_name));
        let Some(target) = target else {
            self.send_plo_rc_chat(&format!("Server: Account {account_name} does not exist."));
            return true;
        };
        let account = target.account.lock().unwrap();
        let mut output = Buffer::new();
        output
            .write_byte(PLO_RC_PLAYERBANGET)
            .write_string8_encoded(&account_name)
            .write_gchar(account.is_banned as u8)
            .write(account.ban_reason.as_bytes());
        drop(account);
        self.send(&output);
        true
    }

    pub fn msg_pli_rc_player_ban_set(&self, packet: &[u8]) -> bool {
        let mut input = Buffer::from_bytes(rc_payload(packet, PLI_RC_PLAYERBANSET));
        let account_name = rc_read_encoded_string(&mut input);
        let banned = input.read_gchar() != 0;
        let reason = input.read_string();
        let _ = self.set_local_ban_from_fields(&[
            format!("account={account_name}"),
            "world=local".to_string(),
            format!("banned={}", if banned { 1 } else { 0 }),
            format!("reason={reason}"),
        ]);
        true
    }

    pub fn msgPLI_RC_CHAT(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_chat(packet)
    }
    pub fn msgPLI_RC_SERVEROPTIONSGET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_server_options_get(packet)
    }
    pub fn msgPLI_RC_SERVEROPTIONSSET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_server_options_set(packet)
    }
    pub fn msgPLI_RC_FOLDERCONFIGGET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_folder_config_get(packet)
    }
    pub fn msgPLI_RC_FOLDERCONFIGSET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_folder_config_set(packet)
    }
    pub fn msgPLI_RC_RESPAWNSET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_noop(packet)
    }
    pub fn msgPLI_RC_HORSELIFESET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_noop(packet)
    }
    pub fn msgPLI_RC_APINCREMENTSET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_noop(packet)
    }
    pub fn msgPLI_RC_BADDYRESPAWNSET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_noop(packet)
    }
    pub fn msgPLI_RC_PLAYERPROPSGET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_player_props_get(packet)
    }
    pub fn msgPLI_RC_PLAYERPROPSSET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_player_props_set(packet)
    }
    pub fn msgPLI_RC_DISCONNECTPLAYER(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_disconnect_player(packet)
    }
    pub fn msgPLI_RC_UPDATELEVELS(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_update_levels(packet)
    }
    pub fn msgPLI_RC_ADMINMESSAGE(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_admin_message(packet)
    }
    pub fn msgPLI_RC_PRIVADMINMESSAGE(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_priv_admin_message(packet)
    }
    pub fn msgPLI_RC_LISTRCS(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_noop(packet)
    }
    pub fn msgPLI_RC_DISCONNECTRC(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_noop(packet)
    }
    pub fn msgPLI_RC_APPLYREASON(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_noop(packet)
    }
    pub fn msgPLI_RC_SERVERFLAGSGET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_server_flags_get(packet)
    }
    pub fn msgPLI_RC_SERVERFLAGSSET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_server_flags_set(packet)
    }
    pub fn msgPLI_RC_ACCOUNTADD(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_account_add(packet)
    }
    pub fn msgPLI_RC_ACCOUNTDEL(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_account_delete(packet)
    }
    pub fn msgPLI_RC_ACCOUNTLISTGET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_account_list_get(packet)
    }
    pub fn msgPLI_RC_PLAYERPROPSGET2(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_player_props_get2(packet)
    }
    pub fn msgPLI_RC_PLAYERPROPSGET3(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_player_props_get3(packet)
    }
    pub fn msgPLI_RC_PLAYERPROPSRESET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_player_props_reset(packet)
    }
    pub fn msgPLI_RC_PLAYERPROPSSET2(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_player_props_set2(packet)
    }
    pub fn msgPLI_RC_ACCOUNTGET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_account_get(packet)
    }
    pub fn msgPLI_RC_ACCOUNTSET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_account_set(packet)
    }
    pub fn msgPLI_PROFILEGET(&self, packet: &[u8]) -> bool {
        self.msg_pli_profile_get(packet)
    }
    pub fn msgPLI_PROFILESET(&self, packet: &[u8]) -> bool {
        self.msg_pli_profile_set(packet)
    }
    pub fn msgPLI_RC_WARPPLAYER(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_warp_player(packet)
    }
    pub fn msgPLI_RC_PLAYERRIGHTSGET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_player_rights_get(packet)
    }
    pub fn msgPLI_RC_PLAYERRIGHTSSET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_player_rights_set(packet)
    }
    pub fn msgPLI_RC_PLAYERCOMMENTSGET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_player_comments_get(packet)
    }
    pub fn msgPLI_RC_PLAYERCOMMENTSSET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_player_comments_set(packet)
    }
    pub fn msgPLI_RC_PLAYERBANGET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_player_ban_get(packet)
    }
    pub fn msgPLI_RC_PLAYERBANSET(&self, packet: &[u8]) -> bool {
        self.msg_pli_rc_player_ban_set(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_server(name: &str) -> (Arc<Server>, PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "gscript-rust-test-{}-{}",
            name,
            system_time_millis()
        ));
        std::fs::create_dir_all(&path).unwrap();
        let server = Server::new_with_logger(name, &path, Arc::new(Logger::new("", false)));
        (server, path)
    }

    #[test]
    fn text_request_subscription_matches_wire_fields() {
        let (server, _path) = test_server("subscriptions");
        let player = Player::new(None, &server);
        player.set_encryption_gen(ENCRYPT_GEN_1);
        player.set_queue_outgoing(true);
        let request = format!("{}\u{1}lister\u{1}subscriptions\u{1}", IRC_BYTES);
        assert!(
            player.msgPLI_REQUESTTEXT([&[PLI_REQUESTTEXT], request.as_bytes()].concat().as_slice())
        );
        let expected = format!(
            "{}{}{}{}{}{}{}{}\n",
            char::from(PLO_SERVERTEXT + 32),
            IRC_BYTES,
            char::from(1),
            "lister",
            char::from(1),
            "subscriptions",
            char::from(1),
            "unlimited\u{1}Unlimited Subscription\u{1}\"\"\u{1}"
        );
        assert_eq!(player.out_queue(), expected.as_bytes());
    }

    #[test]
    fn text_request_local_pm_server_fallback_matches_wire_fields() {
        let (server, _path) = test_server("Orion");
        server.cache_listserver_text(b"Skill Games,classic,12,English,Skill server");
        let player = Player::new(None, &server);
        player.set_encryption_gen(ENCRYPT_GEN_1);
        player.set_queue_outgoing(true);
        let request = format!("{}\u{1}pmservers\u{1}all\u{1}", IRC_BYTES);
        assert!(
            player.msgPLI_REQUESTTEXT([&[PLI_REQUESTTEXT], request.as_bytes()].concat().as_slice())
        );
        let mut want = Buffer::new();
        want.write_byte(PLO_SERVERTEXT).write(
            format!(
                "{}\u{1}pmservers\u{1}all\u{1}Orion\u{1}Skill Games\u{1}",
                IRC_BYTES
            )
            .as_bytes(),
        );
        let mut encoded = want.data;
        encoded[0] = PLO_SERVERTEXT + 32;
        encoded.push(b'\n');
        assert_eq!(player.out_queue(), encoded);
    }

    #[test]
    fn update_script_wraps_bytecode_in_raw_data() {
        let (server, _path) = test_server("updatescript");
        let mut weapon = Weapon::new("-test");
        weapon.bytecode = vec![1, 2, 3];
        server.add_weapon(Arc::new(weapon));
        let player = Player::new(None, &server);
        player.set_encryption_gen(ENCRYPT_GEN_1);
        player.set_queue_outgoing(true);
        let packet = [&[PLI_UPDATESCRIPT][..], b"-test"].concat();
        assert!(player.msgPLI_UPDATESCRIPT(&packet));
        let mut embedded = Buffer::new();
        embedded.write_gchar(PLO_NPCWEAPONSCRIPT).write(&[1, 2, 3]);
        let mut want = Buffer::new();
        want.write_byte(PLO_RAWDATA)
            .write_gint(embedded.len() as u32)
            .write_byte(b'\n')
            .write(&embedded.data);
        want.data[0] = PLO_RAWDATA + 32;
        assert_eq!(player.out_queue(), want.data);
    }

    #[test]
    fn update_gani_setback_packet_uses_gint5_checksum() {
        let (server, _path) = test_server("updategani");
        let gani = b"GANI0001\nSETBACKTO walk\n";
        server.config.save_file("walk.gani", gani).unwrap();
        let player = Player::new(None, &server);
        player.set_encryption_gen(ENCRYPT_GEN_1);
        player.set_queue_outgoing(true);
        let mut packet = Buffer::new();
        packet
            .write_byte(PLI_UPDATEGANI)
            .write_gint5(calculate_crc32_checksum(gani) as u64)
            .write(b"walk");
        assert!(player.msgPLI_UPDATEGANI(&packet.data));
        let mut want = Buffer::new();
        want.write_byte(PLO_UNKNOWN195)
            .write_gchar(4)
            .write(b"walk")
            .write(b"\"SETBACKTO walk\"");
        want.data[0] = PLO_UNKNOWN195 + 32;
        want.data[1] = 4 + 32;
        want.data.push(b'\n');
        assert_eq!(player.out_queue(), want.data);
    }

    #[test]
    fn file_permissions_match_go_segment_regular_expressions() {
        let permissions = FilePermissions::new();
        permissions.add_permission("rw world/*/npc[0-9]+");
        permissions.add_permission("-w world/private/*");

        assert!(permissions.has_permission("world/public/npc12", PermissionRead));
        assert!(permissions.has_permission("world/public/npc12", PermissionWrite));
        assert!(!permissions.has_permission("world/public/npcx", PermissionRead));
        assert!(!permissions.has_permission("world/private/npc12", PermissionWrite));
        assert!(permissions.has_permission("world/private/npc12", PermissionRead));
        assert!(!permissions.has_permission("world/public/npc12/extra", PermissionRead));
    }

    #[test]
    fn joined_class_on_created_runs_before_owner_event() {
        let (server, _path) = test_server("joined-class");
        server.add_class(Arc::new(ScriptClass {
            name: "socklib".to_string(),
            script: "function onCreated() { echo(\"class created\"); }".to_string(),
        }));
        let result = server.run_server_side_gs2(
            "weapon",
            "test",
            "onCreated",
            "join socklib;\nfunction onCreated() { echo(\"owner created\"); }",
            &[],
        );
        assert!(
            result.error.is_empty(),
            "{}; script={}",
            result.error,
            result.script
        );
        assert_eq!(
            result.output,
            ["class created", "owner created"],
            "script={}",
            result.script
        );
    }
}
