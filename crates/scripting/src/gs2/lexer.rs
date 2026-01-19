//! GS2 Lexer and Tokenizer
//!
//! Lexical analysis for GS2 scripting language.

use crate::error::{ScriptError, Result};
use std::iter::Peekable;
use std::str::Chars;

/// GS2 token types
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Literals
    Number(f64),
    String(String),
    Identifier(String),

    // Keywords
    If,
    Else,
    While,
    For,
    Function,
    Class,
    Return,
    True,
    False,
    Null,
    This,
    Super,
    New,

    // Operators
    Plus,           // +
    Minus,          // -
    Star,           // *
    Slash,          // /
    Percent,        // %

    // Comparison
    Equal,          // ==
    NotEqual,       // !=
    Less,           // <
    Greater,        // >
    LessEqual,      // <=
    GreaterEqual,   // >=

    // Logical
    And,            // &&
    Or,             // ||
    Not,            // !

    // Bitwise
    BitAnd,         // &
    BitOr,          // |
    BitXor,         // ^
    BitNot,         // ~
    LeftShift,      // <<
    RightShift,     // >>

    // Assignment
    Assign,         // =
    PlusEqual,      // +=
    MinusEqual,     // -=
    StarEqual,      // *=
    SlashEqual,     // /=

    // Increment/Decrement
    Increment,      // ++
    Decrement,      // --

    // Delimiters
    LParen,         // (
    RParen,         // )
    LBrace,         // {
    RBrace,         // }
    LBracket,       // [
    RBracket,       // ]
    Semicolon,      // ;
    Comma,          // ,
    Dot,            // .
    Colon,          // :

    // Other
    Question,       // ?

    // End of file
    EOF,
}

/// GS2 lexer
pub struct Lexer<'a> {
    input: Peekable<Chars<'a>>,
    position: usize,
    line: usize,
    column: usize,
    ch: Option<char>,
}

impl<'a> Lexer<'a> {
    /// Create a new lexer
    pub fn new(input: &'a str) -> Self {
        let mut chars = input.chars().peekable();
        let ch = chars.next();
        Self {
            input: chars,
            position: 0,
            line: 1,
            column: 0,
            ch,
        }
    }

    /// Get the next token
    pub fn next_token(&mut self) -> Result<Token> {
        self.skip_whitespace();

        match self.ch {
            None => Ok(Token::EOF),

            Some(ch) => {
                match ch {
                    // Numbers
                    '0'..='9' => self.read_number(),

                    // Identifiers and keywords
                    'a'..='z' | 'A'..='Z' | '_' => self.read_identifier(),

                    // Strings
                    '"' => self.read_string(),

                    // Operators and punctuation
                    '+' => {
                        self.advance();
                        // Check current char (which is the one after the first +)
                        if self.ch == Some('=') {
                            self.advance();
                            Ok(Token::PlusEqual)
                        } else if self.ch == Some('+') {
                            self.advance();
                            Ok(Token::Increment)
                        } else {
                            Ok(Token::Plus)
                        }
                    }

                    '-' => {
                        self.advance();
                        if self.ch == Some('=') {
                            self.advance();
                            Ok(Token::MinusEqual)
                        } else if self.ch == Some('-') {
                            self.advance();
                            Ok(Token::Decrement)
                        } else {
                            Ok(Token::Minus)
                        }
                    }

                    '*' => {
                        self.advance();
                        if self.ch == Some('=') {
                            self.advance();
                            Ok(Token::StarEqual)
                        } else {
                            Ok(Token::Star)
                        }
                    }

                    '/' => {
                        self.advance();
                        if self.ch == Some('=') {
                            self.advance();
                            Ok(Token::SlashEqual)
                        } else if self.ch == Some('/') {
                            // Line comment
                            while self.ch.is_some() && self.ch != Some('\n') {
                                self.advance();
                            }
                            self.next_token()
                        } else {
                            Ok(Token::Slash)
                        }
                    }

                    '%' => {
                        self.advance();
                        Ok(Token::Percent)
                    }

                    '=' => {
                        self.advance();
                        if self.ch == Some('=') {
                            self.advance();
                            Ok(Token::Equal)
                        } else {
                            Ok(Token::Assign)
                        }
                    }

                    '!' => {
                        self.advance();
                        if self.ch == Some('=') {
                            self.advance();
                            Ok(Token::NotEqual)
                        } else {
                            Ok(Token::Not)
                        }
                    }

                    '<' => {
                        self.advance();
                        if self.ch == Some('=') {
                            self.advance();
                            Ok(Token::LessEqual)
                        } else if self.ch == Some('<') {
                            self.advance();
                            Ok(Token::LeftShift)
                        } else {
                            Ok(Token::Less)
                        }
                    }

                    '>' => {
                        self.advance();
                        if self.ch == Some('=') {
                            self.advance();
                            Ok(Token::GreaterEqual)
                        } else if self.ch == Some('>') {
                            self.advance();
                            Ok(Token::RightShift)
                        } else {
                            Ok(Token::Greater)
                        }
                    }

                    '&' => {
                        self.advance();
                        if self.ch == Some('&') {
                            self.advance();
                            Ok(Token::And)
                        } else {
                            Ok(Token::BitAnd)
                        }
                    }

                    '|' => {
                        self.advance();
                        if self.ch == Some('|') {
                            self.advance();
                            Ok(Token::Or)
                        } else {
                            Ok(Token::BitOr)
                        }
                    }

                    '^' => {
                        self.advance();
                        Ok(Token::BitXor)
                    }

                    '~' => {
                        self.advance();
                        Ok(Token::BitNot)
                    }

                    '(' => { self.advance(); Ok(Token::LParen) }
                    ')' => { self.advance(); Ok(Token::RParen) }
                    '{' => { self.advance(); Ok(Token::LBrace) }
                    '}' => { self.advance(); Ok(Token::RBrace) }
                    '[' => { self.advance(); Ok(Token::LBracket) }
                    ']' => { self.advance(); Ok(Token::RBracket) }
                    ';' => { self.advance(); Ok(Token::Semicolon) }
                    ',' => { self.advance(); Ok(Token::Comma) }
                    '.' => { self.advance(); Ok(Token::Dot) }
                    ':' => { self.advance(); Ok(Token::Colon) }
                    '?' => { self.advance(); Ok(Token::Question) }

                    '\n' => {
                        self.advance();
                        self.line += 1;
                        self.column = 0;
                        self.next_token()
                    }

                    _ => {
                        let msg = format!("Unexpected character: {}", ch);
                        self.advance();
                        Err(ScriptError::ParseError {
                            line: self.line,
                            message: msg,
                        })
                    }
                }
            }
        }
    }

    /// Read a number literal
    fn read_number(&mut self) -> Result<Token> {
        let start = self.column;
        let mut num_str = String::new();

        while let Some(ch) = self.ch {
            if ch.is_ascii_digit() || ch == '.' {
                num_str.push(ch);
                self.advance();
            } else {
                break;
            }
        }

        let value: f64 = num_str.parse()
            .map_err(|_| ScriptError::ParseError {
                line: self.line,
                message: format!("Invalid number: {}", num_str),
            })?;

        Ok(Token::Number(value))
    }

    /// Read an identifier or keyword
    fn read_identifier(&mut self) -> Result<Token> {
        let mut ident = String::new();

        while let Some(ch) = self.ch {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ident.push(ch);
                self.advance();
            } else {
                break;
            }
        }

        let token = match ident.as_str() {
            "if" => Token::If,
            "else" => Token::Else,
            "while" => Token::While,
            "for" => Token::For,
            "function" => Token::Function,
            "class" => Token::Class,
            "return" => Token::Return,
            "true" => Token::True,
            "false" => Token::False,
            "null" => Token::Null,
            "this" => Token::This,
            "super" => Token::Super,
            "new" => Token::New,
            _ => Token::Identifier(ident),
        };

        Ok(token)
    }

    /// Read a string literal
    fn read_string(&mut self) -> Result<Token> {
        self.advance(); // Skip opening quote

        let mut s = String::new();

        while let Some(ch) = self.ch {
            if ch == '"' {
                self.advance();
                return Ok(Token::String(s));
            } else if ch == '\\' {
                self.advance();
                if let Some(escaped) = self.ch {
                    match escaped {
                        'n' => s.push('\n'),
                        't' => s.push('\t'),
                        'r' => s.push('\r'),
                        '"' => s.push('"'),
                        '\\' => s.push('\\'),
                        _ => s.push(escaped),
                    }
                }
                self.advance();
            } else {
                s.push(ch);
                self.advance();
            }
        }

        Err(ScriptError::ParseError {
            line: self.line,
            message: "Unterminated string".into(),
        })
    }

    /// Check if the next character matches
    fn check_char(&mut self, ch: char) -> bool {
        match self.input.peek() {
            Some(&c) => c == ch,
            None => false,
        }
    }

    /// Advance to the next character
    fn advance(&mut self) {
        self.ch = self.input.next();
        self.column += 1;
        self.position += 1;
    }

    /// Skip whitespace
    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.ch {
            if ch.is_whitespace() && ch != '\n' {
                self.advance();
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_numbers() {
        let mut lexer = Lexer::new("123 45.67");

        assert_eq!(lexer.next_token().unwrap(), Token::Number(123.0));
        assert_eq!(lexer.next_token().unwrap(), Token::Number(45.67));
    }

    #[test]
    fn test_identifiers() {
        let mut lexer = Lexer::new("foo bar_baz");

        assert_eq!(lexer.next_token().unwrap(), Token::Identifier("foo".into()));
        assert_eq!(lexer.next_token().unwrap(), Token::Identifier("bar_baz".into()));
    }

    #[test]
    fn test_keywords() {
        let mut lexer = Lexer::new("if else while function return true false null");

        assert_eq!(lexer.next_token().unwrap(), Token::If);
        assert_eq!(lexer.next_token().unwrap(), Token::Else);
        assert_eq!(lexer.next_token().unwrap(), Token::While);
        assert_eq!(lexer.next_token().unwrap(), Token::Function);
        assert_eq!(lexer.next_token().unwrap(), Token::Return);
        assert_eq!(lexer.next_token().unwrap(), Token::True);
        assert_eq!(lexer.next_token().unwrap(), Token::False);
        assert_eq!(lexer.next_token().unwrap(), Token::Null);
    }

    #[test]
    fn test_operators() {
        let mut lexer = Lexer::new("++ -- && || ! == != < > <= >=");

        assert_eq!(lexer.next_token().unwrap(), Token::Increment);
        assert_eq!(lexer.next_token().unwrap(), Token::Decrement);
        assert_eq!(lexer.next_token().unwrap(), Token::And);
        assert_eq!(lexer.next_token().unwrap(), Token::Or);
        assert_eq!(lexer.next_token().unwrap(), Token::Not);
        assert_eq!(lexer.next_token().unwrap(), Token::Equal);
        assert_eq!(lexer.next_token().unwrap(), Token::NotEqual);
        assert_eq!(lexer.next_token().unwrap(), Token::Less);
        assert_eq!(lexer.next_token().unwrap(), Token::Greater);
        assert_eq!(lexer.next_token().unwrap(), Token::LessEqual);
        assert_eq!(lexer.next_token().unwrap(), Token::GreaterEqual);
    }

    #[test]
    fn test_string() {
        let mut lexer = Lexer::new(r#""hello world""#);

        assert_eq!(lexer.next_token().unwrap(), Token::String("hello world".into()));
    }
}
