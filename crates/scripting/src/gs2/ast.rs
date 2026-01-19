//! GS2 Abstract Syntax Tree
//!
//! AST nodes for GS2 language constructs.

use crate::gs2::lexer::Token;
use std::fmt;

/// GS2 expression
#[derive(Debug, Clone)]
pub enum Expr {
    /// Number literal
    Number(f64),

    /// String literal
    String(String),

    /// Boolean literal
    Bool(bool),

    /// Null literal
    Null,

    /// Variable reference
    Variable(String),

    /// Binary operation
    Binary {
        left: Box<Expr>,
        op: BinaryOp,
        right: Box<Expr>,
    },

    /// Unary operation
    Unary {
        op: UnaryOp,
        operand: Box<Expr>,
    },

    /// Function call
    Call {
        callee: Box<Expr>,
        args: Vec<Expr>,
    },

    /// Member access (obj.prop)
    GetProp {
        object: Box<Expr>,
        name: String,
    },

    /// Property assignment (obj.prop = value)
    SetProp {
        object: Box<Expr>,
        name: String,
        value: Box<Expr>,
    },

    /// Array/index access
    Index {
        object: Box<Expr>,
        index: Box<Expr>,
    },

    /// Array literal
    Array(Vec<Expr>),

    /// Object literal
    Object(Vec<(String, Expr)>),

    /// This expression
    This,

    /// Super expression
    Super,
}

/// Binary operators
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BinaryOp {
    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Mod,

    // Comparison
    Equal,
    NotEqual,
    Less,
    Greater,
    LessEqual,
    GreaterEqual,

    // Logical
    And,
    Or,

    // Bitwise
    BitAnd,
    BitOr,
    BitXor,
    LeftShift,
    RightShift,
}

impl From<Token> for BinaryOp {
    fn from(token: Token) -> Self {
        match token {
            Token::Plus => BinaryOp::Add,
            Token::Minus => BinaryOp::Sub,
            Token::Star => BinaryOp::Mul,
            Token::Slash => BinaryOp::Div,
            Token::Percent => BinaryOp::Mod,

            Token::Equal => BinaryOp::Equal,
            Token::NotEqual => BinaryOp::NotEqual,
            Token::Less => BinaryOp::Less,
            Token::Greater => BinaryOp::Greater,
            Token::LessEqual => BinaryOp::LessEqual,
            Token::GreaterEqual => BinaryOp::GreaterEqual,

            Token::And => BinaryOp::And,
            Token::Or => BinaryOp::Or,

            Token::BitAnd => BinaryOp::BitAnd,
            Token::BitOr => BinaryOp::BitOr,
            Token::BitXor => BinaryOp::BitXor,
            Token::LeftShift => BinaryOp::LeftShift,
            Token::RightShift => BinaryOp::RightShift,

            _ => panic!("Token cannot be converted to BinaryOp"),
        }
    }
}

/// Unary operators
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnaryOp {
    Negate,
    Not,
    BitNot,
}

impl From<Token> for UnaryOp {
    fn from(token: Token) -> Self {
        match token {
            Token::Minus => UnaryOp::Negate,
            Token::Not => UnaryOp::Not,
            Token::BitNot => UnaryOp::BitNot,
            _ => panic!("Token cannot be converted to UnaryOp"),
        }
    }
}

/// GS2 statement
#[derive(Debug, Clone)]
pub enum Stmt {
    /// Expression statement
    Expr(Expr),

    /// Variable declaration
    Var {
        name: String,
        initializer: Option<Expr>,
    },

    /// If statement
    If {
        condition: Expr,
        then_branch: Box<Stmt>,
        else_branch: Option<Box<Stmt>>,
    },

    /// While loop
    While {
        condition: Expr,
        body: Box<Stmt>,
    },

    /// For loop
    For {
        init: Option<Box<Stmt>>,
        condition: Option<Expr>,
        increment: Option<Expr>,
        body: Box<Stmt>,
    },

    /// Function declaration
    Function {
        name: String,
        params: Vec<String>,
        body: Box<Stmt>,
    },

    /// Class declaration
    Class {
        name: String,
        superclass: Option<String>,
        methods: Vec<Stmt>,
    },

    /// Return statement
    Return(Option<Expr>),

    /// Block statement
    Block(Vec<Stmt>),

    /// Break statement
    Break,

    /// Continue statement
    Continue,

    /// Empty statement
    Empty,
}

/// Function declaration
#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub params: Vec<String>,
    pub body: Vec<Stmt>,
}

/// Script (top-level)
#[derive(Debug, Clone)]
pub struct Script {
    pub statements: Vec<Stmt>,
}

impl Script {
    pub fn new(statements: Vec<Stmt>) -> Self {
        Self { statements }
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Expr::Number(n) => write!(f, "{}", n),
            Expr::String(s) => write!(f, "\"{}\"", s),
            Expr::Bool(b) => write!(f, "{}", b),
            Expr::Null => write!(f, "null"),
            Expr::Variable(name) => write!(f, "{}", name),
            Expr::Binary { left, op, right } => {
                write!(f, "({} {:?} {})", left, op, right)
            }
            Expr::Unary { op, operand } => {
                write!(f, "{:?}{}", op, operand)
            }
            Expr::Call { callee, args } => {
                write!(f, "{}({:?})", callee, args)
            }
            Expr::GetProp { object, name } => {
                write!(f, "{}.{}", object, name)
            }
            Expr::SetProp { object, name, value } => {
                write!(f, "{}.{} = {}", object, name, value)
            }
            Expr::Index { object, index } => {
                write!(f, "{}[{}]", object, index)
            }
            Expr::Array(elems) => {
                write!(f, "[{:?}]", elems)
            }
            Expr::Object(props) => {
                write!(f, "{{{:?}}}", props)
            }
            Expr::This => write!(f, "this"),
            Expr::Super => write!(f, "super"),
        }
    }
}
