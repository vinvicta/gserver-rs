//! GS2 Parser
//!
//! Recursive descent parser for GS2 language.

use crate::error::{ScriptError, Result};
use crate::gs2::ast::*;
use crate::gs2::lexer::{Lexer, Token};
use std::cell::RefCell;

/// GS2 parser
pub struct Parser<'a> {
    lexer: RefCell<Lexer<'a>>,
    current: RefCell<Token>,
    previous: RefCell<Token>,
}

impl<'a> Parser<'a> {
    /// Create a new parser
    pub fn new(input: &'a str) -> Self {
        let lexer = RefCell::new(Lexer::new(input));
        let current = RefCell::new(lexer.borrow_mut().next_token().unwrap());
        let previous = RefCell::new(Token::EOF);

        Self { lexer, current, previous }
    }

    /// Parse a script
    pub fn parse(&self) -> Result<Script> {
        let mut statements = Vec::new();

        while !self.check(Token::EOF) {
            statements.push(self.declaration()?);
        }

        Ok(Script::new(statements))
    }

    /// Parse a declaration
    fn declaration(&self) -> Result<Stmt> {
        if self.check(Token::Function) {
            self.function_declaration()
        } else if self.check(Token::Class) {
            self.class_declaration()
        } else {
            self.statement()
        }
    }

    /// Parse a function declaration
    fn function_declaration(&self) -> Result<Stmt> {
        self.consume(Token::Function, "Expected 'function'")?;

        let name = match self.current.clone().into_inner() {
            Token::Identifier(name) => name,
            _ => {
                return Err(ScriptError::ParseError {
                    line: 0,
                    message: "Expected function name".into(),
                })
            }
        };

        self.advance();

        self.consume(Token::LParen, "Expected '(' after function name")?;
        let mut params = Vec::new();

        if !self.check(Token::RParen) {
            loop {
                if let Token::Identifier(param) = self.current.clone().into_inner() {
                    params.push(param);
                    self.advance();

                    if !self.match_token(Token::Comma) {
                        break;
                    }
                } else {
                    return Err(ScriptError::ParseError {
                        line: 0,
                        message: "Expected parameter name".into(),
                    });
                }
            }
        }

        self.consume(Token::RParen, "Expected ')' after parameters")?;
        let body = Box::new(self.block_statement()?);

        Ok(Stmt::Function { name, params, body })
    }

    /// Parse a class declaration
    fn class_declaration(&self) -> Result<Stmt> {
        self.consume(Token::Class, "Expected 'class'")?;

        let name = match self.current.clone().into_inner() {
            Token::Identifier(name) => name,
            _ => {
                return Err(ScriptError::ParseError {
                    line: 0,
                    message: "Expected class name".into(),
                })
            }
        };

        self.advance();

        // Check for superclass (class Name : Superclass { ... })
        let superclass = if self.match_token(Token::Colon) {
            match self.current.clone().into_inner() {
                Token::Identifier(super_name) => {
                    self.advance();
                    Some(super_name)
                }
                _ => {
                    return Err(ScriptError::ParseError {
                        line: 0,
                        message: "Expected superclass name".into(),
                    })
                }
            }
        } else {
            None
        };

        self.consume(Token::LBrace, "Expected '{' before class body")?;

        let mut methods = Vec::new();
        while !self.check(Token::RBrace) && !self.check(Token::EOF) {
            // Parse method as function declaration
            methods.push(self.function_declaration()?);
        }

        self.consume(Token::RBrace, "Expected '}' after class body")?;

        Ok(Stmt::Class { name, superclass, methods })
    }

    /// Parse a statement
    fn statement(&self) -> Result<Stmt> {
        if self.check(Token::If) {
            self.if_statement()
        } else if self.check(Token::While) {
            self.while_statement()
        } else if self.check(Token::For) {
            self.for_statement()
        } else if self.check(Token::Return) {
            self.return_statement()
        } else if self.check(Token::LBrace) {
            self.block_statement()
        } else if self.check(Token::Semicolon) {
            self.advance();
            Ok(Stmt::Empty)
        } else {
            self.expression_statement()
        }
    }

    /// Parse an if statement
    fn if_statement(&self) -> Result<Stmt> {
        self.consume(Token::If, "Expected 'if'")?;
        self.consume(Token::LParen, "Expected '(' after 'if'")?;

        let condition = self.expression()?;

        self.consume(Token::RParen, "Expected ')' after condition")?;
        let then_branch = Box::new(self.statement()?);
        let mut else_branch = None;

        if self.match_token(Token::Else) {
            else_branch = Some(Box::new(self.statement()?));
        }

        Ok(Stmt::If {
            condition,
            then_branch,
            else_branch,
        })
    }

    /// Parse a while statement
    fn while_statement(&self) -> Result<Stmt> {
        self.consume(Token::While, "Expected 'while'")?;
        self.consume(Token::LParen, "Expected '(' after 'while'")?;

        let condition = self.expression()?;

        self.consume(Token::RParen, "Expected ')' after condition")?;
        let body = Box::new(self.statement()?);

        Ok(Stmt::While { condition, body })
    }

    /// Parse a for statement
    fn for_statement(&self) -> Result<Stmt> {
        self.consume(Token::For, "Expected 'for'")?;
        self.consume(Token::LParen, "Expected '(' after 'for'")?;

        let init = if !self.check(Token::Semicolon) {
            Some(Box::new(self.declaration()?))
        } else {
            None
        };

        self.consume(Token::Semicolon, "Expected ';' after init")?;

        let condition = if !self.check(Token::Semicolon) {
            Some(self.expression()?)
        } else {
            None
        };

        self.consume(Token::Semicolon, "Expected ';' after condition")?;

        let increment = if !self.check(Token::RParen) {
            Some(self.expression()?)
        } else {
            None
        };

        self.consume(Token::RParen, "Expected ')' after for clauses")?;
        let body = Box::new(self.statement()?);

        Ok(Stmt::For {
            init,
            condition,
            increment,
            body,
        })
    }

    /// Parse a return statement
    fn return_statement(&self) -> Result<Stmt> {
        self.consume(Token::Return, "Expected 'return'")?;

        let value = if !self.check(Token::Semicolon) {
            Some(self.expression()?)
        } else {
            None
        };

        self.consume(Token::Semicolon, "Expected ';' after return")?;

        Ok(Stmt::Return(value))
    }

    /// Parse a block statement
    fn block_statement(&self) -> Result<Stmt> {
        self.consume(Token::LBrace, "Expected '{'")?;

        let mut statements = Vec::new();

        while !self.check(Token::RBrace) && !self.check(Token::EOF) {
            statements.push(self.declaration()?);
        }

        self.consume(Token::RBrace, "Expected '}' after block")?;

        Ok(Stmt::Block(statements))
    }

    /// Parse an expression statement
    fn expression_statement(&self) -> Result<Stmt> {
        let expr = self.expression()?;

        self.consume(Token::Semicolon, "Expected ';' after expression")?;

        Ok(Stmt::Expr(expr))
    }

    /// Parse an expression
    fn expression(&self) -> Result<Expr> {
        self.assignment()
    }

    /// Parse assignment expression
    fn assignment(&self) -> Result<Expr> {
        let expr = self.or()?;

        if self.match_token(Token::Assign) {
            let value = Box::new(self.assignment()?);
            return Ok(match expr {
                Expr::Variable(name) => Expr::Binary {
                    left: Box::new(Expr::Variable(name)),
                    op: BinaryOp::Equal,
                    right: value,
                },
                _ => return Err(ScriptError::ParseError {
                    line: 0,
                    message: "Invalid assignment target".into(),
                }),
            });
        }

        Ok(expr)
    }

    /// Parse logical OR
    fn or(&self) -> Result<Expr> {
        let mut expr = self.and()?;

        while self.match_token(Token::Or) {
            let right = self.and()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op: BinaryOp::Or,
                right: Box::new(right),
            };
        }

        Ok(expr)
    }

    /// Parse logical AND
    fn and(&self) -> Result<Expr> {
        let mut expr = self.equality()?;

        while self.match_token(Token::And) {
            let right = self.equality()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op: BinaryOp::And,
                right: Box::new(right),
            };
        }

        Ok(expr)
    }

    /// Parse equality
    fn equality(&self) -> Result<Expr> {
        let mut expr = self.comparison()?;

        while self.match_tokens(&[Token::Equal, Token::NotEqual]) {
            let op = BinaryOp::from(self.previous());
            let right = self.comparison()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op,
                right: Box::new(right),
            };
        }

        Ok(expr)
    }

    /// Parse comparison
    fn comparison(&self) -> Result<Expr> {
        let mut expr = self.term()?;

        while self.match_tokens(&[Token::Greater, Token::GreaterEqual, Token::Less, Token::LessEqual]) {
            let op = BinaryOp::from(self.previous());
            let right = self.term()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op,
                right: Box::new(right),
            };
        }

        Ok(expr)
    }

    /// Parse term
    fn term(&self) -> Result<Expr> {
        let mut expr = self.factor()?;

        while self.match_tokens(&[Token::Minus, Token::Plus]) {
            let op = BinaryOp::from(self.previous());
            let right = self.factor()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op,
                right: Box::new(right),
            };
        }

        Ok(expr)
    }

    /// Parse factor
    fn factor(&self) -> Result<Expr> {
        let mut expr = self.unary()?;

        while self.match_tokens(&[Token::Slash, Token::Star, Token::Percent]) {
            let op = BinaryOp::from(self.previous());
            let right = self.unary()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op,
                right: Box::new(right),
            };
        }

        Ok(expr)
    }

    /// Parse unary expression
    fn unary(&self) -> Result<Expr> {
        if self.match_tokens(&[Token::Not, Token::Minus, Token::BitNot]) {
            let op = UnaryOp::from(self.previous());
            let right = self.unary()?;
            return Ok(Expr::Unary {
                op,
                operand: Box::new(right),
            });
        }

        self.call()
    }

    /// Parse function call or member access
    fn call(&self) -> Result<Expr> {
        let mut expr = self.primary()?;

        loop {
            if self.match_token(Token::LParen) {
                let mut args = Vec::new();

                if !self.check(Token::RParen) {
                    loop {
                        args.push(self.expression()?);
                        if !self.match_token(Token::Comma) {
                            break;
                        }
                    }
                }

                self.consume(Token::RParen, "Expected ')' after arguments")?;
                expr = Expr::Call {
                    callee: Box::new(expr),
                    args,
                };
            } else if self.match_token(Token::Dot) {
                if let Token::Identifier(name) = self.current.clone().into_inner() {
                    self.advance();
                    expr = Expr::GetProp {
                        object: Box::new(expr),
                        name,
                    };
                }
            } else if self.match_token(Token::LBracket) {
                let index = self.expression()?;
                self.consume(Token::RBracket, "Expected ']' after index")?;
                expr = Expr::Index {
                    object: Box::new(expr),
                    index: Box::new(index),
                };
            } else {
                break;
            }
        }

        Ok(expr)
    }

    /// Parse primary expression
    fn primary(&self) -> Result<Expr> {
        let token = self.current.clone().into_inner();

        match token {
            Token::Number(n) => {
                self.advance();
                Ok(Expr::Number(n))
            }

            Token::String(s) => {
                self.advance();
                Ok(Expr::String(s))
            }

            Token::True => {
                self.advance();
                Ok(Expr::Bool(true))
            }

            Token::False => {
                self.advance();
                Ok(Expr::Bool(false))
            }

            Token::Null => {
                self.advance();
                Ok(Expr::Null)
            }

            Token::This => {
                self.advance();
                Ok(Expr::This)
            }

            Token::Super => {
                self.advance();
                Ok(Expr::Super)
            }

            Token::Identifier(name) => {
                self.advance();
                Ok(Expr::Variable(name))
            }

            Token::LParen => {
                self.advance();
                let expr = self.expression()?;
                self.consume(Token::RParen, "Expected ')' after expression")?;
                Ok(expr)
            }

            Token::LBracket => {
                self.advance();
                let mut elems = Vec::new();

                if !self.check(Token::RBracket) {
                    loop {
                        elems.push(self.expression()?);
                        if !self.match_token(Token::Comma) {
                            break;
                        }
                    }
                }

                self.consume(Token::RBracket, "Expected ']' after array elements")?;
                Ok(Expr::Array(elems))
            }

            Token::LBrace => {
                self.advance();
                let mut props = Vec::new();

                if !self.check(Token::RBrace) {
                    loop {
                        if let Token::Identifier(key) = self.current.clone().into_inner() {
                            self.advance();
                            self.consume(Token::Colon, "Expected ':' after object key")?;
                            let value = self.expression()?;
                            props.push((key, value));

                            if !self.match_token(Token::Comma) {
                                break;
                            }
                        }
                    }
                }

                self.consume(Token::RBrace, "Expected '}' after object properties")?;
                Ok(Expr::Object(props))
            }

            _ => Err(ScriptError::ParseError {
                line: 0,
                message: format!("Unexpected token: {:?}", token),
            }),
        }
    }

    /// Check if current token matches
    fn check(&self, token: Token) -> bool {
        std::mem::discriminant(&self.current.borrow().clone()) == std::mem::discriminant(&token)
    }

    /// Match token and advance
    fn match_token(&self, token: Token) -> bool {
        if self.check(token.clone()) {
            self.advance();
            return true;
        }
        false
    }

    /// Match any of multiple tokens
    fn match_tokens(&self, tokens: &[Token]) -> bool {
        for token in tokens {
            if self.check(token.clone()) {
                self.advance();
                return true;
            }
        }
        false
    }

    /// Consume a specific token or error
    fn consume(&self, token: Token, message: &str) -> Result<()> {
        if self.check(token.clone()) {
            self.advance();
            return Ok(());
        }

        Err(ScriptError::ParseError {
            line: 0,
            message: message.into(),
        })
    }

    /// Get previous token
    fn previous(&self) -> Token {
        self.previous.borrow().clone()
    }

    /// Advance to next token
    fn advance(&self) -> Token {
        let prev = self.current.borrow().clone();
        *self.previous.borrow_mut() = prev.clone();
        *self.current.borrow_mut() = self.lexer.borrow_mut().next_token().unwrap();
        prev
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_number() {
        let parser = Parser::new("42;");
        let script = parser.parse().unwrap();
        assert_eq!(script.statements.len(), 1);
    }

    #[test]
    fn test_parse_binary_op() {
        let parser = Parser::new("1 + 2;");
        let script = parser.parse().unwrap();
        assert_eq!(script.statements.len(), 1);
    }

    #[test]
    fn test_parse_function() {
        let parser = Parser::new("function foo() { return 42; }");
        let script = parser.parse().unwrap();
        assert_eq!(script.statements.len(), 1);
    }

    #[test]
    fn test_parse_class() {
        let parser = Parser::new("class MyClass { function method() { return 42; } }");
        let script = parser.parse().unwrap();
        assert_eq!(script.statements.len(), 1);
    }

    #[test]
    fn test_parse_class_with_inheritance() {
        let parser = Parser::new("class Derived : BaseClass { function method() { return 42; } }");
        let script = parser.parse().unwrap();
        assert_eq!(script.statements.len(), 1);
    }

    #[test]
    fn test_parse_if_statement() {
        let parser = Parser::new("if (true) { return 1; } else { return 0; }");
        let script = parser.parse().unwrap();
        assert_eq!(script.statements.len(), 1);
    }
}
