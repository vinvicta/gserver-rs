//! GS2 Bytecode Compiler
//!
//! Compiles AST to bytecode.

use crate::error::{ScriptError, Result};
use crate::gs2::ast::*;
use crate::gs2::bytecode::{Chunk, OpCode, Value, Function, Class};

/// GS2 bytecode compiler
pub struct Compiler {
    chunk: Chunk,
    function_name: String,
}

impl Compiler {
    /// Create a new compiler
    pub fn new() -> Self {
        Self {
            chunk: Chunk::new(),
            function_name: "<script>".into(),
        }
    }

    /// Compile a script to bytecode
    pub fn compile(&mut self, script: &Script) -> Result<Chunk> {
        for stmt in &script.statements {
            self.compile_statement(stmt)?;
        }

        // Add a return instruction at the end
        self.chunk.write_op(OpCode::OpReturn, 0);

        Ok(self.chunk.clone())
    }

    /// Compile a function to bytecode
    pub fn compile_function(&mut self, name: &str, params: &[String], body: &Stmt) -> Result<Function> {
        let mut func_compiler = Compiler {
            chunk: Chunk::new(),
            function_name: name.into(),
        };

        // Compile function body
        func_compiler.compile_statement(body)?;
        func_compiler.chunk.write_op(OpCode::OpReturn, 0);

        Ok(Function {
            name: name.into(),
            arity: params.len(),
            chunk: func_compiler.chunk,
        })
    }

    /// Compile a statement
    fn compile_statement(&mut self, stmt: &Stmt) -> Result<()> {
        match stmt {
            Stmt::Expr(expr) => {
                self.compile_expression(expr)?;
                self.chunk.write_op(OpCode::OpPop, 0);
            }

            Stmt::Var { name, initializer } => {
                if let Some(init) = initializer {
                    self.compile_expression(init)?;
                } else {
                    self.chunk.write_op(OpCode::OpNull, 0);
                }
                // TODO: Store variable
                self.chunk.write_op(OpCode::OpPop, 0);
            }

            Stmt::If { condition, then_branch, else_branch } => {
                self.compile_expression(condition)?;
                self.chunk.write_op(OpCode::OpJumpIfFalse, 0);

                let else_jump = self.chunk.code.len();
                self.chunk.write(0, 0); // Placeholder

                self.compile_statement(then_branch)?;

                if let Some(else_br) = else_branch {
                    self.chunk.write_op(OpCode::OpJump, 0);

                    let end_jump = self.chunk.code.len();
                    self.chunk.write(0, 0); // Placeholder

                    // Patch else jump
                    // self.patch_jump(else_jump);

                    self.compile_statement(else_br)?;

                    // Patch end jump
                    // self.patch_jump(end_jump);
                } else {
                    // Patch else jump
                    // self.patch_jump(else_jump);
                }
            }

            Stmt::While { condition, body } => {
                let loop_start = self.chunk.code.len();

                self.compile_expression(condition)?;
                self.chunk.write_op(OpCode::OpJumpIfFalse, 0);

                let exit_jump = self.chunk.code.len();
                self.chunk.write(0, 0); // Placeholder

                self.compile_statement(body)?;

                self.chunk.write_op(OpCode::OpJump, 0);
                // self.patch_jump(loop_start);

                // Patch exit jump
                // self.patch_jump(exit_jump);
            }

            Stmt::For { init, condition, increment, body } => {
                // Compile initializer
                if let Some(i) = init {
                    self.compile_statement(i)?;
                }

                let loop_start = self.chunk.code.len();

                // Compile condition
                if let Some(cond) = condition {
                    self.compile_expression(cond)?;
                } else {
                    self.chunk.write_op(OpCode::OpTrue, 0);
                }

                self.chunk.write_op(OpCode::OpJumpIfFalse, 0);

                let exit_jump = self.chunk.code.len();
                self.chunk.write(0, 0); // Placeholder

                self.compile_statement(body)?;

                // Compile increment
                if let Some(inc) = increment {
                    self.compile_expression(inc)?;
                    self.chunk.write_op(OpCode::OpPop, 0);
                }

                self.chunk.write_op(OpCode::OpJump, 0);
                // self.patch_jump(loop_start);

                // Patch exit jump
                // self.patch_jump(exit_jump);
            }

            Stmt::Function { name, params, body } => {
                // Compile the function
                let function = self.compile_function(name, params, body)?;

                // Store function in constant pool
                let idx = self.chunk.add_constant(Value::Function(function));

                // Create closure and push onto stack
                self.chunk.write_op(OpCode::OpConst, 0);
                self.chunk.write(idx as u8, 0);

                // Store in global variable (using function name)
                // For now, we'll use OpSetGlobal (need to implement)
                // TODO: Implement proper variable storage
            }

            Stmt::Class { name, superclass, methods } => {
                // Compile each method
                let mut compiled_methods = Vec::new();
                for method in methods {
                    match method {
                        Stmt::Function { name: method_name, params, body } => {
                            let method_func = self.compile_function(&method_name, &params, &body)?;
                            compiled_methods.push(method_func);
                        }
                        _ => {
                            return Err(ScriptError::ParseError {
                                line: 0,
                                message: "Only functions can be class methods".into(),
                            });
                        }
                    }
                }

                // Create class object
                let class = Class {
                    name: name.clone(),
                    superclass: superclass.clone(),
                    methods: compiled_methods,
                };

                // Store class in constant pool
                let idx = self.chunk.add_constant(Value::Class(class));

                // Push class onto stack
                self.chunk.write_op(OpCode::OpConst, 0);
                self.chunk.write(idx as u8, 0);
            }

            Stmt::Return(value) => {
                if let Some(v) = value {
                    self.compile_expression(v)?;
                } else {
                    self.chunk.write_op(OpCode::OpNull, 0);
                }
                self.chunk.write_op(OpCode::OpReturn, 0);
            }

            Stmt::Block(statements) => {
                for stmt in statements {
                    self.compile_statement(stmt)?;
                }
            }

            Stmt::Break => {
                // TODO: Implement break
            }

            Stmt::Continue => {
                // TODO: Implement continue
            }

            Stmt::Empty => {}
        }

        Ok(())
    }

    /// Compile an expression
    fn compile_expression(&mut self, expr: &Expr) -> Result<()> {
        match expr {
            Expr::Number(n) => {
                let idx = self.chunk.add_constant(Value::Number(*n));
                self.chunk.write_op(OpCode::OpConst, 0);
                self.chunk.write(idx as u8, 0);
            }

            Expr::String(s) => {
                let idx = self.chunk.add_constant(Value::String(s.clone()));
                self.chunk.write_op(OpCode::OpConst, 0);
                self.chunk.write(idx as u8, 0);
            }

            Expr::Bool(b) => {
                if *b {
                    self.chunk.write_op(OpCode::OpTrue, 0);
                } else {
                    self.chunk.write_op(OpCode::OpFalse, 0);
                }
            }

            Expr::Null => {
                self.chunk.write_op(OpCode::OpNull, 0);
            }

            Expr::Variable(name) => {
                // TODO: Look up variable
                // For now, push a placeholder
                self.chunk.write_op(OpCode::OpNull, 0);
            }

            Expr::Binary { left, op, right } => {
                self.compile_expression(left)?;
                self.compile_expression(right)?;

                match op {
                    BinaryOp::Add => self.chunk.write_op(OpCode::OpAdd, 0),
                    BinaryOp::Sub => self.chunk.write_op(OpCode::OpSub, 0),
                    BinaryOp::Mul => self.chunk.write_op(OpCode::OpMul, 0),
                    BinaryOp::Div => self.chunk.write_op(OpCode::OpDiv, 0),
                    BinaryOp::Mod => self.chunk.write_op(OpCode::OpMod, 0),

                    BinaryOp::Equal => self.chunk.write_op(OpCode::OpEqual, 0),
                    BinaryOp::NotEqual => self.chunk.write_op(OpCode::OpNotEqual, 0),
                    BinaryOp::Less => self.chunk.write_op(OpCode::OpLess, 0),
                    BinaryOp::Greater => self.chunk.write_op(OpCode::OpGreater, 0),
                    BinaryOp::LessEqual => self.chunk.write_op(OpCode::OpLessEqual, 0),
                    BinaryOp::GreaterEqual => self.chunk.write_op(OpCode::OpGreaterEqual, 0),

                    BinaryOp::And => self.chunk.write_op(OpCode::OpAnd, 0),
                    BinaryOp::Or => self.chunk.write_op(OpCode::OpOr, 0),

                    BinaryOp::BitAnd => self.chunk.write_op(OpCode::OpBitAnd, 0),
                    BinaryOp::BitOr => self.chunk.write_op(OpCode::OpBitOr, 0),
                    BinaryOp::BitXor => self.chunk.write_op(OpCode::OpBitXor, 0),
                    BinaryOp::LeftShift => self.chunk.write_op(OpCode::OpLeftShift, 0),
                    BinaryOp::RightShift => self.chunk.write_op(OpCode::OpRightShift, 0),
                }
            }

            Expr::Unary { op, operand } => {
                self.compile_expression(operand)?;

                match op {
                    UnaryOp::Negate => self.chunk.write_op(OpCode::OpNeg, 0),
                    UnaryOp::Not => self.chunk.write_op(OpCode::OpNot, 0),
                    UnaryOp::BitNot => self.chunk.write_op(OpCode::OpBitNot, 0),
                }
            }

            Expr::Call { callee, args } => {
                // Compile arguments
                for arg in args {
                    self.compile_expression(arg)?;
                }

                // Compile callee
                self.compile_expression(callee)?;

                self.chunk.write_op(OpCode::OpCall, 0);
                self.chunk.write(args.len() as u8, 0);
            }

            Expr::GetProp { object, name } => {
                self.compile_expression(object)?;
                // TODO: Push property name
                self.chunk.write_op(OpCode::OpGetProp, 0);
            }

            Expr::SetProp { object, name, value } => {
                self.compile_expression(object)?;
                // TODO: Push property name
                self.compile_expression(value)?;
                self.chunk.write_op(OpCode::OpSetProp, 0);
            }

            Expr::Index { object, index } => {
                self.compile_expression(object)?;
                self.compile_expression(index)?;
                self.chunk.write_op(OpCode::OpGetIndex, 0);
            }

            Expr::Array(elems) => {
                // Compile elements
                for elem in elems {
                    self.compile_expression(elem)?;
                }

                self.chunk.write_op(OpCode::OpMakeArray, 0);
                self.chunk.write(elems.len() as u8, 0);
            }

            Expr::Object(props) => {
                // Compile properties
                for (key, value) in props {
                    // Push key
                    let idx = self.chunk.add_constant(Value::String(key.clone()));
                    self.chunk.write_op(OpCode::OpConst, 0);
                    self.chunk.write(idx as u8, 0);

                    // Push value
                    self.compile_expression(value)?;
                }

                self.chunk.write_op(OpCode::OpMakeObject, 0);
                self.chunk.write(props.len() as u8, 0);
            }

            Expr::This => {
                self.chunk.write_op(OpCode::OpThis, 0);
            }

            Expr::Super => {
                self.chunk.write_op(OpCode::OpSuper, 0);
            }
        }

        Ok(())
    }
}

impl Default for Compiler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_number() {
        let mut compiler = Compiler::new();
        let parser = crate::gs2::parser::Parser::new("42;");
        let script = parser.parse().unwrap();
        let chunk = compiler.compile(&script).unwrap();

        assert!(!chunk.code.is_empty());
    }

    #[test]
    fn test_compile_binary_op() {
        let mut compiler = Compiler::new();
        let parser = crate::gs2::parser::Parser::new("1 + 2;");
        let script = parser.parse().unwrap();
        let chunk = compiler.compile(&script).unwrap();

        assert!(!chunk.code.is_empty());
    }

    #[test]
    fn test_compile_function() {
        let mut compiler = Compiler::new();
        let parser = crate::gs2::parser::Parser::new("function foo() { return 42; }");
        let script = parser.parse().unwrap();
        let chunk = compiler.compile(&script).unwrap();

        // Should have a function in constants
        assert!(!chunk.constants.is_empty());
    }

    #[test]
    fn test_compile_function_with_params() {
        let mut compiler = Compiler::new();
        let parser = crate::gs2::parser::Parser::new("function add(a, b) { return a + b; }");
        let script = parser.parse().unwrap();
        let chunk = compiler.compile(&script).unwrap();

        // Should have a function in constants
        assert!(!chunk.constants.is_empty());
    }

    #[test]
    fn test_compile_class() {
        let mut compiler = Compiler::new();
        let parser = crate::gs2::parser::Parser::new("class MyClass { function method() { return 42; } }");
        let script = parser.parse().unwrap();
        let chunk = compiler.compile(&script).unwrap();

        // Should have a class in constants
        assert!(!chunk.constants.is_empty());
    }

    #[test]
    fn test_compile_class_with_multiple_methods() {
        let mut compiler = Compiler::new();
        let parser = crate::gs2::parser::Parser::new(
            "class MyClass {
                function foo() { return 1; }
                function bar() { return 2; }
            }"
        );
        let script = parser.parse().unwrap();
        let chunk = compiler.compile(&script).unwrap();

        // Should have a class in constants
        assert!(!chunk.constants.is_empty());
    }
}
