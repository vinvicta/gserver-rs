//! GS2 Bytecode VM
//!
//! Virtual machine for executing GS2 bytecode.

use crate::error::{ScriptError, Result};
use crate::gs2::bytecode::{Chunk, OpCode, Value, Function};
use std::collections::HashMap;

/// Stack frame for function calls
#[derive(Debug)]
struct CallFrame {
    /// Return address
    return_ip: usize,

    /// Previous chunk
    chunk: Chunk,

    /// Stack base
    stack_start: usize,
}

/// GS2 bytecode VM
pub struct VM {
    /// Bytecode chunk
    chunk: Chunk,

    /// Instruction pointer
    ip: usize,

    /// Value stack
    stack: Vec<Value>,

    /// Call stack
    call_stack: Vec<CallFrame>,

    /// Global variables
    globals: HashMap<String, Value>,

    /// Local variables
    locals: HashMap<String, Value>,
}

impl VM {
    /// Create a new VM
    pub fn new(chunk: Chunk) -> Self {
        Self {
            chunk,
            ip: 0,
            stack: Vec::new(),
            call_stack: Vec::new(),
            globals: HashMap::new(),
            locals: HashMap::new(),
        }
    }

    /// Interpret the bytecode
    pub fn interpret(&mut self) -> Result<Value> {
        loop {
            if self.ip >= self.chunk.code.len() {
                break;
            }

            let instruction = self.read_byte();
            let op = OpCode::from_byte(instruction);

            match op {
                Some(OpCode::OpConst) => {
                    let constant_idx = self.read_byte() as usize;
                    let value = self.chunk.constants[constant_idx].clone();
                    self.push(value);
                }

                Some(OpCode::OpNull) => {
                    self.push(Value::Null);
                }

                Some(OpCode::OpTrue) => {
                    self.push(Value::Bool(true));
                }

                Some(OpCode::OpFalse) => {
                    self.push(Value::Bool(false));
                }

                Some(OpCode::OpPop) => {
                    self.pop();
                }

                Some(OpCode::OpDup) => {
                    let value = self.peek();
                    self.push(value);
                }

                Some(OpCode::OpSwap) => {
                    let a = self.pop();
                    let b = self.pop();
                    self.push(a);
                    self.push(b);
                }

                Some(OpCode::OpGetLocal) => {
                    let name_idx = self.read_byte() as usize;
                    // TODO: Implement proper local variable lookup
                    self.push(Value::Null);
                }

                Some(OpCode::OpSetLocal) => {
                    let name_idx = self.read_byte() as usize;
                    let value = self.peek();
                    // TODO: Store local variable
                }

                Some(OpCode::OpGetGlobal) => {
                    let name_idx = self.read_byte() as usize;
                    // TODO: Implement proper global variable lookup
                    self.push(Value::Null);
                }

                Some(OpCode::OpSetGlobal) => {
                    let name_idx = self.read_byte() as usize;
                    let value = self.peek();
                    // TODO: Store global variable
                }

                Some(OpCode::OpGetProp) => {
                    let prop_name_idx = self.read_byte() as usize;
                    let object = self.pop();
                    // TODO: Get property from object
                    self.push(Value::Null);
                }

                Some(OpCode::OpSetProp) => {
                    let prop_name_idx = self.read_byte() as usize;
                    let value = self.pop();
                    let object = self.pop();
                    // TODO: Set property on object
                }

                Some(OpCode::OpGetIndex) => {
                    let index = self.pop();
                    let object = self.pop();
                    // TODO: Get array element
                    self.push(Value::Null);
                }

                Some(OpCode::OpSetIndex) => {
                    let value = self.pop();
                    let index = self.pop();
                    let object = self.pop();
                    // TODO: Set array element
                }

                Some(OpCode::OpMakeArray) => {
                    let count = self.read_byte() as usize;
                    let mut elems = Vec::new();
                    for _ in 0..count {
                        elems.push(self.pop());
                    }
                    elems.reverse();
                    self.push(Value::Array); // Placeholder
                }

                Some(OpCode::OpMakeObject) => {
                    let count = self.read_byte() as usize;
                    for _ in 0..count {
                        let value = self.pop();
                        let key = self.pop();
                        // TODO: Build object
                    }
                    self.push(Value::Object); // Placeholder
                }

                Some(OpCode::OpAdd) => {
                    let b = self.pop();
                    let a = self.pop();
                    let result = self.arithmetic_op(a, b, |a, b| a + b)?;
                    self.push(result);
                }

                Some(OpCode::OpSub) => {
                    let b = self.pop();
                    let a = self.pop();
                    let result = self.arithmetic_op(a, b, |a, b| a - b)?;
                    self.push(result);
                }

                Some(OpCode::OpMul) => {
                    let b = self.pop();
                    let a = self.pop();
                    let result = self.arithmetic_op(a, b, |a, b| a * b)?;
                    self.push(result);
                }

                Some(OpCode::OpDiv) => {
                    let b = self.pop();
                    let a = self.pop();
                    let result = self.arithmetic_op(a, b, |a, b| a / b)?;
                    self.push(result);
                }

                Some(OpCode::OpMod) => {
                    let b = self.pop();
                    let a = self.pop();
                    let result = self.arithmetic_op(a, b, |a, b| a % b)?;
                    self.push(result);
                }

                Some(OpCode::OpNeg) => {
                    let value = self.pop();
                    match value {
                        Value::Number(n) => self.push(Value::Number(-n)),
                        _ => {
                            return Err(ScriptError::RuntimeError(
                                "Operand must be a number".into()
                            ));
                        }
                    }
                }

                Some(OpCode::OpEqual) => {
                    let b = self.pop();
                    let a = self.pop();
                    self.push(Value::Bool(a == b));
                }

                Some(OpCode::OpNotEqual) => {
                    let b = self.pop();
                    let a = self.pop();
                    self.push(Value::Bool(a != b));
                }

                Some(OpCode::OpLess) => {
                    let b = self.pop();
                    let a = self.pop();
                    let result = self.comparison_op(a, b, |a, b| a < b)?;
                    self.push(result);
                }

                Some(OpCode::OpGreater) => {
                    let b = self.pop();
                    let a = self.pop();
                    let result = self.comparison_op(a, b, |a, b| a > b)?;
                    self.push(result);
                }

                Some(OpCode::OpLessEqual) => {
                    let b = self.pop();
                    let a = self.pop();
                    let result = self.comparison_op(a, b, |a, b| a <= b)?;
                    self.push(result);
                }

                Some(OpCode::OpGreaterEqual) => {
                    let b = self.pop();
                    let a = self.pop();
                    let result = self.comparison_op(a, b, |a, b| a >= b)?;
                    self.push(result);
                }

                Some(OpCode::OpAnd) => {
                    let b = self.pop();
                    let a = self.pop();
                    let result = Value::Bool(a.is_truthy() && b.is_truthy());
                    self.push(result);
                }

                Some(OpCode::OpOr) => {
                    let b = self.pop();
                    let a = self.pop();
                    let result = Value::Bool(a.is_truthy() || b.is_truthy());
                    self.push(result);
                }

                Some(OpCode::OpNot) => {
                    let value = self.pop();
                    self.push(Value::Bool(!value.is_truthy()));
                }

                Some(OpCode::OpBitAnd) => {
                    let b = self.pop();
                    let a = self.pop();
                    let result = self.bitwise_op(a, b, |a, b| a & b)?;
                    self.push(result);
                }

                Some(OpCode::OpBitOr) => {
                    let b = self.pop();
                    let a = self.pop();
                    let result = self.bitwise_op(a, b, |a, b| a | b)?;
                    self.push(result);
                }

                Some(OpCode::OpBitXor) => {
                    let b = self.pop();
                    let a = self.pop();
                    let result = self.bitwise_op(a, b, |a, b| a ^ b)?;
                    self.push(result);
                }

                Some(OpCode::OpBitNot) => {
                    let value = self.pop();
                    match value {
                        Value::Number(n) => {
                            let result = !(n as i64);
                            self.push(Value::Number(result as f64));
                        }
                        _ => {
                            return Err(ScriptError::RuntimeError(
                                "Operand must be a number".into()
                            ));
                        }
                    }
                }

                Some(OpCode::OpLeftShift) => {
                    let b = self.pop();
                    let a = self.pop();
                    let result = self.bitshift_op(a, b, |a, b| a << b)?;
                    self.push(result);
                }

                Some(OpCode::OpRightShift) => {
                    let b = self.pop();
                    let a = self.pop();
                    let result = self.bitshift_op(a, b, |a, b| a >> b)?;
                    self.push(result);
                }

                Some(OpCode::OpJump) => {
                    let offset = self.read_byte() as usize;
                    self.ip = offset;
                }

                Some(OpCode::OpJumpIfFalse) => {
                    let offset = self.read_byte() as usize;
                    if !self.peek().is_truthy() {
                        self.ip = offset;
                    }
                }

                Some(OpCode::OpJumpIfTrue) => {
                    let offset = self.read_byte() as usize;
                    if self.peek().is_truthy() {
                        self.ip = offset;
                    }
                }

                Some(OpCode::OpCall) => {
                    let arg_count = self.read_byte() as usize;

                    // Pop callee from stack
                    let callee = self.pop();

                    match callee {
                        Value::Function(func) => {
                            // Check arity
                            if func.arity != arg_count {
                                return Err(ScriptError::RuntimeError(
                                    format!("Expected {} arguments but got {}", func.arity, arg_count)
                                ));
                            }

                            // Pop arguments from stack (they're in reverse order)
                            let mut args = Vec::with_capacity(arg_count);
                            for _ in 0..arg_count {
                                args.push(self.pop());
                            }
                            args.reverse();

                            // Push arguments onto stack as local variables
                            for arg in args {
                                self.stack.push(arg);
                            }

                            // Save current state and switch to function
                            let old_chunk = std::mem::replace(&mut self.chunk, func.chunk);
                            self.call_stack.push(CallFrame {
                                return_ip: self.ip,
                                chunk: old_chunk,
                                stack_start: self.stack.len() - arg_count,
                            });

                            // Start executing function
                            self.ip = 0;
                        }
                        _ => {
                            return Err(ScriptError::RuntimeError(
                                "Can only call functions".into()
                            ));
                        }
                    }
                }

                Some(OpCode::OpReturn) => {
                    let value = self.pop();

                    // Check if we're in a function call
                    if let Some(frame) = self.call_stack.pop() {
                        // Restore previous state
                        self.chunk = frame.chunk;
                        self.ip = frame.return_ip;

                        // Clean up stack
                        while self.stack.len() > frame.stack_start {
                            self.stack.pop();
                        }
                    } else {
                        // Top-level return
                        return Ok(value);
                    }

                    // Push return value
                    self.push(value);
                }

                Some(OpCode::OpThis) => {
                    self.push(Value::Object); // Placeholder
                }

                Some(OpCode::OpSuper) => {
                    self.push(Value::Object); // Placeholder
                }

                None => {
                    return Err(ScriptError::RuntimeError(
                        format!("Unknown opcode: {}", instruction)
                    ));
                }
            }
        }

        Ok(Value::Null)
    }

    /// Read a byte from the chunk
    fn read_byte(&mut self) -> u8 {
        let byte = self.chunk.code[self.ip];
        self.ip += 1;
        byte
    }

    /// Push a value onto the stack
    fn push(&mut self, value: Value) {
        self.stack.push(value);
    }

    /// Pop a value from the stack
    fn pop(&mut self) -> Value {
        self.stack.pop().unwrap_or(Value::Null)
    }

    /// Peek at the top value on the stack
    fn peek(&self) -> Value {
        self.stack.last().cloned().unwrap_or(Value::Null)
    }

    /// Perform arithmetic operation
    fn arithmetic_op<F>(&self, a: Value, b: Value, op: F) -> Result<Value>
    where
        F: FnOnce(f64, f64) -> f64,
    {
        match (a, b) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Number(op(a, b))),
            _ => Err(ScriptError::RuntimeError("Operands must be numbers".into())),
        }
    }

    /// Perform comparison operation
    fn comparison_op<F>(&self, a: Value, b: Value, op: F) -> Result<Value>
    where
        F: FnOnce(f64, f64) -> bool,
    {
        match (a, b) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Bool(op(a, b))),
            _ => Err(ScriptError::RuntimeError("Operands must be numbers".into())),
        }
    }

    /// Perform bitwise operation
    fn bitwise_op<F>(&self, a: Value, b: Value, op: F) -> Result<Value>
    where
        F: FnOnce(i64, i64) -> i64,
    {
        match (a, b) {
            (Value::Number(a), Value::Number(b)) => {
                Ok(Value::Number(op(a as i64, b as i64) as f64))
            }
            _ => Err(ScriptError::RuntimeError("Operands must be numbers".into())),
        }
    }

    /// Perform bitshift operation
    fn bitshift_op<F>(&self, a: Value, b: Value, op: F) -> Result<Value>
    where
        F: FnOnce(i64, i64) -> i64,
    {
        match (a, b) {
            (Value::Number(a), Value::Number(b)) => {
                Ok(Value::Number(op(a as i64, b as i64) as f64))
            }
            _ => Err(ScriptError::RuntimeError("Operands must be numbers".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gs2::compiler::Compiler;

    #[test]
    fn test_vm_arithmetic() {
        let mut compiler = Compiler::new();
        let parser = crate::gs2::parser::Parser::new("1 + 2;");
        let script = parser.parse().unwrap();
        let chunk = compiler.compile(&script).unwrap();

        let mut vm = VM::new(chunk);
        let result = vm.interpret().unwrap();
        // Should return null after popping the result
    }

    #[test]
    fn test_vm_boolean() {
        let mut compiler = Compiler::new();
        let parser = crate::gs2::parser::Parser::new("true && false;");
        let script = parser.parse().unwrap();
        let chunk = compiler.compile(&script).unwrap();

        let mut vm = VM::new(chunk);
        let result = vm.interpret().unwrap();
    }

    #[test]
    fn test_vm_function_call() {
        use crate::gs2::bytecode::Function;

        // Create a simple function chunk
        let mut func_chunk = Chunk::new();
        func_chunk.write_op(OpCode::OpConst, 0);
        func_chunk.write(0, 0);  // Push constant 0 from function's own constant pool
        func_chunk.write_op(OpCode::OpReturn, 0);

        // Add constant to function chunk
        func_chunk.add_constant(Value::Number(42.0));

        let function = Function {
            name: "foo".into(),
            arity: 0,
            chunk: func_chunk,
        };

        // Create main chunk that calls the function
        let mut chunk = Chunk::new();

        // Push function constant
        chunk.write_op(OpCode::OpConst, 0);
        chunk.write(0, 0);  // Function at index 0

        // Add the function to constants
        chunk.add_constant(Value::Function(function));

        // Call the function
        chunk.write_op(OpCode::OpCall, 0);
        chunk.write(0, 0);  // 0 arguments

        chunk.write_op(OpCode::OpReturn, 0);

        let mut vm = VM::new(chunk);
        let result = vm.interpret().unwrap();

        // The function call should return 42
        assert_eq!(result, Value::Number(42.0));
    }

    #[test]
    fn test_vm_function_with_params() {
        use crate::gs2::bytecode::Function;

        // Create a function that adds two parameters: a + b
        let mut func_chunk = Chunk::new();
        // Parameters are already on the stack, just add them
        func_chunk.write_op(OpCode::OpAdd, 0);
        func_chunk.write_op(OpCode::OpReturn, 0);

        let function = Function {
            name: "add".into(),
            arity: 2,
            chunk: func_chunk,
        };

        // Create main chunk
        let mut chunk = Chunk::new();

        // Push arguments
        chunk.write_op(OpCode::OpConst, 0);
        chunk.write(0, 0);  // 1
        chunk.write_op(OpCode::OpConst, 0);
        chunk.write(1, 0);  // 2

        // Push function
        chunk.write_op(OpCode::OpConst, 0);
        chunk.write(2, 0);  // Function index

        // Add constants
        chunk.add_constant(Value::Number(1.0));
        chunk.add_constant(Value::Number(2.0));
        chunk.add_constant(Value::Function(function));

        // Call the function with 2 arguments
        chunk.write_op(OpCode::OpCall, 0);
        chunk.write(2, 0);  // 2 arguments

        chunk.write_op(OpCode::OpReturn, 0);

        let mut vm = VM::new(chunk);
        let result = vm.interpret().unwrap();

        // Should return 3
        assert_eq!(result, Value::Number(3.0));
    }
}
