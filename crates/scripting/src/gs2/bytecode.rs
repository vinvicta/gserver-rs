//! GS2 Bytecode
//!
//! Bytecode instruction set and constants.

/// GS2 opcodes
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum OpCode {
    // Constants
    OpConst,       // Push constant
    OpNull,        // Push null
    OpTrue,        // Push true
    OpFalse,       // Push false

    // Stack operations
    OpPop,         // Pop top value
    OpDup,         // Duplicate top value
    OpSwap,        // Swap top two values

    // Variables
    OpGetLocal,    // Get local variable
    OpSetLocal,    // Set local variable
    OpGetGlobal,   // Get global variable
    OpSetGlobal,   // Set global variable

    // Properties
    OpGetProp,     // Get property
    OpSetProp,     // Set property

    // Array operations
    OpGetIndex,    // Get array element
    OpSetIndex,    // Set array element
    OpMakeArray,   // Create array

    // Object operations
    OpMakeObject,  // Create object

    // Arithmetic
    OpAdd,         // Addition
    OpSub,         // Subtraction
    OpMul,         // Multiplication
    OpDiv,         // Division
    OpMod,         // Modulo
    OpNeg,         // Negation

    // Comparison
    OpEqual,       // Equality check
    OpNotEqual,    // Inequality check
    OpLess,        // Less than
    OpGreater,     // Greater than
    OpLessEqual,   // Less than or equal
    OpGreaterEqual,// Greater than or equal

    // Logical
    OpAnd,         // Logical and
    OpOr,          // Logical or
    OpNot,         // Logical not

    // Bitwise
    OpBitAnd,      // Bitwise and
    OpBitOr,       // Bitwise or
    OpBitXor,      // Bitwise xor
    OpBitNot,      // Bitwise not
    OpLeftShift,   // Left shift
    OpRightShift,  // Right shift

    // Control flow
    OpJump,        // Unconditional jump
    OpJumpIfFalse, // Jump if top is false
    OpJumpIfTrue,  // Jump if top is true
    OpCall,        // Function call
    OpReturn,      // Return from function

    // Special
    OpThis,        // Push 'this'
    OpSuper,       // Push 'super'
}

impl OpCode {
    /// Convert opcode to byte
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Convert byte to opcode
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(OpCode::OpConst),
            1 => Some(OpCode::OpNull),
            2 => Some(OpCode::OpTrue),
            3 => Some(OpCode::OpFalse),

            4 => Some(OpCode::OpPop),
            5 => Some(OpCode::OpDup),
            6 => Some(OpCode::OpSwap),

            7 => Some(OpCode::OpGetLocal),
            8 => Some(OpCode::OpSetLocal),
            9 => Some(OpCode::OpGetGlobal),
            10 => Some(OpCode::OpSetGlobal),

            11 => Some(OpCode::OpGetProp),
            12 => Some(OpCode::OpSetProp),

            13 => Some(OpCode::OpGetIndex),
            14 => Some(OpCode::OpSetIndex),
            15 => Some(OpCode::OpMakeArray),

            16 => Some(OpCode::OpMakeObject),

            17 => Some(OpCode::OpAdd),
            18 => Some(OpCode::OpSub),
            19 => Some(OpCode::OpMul),
            20 => Some(OpCode::OpDiv),
            21 => Some(OpCode::OpMod),
            22 => Some(OpCode::OpNeg),

            23 => Some(OpCode::OpEqual),
            24 => Some(OpCode::OpNotEqual),
            25 => Some(OpCode::OpLess),
            26 => Some(OpCode::OpGreater),
            27 => Some(OpCode::OpLessEqual),
            28 => Some(OpCode::OpGreaterEqual),

            29 => Some(OpCode::OpAnd),
            30 => Some(OpCode::OpOr),
            31 => Some(OpCode::OpNot),

            32 => Some(OpCode::OpBitAnd),
            33 => Some(OpCode::OpBitOr),
            34 => Some(OpCode::OpBitXor),
            35 => Some(OpCode::OpBitNot),
            36 => Some(OpCode::OpLeftShift),
            37 => Some(OpCode::OpRightShift),

            38 => Some(OpCode::OpJump),
            39 => Some(OpCode::OpJumpIfFalse),
            40 => Some(OpCode::OpJumpIfTrue),
            41 => Some(OpCode::OpCall),
            42 => Some(OpCode::OpReturn),

            43 => Some(OpCode::OpThis),
            44 => Some(OpCode::OpSuper),

            _ => None,
        }
    }
}

/// Compiled chunk of bytecode
#[derive(Debug, Clone)]
pub struct Chunk {
    /// Bytecode instructions
    pub code: Vec<u8>,

    /// Constant pool
    pub constants: Vec<Value>,

    /// Line information for debugging
    pub lines: Vec<usize>,
}

impl Chunk {
    /// Create a new chunk
    pub fn new() -> Self {
        Self {
            code: Vec::new(),
            constants: Vec::new(),
            lines: Vec::new(),
        }
    }

    /// Write a byte to the chunk
    pub fn write(&mut self, byte: u8, line: usize) {
        self.code.push(byte);
        self.lines.push(line);
    }

    /// Write an opcode to the chunk
    pub fn write_op(&mut self, op: OpCode, line: usize) {
        self.write(op.to_byte(), line);
    }

    /// Add a constant to the constant pool
    pub fn add_constant(&mut self, value: Value) -> usize {
        self.constants.push(value);
        self.constants.len() - 1
    }

    /// Disassemble the chunk for debugging
    pub fn disassemble(&self, name: &str) -> String {
        let mut output = format!("== {} ==\n", name);

        let mut offset = 0;
        while offset < self.code.len() {
            let instruction = self.disassemble_instruction(offset);
            output.push_str(&instruction);
            output.push('\n');
            offset += self.instruction_length(offset);
        }

        output
    }

    /// Disassemble a single instruction
    fn disassemble_instruction(&self, offset: usize) -> String {
        let op = self.code[offset];
        let op_name = OpCode::from_byte(op)
            .map(|op| format!("{:?}", op))
            .unwrap_or(format!("UNKNOWN_OP({})", op));

        format!("{:04} {}", offset, op_name)
    }

    /// Get the length of an instruction
    fn instruction_length(&self, offset: usize) -> usize {
        // For now, all instructions are 1 byte
        // Some instructions will have operands and be longer
        1
    }
}

impl Default for Chunk {
    fn default() -> Self {
        Self::new()
    }
}

/// Function object
#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub arity: usize,
    pub chunk: Chunk,
}

/// Class object
#[derive(Debug, Clone)]
pub struct Class {
    pub name: String,
    pub superclass: Option<String>,
    pub methods: Vec<Function>,
}

/// Instance object
#[derive(Debug, Clone)]
pub struct Instance {
    pub class: Class,
    pub fields: std::collections::HashMap<String, Value>,
}

/// Runtime value
#[derive(Debug, Clone)]
pub enum Value {
    Number(f64),
    String(String),
    Bool(bool),
    Null,
    Object,    // Placeholder for objects
    Array,     // Placeholder for arrays
    Function(Function),
    Class(Class),
    Instance(Instance),
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Number(a), Value::Number(b)) => a == b,
            (Value::String(a), Value::String(b)) => a == b,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Null, Value::Null) => true,
            _ => false,
        }
    }
}

impl Value {
    /// Check if value is truthy
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Bool(b) => *b,
            Value::Null => false,
            Value::Number(n) => *n != 0.0,
            Value::String(s) => !s.is_empty(),
            _ => true,
        }
    }
}
