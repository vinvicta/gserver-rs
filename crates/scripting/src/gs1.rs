//! GS1 Scripting System
//!
//! GS1 is Graal's simple line-based scripting language.
//! It's event-driven and uses text-based commands.

use crate::error::{ScriptError, Result};
use crate::context::ScriptContext;
use std::collections::HashMap;

/// GS1 script event types
#[derive(Debug, Clone, PartialEq)]
pub enum EventType {
    /// Script runs when created
    Created,

    /// Script runs when player enters level
    PlayerEnter,

    /// Script runs when player leaves level
    PlayerLeave,

    /// Script runs at timeout (recurring)
    Timeout { seconds: f64 },

    /// Script runs when player touches NPC
    PlayerTouch,

    /// Script runs when player clicks NPC
    PlayerClick,

    /// Script runs when player says something
    PlayerSay,

    /// Script runs when an event is triggered
    Event { name: String },
}

impl EventType {
    /// Parse event type from string
    pub fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        
        match parts.get(0).map(|s| *s) {
            Some("timeout") => {
                let seconds = parts.get(1)
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| ScriptError::ParseError {
                        line: 0,
                        message: "Invalid timeout format".into(),
                    })?;
                Ok(EventType::Timeout { seconds })
            }
            Some("event") => {
                let name = parts.get(1).unwrap_or(&"").to_string();
                Ok(EventType::Event { name })
            }
            Some("created") => Ok(EventType::Created),
            Some("playerenter") => Ok(EventType::PlayerEnter),
            Some("playerleave") => Ok(EventType::PlayerLeave),
            Some("playertouch") => Ok(EventType::PlayerTouch),
            Some("playerclick") => Ok(EventType::PlayerClick),
            Some("playersay") => Ok(EventType::PlayerSay),
            _ => Err(ScriptError::ParseError {
                line: 0,
                message: format!("Unknown event type: {}", s),
            }),
        }
    }
}

/// A single GS1 script statement
#[derive(Debug, Clone)]
pub enum Statement {
    /// If statement
    If {
        condition: String,
        then_block: Vec<Statement>,
        else_block: Option<Vec<Statement>>,
    },
    
    /// Function call
    FunctionCall { name: String, args: Vec<String> },
    
    /// Variable assignment
    Assignment { var: String, value: String },
    
    /// Event trigger
    Trigger { event: EventType },
    
    /// No-op (comment or empty)
    NoOp,
}

/// A parsed GS1 script
#[derive(Debug, Clone)]
pub struct GS1Script {
    /// Script name/ID
    pub name: String,
    
    /// Script events indexed by event type
    pub events: HashMap<String, Vec<Statement>>,
    
    /// Script timeout (if any)
    pub timeout: Option<f64>,
}

impl GS1Script {
    /// Create a new empty script
    pub fn new(name: String) -> Self {
        Self {
            name,
            events: HashMap::new(),
            timeout: None,
        }
    }
    
    /// Parse GS1 script from string
    pub fn parse(name: String, source: &str) -> Result<Self> {
        let mut script = Self::new(name);
        let mut current_event = "created".to_string();
        let mut current_block: Vec<Statement> = Vec::new();
        
        for (line_num, line) in source.lines().enumerate() {
            let line = line.trim();
            
            // Skip empty lines and comments
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            
            // Check for event definition
            if let Some(event_name) = line.strip_prefix("//").and_then(|_| {
                if line.ends_with("EVENT") {
                    Some(line.trim_start_matches("//").trim_end_matches("EVENT").trim())
                } else {
                    None
                }
            }) {
                // Save previous event
                if !current_block.is_empty() {
                    script.events.insert(current_event.clone(), current_block);
                    current_block = Vec::new();
                }
                current_event = event_name.to_lowercase();
                continue;
            }
            
            // Parse statement
            let statement = Self::parse_statement(line, line_num)?;
            current_block.push(statement);
        }
        
        // Save last event
        if !current_block.is_empty() {
            script.events.insert(current_event, current_block);
        }
        
        Ok(script)
    }
    
    /// Parse a single statement
    fn parse_statement(line: &str, line_num: usize) -> Result<Statement> {
        let line = line.trim();
        
        // Check for if statement
        if let Some(rest) = line.strip_prefix("if ") {
            let (condition, then_part) = rest.split_once("then")
                .ok_or_else(|| ScriptError::ParseError {
                    line: line_num,
                    message: "If statement missing 'then'".into(),
                })?;
            
            let then_block = vec![Statement::FunctionCall {
                name: "echo".to_string(),
                args: vec![then_part.to_string()],
            }];
            
            return Ok(Statement::If {
                condition: condition.trim().to_string(),
                then_block,
                else_block: None,
            });
        }
        
        // Check for function call
        if line.contains('(') && line.contains(')') {
            let (name, rest) = line.split_once('(')
                .ok_or_else(|| ScriptError::ParseError {
                    line: line_num,
                    message: "Invalid function call".into(),
                })?;
            
            let args_str = rest.strip_prefix(')')
                .ok_or_else(|| ScriptError::ParseError {
                    line: line_num,
                    message: "Unclosed parenthesis".into(),
                })?;
            
            let args: Vec<String> = args_str.split(',')
                .map(|s| s.trim().to_string())
                .collect();
            
            return Ok(Statement::FunctionCall {
                name: name.trim().to_string(),
                args,
            });
        }
        
        // Check for assignment
        if line.contains('=') {
            let parts: Vec<&str> = line.splitn(2, '=').collect();
            return Ok(Statement::Assignment {
                var: parts[0].trim().to_string(),
                value: parts[1].trim().to_string(),
            });
        }
        
        // Default: treat as noop
        Ok(Statement::NoOp)
    }
}

/// GS1 interpreter
pub struct GS1Interpreter {
    /// Script context
    context: ScriptContext,
    
    /// Local variables
    variables: HashMap<String, String>,
}

impl GS1Interpreter {
    /// Create a new interpreter
    pub fn new(context: ScriptContext) -> Self {
        Self {
            context,
            variables: HashMap::new(),
        }
    }
    
    /// Execute a script
    pub fn execute(&mut self, script: &GS1Script, event: &str) -> Result<()> {
        let statements = script.events.get(event)
            .ok_or_else(|| ScriptError::RuntimeError(
                format!("Event not found: {}", event)
            ))?;
        
        for statement in statements {
            self.execute_statement(statement)?;
        }
        
        Ok(())
    }
    
    /// Execute a single statement
    fn execute_statement(&mut self, statement: &Statement) -> Result<()> {
        match statement {
            Statement::If { condition, then_block, .. } => {
                // Evaluate condition (simplified)
                if self.evaluate_condition(condition)? {
                    for stmt in then_block {
                        self.execute_statement(stmt)?;
                    }
                }
            }
            
            Statement::FunctionCall { name, args } => {
                self.call_function(name, args)?;
            }
            
            Statement::Assignment { var, value } => {
                self.variables.insert(var.clone(), value.clone());
            }
            
            Statement::NoOp => {}
            
            Statement::Trigger { .. } => {
                // Event triggering handled externally
            }
        }
        
        Ok(())
    }
    
    /// Evaluate a condition (simplified)
    fn evaluate_condition(&self, condition: &str) -> Result<bool> {
        // Simple evaluation: check if variable exists
        let has_local = self.variables.contains_key(condition);
        let has_global = self.context.get_global(condition).is_some();

        Ok(has_local || has_global)
    }
    
    /// Call a built-in function
    fn call_function(&mut self, name: &str, args: &[String]) -> Result<()> {
        // This would call into the builtins module
        // For now, just log it
        tracing::debug!("Calling function {} with args: {:?}", name, args);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_empty_script() {
        let script = GS1Script::parse("test".to_string(), "").unwrap();
        assert!(script.events.is_empty());
    }
    
    #[test]
    fn test_parse_simple_script() {
        let source = r#"
// This is a comment
timeout = 5
message = Hello!
"#;
        let script = GS1Script::parse("test".to_string(), source).unwrap();
        assert!(!script.events.is_empty());
    }
    
    #[test]
    fn test_event_type_parsing() {
        assert_eq!(EventType::from_str("timeout 5").unwrap(), EventType::Timeout { seconds: 5.0 });
        assert_eq!(EventType::from_str("created").unwrap(), EventType::Created);
        assert_eq!(EventType::from_str("playerenter").unwrap(), EventType::PlayerEnter);
    }
}
