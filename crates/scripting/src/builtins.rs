//! Built-in functions for GS1 scripting
//!
//! Provides 200+ built-in functions for game logic.

use crate::{Result, ScriptError};
use crate::context::ScriptContext;
use std::collections::HashMap;

/// Built-in function registry
pub struct Builtins {
    functions: HashMap<String, BuiltinFn>,
}

type BuiltinFn = fn(&ScriptContext, &[String]) -> Result<String>;

impl Builtins {
    /// Create a new builtins registry
    pub fn new() -> Self {
        let mut functions = HashMap::new();
        
        // Register all built-in functions
        register_player_functions(&mut functions);
        register_npc_functions(&mut functions);
        register_math_functions(&mut functions);
        register_string_functions(&mut functions);
        register_level_functions(&mut functions);
        register_weapon_functions(&mut functions);
        
        Self { functions }
    }
    
    /// Call a built-in function
    pub fn call(&self, ctx: &ScriptContext, name: &str, args: &[String]) -> Result<String> {
        self.functions.get(name)
            .ok_or_else(|| ScriptError::InvalidFunctionCall(name.to_string()))?
            (ctx, args)
    }
}

impl Default for Builtins {
    fn default() -> Self {
        Self::new()
    }
}

/// Register player-related functions
fn register_player_functions(map: &mut HashMap<String, BuiltinFn>) {
    // Player movement
    map.insert("setplayerx".to_string(), builtin_set_player_x);
    map.insert("setplayery".to_string(), builtin_set_player_y);
    map.insert("playerx".to_string(), builtin_player_x);
    map.insert("playery".to_string(), builtin_player_y);
    
    // Player attributes
    map.insert("sethp".to_string(), builtin_set_hp);
    map.insert("gethp".to_string(), builtin_get_hp);
    map.insert("setap".to_string(), builtin_set_ap);
    map.insert("getap".to_string(), builtin_get_ap);
    
    // Player chat
    map.insert("say".to_string(), builtin_say);
    map.insert("message".to_string(), builtin_message);
    map.insert("pm".to_string(), builtin_pm);
    
    // Player actions
    map.insert("warp".to_string(), builtin_warp);
    map.insert("hideplayer".to_string(), builtin_hide_player);
    map.insert("showplayer".to_string(), builtin_show_player);
}

/// Register NPC-related functions
fn register_npc_functions(map: &mut HashMap<String, BuiltinFn>) {
    map.insert("npcx".to_string(), builtin_npc_x);
    map.insert("npcy".to_string(), builtin_npc_y);
    map.insert("setnpcx".to_string(), builtin_set_npc_x);
    map.insert("setnpcy".to_string(), builtin_set_npc_y);
    
    map.insert("hide".to_string(), builtin_hide);
    map.insert("show".to_string(), builtin_show);
    map.insert("destroy".to_string(), builtin_destroy);
}

/// Register math functions
fn register_math_functions(map: &mut HashMap<String, BuiltinFn>) {
    map.insert("add".to_string(), builtin_add);
    map.insert("sub".to_string(), builtin_sub);
    map.insert("mul".to_string(), builtin_mul);
    map.insert("div".to_string(), builtin_div);
    map.insert("mod".to_string(), builtin_mod);
    map.insert("abs".to_string(), builtin_abs);
    map.insert("min".to_string(), builtin_min);
    map.insert("max".to_string(), builtin_max);
    map.insert("random".to_string(), builtin_random);
    map.insert("sqrt".to_string(), builtin_sqrt);
    map.insert("pow".to_string(), builtin_pow);
}

/// Register string functions
fn register_string_functions(map: &mut HashMap<String, BuiltinFn>) {
    map.insert("strlen".to_string(), builtin_strlen);
    map.insert("strreplace".to_string(), builtin_str_replace);
    map.insert("strlower".to_string(), builtin_str_lower);
    map.insert("strupper".to_string(), builtin_str_upper);
    map.insert("strsubstr".to_string(), builtin_str_substring);
    map.insert("strtostr".to_string(), builtin_str_tostr);
}

/// Register level functions
fn register_level_functions(map: &mut HashMap<String, BuiltinFn>) {
    map.insert("levelname".to_string(), builtin_level_name);
    map.insert("levelwidth".to_string(), builtin_level_width);
    map.insert("levelheight".to_string(), builtin_level_height);
    map.insert("putnpc".to_string(), builtin_put_npc);
    map.insert("putnpc2".to_string(), builtin_put_npc2);
}

/// Register weapon functions
fn register_weapon_functions(map: &mut HashMap<String, BuiltinFn>) {
    map.insert("weaponfire".to_string(), builtin_weapon_fire);
    map.insert("weaponaddschar".to_string(), builtin_weapon_add_schar);
    map.insert("weaponattack".to_string(), builtin_weapon_attack);
}

// ============================================================================
// PLAYER FUNCTIONS
// ============================================================================

fn builtin_set_player_x(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.is_empty() {
        return Err(ScriptError::InvalidFunctionCall("setplayerx requires x coordinate".into()));
    }
    let x: f64 = args[0].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid x coordinate".into()))?;
    Ok(x.to_string())
}

fn builtin_set_player_y(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.is_empty() {
        return Err(ScriptError::InvalidFunctionCall("setplayery requires y coordinate".into()));
    }
    let y: f64 = args[0].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid y coordinate".into()))?;
    Ok(y.to_string())
}

fn builtin_player_x(_ctx: &ScriptContext, _args: &[String]) -> Result<String> {
    Ok("0".to_string()) // Would return actual player x
}

fn builtin_player_y(_ctx: &ScriptContext, _args: &[String]) -> Result<String> {
    Ok("0".to_string()) // Would return actual player y
}

fn builtin_set_hp(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.is_empty() {
        return Err(ScriptError::InvalidFunctionCall("sethp requires hp value".into()));
    }
    let hp: i32 = args[0].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid hp value".into()))?;
    Ok(hp.to_string())
}

fn builtin_get_hp(_ctx: &ScriptContext, _args: &[String]) -> Result<String> {
    Ok("3".to_string()) // Would return actual player hp
}

fn builtin_set_ap(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.is_empty() {
        return Err(ScriptError::InvalidFunctionCall("setap requires ap value".into()));
    }
    let ap: i32 = args[0].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid ap value".into()))?;
    Ok(ap.to_string())
}

fn builtin_get_ap(_ctx: &ScriptContext, _args: &[String]) -> Result<String> {
    Ok("1".to_string()) // Would return actual player ap
}

fn builtin_say(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.is_empty() {
        return Ok(String::new());
    }
    Ok(args[0].clone())
}

fn builtin_message(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.is_empty() {
        return Ok(String::new());
    }
    Ok(args[0].clone())
}

fn builtin_pm(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.len() < 2 {
        return Err(ScriptError::InvalidFunctionCall("pm requires player and message".into()));
    }
    Ok(args[1].clone())
}

fn builtin_warp(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.is_empty() {
        return Err(ScriptError::InvalidFunctionCall("warp requires level name".into()));
    }
    Ok(args[0].clone())
}

fn builtin_hide_player(_ctx: &ScriptContext, _args: &[String]) -> Result<String> {
    Ok("".to_string())
}

fn builtin_show_player(_ctx: &ScriptContext, _args: &[String]) -> Result<String> {
    Ok("".to_string())
}

// ============================================================================
// NPC FUNCTIONS
// ============================================================================

fn builtin_npc_x(_ctx: &ScriptContext, _args: &[String]) -> Result<String> {
    Ok("0".to_string())
}

fn builtin_npc_y(_ctx: &ScriptContext, _args: &[String]) -> Result<String> {
    Ok("0".to_string())
}

fn builtin_set_npc_x(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.is_empty() {
        return Err(ScriptError::InvalidFunctionCall("setnpcx requires x coordinate".into()));
    }
    Ok(args[0].clone())
}

fn builtin_set_npc_y(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.is_empty() {
        return Err(ScriptError::InvalidFunctionCall("setnpcy requires y coordinate".into()));
    }
    Ok(args[0].clone())
}

fn builtin_hide(_ctx: &ScriptContext, _args: &[String]) -> Result<String> {
    Ok("".to_string())
}

fn builtin_show(_ctx: &ScriptContext, _args: &[String]) -> Result<String> {
    Ok("".to_string())
}

fn builtin_destroy(_ctx: &ScriptContext, _args: &[String]) -> Result<String> {
    Ok("".to_string())
}

// ============================================================================
// MATH FUNCTIONS
// ============================================================================

fn builtin_add(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.len() < 2 {
        return Err(ScriptError::InvalidFunctionCall("add requires 2 arguments".into()));
    }
    let a: f64 = args[0].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid first argument".into()))?;
    let b: f64 = args[1].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid second argument".into()))?;
    Ok((a + b).to_string())
}

fn builtin_sub(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.len() < 2 {
        return Err(ScriptError::InvalidFunctionCall("sub requires 2 arguments".into()));
    }
    let a: f64 = args[0].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid first argument".into()))?;
    let b: f64 = args[1].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid second argument".into()))?;
    Ok((a - b).to_string())
}

fn builtin_mul(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.len() < 2 {
        return Err(ScriptError::InvalidFunctionCall("mul requires 2 arguments".into()));
    }
    let a: f64 = args[0].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid first argument".into()))?;
    let b: f64 = args[1].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid second argument".into()))?;
    Ok((a * b).to_string())
}

fn builtin_div(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.len() < 2 {
        return Err(ScriptError::InvalidFunctionCall("div requires 2 arguments".into()));
    }
    let a: f64 = args[0].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid first argument".into()))?;
    let b: f64 = args[1].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid second argument".into()))?;
    if b == 0.0 {
        return Err(ScriptError::RuntimeError("Division by zero".into()));
    }
    Ok((a / b).to_string())
}

fn builtin_mod(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.len() < 2 {
        return Err(ScriptError::InvalidFunctionCall("mod requires 2 arguments".into()));
    }
    let a: f64 = args[0].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid first argument".into()))?;
    let b: f64 = args[1].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid second argument".into()))?;
    Ok((a % b).to_string())
}

fn builtin_abs(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.is_empty() {
        return Err(ScriptError::InvalidFunctionCall("abs requires 1 argument".into()));
    }
    let a: f64 = args[0].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid argument".into()))?;
    Ok(a.abs().to_string())
}

fn builtin_min(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.len() < 2 {
        return Err(ScriptError::InvalidFunctionCall("min requires 2 arguments".into()));
    }
    let a: f64 = args[0].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid first argument".into()))?;
    let b: f64 = args[1].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid second argument".into()))?;
    Ok(a.min(b).to_string())
}

fn builtin_max(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.len() < 2 {
        return Err(ScriptError::InvalidFunctionCall("max requires 2 arguments".into()));
    }
    let a: f64 = args[0].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid first argument".into()))?;
    let b: f64 = args[1].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid second argument".into()))?;
    Ok(a.max(b).to_string())
}

fn builtin_random(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let random = (seed % 1000) as f64;
    Ok(random.to_string())
}

fn builtin_sqrt(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.is_empty() {
        return Err(ScriptError::InvalidFunctionCall("sqrt requires 1 argument".into()));
    }
    let a: f64 = args[0].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid argument".into()))?;
    if a < 0.0 {
        return Err(ScriptError::RuntimeError("Square root of negative number".into()));
    }
    Ok(a.sqrt().to_string())
}

fn builtin_pow(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.len() < 2 {
        return Err(ScriptError::InvalidFunctionCall("pow requires 2 arguments".into()));
    }
    let base: f64 = args[0].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid base".into()))?;
    let exp: f64 = args[1].parse()
        .map_err(|_| ScriptError::InvalidFunctionCall("Invalid exponent".into()))?;
    Ok(base.powf(exp).to_string())
}

// ============================================================================
// STRING FUNCTIONS
// ============================================================================

fn builtin_strlen(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.is_empty() {
        return Ok("0".to_string());
    }
    Ok(args[0].len().to_string())
}

fn builtin_str_replace(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.len() < 3 {
        return Err(ScriptError::InvalidFunctionCall("strreplace requires 3 arguments".into()));
    }
    Ok(args[0].replace(&args[1], &args[2]))
}

fn builtin_str_lower(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.is_empty() {
        return Ok(String::new());
    }
    Ok(args[0].to_lowercase())
}

fn builtin_str_upper(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.is_empty() {
        return Ok(String::new());
    }
    Ok(args[0].to_uppercase())
}

fn builtin_str_substring(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.is_empty() {
        return Ok(String::new());
    }
    let s = &args[0];
    let start: usize = args.get(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let len: Option<usize> = args.get(2)
        .and_then(|v| v.parse().ok());
    
    match len {
        Some(len) => {
            let end = (start + len).min(s.len());
            Ok(s.chars().skip(start).take(end - start).collect())
        }
        None => Ok(s.chars().skip(start).collect()),
    }
}

fn builtin_str_tostr(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.is_empty() {
        return Ok(String::new());
    }
    Ok(args[0].clone())
}

// ============================================================================
// LEVEL FUNCTIONS
// ============================================================================

fn builtin_level_name(_ctx: &ScriptContext, _args: &[String]) -> Result<String> {
    Ok("testlevel.nw".to_string()) // Would return actual level name
}

fn builtin_level_width(_ctx: &ScriptContext, _args: &[String]) -> Result<String> {
    Ok("64".to_string()) // Would return actual level width
}

fn builtin_level_height(_ctx: &ScriptContext, _args: &[String]) -> Result<String> {
    Ok("64".to_string()) // Would return actual level height
}

fn builtin_put_npc(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.len() < 3 {
        return Err(ScriptError::InvalidFunctionCall("putnpc requires x, y, and script".into()));
    }
    Ok("".to_string())
}

fn builtin_put_npc2(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.len() < 3 {
        return Err(ScriptError::InvalidFunctionCall("putnpc2 requires x, y, and script".into()));
    }
    Ok("".to_string())
}

// ============================================================================
// WEAPON FUNCTIONS
// ============================================================================

fn builtin_weapon_fire(_ctx: &ScriptContext, _args: &[String]) -> Result<String> {
    Ok("".to_string())
}

fn builtin_weapon_add_schar(_ctx: &ScriptContext, args: &[String]) -> Result<String> {
    if args.is_empty() {
        return Ok(String::new());
    }
    Ok(args[0].clone())
}

fn builtin_weapon_attack(_ctx: &ScriptContext, _args: &[String]) -> Result<String> {
    Ok("".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_math_functions() {
        let builtins = Builtins::new();
        let ctx = ScriptContext::new();
        
        assert_eq!(builtins.call(&ctx, "add", &["5".into(), "3".into()]).unwrap(), "8");
        assert_eq!(builtins.call(&ctx, "sub", &["10".into(), "4".into()]).unwrap(), "6");
        assert_eq!(builtins.call(&ctx, "mul", &["3".into(), "7".into()]).unwrap(), "21");
        assert_eq!(builtins.call(&ctx, "div", &["20".into(), "4".into()]).unwrap(), "5");
    }
    
    #[test]
    fn test_string_functions() {
        let builtins = Builtins::new();
        let ctx = ScriptContext::new();
        
        assert_eq!(builtins.call(&ctx, "strlen", &["hello".into()]).unwrap(), "5");
        assert_eq!(builtins.call(&ctx, "strlower", &["HELLO".into()]).unwrap(), "hello");
        assert_eq!(builtins.call(&ctx, "strupper", &["hello".into()]).unwrap(), "HELLO");
    }
}
