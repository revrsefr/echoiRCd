//! A small, dependency-free regular-expression engine (Thompson NFA). Linear time
//! in the input length with no backtracking, so a hostile pattern/input pair can't
//! blow up the single-threaded core — important because operators drive it via
//! RLINE (see [`crate::xline`]).
//!
//! Supported: literals, `.`, character classes `[...]`/`[^...]` with ranges and the
//! `\d \w \s \D \W \S` shorthands, the quantifiers `* + ? {n} {n,} {n,m}` (all
//! treated greedily — greediness can't change whether a match exists), alternation
//! `|`, grouping `(...)` and non-capturing `(?:...)`, the anchors `^` `$`, and the
//! escapes `\n \t \r` plus `\<char>` for a literal. Matching is an unanchored
//! search (use `^`/`$` to anchor); there are no capture groups or backreferences.

/// One member test inside a character class (or a bare shorthand like `\d`).
#[derive(Clone)]
enum ClassItem {
    Range(char, char),
    Digit,
    NotDigit,
    Word,
    NotWord,
    Space,
    NotSpace,
}

impl ClassItem {
    fn matches(&self, c: char) -> bool {
        match self {
            ClassItem::Range(lo, hi) => *lo <= c && c <= *hi,
            ClassItem::Digit => c.is_ascii_digit(),
            ClassItem::NotDigit => !c.is_ascii_digit(),
            ClassItem::Word => c.is_ascii_alphanumeric() || c == '_',
            ClassItem::NotWord => !(c.is_ascii_alphanumeric() || c == '_'),
            ClassItem::Space => c.is_ascii_whitespace(),
            ClassItem::NotSpace => !c.is_ascii_whitespace(),
        }
    }
}

/// The pattern AST.
enum Ast {
    Empty,
    Char(char),
    Any,
    Class(Vec<ClassItem>, bool), // items + whether the whole class is negated
    Start,
    End,
    Concat(Vec<Ast>),
    Alt(Vec<Ast>),
    Star(Box<Ast>),
    Plus(Box<Ast>),
    Quest(Box<Ast>),
    Repeat(Box<Ast>, u32, Option<u32>),
}

/// A compiled instruction. Split/Jmp/Start/End are the zero-width (epsilon) ones;
/// Char/Any/Class consume a character; Match accepts.
enum Inst {
    Char(char),
    Any,
    Class(Vec<ClassItem>, bool),
    Split(usize, usize),
    Jmp(usize),
    Start,
    End,
    Match,
}

const MAX_DEPTH: usize = 200; // parser nesting guard
const MAX_REPEAT: u32 = 1000; // {n,m} bound cap
const MAX_PROG: usize = 200_000; // compiled-program size cap

pub struct Regex {
    prog: Vec<Inst>,
}

impl Regex {
    /// Compile `pattern`, or return a human-readable error.
    pub fn new(pattern: &str) -> Result<Regex, String> {
        let mut p = Parser {
            chars: pattern.chars().collect(),
            pos: 0,
            depth: 0,
        };
        let ast = p.parse_alt()?;
        if p.pos != p.chars.len() {
            return Err(format!("unexpected `{}`", p.chars[p.pos]));
        }
        // Unanchored search: a `.*` prefix lets the match begin anywhere while the
        // real anchors (^/$) still see the true string position.
        let mut c = Compiler {
            prog: vec![Inst::Split(1, 3), Inst::Any, Inst::Jmp(0)],
        };
        c.compile(&ast)?;
        c.prog.push(Inst::Match);
        Ok(Regex { prog: c.prog })
    }

    /// Whether `text` contains a match.
    pub fn is_match(&self, text: &str) -> bool {
        let chars: Vec<char> = text.chars().collect();
        let n = chars.len();
        let mut seen = vec![0u32; self.prog.len()];
        let mut gen = 1u32;
        let mut clist: Vec<usize> = Vec::new();
        let mut nlist: Vec<usize> = Vec::new();
        self.add_thread(&mut clist, &mut seen, gen, 0, 0, n);
        for pos in 0..=n {
            gen += 1;
            nlist.clear();
            for i in 0..clist.len() {
                let pc = clist[i];
                let hit = match &self.prog[pc] {
                    Inst::Match => return true,
                    Inst::Char(c) => pos < n && chars[pos] == *c,
                    Inst::Any => pos < n && chars[pos] != '\n',
                    Inst::Class(items, neg) => {
                        pos < n && class_hit(items, *neg, chars[pos])
                    }
                    _ => false, // epsilon insts never reach clist
                };
                if hit {
                    self.add_thread(&mut nlist, &mut seen, gen, pc + 1, pos + 1, n);
                }
            }
            std::mem::swap(&mut clist, &mut nlist);
            if pos == n {
                break;
            }
        }
        false
    }

    /// Epsilon-closure: add `start` and everything reachable from it by
    /// Split/Jmp/anchor transitions to `list`, deduped by `seen`/`gen`. Iterative so
    /// a pathological pattern can't overflow the stack.
    fn add_thread(
        &self,
        list: &mut Vec<usize>,
        seen: &mut [u32],
        gen: u32,
        start: usize,
        pos: usize,
        n: usize,
    ) {
        let mut stack = vec![start];
        while let Some(pc) = stack.pop() {
            if seen[pc] == gen {
                continue;
            }
            seen[pc] = gen;
            match &self.prog[pc] {
                Inst::Jmp(x) => stack.push(*x),
                Inst::Split(x, y) => {
                    stack.push(*y);
                    stack.push(*x);
                }
                Inst::Start => {
                    if pos == 0 {
                        stack.push(pc + 1);
                    }
                }
                Inst::End => {
                    if pos == n {
                        stack.push(pc + 1);
                    }
                }
                _ => list.push(pc), // Char/Any/Class/Match
            }
        }
    }
}

fn class_hit(items: &[ClassItem], negated: bool, c: char) -> bool {
    let any = items.iter().any(|it| it.matches(c));
    any != negated
}

// --- compiler ----------------------------------------------------------------

struct Compiler {
    prog: Vec<Inst>,
}

impl Compiler {
    fn compile(&mut self, ast: &Ast) -> Result<(), String> {
        if self.prog.len() > MAX_PROG {
            return Err("pattern too large".into());
        }
        match ast {
            Ast::Empty => {}
            Ast::Char(c) => self.prog.push(Inst::Char(*c)),
            Ast::Any => self.prog.push(Inst::Any),
            Ast::Class(items, neg) => self.prog.push(Inst::Class(items.clone(), *neg)),
            Ast::Start => self.prog.push(Inst::Start),
            Ast::End => self.prog.push(Inst::End),
            Ast::Concat(v) => {
                for a in v {
                    self.compile(a)?;
                }
            }
            Ast::Alt(v) => {
                let mut jmps = Vec::new();
                for (i, a) in v.iter().enumerate() {
                    if i + 1 < v.len() {
                        let split = self.prog.len();
                        self.prog.push(Inst::Split(0, 0));
                        let l1 = self.prog.len();
                        self.compile(a)?;
                        jmps.push(self.prog.len());
                        self.prog.push(Inst::Jmp(0));
                        let l2 = self.prog.len();
                        self.prog[split] = Inst::Split(l1, l2);
                    } else {
                        self.compile(a)?;
                    }
                }
                let end = self.prog.len();
                for j in jmps {
                    self.prog[j] = Inst::Jmp(end);
                }
            }
            Ast::Star(a) => {
                let l1 = self.prog.len();
                self.prog.push(Inst::Split(0, 0));
                let body = self.prog.len();
                self.compile(a)?;
                self.prog.push(Inst::Jmp(l1));
                let l3 = self.prog.len();
                self.prog[l1] = Inst::Split(body, l3);
            }
            Ast::Plus(a) => {
                let l1 = self.prog.len();
                self.compile(a)?;
                let split = self.prog.len();
                self.prog.push(Inst::Split(0, 0));
                let l3 = self.prog.len();
                self.prog[split] = Inst::Split(l1, l3);
            }
            Ast::Quest(a) => {
                let split = self.prog.len();
                self.prog.push(Inst::Split(0, 0));
                let l1 = self.prog.len();
                self.compile(a)?;
                let l2 = self.prog.len();
                self.prog[split] = Inst::Split(l1, l2);
            }
            Ast::Repeat(a, min, max) => {
                for _ in 0..*min {
                    self.compile(a)?;
                }
                match max {
                    None => self.compile(&Ast::Star(clone_ast(a)))?,
                    Some(mx) => {
                        for _ in *min..*mx {
                            self.compile(&Ast::Quest(clone_ast(a)))?;
                        }
                    }
                }
            }
        }
        if self.prog.len() > MAX_PROG {
            return Err("pattern too large".into());
        }
        Ok(())
    }
}

/// Deep-clone an AST node (only needed to expand bounded repetition).
fn clone_ast(a: &Ast) -> Box<Ast> {
    Box::new(match a {
        Ast::Empty => Ast::Empty,
        Ast::Char(c) => Ast::Char(*c),
        Ast::Any => Ast::Any,
        Ast::Class(i, n) => Ast::Class(i.clone(), *n),
        Ast::Start => Ast::Start,
        Ast::End => Ast::End,
        Ast::Concat(v) => Ast::Concat(v.iter().map(|x| *clone_ast(x)).collect()),
        Ast::Alt(v) => Ast::Alt(v.iter().map(|x| *clone_ast(x)).collect()),
        Ast::Star(x) => Ast::Star(clone_ast(x)),
        Ast::Plus(x) => Ast::Plus(clone_ast(x)),
        Ast::Quest(x) => Ast::Quest(clone_ast(x)),
        Ast::Repeat(x, lo, hi) => Ast::Repeat(clone_ast(x), *lo, *hi),
    })
}

// --- parser ------------------------------------------------------------------

struct Parser {
    chars: Vec<char>,
    pos: usize,
    depth: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }
    fn at(&self, off: usize) -> Option<char> {
        self.chars.get(self.pos + off).copied()
    }
    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }
    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn parse_alt(&mut self) -> Result<Ast, String> {
        let mut alts = vec![self.parse_concat()?];
        while self.eat('|') {
            alts.push(self.parse_concat()?);
        }
        Ok(if alts.len() == 1 {
            alts.pop().unwrap()
        } else {
            Ast::Alt(alts)
        })
    }

    fn parse_concat(&mut self) -> Result<Ast, String> {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            items.push(self.parse_repeat()?);
        }
        Ok(match items.len() {
            0 => Ast::Empty,
            1 => items.pop().unwrap(),
            _ => Ast::Concat(items),
        })
    }

    fn parse_repeat(&mut self) -> Result<Ast, String> {
        let atom = self.parse_atom()?;
        let node = match self.peek() {
            Some('*') => {
                self.pos += 1;
                Ast::Star(Box::new(atom))
            }
            Some('+') => {
                self.pos += 1;
                Ast::Plus(Box::new(atom))
            }
            Some('?') => {
                self.pos += 1;
                Ast::Quest(Box::new(atom))
            }
            Some('{') => match self.try_bound()? {
                Some((min, max)) => Ast::Repeat(Box::new(atom), min, max),
                None => return Ok(atom), // a lone `{` is a literal (parsed next round)
            },
            _ => return Ok(atom),
        };
        self.eat('?'); // accept and ignore a lazy modifier
        Ok(node)
    }

    /// Try to parse `{n}` / `{n,}` / `{n,m}` at the cursor. Returns None (without
    /// consuming) if it isn't a well-formed bound, so `{` falls back to a literal.
    fn try_bound(&mut self) -> Result<Option<(u32, Option<u32>)>, String> {
        let save = self.pos;
        self.pos += 1; // consume '{'
        let min = self.parse_int();
        let (min, max) = match self.peek() {
            Some('}') if min.is_some() => {
                self.pos += 1;
                let m = min.unwrap();
                (m, Some(m))
            }
            Some(',') => {
                self.pos += 1;
                let max = self.parse_int();
                if !self.eat('}') {
                    self.pos = save;
                    return Ok(None);
                }
                (min.unwrap_or(0), max)
            }
            _ => {
                self.pos = save;
                return Ok(None);
            }
        };
        if min > MAX_REPEAT || max.map(|m| m > MAX_REPEAT).unwrap_or(false) {
            return Err("repetition count too large".into());
        }
        if let Some(m) = max {
            if m < min {
                return Err("bad repetition range".into());
            }
        }
        Ok(Some((min, max)))
    }

    fn parse_int(&mut self) -> Option<u32> {
        let start = self.pos;
        while self.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            self.pos += 1;
        }
        if self.pos == start {
            return None;
        }
        self.chars[start..self.pos]
            .iter()
            .collect::<String>()
            .parse()
            .ok()
    }

    fn parse_atom(&mut self) -> Result<Ast, String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err("pattern too deeply nested".into());
        }
        let r = match self.bump() {
            Some('(') => {
                if self.peek() == Some('?') {
                    // non-capturing (?:...) or a flag group (?i) — we only match, so
                    // just skip to the ':' (or ')') and treat the body plainly.
                    self.pos += 1;
                    while let Some(c) = self.peek() {
                        self.pos += 1;
                        if c == ':' || c == ')' {
                            break;
                        }
                    }
                }
                let inner = self.parse_alt()?;
                if !self.eat(')') {
                    return Err("unmatched `(`".into());
                }
                inner
            }
            Some('[') => self.parse_class()?,
            Some('.') => Ast::Any,
            Some('^') => Ast::Start,
            Some('$') => Ast::End,
            Some('\\') => self.parse_escape()?,
            Some(c) if c == '*' || c == '+' || c == '?' => {
                return Err("nothing to repeat".into())
            }
            Some(c) => Ast::Char(c),
            None => Ast::Empty,
        };
        self.depth -= 1;
        Ok(r)
    }

    fn parse_escape(&mut self) -> Result<Ast, String> {
        match self.bump() {
            Some('d') => Ok(Ast::Class(vec![ClassItem::Digit], false)),
            Some('D') => Ok(Ast::Class(vec![ClassItem::NotDigit], false)),
            Some('w') => Ok(Ast::Class(vec![ClassItem::Word], false)),
            Some('W') => Ok(Ast::Class(vec![ClassItem::NotWord], false)),
            Some('s') => Ok(Ast::Class(vec![ClassItem::Space], false)),
            Some('S') => Ok(Ast::Class(vec![ClassItem::NotSpace], false)),
            Some('n') => Ok(Ast::Char('\n')),
            Some('t') => Ok(Ast::Char('\t')),
            Some('r') => Ok(Ast::Char('\r')),
            Some(c) => Ok(Ast::Char(c)),
            None => Err("trailing backslash".into()),
        }
    }

    fn parse_class(&mut self) -> Result<Ast, String> {
        let negated = self.eat('^');
        let mut items = Vec::new();
        let mut first = true;
        loop {
            match self.peek() {
                None => return Err("unterminated `[`".into()),
                Some(']') if !first => {
                    self.pos += 1;
                    return Ok(Ast::Class(items, negated));
                }
                _ => {}
            }
            first = false;
            // one class member: a shorthand, or a (possibly ranged) char
            if self.peek() == Some('\\') {
                self.pos += 1;
                match self.bump() {
                    Some('d') => items.push(ClassItem::Digit),
                    Some('D') => items.push(ClassItem::NotDigit),
                    Some('w') => items.push(ClassItem::Word),
                    Some('W') => items.push(ClassItem::NotWord),
                    Some('s') => items.push(ClassItem::Space),
                    Some('S') => items.push(ClassItem::NotSpace),
                    Some(c) => {
                        let lo = match c {
                            'n' => '\n',
                            't' => '\t',
                            'r' => '\r',
                            other => other,
                        };
                        self.class_maybe_range(&mut items, lo)?;
                    }
                    None => return Err("unterminated `[`".into()),
                }
            } else {
                let lo = self.bump().unwrap();
                self.class_maybe_range(&mut items, lo)?;
            }
        }
    }

    /// Having read class-member start `lo`, consume an optional `-hi` range.
    fn class_maybe_range(&mut self, items: &mut Vec<ClassItem>, lo: char) -> Result<(), String> {
        if self.peek() == Some('-') && self.at(1).map(|c| c != ']').unwrap_or(false) {
            self.pos += 1; // consume '-'
            let hi = if self.peek() == Some('\\') {
                self.pos += 1;
                match self.bump() {
                    Some('n') => '\n',
                    Some('t') => '\t',
                    Some('r') => '\r',
                    Some(c) => c,
                    None => return Err("unterminated `[`".into()),
                }
            } else {
                self.bump().ok_or("unterminated `[`")?
            };
            if hi < lo {
                return Err("bad character range".into());
            }
            items.push(ClassItem::Range(lo, hi));
        } else {
            items.push(ClassItem::Range(lo, lo));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Fuzz the regex engine: no pattern may panic the compiler, and no
        // (pattern, text) pair may panic the matcher. The NFA is linear-time, so a
        // pathological pattern can't hang it either.
        #[test]
        fn regex_new_and_match_never_panic(pat in ".*", text in ".*") {
            if let Ok(re) = Regex::new(&pat) {
                let _ = re.is_match(&text);
            }
        }
    }

    fn m(pat: &str, text: &str) -> bool {
        Regex::new(pat).unwrap().is_match(text)
    }

    #[test]
    fn literals_and_search() {
        assert!(m("abc", "xxabcyy"));
        assert!(!m("abc", "ab_c"));
        assert!(m("", "anything")); // empty matches
    }

    #[test]
    fn anchors() {
        assert!(m("^abc", "abcdef"));
        assert!(!m("^abc", "zabc"));
        assert!(m("abc$", "zzabc"));
        assert!(!m("abc$", "abcz"));
        assert!(m("^a.c$", "axc"));
        assert!(!m("^a.c$", "axcd"));
    }

    #[test]
    fn quantifiers() {
        assert!(m("^a*$", ""));
        assert!(m("^a*$", "aaaa"));
        assert!(!m("^a+$", ""));
        assert!(m("^ab?c$", "ac"));
        assert!(m("^ab?c$", "abc"));
        assert!(m("^a{2,3}$", "aa"));
        assert!(m("^a{2,3}$", "aaa"));
        assert!(!m("^a{2,3}$", "a"));
        assert!(!m("^a{2,3}$", "aaaa"));
        assert!(m("^x{3}$", "xxx"));
        assert!(m("^x{2,}$", "xxxxx"));
    }

    #[test]
    fn classes_and_shorthands() {
        assert!(m("^[a-z]+$", "hello"));
        assert!(!m("^[a-z]+$", "Hello"));
        assert!(m("^[^0-9]+$", "abc"));
        assert!(!m("^[^0-9]+$", "ab3"));
        assert!(m(r"^\d{3}$", "123"));
        assert!(!m(r"^\d{3}$", "12a"));
        assert!(m(r"^\w+$", "a_1B"));
        assert!(!m(r"^\w+$", "a b"));
        assert!(m(r"foo\s+bar", "foo   bar"));
        assert!(m("^[]a]$", "]")); // leading ] is literal
    }

    #[test]
    fn alternation_and_groups() {
        assert!(m("^(cat|dog|bird)$", "dog"));
        assert!(!m("^(cat|dog)$", "cow"));
        assert!(m("^(ab)+$", "ababab"));
        assert!(m("^(?:xy)+z$", "xyxyz"));
    }

    #[test]
    fn realname_style_bans() {
        // nick!user@host realname matchtext, like RLINE uses
        let rx = Regex::new(r"^.+!.+@.+ .*spamword.*$").unwrap();
        assert!(rx.is_match("bad!user@host.com i sell spamword cheap"));
        assert!(!rx.is_match("good!user@host.com hello there"));
        // ip-ish host anchor
        assert!(Regex::new(r"@(10|192)\.").unwrap().is_match("n!u@192.168.0.1 real"));
    }

    #[test]
    fn dot_excludes_newline_and_escapes() {
        assert!(!m("^a.b$", "a\nb"));
        assert!(m(r"^a\.b$", "a.b"));
        assert!(!m(r"^a\.b$", "axb"));
    }

    #[test]
    fn invalid_patterns_rejected() {
        assert!(Regex::new("(unclosed").is_err());
        assert!(Regex::new("[unterminated").is_err());
        assert!(Regex::new("*nothing").is_err());
        assert!(Regex::new(r"a\").is_err());
        assert!(Regex::new("a{2,1}").is_err());
    }

    #[test]
    fn no_catastrophic_backtracking() {
        // the classic ReDoS pattern; a backtracking engine hangs, the NFA is linear
        let rx = Regex::new("^(a+)+$").unwrap();
        assert!(!rx.is_match(&("a".repeat(40) + "!")));
        assert!(rx.is_match(&"a".repeat(40)));
    }
}
