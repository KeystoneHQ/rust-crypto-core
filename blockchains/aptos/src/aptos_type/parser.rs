// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

// use crate::{
//     account_address::AccountAddress,
//     identifier::{self, Identifier},
//     language_storage::{StructTag, TypeTag},
//     transaction_argument::TransactionArgument,
// };
use anyhow::{bail, format_err, Result};
use std::iter::Peekable;
use crate::aptos_type::account_address::AccountAddress;
use crate::aptos_type::identifier;
use crate::aptos_type::identifier::Identifier;
use crate::aptos_type::language_storage::{StructTag, TypeTag};
use crate::aptos_type::transaction_argument::TransactionArgument;
use crate::aptos_type::safe_serialize;

#[derive(Eq, PartialEq, Debug)]
enum Token {
    U8Type,
    U64Type,
    U128Type,
    BoolType,
    AddressType,
    VectorType,
    SignerType,
    Whitespace(String),
    Name(String),
    Address(String),
    U8(String),
    U64(String),
    U128(String),
    Bytes(String),
    True,
    False,
    ColonColon,
    Lt,
    Gt,
    Comma,
    EOF,
}

impl Token {
    fn is_whitespace(&self) -> bool {
        matches!(self, Self::Whitespace(_))
    }
}

fn name_token(s: String) -> Token {
    match s.as_str() {
        "u8" => Token::U8Type,
        "u64" => Token::U64Type,
        "u128" => Token::U128Type,
        "bool" => Token::BoolType,
        "address" => Token::AddressType,
        "vector" => Token::VectorType,
        "true" => Token::True,
        "false" => Token::False,
        "signer" => Token::SignerType,
        _ => Token::Name(s),
    }
}

fn next_number(initial: char, mut it: impl Iterator<Item = char>) -> Result<(Token, usize)> {
    let mut num = String::new();
    num.push(initial);
    loop {
        match it.next() {
            Some(c) if c.is_ascii_digit() => num.push(c),
            Some(c) if c.is_alphanumeric() => {
                let mut suffix = String::new();
                suffix.push(c);
                loop {
                    match it.next() {
                        Some(c) if c.is_ascii_alphanumeric() => suffix.push(c),
                        _ => {
                            let len = num.len() + suffix.len();
                            let tok = match suffix.as_str() {
                                "u8" => Token::U8(num),
                                "u64" => Token::U64(num),
                                "u128" => Token::U128(num),
                                _ => bail!("invalid suffix"),
                            };
                            return Ok((tok, len));
                        }
                    }
                }
            }
            _ => {
                let len = num.len();
                return Ok((Token::U64(num), len));
            }
        }
    }
}

#[allow(clippy::many_single_char_names)]
fn next_token(s: &str) -> Result<Option<(Token, usize)>> {
    let mut it = s.chars().peekable();
    match it.next() {
        None => Ok(None),
        Some(c) => Ok(Some(match c {
            '<' => (Token::Lt, 1),
            '>' => (Token::Gt, 1),
            ',' => (Token::Comma, 1),
            ':' => match it.next() {
                Some(':') => (Token::ColonColon, 2),
                _ => bail!("unrecognized token"),
            },
            '0' if it.peek() == Some(&'x') || it.peek() == Some(&'X') => {
                it.next().unwrap();
                match it.next() {
                    Some(c) if c.is_ascii_hexdigit() => {
                        let mut r = String::new();
                        r.push('0');
                        r.push('x');
                        r.push(c);
                        for c in it {
                            if c.is_ascii_hexdigit() {
                                r.push(c);
                            } else {
                                break;
                            }
                        }
                        let len = r.len();
                        (Token::Address(r), len)
                    }
                    _ => bail!("unrecognized token"),
                }
            }
            c if c.is_ascii_digit() => next_number(c, it)?,
            'b' if it.peek() == Some(&'"') => {
                it.next().unwrap();
                let mut r = String::new();
                loop {
                    match it.next() {
                        Some('"') => break,
                        Some(c) if c.is_ascii() => r.push(c),
                        _ => bail!("unrecognized token"),
                    }
                }
                let len = r.len() + 3;
                (Token::Bytes(hex::encode(r)), len)
            }
            'x' if it.peek() == Some(&'"') => {
                it.next().unwrap();
                let mut r = String::new();
                loop {
                    match it.next() {
                        Some('"') => break,
                        Some(c) if c.is_ascii_hexdigit() => r.push(c),
                        _ => bail!("unrecognized token"),
                    }
                }
                let len = r.len() + 3;
                (Token::Bytes(r), len)
            }
            c if c.is_ascii_whitespace() => {
                let mut r = String::new();
                r.push(c);
                for c in it {
                    if c.is_ascii_whitespace() {
                        r.push(c);
                    } else {
                        break;
                    }
                }
                let len = r.len();
                (Token::Whitespace(r), len)
            }
            c if c.is_ascii_alphabetic() => {
                let mut r = String::new();
                r.push(c);
                for c in it {
                    if identifier::is_valid_identifier_char(c) {
                        r.push(c);
                    } else {
                        break;
                    }
                }
                let len = r.len();
                (name_token(r), len)
            }
            _ => bail!("unrecognized token"),
        })),
    }
}

fn tokenize(mut s: &str) -> Result<Vec<Token>> {
    let mut v = vec![];
    while let Some((tok, n)) = next_token(s)? {
        v.push(tok);
        s = &s[n..];
    }
    Ok(v)
}

struct Parser<I: Iterator<Item = Token>> {
    it: Peekable<I>,
}

impl<I: Iterator<Item = Token>> Parser<I> {
    fn new<T: IntoIterator<Item = Token, IntoIter = I>>(v: T) -> Self {
        Self {
            it: v.into_iter().peekable(),
        }
    }

    fn next(&mut self) -> Result<Token> {
        match self.it.next() {
            Some(tok) => Ok(tok),
            None => bail!("out of tokens, this should not happen"),
        }
    }

    fn peek(&mut self) -> Option<&Token> {
        self.it.peek()
    }

    fn consume(&mut self, tok: Token) -> Result<()> {
        let t = self.next()?;
        if t != tok {
            bail!("expected token {:?}, got {:?}", tok, t)
        }
        Ok(())
    }

    fn parse_comma_list<F, R>(
        &mut self,
        parse_list_item: F,
        end_token: Token,
        allow_trailing_comma: bool,
    ) -> Result<Vec<R>>
    where
        F: Fn(&mut Self) -> Result<R>,
        R: std::fmt::Debug,
    {
        let mut v = vec![];
        if !(self.peek() == Some(&end_token)) {
            loop {
                v.push(parse_list_item(self)?);
                if self.peek() == Some(&end_token) {
                    break;
                }
                self.consume(Token::Comma)?;
                if self.peek() == Some(&end_token) && allow_trailing_comma {
                    break;
                }
            }
        }
        Ok(v)
    }

    fn parse_string(&mut self) -> Result<String> {
        Ok(match self.next()? {
            Token::Name(s) => s,
            tok => bail!("unexpected token {:?}, expected string", tok),
        })
    }

    fn parse_type_tag(&mut self, depth: u8) -> Result<TypeTag> {
        if depth >= safe_serialize::MAX_TYPE_TAG_NESTING {
            bail!("Exceeded TypeTag nesting limit during parsing: {}", depth);
        }

        Ok(match self.next()? {
            Token::U8Type => TypeTag::U8,
            Token::U64Type => TypeTag::U64,
            Token::U128Type => TypeTag::U128,
            Token::BoolType => TypeTag::Bool,
            Token::AddressType => TypeTag::Address,
            Token::SignerType => TypeTag::Signer,
            Token::VectorType => {
                self.consume(Token::Lt)?;
                let ty = self.parse_type_tag(depth + 1)?;
                self.consume(Token::Gt)?;
                TypeTag::Vector(Box::new(ty))
            }
            Token::Address(addr) => {
                self.consume(Token::ColonColon)?;
                match self.next()? {
                    Token::Name(module) => {
                        self.consume(Token::ColonColon)?;
                        match self.next()? {
                            Token::Name(name) => {
                                let ty_args = if self.peek() == Some(&Token::Lt) {
                                    self.next()?;
                                    let ty_args = self.parse_comma_list(
                                        |parser| parser.parse_type_tag(depth + 1),
                                        Token::Gt,
                                        true,
                                    )?;
                                    self.consume(Token::Gt)?;
                                    ty_args
                                } else {
                                    vec![]
                                };
                                TypeTag::Struct(Box::new(StructTag {
                                    address: AccountAddress::from_hex_literal(&addr)?,
                                    module: Identifier::new(module)?,
                                    name: Identifier::new(name)?,
                                    type_params: ty_args,
                                }))
                            }
                            t => bail!("expected name, got {:?}", t),
                        }
                    }
                    t => bail!("expected name, got {:?}", t),
                }
            }
            tok => bail!("unexpected token {:?}, expected type tag", tok),
        })
    }

    fn parse_transaction_argument(&mut self) -> Result<TransactionArgument> {
        Ok(match self.next()? {
            Token::U8(s) => TransactionArgument::U8(s.parse()?),
            Token::U64(s) => TransactionArgument::U64(s.parse()?),
            Token::U128(s) => TransactionArgument::U128(s.parse()?),
            Token::True => TransactionArgument::Bool(true),
            Token::False => TransactionArgument::Bool(false),
            Token::Address(addr) => {
                TransactionArgument::Address(AccountAddress::from_hex_literal(&addr)?)
            }
            Token::Bytes(s) => TransactionArgument::U8Vector(hex::decode(s)?),
            tok => bail!("unexpected token {:?}, expected transaction argument", tok),
        })
    }
}

fn parse<F, T>(s: &str, f: F) -> Result<T>
where
    F: Fn(&mut Parser<std::vec::IntoIter<Token>>) -> Result<T>,
{
    let mut tokens: Vec<_> = tokenize(s)?
        .into_iter()
        .filter(|tok| !tok.is_whitespace())
        .collect();
    tokens.push(Token::EOF);
    let mut parser = Parser::new(tokens);
    let res = f(&mut parser)?;
    parser.consume(Token::EOF)?;
    Ok(res)
}

pub fn parse_string_list(s: &str) -> Result<Vec<String>> {
    parse(s, |parser| {
        parser.parse_comma_list(|parser| parser.parse_string(), Token::EOF, true)
    })
}

pub fn parse_type_tags(s: &str) -> Result<Vec<TypeTag>> {
    parse(s, |parser| {
        parser.parse_comma_list(|parser| parser.parse_type_tag(0), Token::EOF, true)
    })
}

pub fn parse_type_tag(s: &str) -> Result<TypeTag> {
    parse(s, |parser| parser.parse_type_tag(0))
}

pub fn parse_transaction_arguments(s: &str) -> Result<Vec<TransactionArgument>> {
    parse(s, |parser| {
        parser.parse_comma_list(
            |parser| parser.parse_transaction_argument(),
            Token::EOF,
            true,
        )
    })
}

pub fn parse_transaction_argument(s: &str) -> Result<TransactionArgument> {
    parse(s, |parser| parser.parse_transaction_argument())
}

pub fn parse_struct_tag(s: &str) -> Result<StructTag> {
    let type_tag = parse(s, |parser| parser.parse_type_tag(0))
        .map_err(|e| format_err!("invalid struct tag: {}, {}", s, e))?;
    if let TypeTag::Struct(struct_tag) = type_tag {
        Ok(*struct_tag)
    } else {
        bail!("invalid struct tag: {}", s)
    }
}


