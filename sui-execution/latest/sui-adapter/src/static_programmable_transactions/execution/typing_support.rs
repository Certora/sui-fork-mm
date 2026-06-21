// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Items extracted from `execution::context` that the loading/typing pipeline needs
//! independently of the interpreter. They live in a dedicated, always-compiled module so
//! the rest of `context` (and `values`/`trace_utils`/`interpreter`) can be compiled out
//! under `--cfg=fuzzing` without removing the parts the typing fuzz target exercises.

use move_binary_format::errors::{Location, PartialVMResult, VMResult};
use move_core_types::u256::U256;
use move_vm_runtime::execution::{Type as VMType, TypeSubst as _, vm::LoadedFunctionInformation};
use serde::{Deserialize, de::DeserializeSeed};
use std::fmt;
use sui_types::{
    base_types::{RESOLVED_ASCII_STR, RESOLVED_UTF8_STR, SuiAddress},
    error::{ExecutionError, ExecutionErrorTrait, command_argument_error},
    execution_status::{CommandArgumentError, ExecutionErrorKind},
};

/// substitutes the type arguments into the parameter and return types
pub fn subst_signature(
    signature: LoadedFunctionInformation,
    type_arguments: &[VMType],
) -> VMResult<LoadedFunctionInformation> {
    let LoadedFunctionInformation {
        parameters,
        return_,
        is_entry,
        is_native,
        visibility,
        index,
        instruction_count,
    } = signature;
    let parameters = parameters
        .into_iter()
        .map(|ty| ty.subst(type_arguments))
        .collect::<PartialVMResult<Vec<_>>>()
        .map_err(|err| err.finish(Location::Undefined))?;
    let return_ = return_
        .into_iter()
        .map(|ty| ty.subst(type_arguments))
        .collect::<PartialVMResult<Vec<_>>>()
        .map_err(|err| err.finish(Location::Undefined))?;
    Ok(LoadedFunctionInformation {
        parameters,
        return_,
        is_entry,
        is_native,
        visibility,
        index,
        instruction_count,
    })
}

pub enum EitherError<E: ExecutionErrorTrait = ExecutionError> {
    CommandArgument(CommandArgumentError),
    Execution(E),
}

impl<E: ExecutionErrorTrait> From<ExecutionError> for EitherError<E> {
    fn from(e: ExecutionError) -> Self {
        EitherError::Execution(e.into())
    }
}

impl<E: ExecutionErrorTrait> From<CommandArgumentError> for EitherError<E> {
    fn from(e: CommandArgumentError) -> Self {
        EitherError::CommandArgument(e)
    }
}

impl<E: ExecutionErrorTrait> EitherError<E> {
    pub fn into_execution_error(self, command_index: usize) -> E {
        match self {
            EitherError::CommandArgument(e) => command_argument_error(e, command_index).into(),
            EitherError::Execution(e) => e,
        }
    }
}

/***************************************************************************************************
 * Special serialization formats
 **************************************************************************************************/

/// Special enum for values that need additional validation, in other words
/// There is validation to do on top of the BCS layout. Currently only needed for
/// strings
#[derive(Debug)]
pub enum PrimitiveArgumentLayout {
    /// An option
    Option(Box<PrimitiveArgumentLayout>),
    /// A vector
    Vector(Box<PrimitiveArgumentLayout>),
    /// An ASCII encoded string
    Ascii,
    /// A UTF8 encoded string
    UTF8,
    // needed for Option validation
    Bool,
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    Address,
}

impl PrimitiveArgumentLayout {
    /// returns true iff all BCS compatible bytes are actually values for this type.
    /// For example, this function returns false for Option and Strings since they need additional
    /// validation.
    pub fn bcs_only(&self) -> bool {
        match self {
            // have additional restrictions past BCS
            PrimitiveArgumentLayout::Option(_)
            | PrimitiveArgumentLayout::Ascii
            | PrimitiveArgumentLayout::UTF8 => false,
            // Move primitives are BCS compatible and do not need additional validation
            PrimitiveArgumentLayout::Bool
            | PrimitiveArgumentLayout::U8
            | PrimitiveArgumentLayout::U16
            | PrimitiveArgumentLayout::U32
            | PrimitiveArgumentLayout::U64
            | PrimitiveArgumentLayout::U128
            | PrimitiveArgumentLayout::U256
            | PrimitiveArgumentLayout::Address => true,
            // vector only needs validation if it's inner type does
            PrimitiveArgumentLayout::Vector(inner) => inner.bcs_only(),
        }
    }
}

/// Checks the bytes against the `SpecialArgumentLayout` using `bcs`. It does not actually generate
/// the deserialized value, only walks the bytes. While not necessary if the layout does not contain
/// special arguments (e.g. Option or String) we check the BCS bytes for predictability
pub fn bcs_argument_validate(
    bytes: &[u8],
    idx: u16,
    layout: PrimitiveArgumentLayout,
) -> Result<(), ExecutionError> {
    bcs::from_bytes_seed(&layout, bytes).map_err(|_| {
        ExecutionError::new_with_source(
            ExecutionErrorKind::command_argument_error(CommandArgumentError::InvalidBCSBytes, idx),
            format!("Function expects {layout} but provided argument's value does not match",),
        )
    })
}

impl<'d> serde::de::DeserializeSeed<'d> for &PrimitiveArgumentLayout {
    type Value = ();
    fn deserialize<D: serde::de::Deserializer<'d>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        use serde::de::Error;
        match self {
            PrimitiveArgumentLayout::Ascii => {
                let s: &str = serde::Deserialize::deserialize(deserializer)?;
                if !s.is_ascii() {
                    Err(D::Error::custom("not an ascii string"))
                } else {
                    Ok(())
                }
            }
            PrimitiveArgumentLayout::UTF8 => {
                deserializer.deserialize_string(serde::de::IgnoredAny)?;
                Ok(())
            }
            PrimitiveArgumentLayout::Option(layout) => {
                deserializer.deserialize_option(OptionElementVisitor(layout))
            }
            PrimitiveArgumentLayout::Vector(layout) => {
                deserializer.deserialize_seq(VectorElementVisitor(layout))
            }
            // primitive move value cases, which are hit to make sure the correct number of bytes
            // are removed for elements of an option/vector
            PrimitiveArgumentLayout::Bool => {
                deserializer.deserialize_bool(serde::de::IgnoredAny)?;
                Ok(())
            }
            PrimitiveArgumentLayout::U8 => {
                deserializer.deserialize_u8(serde::de::IgnoredAny)?;
                Ok(())
            }
            PrimitiveArgumentLayout::U16 => {
                deserializer.deserialize_u16(serde::de::IgnoredAny)?;
                Ok(())
            }
            PrimitiveArgumentLayout::U32 => {
                deserializer.deserialize_u32(serde::de::IgnoredAny)?;
                Ok(())
            }
            PrimitiveArgumentLayout::U64 => {
                deserializer.deserialize_u64(serde::de::IgnoredAny)?;
                Ok(())
            }
            PrimitiveArgumentLayout::U128 => {
                deserializer.deserialize_u128(serde::de::IgnoredAny)?;
                Ok(())
            }
            PrimitiveArgumentLayout::U256 => {
                U256::deserialize(deserializer)?;
                Ok(())
            }
            PrimitiveArgumentLayout::Address => {
                SuiAddress::deserialize(deserializer)?;
                Ok(())
            }
        }
    }
}

struct VectorElementVisitor<'a>(&'a PrimitiveArgumentLayout);

impl<'d> serde::de::Visitor<'d> for VectorElementVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Vector")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'d>,
    {
        while seq.next_element_seed(self.0)?.is_some() {}
        Ok(())
    }
}

struct OptionElementVisitor<'a>(&'a PrimitiveArgumentLayout);

impl<'d> serde::de::Visitor<'d> for OptionElementVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Option")
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'d>,
    {
        self.0.deserialize(deserializer)
    }
}

impl fmt::Display for PrimitiveArgumentLayout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrimitiveArgumentLayout::Vector(inner) => {
                write!(f, "vector<{inner}>")
            }
            PrimitiveArgumentLayout::Option(inner) => {
                write!(f, "std::option::Option<{inner}>")
            }
            PrimitiveArgumentLayout::Ascii => {
                write!(f, "std::{}::{}", RESOLVED_ASCII_STR.1, RESOLVED_ASCII_STR.2)
            }
            PrimitiveArgumentLayout::UTF8 => {
                write!(f, "std::{}::{}", RESOLVED_UTF8_STR.1, RESOLVED_UTF8_STR.2)
            }
            PrimitiveArgumentLayout::Bool => write!(f, "bool"),
            PrimitiveArgumentLayout::U8 => write!(f, "u8"),
            PrimitiveArgumentLayout::U16 => write!(f, "u16"),
            PrimitiveArgumentLayout::U32 => write!(f, "u32"),
            PrimitiveArgumentLayout::U64 => write!(f, "u64"),
            PrimitiveArgumentLayout::U128 => write!(f, "u128"),
            PrimitiveArgumentLayout::U256 => write!(f, "u256"),
            PrimitiveArgumentLayout::Address => write!(f, "address"),
        }
    }
}
