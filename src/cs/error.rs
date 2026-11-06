//! Errors produced while building witnesses and constraints.

use std::error::Error;
use std::fmt;

/// Failure reported at a circuit-construction boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConstructionError {
    /// During circuit construction, we load the param with a wrong format.
    ParamFormatError,
    /// During circuit construction, we encountered a duplicate variable assignment.
    WitnessAssignmentError,
    /// During circuit construction, we lacked knowledge of a variable assignment.
    AssignmentMissing,
    /// During circuit construction, we divided by zero.
    DivisionByZero,
    /// During circuit construction, we constructed an unsatisfiable constraint system.
    Unsatisfiable,
    /// During circuit construction, we encountered an error from the adapter.
    AdapterError,
    /// A formula from a different circuit was used in the same operation.
    CircuitMismatch,
    /// A patch requires at least one input formula.
    EmptyPatch,
    /// An operation required an allocated signal, but received a constant or expression.
    ExpectedSignal,
    /// A fixed-size collection was built with an unexpected number of elements.
    InvalidArrayLength,
    /// An integer gadget was declared with a zero bit width.
    InvalidBitWidth,
    /// Witness data was requested from a driver that does not build witnesses.
    WitnessUnavailable,
    /// A requested witness index has no assigned value.
    WitnessValueMissing,
    /// The signal index counter exceeded the representable range.
    IndexOverflow,
    /// The circuit allocated signals, public inputs, or constraints differently across passes.
    CircuitShapeMismatch,
    /// A patch script returned a different number of outputs than the caller requested.
    PatchOutputCountMismatch {
        /// Output count declared by the caller.
        expected: usize,
        /// Output count returned by the witness script.
        actual: usize,
    },
    /// A serialized expression was malformed.
    MalformedExpression,
    /// A signal index was not present in the adapter's allocation table.
    SignalIndexOutOfBounds,
    /// A patch key or its parameters are unsupported by the selected adapter.
    UnsupportedPatch,
    /// A field value could not be represented by the adapter's native field.
    FieldConversion,
    /// A bit width exceeded the largest range that is injective in the field.
    BitWidthExceedsFieldCapacity {
        /// Requested decomposition width.
        requested: usize,
        /// Largest injective decomposition width for the field.
        max_supported: usize,
    },
}

impl Error for ConstructionError {}

impl fmt::Display for ConstructionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            Self::ParamFormatError => f.write_str("invalid field element encoding"),
            Self::WitnessAssignmentError => f.write_str("signal was assigned more than once"),
            Self::AssignmentMissing => f.write_str("required witness assignment is missing"),
            Self::DivisionByZero => f.write_str("attempted to divide by zero"),
            Self::Unsatisfiable => f.write_str("witness does not satisfy the circuit"),
            Self::AdapterError => f.write_str("constraint adapter rejected the operation"),
            Self::CircuitMismatch => f.write_str("formulas belong to different circuits"),
            Self::EmptyPatch => f.write_str("patch requires at least one input formula"),
            Self::ExpectedSignal => f.write_str("operation requires an allocated signal"),
            Self::InvalidArrayLength => f.write_str("collection has an unexpected length"),
            Self::InvalidBitWidth => f.write_str("bit width must be greater than zero"),
            Self::WitnessUnavailable => f.write_str("driver does not contain witness data"),
            Self::WitnessValueMissing => f.write_str("witness value is missing at this index"),
            Self::IndexOverflow => f.write_str("signal index counter overflowed"),
            Self::CircuitShapeMismatch => {
                f.write_str("witness and constraint passes produced different circuit shapes")
            }
            Self::PatchOutputCountMismatch { expected, actual } => write!(
                f,
                "patch returned {actual} outputs, but the caller requested {expected}"
            ),
            Self::MalformedExpression => f.write_str("constraint expression is malformed"),
            Self::SignalIndexOutOfBounds => {
                f.write_str("constraint references an unallocated signal")
            }
            Self::UnsupportedPatch => f.write_str("patch is unsupported or has invalid parameters"),
            Self::FieldConversion => f.write_str("field conversion failed"),
            Self::BitWidthExceedsFieldCapacity {
                requested,
                max_supported,
            } => write!(
                f,
                "bit width {requested} exceeds field capacity {max_supported}"
            ),
        }
    }
}
