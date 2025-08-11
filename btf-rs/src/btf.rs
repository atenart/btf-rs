//! Main object of the `btf-rs` crate, providing a way to parse BTF data and
//! helpers to query the information it describes.

use std::{
    convert::AsRef,
    fs::File,
    io::{BufReader, Cursor, Read, Write},
    path::Path,
    sync::Arc,
};

use btf_rs_derive::btf_type;
use fallible_iterator::FallibleIterator;
use memmap2::MmapOptions;

use crate::{cbtf, section::BtfSection, Error, Result};

/// Backend used by the [`Btf`] object to store and access the underlying BTF
/// information.
#[non_exhaustive]
pub enum Backend {
    /// Parse the BTF data during initialization and then store the result. This
    /// provides faster API calls at the cost of a slower initialization and
    /// larger memory footprint.
    Cache,
    /// Mmap the BTF data without parsing all of it. This provides a smaller
    /// memory footprint and faster initialization at the cost of slower API
    /// calls.
    Mmap,
}

/// Main representation of parsed BTF data. Provides helpers to resolve types
/// and their associated names.
pub struct Btf {
    obj: Arc<BtfSection>,
    base: Option<Arc<BtfSection>>,
}

impl Btf {
    /// Parse a stand-alone BTF section from a file and construct a Rust
    /// representation for later use. By default [`Backend::Cache`] is used.
    ///
    /// Trying to open split BTF files using this function will fail. For split
    /// BTF files use [`Btf::from_split_file`].
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::from_file_with_backend(&path, Backend::Cache)
    }

    /// Same as [`Btf::from_file`] but forcing a given [`Backend`] to be used.
    /// This allows selecting the desired behavior and balance, but can fail if
    /// a given [`Backend`] isn't supported by the underlying system.
    pub fn from_file_with_backend<P: AsRef<Path>>(path: P, backend: Backend) -> Result<Self> {
        Ok(Btf {
            obj: Arc::new(match backend {
                Backend::Cache => {
                    BtfSection::from_reader(&mut BufReader::new(File::open(path)?), None)?
                }
                Backend::Mmap => BtfSection::from_mmap(
                    unsafe { MmapOptions::new().map_copy_read_only(&File::open(path)?)? },
                    None,
                )?,
            }),
            base: None,
        })
    }

    /// Parse a split BTF section from a file and construct a Rust
    /// representation for later use. A base [`Btf`] containing the base section
    /// must be provided.
    pub fn from_split_file<P: AsRef<Path>>(path: P, base: &Btf) -> Result<Btf> {
        if base.base.is_some() {
            return Err(Error::OpNotSupp("Provided base is a split BTF".to_string()));
        }

        Ok(Btf {
            obj: Arc::new(BtfSection::from_reader(
                &mut BufReader::new(File::open(path)?),
                Some(base.obj.clone()),
            )?),
            base: Some(base.obj.clone()),
        })
    }

    /// Perform the same actions as [`Btf::from_file`], but fed with a byte
    /// slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Btf> {
        Ok(Btf {
            obj: Arc::new(BtfSection::from_reader(&mut Cursor::new(bytes), None)?),
            base: None,
        })
    }

    /// Performs the same actions as [`Btf::from_split_file`], but fed with a
    /// byte slice.
    pub fn from_split_bytes(bytes: &[u8], base: &Btf) -> Result<Btf> {
        if base.base.is_some() {
            return Err(Error::OpNotSupp("Provided base is a split BTF".to_string()));
        }

        let base = base.obj.clone();
        Ok(Btf {
            obj: Arc::new(BtfSection::from_reader(
                &mut Cursor::new(bytes),
                Some(base.clone()),
            )?),
            base: Some(base),
        })
    }

    /// Returns a reference the base BTF section. For non-split `Btf` the base
    /// BTF section holds the full BTF representation. Base BTF sections are
    /// standalone representations (no reference to external BTF sections).
    pub fn base(&self) -> &BtfSection {
        match &self.base {
            Some(base) => base,
            None => &self.obj,
        }
    }

    /// Returns a reference to the split BTF section, if any. A split BTF
    /// section is not a standalone representation (it uses references to a base
    /// BTF section).
    pub fn split(&self) -> Option<&BtfSection> {
        self.base.as_ref()?;
        Some(&self.obj)
    }

    /// Find a list of BTF ids with a given name.
    ///
    /// Using an empty name (`""`) resolves anonymous ids.
    pub fn resolve_ids_by_name(&self, name: &str) -> Result<Vec<u32>> {
        let mut ids = self.obj.resolve_ids_by_name(name)?;

        if let Some(base) = &self.base {
            ids.append(&mut base.resolve_ids_by_name(name)?);
        }

        Ok(ids)
    }

    /// Find a list of BTF ids whose names match a regex.
    ///
    /// If the regex matches the empty name (`""`), e.g. `"^$"`, the result will
    /// contain anonymous ids.
    #[cfg(feature = "regex")]
    pub fn resolve_ids_by_regex(&self, re: &regex::Regex) -> Result<Vec<u32>> {
        let mut ids = self.obj.resolve_ids_by_regex(re)?;

        if let Some(base) = &self.base {
            ids.append(&mut base.resolve_ids_by_regex(re)?);
        }

        Ok(ids)
    }

    /// Find a BTF type with a given id.
    pub fn resolve_type_by_id(&self, id: u32) -> Result<Type> {
        if let Some(base) = &self.base {
            if let Ok(r#type) = base.resolve_type_by_id(id) {
                return Ok(r#type);
            }
        }

        self.obj.resolve_type_by_id(id)
    }

    /// Find a list of BTF types with a given name.
    ///
    /// Using an empty name (`""`) resolves anonymous types.
    pub fn resolve_types_by_name(&self, name: &str) -> Result<Vec<Type>> {
        let mut types = self.obj.resolve_types_by_name(name)?;

        if let Some(base) = &self.base {
            types.append(&mut base.resolve_types_by_name(name)?);
        }

        Ok(types)
    }

    /// Find a list of BTF types whose names match a regex.
    ///
    /// If the regex matches the empty name (`""`), e.g. `"^$"`, the result will
    /// contain anonymous types.
    #[cfg(feature = "regex")]
    pub fn resolve_types_by_regex(&self, re: &regex::Regex) -> Result<Vec<Type>> {
        let mut types = self.obj.resolve_types_by_regex(re)?;

        if let Some(base) = &self.base {
            types.append(&mut base.resolve_types_by_regex(re)?);
        }

        Ok(types)
    }

    /// Resolve a name referenced by a Type which is defined in the current
    /// [`Btf`] object.
    pub fn resolve_name(&self, r#type: &dyn BtfType) -> Result<String> {
        match &self.base {
            Some(base) => base
                .resolve_name(r#type)
                .or_else(|_| self.obj.resolve_name(r#type)),
            None => self.obj.resolve_name(r#type),
        }
    }

    /// Return an iterator over all types defined in the current BTF object.
    pub fn type_iter(&self) -> TypeIter<'_> {
        TypeIter::new(&self.obj, self.base.as_ref().map(|s| s.as_ref()))
    }

    /// Types can have a reference to another one, e.g. `Ptr -> Int`. This
    /// helper resolve a Type referenced in an other one. It is the main helper
    /// to traverse the Type tree.
    pub fn resolve_chained_type<T: BtfType + ?Sized>(&self, r#type: &T) -> Result<Type> {
        let id = r#type
            .get_type_id()
            .ok_or(Error::OpNotSupp("No chained type in type".to_string()))?;
        self.resolve_type_by_id(id)
    }

    /// This helper returns an iterator that allow to resolve a Type
    /// referenced in another one all the way down to the chain.
    /// The helper makes use of [`Btf::resolve_chained_type`].
    pub fn chained_type_iter<T: BtfType + ?Sized>(&self, r#type: &T) -> ChainedTypeIter<'_> {
        ChainedTypeIter {
            btf: self,
            r#type: self.resolve_chained_type(r#type).ok(),
        }
    }
}

/// Iterator over BTF types.
pub struct TypeIter<'a> {
    pub(crate) section: &'a BtfSection,
    pub(crate) next_section: Option<&'a BtfSection>,
    cursor: u32,
    end: u32,
}

impl<'a> TypeIter<'a> {
    pub(crate) fn new(section: &'a BtfSection, next_section: Option<&'a BtfSection>) -> Self {
        let (start, end) = section.type_id_range();

        TypeIter {
            section,
            next_section,
            cursor: start,
            end,
        }
    }
}

impl FallibleIterator for TypeIter<'_> {
    type Item = Type;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        loop {
            // Go to the next section if needed.
            if self.cursor > self.end {
                self.section = match self.next_section.take() {
                    Some(section) => section,
                    None => return Ok(None),
                };

                (self.cursor, self.end) = self.section.type_id_range();
            }

            let r#type = self.section.resolve_type_by_id(self.cursor);
            self.cursor += 1;

            if matches!(r#type, Err(Error::UndefinedKind(_))) {
                continue;
            }

            return r#type.map(Some);
        }
    }
}

/// Iterator over chained types (types referencing other types in a chain).
pub struct ChainedTypeIter<'a> {
    btf: &'a Btf,
    r#type: Option<Type>,
}

impl Iterator for ChainedTypeIter<'_> {
    type Item = Type;

    fn next(&mut self) -> Option<Self::Item> {
        match self.r#type.clone() {
            None => None,
            Some(ty) => {
                self.r#type = match ty.as_btf_type() {
                    Some(x) => self.btf.resolve_chained_type(x).ok(),
                    // We might have encountered Void or other
                    // non-BtfType types.
                    None => None,
                };
                Some(ty)
            }
        }
    }
}

/// Rust representation of BTF types. Each type then contains its own specific
/// data and provides helpers to access it.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Type {
    Void,
    Int(Int),
    Ptr(Ptr),
    Array(Array),
    Struct(Struct),
    Union(Union),
    Enum(Enum),
    Fwd(Fwd),
    Typedef(Typedef),
    Volatile(Volatile),
    Const(Const),
    Restrict(Restrict),
    Func(Func),
    FuncProto(FuncProto),
    Var(Var),
    Datasec(Datasec),
    Float(Float),
    DeclTag(DeclTag),
    TypeTag(TypeTag),
    Enum64(Enum64),
    LocParam(LocParam),
    LocSec(LocSec),
    LocProto(LocProto),
}

impl Type {
    // Creates a new Type reading a BTF definition from a reader.
    pub(super) fn from_reader<R: Read>(
        reader: &mut R,
        endianness: cbtf::Endianness,
        bt: cbtf::btf_type,
    ) -> Result<Self> {
        // Each BTF type needs specific handling to parse its type-specific header.
        macro_rules! init_kinds {
            ($kind:expr, $( $ty:ident ),*) => {
                match $kind {
                    $(
                        cbtf::BtfKind::$ty => Type::$ty($ty::from_reader(reader, endianness, bt)?),
                    )*
                    cbtf::BtfKind::Undefined => return Err(Error::UndefinedKind(bt.kind())),
                }
            };
        }
        Ok(init_kinds!(
            cbtf::BtfKind::from_id(bt.kind()),
            Int,
            Ptr,
            Array,
            Struct,
            Union,
            Enum,
            Fwd,
            Typedef,
            Volatile,
            Const,
            Restrict,
            Func,
            FuncProto,
            Var,
            Datasec,
            Float,
            DeclTag,
            TypeTag,
            Enum64,
            LocParam,
            LocProto,
            LocSec
        ))
    }

    // Creates a new Type reading a BTF definition from bytes.
    pub(crate) fn from_bytes(
        buf: &[u8],
        endianness: cbtf::Endianness,
        bt: cbtf::btf_type,
    ) -> Result<Self> {
        Self::from_reader(&mut Cursor::new(buf), endianness, bt)
    }

    // Write the Type as a valid BTF representation.
    pub(crate) fn write(&self, w: &mut dyn Write, endianness: cbtf::Endianness) -> Result<()> {
        macro_rules! write_kinds {
            ($( $ty:ident ),*) => {
                match &self {
                    Type::Void => Err(Error::OpNotSupp(
                        "cannot write a BTF represention of 'void'".to_string(),
                    )),
                    $(
                        Type::$ty(inner) => inner.write(w, endianness),
                    )*
                }
            };
        }
        write_kinds!(
            Int, Ptr, Array, Struct, Union, Enum, Fwd, Typedef, Volatile, Const, Restrict, Func,
            FuncProto, Var, Datasec, Float, DeclTag, TypeTag, Enum64, LocParam, LocProto, LocSec
        )
    }

    /// Returns an `str` representation of the [`Type`].
    pub fn name(&self) -> &'static str {
        match &self {
            Type::Void => "void",
            Type::Int(_) => "int",
            Type::Ptr(_) => "ptr",
            Type::Array(_) => "array",
            Type::Struct(_) => "struct",
            Type::Union(_) => "union",
            Type::Enum(_) => "enum",
            Type::Fwd(_) => "fwd",
            Type::Typedef(_) => "typedef",
            Type::Volatile(_) => "volatile",
            Type::Const(_) => "const",
            Type::Restrict(_) => "restrict",
            Type::Func(_) => "func",
            Type::FuncProto(_) => "func-proto",
            Type::Var(_) => "var",
            Type::Datasec(_) => "datasec",
            Type::Float(_) => "float",
            Type::DeclTag(_) => "decl-tag",
            Type::TypeTag(_) => "type-tag",
            Type::Enum64(_) => "enum64",
            Type::LocParam(_) => "loc-param",
            Type::LocProto(_) => "loc-proto",
            Type::LocSec(_) => "loc-sec",
        }
    }

    pub fn as_btf_type(&self) -> Option<&dyn BtfType> {
        match self {
            Type::Int(i) => Some(i),
            Type::Ptr(p) => Some(p),
            Type::Array(a) => Some(a),
            Type::Struct(s) => Some(s),
            Type::Union(u) => Some(u),
            Type::Enum(e) => Some(e),
            Type::Fwd(f) => Some(f),
            Type::Typedef(td) => Some(td),
            Type::Volatile(v) => Some(v),
            Type::Const(c) => Some(c),
            Type::Restrict(r) => Some(r),
            Type::Func(fu) => Some(fu),
            Type::Var(v) => Some(v),
            Type::Datasec(ds) => Some(ds),
            Type::Float(f) => Some(f),
            Type::DeclTag(dt) => Some(dt),
            Type::TypeTag(tt) => Some(tt),
            Type::Enum64(e64) => Some(e64),
            _ => None,
        }
    }
}

/// Helpers common to all BTF types. Ease the use of types.
pub trait BtfType {
    /// Returns the offset of the string associated with the type, if any.
    fn get_name_offset(&self) -> Option<u32> {
        None
    }

    /// Returns the type id associated with the current type, if any.
    fn get_type_id(&self) -> Option<u32> {
        None
    }
}

/// Rust representation for BTF type `BTF_KIND_INT`.
#[btf_type]
pub struct Int {
    btf_type: cbtf::btf_type,
    btf_int: cbtf::btf_int,
}

impl Int {
    pub fn is_signed(&self) -> bool {
        self.btf_int.encoding() & cbtf::BTF_INT_SIGNED == cbtf::BTF_INT_SIGNED
    }

    pub fn is_char(&self) -> bool {
        self.btf_int.encoding() & cbtf::BTF_INT_CHAR == cbtf::BTF_INT_CHAR
    }

    pub fn is_bool(&self) -> bool {
        self.btf_int.encoding() & cbtf::BTF_INT_BOOL == cbtf::BTF_INT_BOOL
    }

    pub fn size(&self) -> usize {
        self.btf_type.size().expect("int should have a size")
    }
}

impl BtfType for Int {
    fn get_name_offset(&self) -> Option<u32> {
        self.btf_type.name_offset()
    }
}

/// Rust representation for BTF type `BTF_KIND_PTR`.
#[btf_type]
pub struct Ptr {
    btf_type: cbtf::btf_type,
}

impl BtfType for Ptr {
    fn get_type_id(&self) -> Option<u32> {
        self.btf_type.r#type()
    }
}

/// Rust representation for BTF type `BTF_KIND_ARRAY`.
#[btf_type]
pub struct Array {
    btf_type: cbtf::btf_type,
    btf_array: cbtf::btf_array,
}

#[allow(clippy::len_without_is_empty)]
impl Array {
    /// Number of elements in the `Array`.
    pub fn len(&self) -> usize {
        self.btf_array.nelems as usize
    }
}

impl BtfType for Array {
    fn get_type_id(&self) -> Option<u32> {
        Some(self.btf_array.r#type)
    }
}

/// Rust representation for BTF type `BTF_KIND_STRUCT`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Struct {
    btf_type: cbtf::btf_type,
    /// The members information. Use `.len()` to count them.
    pub members: Vec<Member>,
}

impl Struct {
    fn from_reader<R: Read>(
        reader: &mut R,
        endianness: cbtf::Endianness,
        btf_type: cbtf::btf_type,
    ) -> Result<Struct> {
        let mut members = Vec::new();

        for _ in 0..btf_type.vlen() {
            members.push(Member::from_reader(
                reader,
                endianness,
                btf_type.kind_flag(),
            )?);
        }

        Ok(Struct { btf_type, members })
    }

    fn write(&self, w: &mut dyn Write, endianness: cbtf::Endianness) -> Result<()> {
        self.btf_type.write(w, endianness)?;
        self.members.iter().try_for_each(|m| m.write(w, endianness))
    }

    pub fn size(&self) -> usize {
        self.btf_type
            .size()
            .expect("struct and union should have a size")
    }
}

impl BtfType for Struct {
    fn get_name_offset(&self) -> Option<u32> {
        self.btf_type.name_offset()
    }
}

/// Rust representation for BTF type `BTF_KIND_UNION`.
pub type Union = Struct;

/// Represents a [`Struct`] member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Member {
    kind_flag: u32,
    btf_member: cbtf::btf_member,
}

impl Member {
    fn from_reader<R: Read>(
        reader: &mut R,
        endianness: cbtf::Endianness,
        kind_flag: u32,
    ) -> Result<Member> {
        Ok(Member {
            kind_flag,
            btf_member: cbtf::btf_member::from_reader(reader, endianness)?,
        })
    }

    fn write(&self, w: &mut dyn Write, endianness: cbtf::Endianness) -> Result<()> {
        self.btf_member.write(w, endianness)
    }

    pub fn bit_offset(&self) -> u32 {
        match self.kind_flag {
            1 => self.btf_member.offset & 0xffffff,
            _ => self.btf_member.offset,
        }
    }

    pub fn bitfield_size(&self) -> Option<u32> {
        match self.kind_flag {
            1 => Some(self.btf_member.offset >> 24),
            _ => None,
        }
    }
}

impl BtfType for Member {
    fn get_name_offset(&self) -> Option<u32> {
        Some(self.btf_member.name_off)
    }

    fn get_type_id(&self) -> Option<u32> {
        Some(self.btf_member.r#type)
    }
}

/// Rust representation for BTF type `BTF_KIND_ENUM`.
#[btf_type]
pub struct Enum {
    btf_type: cbtf::btf_type,
    /// The enum members information. Use `.len()` to count them.
    pub members: Vec<EnumMember>,
}

#[allow(clippy::len_without_is_empty)]
impl Enum {
    pub fn is_signed(&self) -> bool {
        self.btf_type.kind_flag() == 1
    }

    pub fn size(&self) -> usize {
        self.btf_type.size().expect("enum should have a size")
    }
}

impl BtfType for Enum {
    fn get_name_offset(&self) -> Option<u32> {
        self.btf_type.name_offset()
    }
}

/// Represents an [`Enum`] member.
#[btf_type]
pub struct EnumMember {
    btf_enum: cbtf::btf_enum,
}

impl EnumMember {
    pub fn val(&self) -> u32 {
        self.btf_enum.val
    }
}

impl BtfType for EnumMember {
    fn get_name_offset(&self) -> Option<u32> {
        Some(self.btf_enum.name_off)
    }
}

/// Rust representation for BTF type `BTF_KIND_FWD`.
#[btf_type]
pub struct Fwd {
    btf_type: cbtf::btf_type,
}

impl Fwd {
    /// Tests if the forward declaration is for a struct type.
    pub fn is_struct(&self) -> bool {
        self.btf_type.kind_flag() == 0
    }

    /// Tests if the forward declaration is for a union type.
    pub fn is_union(&self) -> bool {
        self.btf_type.kind_flag() == 1
    }
}

impl BtfType for Fwd {
    fn get_name_offset(&self) -> Option<u32> {
        self.btf_type.name_offset()
    }
}

/// Rust representation for BTF type `BTF_KIND_TYPEDEF`.
#[btf_type]
pub struct Typedef {
    btf_type: cbtf::btf_type,
}

impl BtfType for Typedef {
    fn get_name_offset(&self) -> Option<u32> {
        self.btf_type.name_offset()
    }

    fn get_type_id(&self) -> Option<u32> {
        self.btf_type.r#type()
    }
}

/// Rust representation for BTF type `BTF_KIND_VOLATILE`.
#[btf_type]
pub struct Volatile {
    btf_type: cbtf::btf_type,
}

impl BtfType for Volatile {
    fn get_type_id(&self) -> Option<u32> {
        self.btf_type.r#type()
    }
}

/// Rust representation for BTF type `BTF_KIND_CONST`.
pub type Const = Volatile;

/// Rust representation for BTF type `BTF_KIND_RESTRICT`.
pub type Restrict = Volatile;

/// Rust representation for BTF type `BTF_KIND_FUNC`.
#[btf_type]
pub struct Func {
    btf_type: cbtf::btf_type,
}

impl Func {
    pub fn is_static(&self) -> bool {
        self.btf_type.vlen() == cbtf::BTF_FUNC_STATIC
    }

    pub fn is_global(&self) -> bool {
        self.btf_type.vlen() == cbtf::BTF_FUNC_GLOBAL
    }

    pub fn is_extern(&self) -> bool {
        self.btf_type.vlen() == cbtf::BTF_FUNC_EXTERN
    }
}

impl BtfType for Func {
    fn get_name_offset(&self) -> Option<u32> {
        self.btf_type.name_offset()
    }

    fn get_type_id(&self) -> Option<u32> {
        self.btf_type.r#type()
    }
}

/// Rust representation for BTF type `BTF_KIND_FUNC_PROTO`.
#[btf_type]
pub struct FuncProto {
    btf_type: cbtf::btf_type,
    pub parameters: Vec<Parameter>,
}

impl FuncProto {
    pub fn return_type_id(&self) -> u32 {
        self.btf_type
            .r#type()
            .expect("func proto should have a type")
    }
}

/// Represents a [`FuncProto`] parameter.
#[btf_type]
pub struct Parameter {
    btf_param: cbtf::btf_param,
}

impl Parameter {
    pub fn is_variadic(&self) -> bool {
        self.btf_param.name_off == 0 && self.btf_param.r#type == 0
    }
}

impl BtfType for Parameter {
    fn get_name_offset(&self) -> Option<u32> {
        Some(self.btf_param.name_off)
    }

    fn get_type_id(&self) -> Option<u32> {
        Some(self.btf_param.r#type)
    }
}

/// Rust representation for BTF type `BTF_KIND_VAR`.
#[btf_type]
pub struct Var {
    btf_type: cbtf::btf_type,
    btf_var: cbtf::btf_var,
}

impl Var {
    pub fn is_static(&self) -> bool {
        self.btf_var.linkage == cbtf::BTF_VAR_STATIC
    }

    pub fn is_global(&self) -> bool {
        self.btf_var.linkage == cbtf::BTF_VAR_GLOBAL_ALLOCATED
    }

    pub fn is_extern(&self) -> bool {
        self.btf_var.linkage == cbtf::BTF_VAR_GLOBAL_EXTERN
    }
}

impl BtfType for Var {
    fn get_name_offset(&self) -> Option<u32> {
        self.btf_type.name_offset()
    }

    fn get_type_id(&self) -> Option<u32> {
        self.btf_type.r#type()
    }
}

/// Rust representation for BTF type `BTF_KIND_DATASEC`.
#[btf_type]
pub struct Datasec {
    btf_type: cbtf::btf_type,
    pub variables: Vec<VarSecinfo>,
}

impl Datasec {
    pub fn size(&self) -> usize {
        self.btf_type.size().expect("datasec should have a size")
    }
}

impl BtfType for Datasec {
    fn get_name_offset(&self) -> Option<u32> {
        self.btf_type.name_offset()
    }
}

/// Represents a [`Datasec`] variable.
#[btf_type]
pub struct VarSecinfo {
    btf_var_secinfo: cbtf::btf_var_secinfo,
}

impl VarSecinfo {
    pub fn offset(&self) -> u32 {
        self.btf_var_secinfo.offset
    }

    pub fn size(&self) -> usize {
        self.btf_var_secinfo.size as usize
    }
}

impl BtfType for VarSecinfo {
    fn get_type_id(&self) -> Option<u32> {
        Some(self.btf_var_secinfo.r#type)
    }
}

/// Rust representation for BTF type `BTF_KIND_FLOAT`.
#[btf_type]
pub struct Float {
    btf_type: cbtf::btf_type,
}

impl Float {
    pub fn size(&self) -> usize {
        self.btf_type.size().expect("float should have a size")
    }
}

impl BtfType for Float {
    fn get_name_offset(&self) -> Option<u32> {
        self.btf_type.name_offset()
    }
}

/// Rust representation for BTF type `BTF_KIND_DECL_TAG`.
#[btf_type]
pub struct DeclTag {
    btf_type: cbtf::btf_type,
    btf_decl_tag: cbtf::btf_decl_tag,
}

impl DeclTag {
    pub fn component_index(&self) -> Option<u32> {
        let component_idx = self.btf_decl_tag.component_idx;
        match component_idx {
            x if x < 0 => None,
            x => Some(x as u32),
        }
    }

    pub fn is_attribute(&self) -> bool {
        self.btf_type.kind_flag() == 1
    }
}

impl BtfType for DeclTag {
    fn get_name_offset(&self) -> Option<u32> {
        self.btf_type.name_offset()
    }

    fn get_type_id(&self) -> Option<u32> {
        self.btf_type.r#type()
    }
}

/// Rust representation for BTF type `BTF_KIND_TYPE_TAG`.
#[btf_type]
pub struct TypeTag {
    btf_type: cbtf::btf_type,
}

impl TypeTag {
    pub fn is_attribute(&self) -> bool {
        self.btf_type.kind_flag() == 1
    }
}

impl BtfType for TypeTag {
    fn get_name_offset(&self) -> Option<u32> {
        self.btf_type.name_offset()
    }

    fn get_type_id(&self) -> Option<u32> {
        self.btf_type.r#type()
    }
}

/// Rust representation for BTF type `BTF_KIND_ENUM64`.
#[btf_type]
pub struct Enum64 {
    btf_type: cbtf::btf_type,
    /// The enum members information. Use `.len()` to count them.
    pub members: Vec<Enum64Member>,
}

#[allow(clippy::len_without_is_empty)]
impl Enum64 {
    pub fn is_signed(&self) -> bool {
        self.btf_type.kind_flag() == 1
    }

    pub fn size(&self) -> usize {
        self.btf_type.size().expect("enum64 should have a size")
    }
}

impl BtfType for Enum64 {
    fn get_name_offset(&self) -> Option<u32> {
        self.btf_type.name_offset()
    }
}

/// Represents an [`Enum64`] member.
#[btf_type]
pub struct Enum64Member {
    btf_enum64: cbtf::btf_enum64,
}

impl Enum64Member {
    pub fn val(&self) -> u64 {
        ((self.btf_enum64.val_hi32 as u64) << 32) | self.btf_enum64.val_lo32 as u64
    }
}

impl BtfType for Enum64Member {
    fn get_name_offset(&self) -> Option<u32> {
        Some(self.btf_enum64.name_off)
    }
}

/// Rust representation for BTF type `BTF_KIND_LOC_PARAM`.
#[btf_type]
pub struct LocParam {
    btf_type: cbtf::btf_type,
    loc_param: cbtf::btf_loc_param,
    // This hold raw data, do not expose as a proper Rust type.
    values: Vec<cbtf::btfrs_loc_param_value>,
}

impl LocParam {
    pub fn addr(&self) -> LocAddr {
        let flags = self.loc_param.flags;
        let vlen = self.btf_type.vlen();

        // Get the const/offset index and check vlen to allow unwrapping the
        // values var-length array accesses below.
        let offset = match vlen {
            1 | 2 if flags & cbtf::BTF_LOC_PARAM_OFFSET == 0 => 0,
            2 | 3 if flags & cbtf::BTF_LOC_PARAM_OFFSET == cbtf::BTF_LOC_PARAM_OFFSET => 1,
            _ => return LocAddr::Unknown,
        };

        // Retrieve the const/offset value, if any.
        let mut val = None;
        if flags & (cbtf::BTF_LOC_PARAM_CONST | cbtf::BTF_LOC_PARAM_OFFSET) != 0 {
            val = Some(match vlen - offset {
                1 => self.values.get(offset as usize).unwrap().value as u64,
                2 => {
                    self.values.get(offset as usize).unwrap().value as u64
                        | (self.values.get(offset as usize + 1).unwrap().value as u64) << 32
                }
                _ => unreachable!(),
            });
        }

        // Construct the location information, strictly checking the definition
        // is genuine.
        if flags == cbtf::BTF_LOC_PARAM_CONST {
            LocAddr::UnsignedConst(val.unwrap())
        } else if flags == cbtf::BTF_LOC_PARAM_CONST | cbtf::BTF_LOC_PARAM_SIGNED {
            LocAddr::SignedConst(val.unwrap() as i64)
        } else if flags == cbtf::BTF_LOC_PARAM_CONST | cbtf::BTF_LOC_PARAM_ADDR {
            LocAddr::Address(val.unwrap())
        } else if (flags & !cbtf::BTF_LOC_PARAM_DEREF) == cbtf::BTF_LOC_PARAM_REG {
            match vlen {
                1 => LocAddr::Reg(self.values.first().unwrap().value),
                2 => LocAddr::Regs(
                    self.values.first().unwrap().value,
                    self.values.get(1).unwrap().value,
                ),
                _ => unreachable!(),
            }
        } else if (flags & !cbtf::BTF_LOC_PARAM_DEREF)
            == (cbtf::BTF_LOC_PARAM_REG | cbtf::BTF_LOC_PARAM_OFFSET)
        {
            LocAddr::RegOffset(self.values.first().unwrap().value, val.unwrap() as i128)
        } else {
            LocAddr::Unknown
        }
    }

    pub fn is_deref(&self) -> bool {
        self.loc_param.flags == cbtf::BTF_LOC_PARAM_REG | cbtf::BTF_LOC_PARAM_DEREF
            || self.loc_param.flags
                == cbtf::BTF_LOC_PARAM_REG | cbtf::BTF_LOC_PARAM_OFFSET | cbtf::BTF_LOC_PARAM_DEREF
    }
}

/// FIXME: doc & name
pub enum LocAddr {
    UnsignedConst(u64),
    SignedConst(i64),
    Address(u64),
    /// Check `LocParam::is_deref()` to know if the value should be dereferenced.
    Reg(u32),
    /// Check `LocParam::is_deref()` to know if the value should be dereferenced.
    Regs(u32, u32),
    /// Check `LocParam::is_deref()` to know if the value should be dereferenced.
    RegOffset(u32, i128),
    Unknown,
}

/// Rust representation for BTF type `BTF_KIND_LOC_PROTO`.
#[btf_type]
pub struct LocProto {
    btf_type: cbtf::btf_type,
    parameters: Vec<LocProtoParam>,
}

/// Rust representation of prototypes following a `BTF_KIND_LOC_PROTO`
/// definition.
/// FIXME: name
#[btf_type]
pub struct LocProtoParam {
    param: cbtf::btfrs_loc_proto_param,
}

impl BtfType for LocProtoParam {
    fn get_type_id(&self) -> Option<u32> {
        Some(self.param.r#type)
    }
}

/// Rust representation for BTF type `BTF_KIND_LOC_SEC`.
#[btf_type]
pub struct LocSec {
    btf_type: cbtf::btf_type,
    locations: Vec<Location>,
}

/// Rust representation for BTF type `BTF_KIND_LOC_SEC` entries.
/// FIXME: name
#[btf_type]
pub struct Location {
    location: cbtf::btf_loc,
}

impl BtfType for Location {
    fn get_type_id(&self) -> Option<u32> {
        Some(self.location.loc_proto)
    }
}
