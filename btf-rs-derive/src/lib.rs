use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::*;

#[proc_macro_attribute]
pub fn cbtf_type(_: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as Item);

    quote! {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, btf_rs_derive::CBtfType)]
        #[repr(C, packed)]
        #input
    }
    .into()
}

#[proc_macro_derive(CBtfType)]
pub fn cbtf_type_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let name = &ast.ident;

    let fields = match ast.data {
        Data::Struct(data) => match data.fields {
            Fields::Named(fields) => fields.named,
            _ => panic!("{name} is not a struct with named fields"),
        },
        _ => panic!("{name} is not a struct"),
    };

    let mut offset = 0;
    let bytes_fields = fields
        .iter()
        .map(|f| gen_cbtf_bytes_field(f.ident.as_ref().unwrap(), &f.ty, &mut offset));
    let reader_fields = fields
        .iter()
        .map(|f| gen_cbtf_reader_field(f.ident.as_ref().unwrap(), &f.ty));
    let writer_fields = fields
        .iter()
        .map(|f| gen_cbtf_write_inst(f.ident.as_ref().unwrap(), &f.ty));

    quote! {
        impl #name {
            pub(super) fn from_bytes(
                buf: &[u8],
                endianness: crate::cbtf::Endianness
            ) -> crate::Result<Self> {
                Ok(#name {
                    #( #bytes_fields )*
                })
            }

            pub(super) fn from_reader<R: std::io::Read>(
                reader: &mut R,
                endianness: crate::cbtf::Endianness,
            ) -> crate::Result<Self> {
                Ok(#name {
                    #( #reader_fields )*
                })
            }

            pub(crate) fn write(
                &self,
                w: &mut dyn std::io::Write,
                endianness: crate::cbtf::Endianness,
            ) -> crate::Result<()> {
                #( #writer_fields )*
                Ok(())
            }
        }
    }
    .into()
}

// Generate struct fields initialization using the input data from bytes.
// e.g. `u32 val: endianness.u32_from_bytes(&buf[0..4])?,`
fn gen_cbtf_bytes_field(
    ident: &Ident,
    r#type: &Type,
    offset: &mut usize,
) -> proc_macro2::TokenStream {
    let ty = match r#type {
        Type::Path(tp) => &tp.path,
        _ => panic!("Field {ident:?} is not a plain type"),
    };

    let from = *offset;
    match ty.to_token_stream().to_string().as_str() {
        "u8" => {
            *offset += 1;
            quote! {
                #ident: *buf.first().ok_or(Error::Format("Not enough bytes to read".to_string()))?,
            }
        }
        "u16" => {
            *offset += 2;
            quote! {
                #ident: endianness.u16_from_bytes(&buf[#from..])?,
            }
        }
        "u32" => {
            *offset += 4;
            quote! {
                #ident: endianness.u32_from_bytes(&buf[#from..])?,
            }
        }
        "i32" => {
            *offset += 4;
            quote! {
                #ident: endianness.i32_from_bytes(&buf[#from..])?,
            }
        }
        ty => panic!("Unsupported field type ({ty})"),
    }
}

// Generate struct fields initialization using the input data from a reader.
// e.g. `u32 val: endianness.u32_from_reader(reader)?,`
fn gen_cbtf_reader_field(ident: &Ident, r#type: &Type) -> proc_macro2::TokenStream {
    let ty = match r#type {
        Type::Path(tp) => &tp.path,
        _ => panic!("Field {ident:?} is not a plain type"),
    };

    match ty.to_token_stream().to_string().as_str() {
        "u8" => {
            quote! {
                #ident: {
                    let mut byte = [0u8];
                    reader.read_exact(&mut byte)?;
                    byte[0]
                },
            }
        }
        "u16" => quote! {
            #ident: endianness.u16_from_reader(reader)?,
        },
        "u32" => quote! {
            #ident: endianness.u32_from_reader(reader)?,
        },
        "i32" => quote! {
            #ident: endianness.i32_from_reader(reader)?,
        },
        ty => panic!("Unsupported field type ({ty})"),
    }
}
// Generate per-field write instructions.
fn gen_cbtf_write_inst(ident: &Ident, r#type: &Type) -> proc_macro2::TokenStream {
    let ty = match r#type {
        Type::Path(tp) => &tp.path,
        _ => panic!("Field {ident:?} is not a plain type"),
    };

    match ty.to_token_stream().to_string().as_str() {
        "u8" => quote! {
            w.write_u8(self.#ident)?;
        },
        "u16" => quote! {
            endianness.write_u16(w, self.#ident)?;
        },
        "u32" => quote! {
            endianness.write_u32(w, self.#ident)?;
        },
        "i32" => quote! {
            endianness.write_i32(w, self.#ident)?;
        },
        ty => panic!("Unsupported field type ({ty})"),
    }
}

#[proc_macro_attribute]
pub fn btf_type(_: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as Item);

    quote! {
        #[derive(Clone, Debug, Eq, PartialEq, btf_rs_derive::BtfType)]
        #input
    }
    .into()
}

#[proc_macro_derive(BtfType)]
pub fn btf_type_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let name = &ast.ident;

    let fields = match ast.data {
        Data::Struct(data) => match data.fields {
            Fields::Named(fields) => fields.named,
            _ => panic!("{name} is not a struct with named fields"),
        },
        _ => panic!("{name} is not a struct"),
    };

    // Special case when `btf_type` is available, as it is already read by the
    // caller of the `Type` constructors.
    let btf_type = fields
        .iter()
        .any(|f| f.ident.as_ref().is_some_and(|ident| ident == "btf_type"))
        .then(|| quote! { btf_type: crate::cbtf::btf_type, });

    let reader_fields = fields
        .iter()
        .map(|f| gen_btf_reader_field(f.ident.as_ref().unwrap(), &f.ty));
    let writer_fields = fields
        .iter()
        .map(|f| gen_btf_writer_field(f.ident.as_ref().unwrap(), &f.ty));

    quote! {
        impl #name {
            pub(super) fn from_reader<R: std::io::Read>(
                reader: &mut R,
                endianness: crate::cbtf::Endianness,
                #btf_type
            ) -> crate::Result<Self> {
                Ok(#name {
                    #( #reader_fields )*
                })
            }

            pub(super) fn write(
                &self,
                writer: &mut dyn std::io::Write,
                endianness: crate::cbtf::Endianness,
            ) -> crate::Result<()> {
                #( #writer_fields )*
                Ok(())
            }
        }
    }
    .into()
}

// Generate inner btf::Type struct fields initialization using the input data
// from a reader.
fn gen_btf_reader_field(ident: &Ident, r#type: &Type) -> proc_macro2::TokenStream {
    // Special case `btf_type`.
    if ident == "btf_type" {
        return quote! { btf_type, };
    }

    let ty = match r#type {
        Type::Path(tp) => &tp.path,
        _ => panic!("{ident:?} is not a plain type"),
    };

    // Handle vectors.
    if let Some(last) = ty.segments.last() {
        if last.ident == "Vec" {
            if let PathArguments::AngleBracketed(args) = &last.arguments {
                for arg in args.args.iter() {
                    if let GenericArgument::Type(ty) = arg {
                        return quote! {
                            #ident: {
                                let mut elements = Vec::new();
                                for _ in 0..btf_type.vlen() {
                                    elements.push(#ty::from_reader(reader, endianness)?);
                                }
                                elements
                            }
                        };
                    }
                }
            }
        }
    }

    quote! {
        #ident: #ty::from_reader(reader, endianness)?,
    }
}

// Generate inner btf::Type struct field writers.
fn gen_btf_writer_field(ident: &Ident, r#type: &Type) -> proc_macro2::TokenStream {
    let ty = match r#type {
        Type::Path(tp) => &tp.path,
        _ => panic!("{ident:?} is not a plain type"),
    };

    // Handle vectors.
    if let Some(last) = ty.segments.last() {
        if last.ident == "Vec" {
            if let PathArguments::AngleBracketed(args) = &last.arguments {
                for arg in args.args.iter() {
                    if matches!(arg, GenericArgument::Type(_)) {
                        return quote! {
                            self.#ident.iter().try_for_each(|elem| elem.write(writer, endianness))?;
                        };
                    }
                }
            }
        }
    }

    quote! {
        self.#ident.write(writer, endianness)?;
    }
}
