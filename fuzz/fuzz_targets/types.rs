// Fuzz Type. Only use from_bytes as it internally also covers from_reader.
//
// Use `cargo fuzz run btf_types`.
#![no_main]

use btf_rs::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let r#type = match fuzz::btf::Type::from_bytes(data) {
        Ok(r#type) => r#type,
        _ => return,
    };

    if let Some(bt) = r#type.as_btf_type() {
        let _ = bt.get_name_offset();
        let _ = bt.get_type_id();
    }

    match &*r#type {
        Type::Void => (),
        Type::Int(int) => {
            let _ = int.is_signed();
            let _ = int.is_char();
            let _ = int.is_bool();
            let _ = int.size();
        }
        Type::Ptr(_) => (),
        Type::Array(array) => _ = array.len(),
        Type::Struct(r#struct) | Type::Union(r#struct) => {
            let _ = r#struct.size();
            let _ = r#struct.members.len();

            for member in &r#struct.members {
                let _ = member.bit_offset();
                let _ = member.bitfield_size();

                let _ = member.get_name_offset();
                let _ = member.get_type_id();
            }
        }
        Type::Enum(r#enum) => {
            let _ = r#enum.is_signed();
            let _ = r#enum.size();
            let _ = r#enum.members.len();

            for member in &r#enum.members {
                let _ = member.val();

                let _ = member.get_name_offset();
                let _ = member.get_type_id();
            }
        }
        Type::Fwd(fwd) => {
            let _ = fwd.is_struct();
            let _ = fwd.is_union();
        }
        Type::Typedef(_) => (),
        Type::Volatile(_) | Type::Const(_) | Type::Restrict(_) => (),
        Type::Func(func) => {
            let _ = func.is_static();
            let _ = func.is_global();
            let _ = func.is_extern();
        }
        Type::FuncProto(func_proto) => {
            let _ = func_proto.return_type_id();

            for param in &func_proto.parameters {
                let _ = param.is_variadic();

                let _ = param.get_name_offset();
                let _ = param.get_type_id();
            }
        }
        Type::Var(var) => {
            let _ = var.is_static();
            let _ = var.is_global();
            let _ = var.is_extern();
        }
        Type::Datasec(datasec) => {
            let _ = datasec.size();

            for var in &datasec.variables {
                let _ = var.offset();
                let _ = var.size();

                let _ = var.get_name_offset();
                let _ = var.get_type_id();
            }
        }
        Type::Float(float) => _ = float.size(),
        Type::DeclTag(decl_tag) => {
            let _ = decl_tag.component_index();
            let _ = decl_tag.is_attribute();
        }
        Type::TypeTag(type_tag) => _ = type_tag.is_attribute(),
        Type::Enum64(enum64) => {
            let _ = r#enum64.is_signed();
            let _ = r#enum64.size();
            let _ = r#enum64.members.len();

            for member in &r#enum64.members {
                let _ = member.val();

                let _ = member.get_name_offset();
                let _ = member.get_type_id();
            }
        }
        _ => panic!("Not all types are covered"),
    }
});
