#![deny(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_in_result,
    clippy::unnecessary_unwrap,
    clippy::unused_async,
    clippy::redundant_clone,
    clippy::todo,
    clippy::unimplemented
)]

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{DeriveInput, Expr, Fields, Ident, LitStr, parse_macro_input};

struct ErrorResponseArgs {
    status: Expr,
    details: Option<LitStr>,
}

impl syn::parse::Parse for ErrorResponseArgs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let status = input.parse()?;
        let details = if input.peek(syn::token::Comma) {
            input.parse::<syn::token::Comma>()?;
            let key: syn::Ident = input.parse()?;
            if key != "details" {
                return Err(syn::Error::new(key.span(), "expected `details`"));
            }
            input.parse::<syn::token::Eq>()?;
            Some(input.parse()?)
        } else {
            None
        };
        Ok(ErrorResponseArgs { status, details })
    }
}

struct VariantInfo {
    ident: Ident,
    fields: Fields,
    status: Expr,
    details: Option<LitStr>,
}

/// Derive `IntoResponse` and `OperationOutput` for an error enum.
///
/// Each variant must be annotated with `#[error_response(StatusCode::NOT_FOUND)]`.
/// Optional details can be added: `#[error_response(StatusCode::NOT_FOUND, details = "Not found")]`.
/// If no details are provided, the status code's canonical reason phrase is used. This text
/// becomes both the OpenAPI response description and the `details` field of the response body.
///
/// The derived `IntoResponse` impl maps each variant to its HTTP status code and
/// returns a JSON body using `ErrorResponse`.
///
/// The derived `OperationOutput` impl provides `inferred_responses` that maps each
/// variant to its status code with the details, enabling automatic OpenAPI response
/// documentation when the error type appears in a handler return type like `Result<T, MyError>`.
///
/// OpenAPI only allows one response object per status code. When multiple variants share the
/// same `#[error_response(StatusCode::X)]`, they are merged into a single response for that
/// code: the top-level description joins every variant's details, and each variant gets its
/// own named example (keyed by variant name) under the response body's `application/json`
/// content, so each distinct reason is still visible in the generated docs.
///
/// The derived `IntoResponse` impl also sets a `reason` field on the response body to the enum
/// variant's name (e.g. `"NotFound"`), so callers can distinguish variants that share a status code.
///
/// By default the error response type is `::common::responses::ErrorResponse`. Override with the
/// `#[error_response_type(path::to::MyErrorResponse)]` attribute on the enum. The error response type
/// must implement `schemars::JsonSchema` and have a
/// `fn new(impl Into<String>, impl Into<String>) -> Self` constructor taking `(details, reason)`.
///
/// Crates that don't use `aide` for OpenAPI generation (no `TransformOperation`/`_doc()`
/// companion functions) can put `#[error_response_no_openapi]` on the enum to derive only
/// `IntoResponse`, skipping the `aide::operation::OperationOutput` impl entirely -- this also
/// drops the `schemars::JsonSchema` requirement on the error response type, since nothing
/// generates a JSON schema for it.
///
/// # Example
///
/// ```
/// # use thiserror::Error;
/// # use axum::http::StatusCode;
/// # use serde::Serialize;
/// # use schemars::JsonSchema;
/// # use aide::OperationOutput;
/// #
/// # #[derive(Serialize, JsonSchema)]
/// # pub struct MyErrorResponse {
/// #     message: String,
/// #     reason: String,
/// # }
/// # impl MyErrorResponse {
/// #     pub fn new(message: impl Into<String>, reason: impl Into<String>) -> Self {
/// #         Self { message: message.into(), reason: reason.into() }
/// #     }
/// # }
/// use common_macros::ErrorResponses;
///
/// #[derive(Debug, Error, ErrorResponses)]
/// #[error_response_type(MyErrorResponse)]
/// pub enum MyError {
///     #[error("Entity not found")]
///     #[error_response(StatusCode::NOT_FOUND, details = "The requested entity was not found")]
///     NotFound,
///     #[error("Internal error")]
///     #[error_response(StatusCode::INTERNAL_SERVER_ERROR)]
///     InternalError,
/// }
/// ```
#[proc_macro_derive(
    ErrorResponses,
    attributes(error_response, error_response_type, error_response_no_openapi)
)]
pub fn derive_error_responses(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(&input) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn parse_error_response_type(attrs: &[syn::Attribute]) -> syn::Path {
    attrs
        .iter()
        .find(|a| a.path().is_ident("error_response_type"))
        .and_then(|a| a.parse_args::<syn::Path>().ok())
        .unwrap_or_else(|| syn::parse_quote!(::common::responses::ErrorResponse))
}

fn expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;

    let syn::Data::Enum(data_enum) = &input.data else {
        return Err(syn::Error::new_spanned(
            input,
            "ErrorResponses can only be derived for enums",
        ));
    };

    let error_type = parse_error_response_type(&input.attrs);
    let skip_openapi = input
        .attrs
        .iter()
        .any(|a| a.path().is_ident("error_response_no_openapi"));

    let mut variants = Vec::new();

    for variant in &data_enum.variants {
        for attr in &variant.attrs {
            if !attr.path().is_ident("error_response") {
                continue;
            }
            let args = attr.parse_args::<ErrorResponseArgs>()?;
            variants.push(VariantInfo {
                ident: variant.ident.clone(),
                fields: variant.fields.clone(),
                status: args.status,
                details: args.details,
            });
        }
    }

    let into_response = generate_into_response(name, &variants, &error_type);
    let operation_output = if skip_openapi {
        quote!()
    } else {
        generate_operation_output(name, &variants, &error_type)
    };

    Ok(quote! {
        #into_response
        #operation_output
    })
}

fn generate_into_response(
    name: &Ident,
    variants: &[VariantInfo],
    error_type: &syn::Path,
) -> TokenStream2 {
    let status_arms = variants.iter().map(|v| {
        let ident = &v.ident;
        let status = &v.status;
        let pattern = match &v.fields {
            Fields::Unit => quote!(Self::#ident),
            Fields::Unnamed(_) => quote!(Self::#ident(..)),
            Fields::Named(_) => quote!(Self::#ident { .. }),
        };
        quote!(#pattern => #status,)
    });
    let reason_arms = variants.iter().map(|v| {
        let ident = &v.ident;
        let ident_str = ident.to_string();
        let pattern = match &v.fields {
            Fields::Unit => quote!(Self::#ident),
            Fields::Unnamed(_) => quote!(Self::#ident(..)),
            Fields::Named(_) => quote!(Self::#ident { .. }),
        };
        quote!(#pattern => #ident_str,)
    });

    quote! {
        impl ::axum::response::IntoResponse for #name {
            fn into_response(self) -> ::axum::response::Response {
                let status = match &self {
                    #(#status_arms)*
                };
                let reason = match &self {
                    #(#reason_arms)*
                };
                let body = #error_type::new(self.to_string(), reason);
                (status, ::axum::Json(body)).into_response()
            }
        }
    }
}

/// A variant with its status-group key and resolved (runtime) description expression precomputed,
/// so grouping and codegen below never need to index back into `variants` by position.
struct ResolvedVariant<'a> {
    variant: &'a VariantInfo,
    description: TokenStream2,
    status_key: String,
}

fn generate_operation_output(
    name: &Ident,
    variants: &[VariantInfo],
    error_type: &syn::Path,
) -> TokenStream2 {
    // Resolve each variant's details as an expression evaluating to a `String` at doc-generation
    // time: the explicit `details`, or else the status code's canonical reason phrase.
    let resolved: Vec<ResolvedVariant> = variants
        .iter()
        .map(|v| {
            let status = &v.status;
            let description = match &v.details {
                Some(details) => quote!(#details.to_string()),
                None => quote!(#status.canonical_reason().unwrap_or("Error").to_string()),
            };
            let status_key = quote!(#status).to_string();
            ResolvedVariant {
                variant: v,
                description,
                status_key,
            }
        })
        .collect();

    // Group variants by their (textual) status expression, preserving first-seen order, since
    // OpenAPI allows only one response object per status code.
    let mut groups: Vec<(String, Vec<&ResolvedVariant>)> = Vec::new();
    for r in &resolved {
        match groups.iter_mut().find(|(key, _)| *key == r.status_key) {
            Some((_, members)) => members.push(r),
            None => groups.push((r.status_key.clone(), vec![r])),
        }
    }

    let response_entries = groups.iter().map(|(_key, members)| {
        let Some(first) = members.first() else {
            return quote!();
        };
        let status = &first.variant.status;

        let group_descriptions: Vec<&TokenStream2> =
            members.iter().map(|m| &m.description).collect();

        let top_description = match (members.len(), group_descriptions.first()) {
            (1, Some(d)) => quote!(#d),
            _ => quote!([#(#group_descriptions),*].join("; ")),
        };

        let example_inserts = members.iter().map(|m| {
            let ident_str = m.variant.ident.to_string();
            let desc = &m.description;
            quote! {
                examples.insert(
                    #ident_str.to_string(),
                    ::aide::openapi::ReferenceOr::Item({
                        let description = #desc;
                        ::aide::openapi::Example {
                            summary: ::std::option::Option::Some(description.clone()),
                            value: ::serde_json::to_value(&#error_type::new(description, #ident_str)).ok(),
                            ..::std::default::Default::default()
                        }
                    }),
                );
            }
        });

        quote! {
            (
                Some(::aide::openapi::StatusCode::Code(#status.as_u16())),
                ::aide::openapi::Response {
                    description: #top_description,
                    content: {
                        let mut content = ::aide::openapi::Response::default().content;
                        let mut examples = ::aide::openapi::MediaType::default().examples;
                        #(#example_inserts)*
                        content.insert(
                            "application/json".to_string(),
                            ::aide::openapi::MediaType {
                                schema: ::std::option::Option::Some(::aide::openapi::SchemaObject {
                                    json_schema: ctx.schema.subschema_for::<#error_type>(),
                                    example: None,
                                    external_docs: None,
                                }),
                                examples,
                                ..::std::default::Default::default()
                            },
                        );
                        content
                    },
                    ..::std::default::Default::default()
                },
            )
        }
    });

    quote! {
        impl ::aide::operation::OperationOutput for #name {
            type Inner = #error_type;

            fn inferred_responses(
                ctx: &mut ::aide::generate::GenContext,
                _operation: &mut ::aide::openapi::Operation,
            ) -> ::std::vec::Vec<(::std::option::Option<::aide::openapi::StatusCode>, ::aide::openapi::Response)> {
                ::std::vec![
                    #(#response_entries),*
                ]
            }
        }
    }
}
