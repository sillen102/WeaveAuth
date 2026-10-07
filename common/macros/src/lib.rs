#![forbid(unsafe_code)]
#![deny(
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
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
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
        let mut details = None;
        if input.peek(syn::token::Comma) {
            input.parse::<syn::token::Comma>()?;
            let key: syn::Ident = input.parse()?;
            if key != "details" {
                return Err(syn::Error::new(key.span(), "expected `details`"));
            }
            input.parse::<syn::token::Eq>()?;
            details = Some(input.parse::<LitStr>()?);
        }
        Ok(ErrorResponseArgs { status, details })
    }
}

struct VariantInfo {
    ident: Ident,
    fields: Fields,
    status: Expr,
    details: Option<LitStr>,
}

/// Derive `IntoResponse` for an error enum.
///
/// Each variant must be annotated with `#[error_response(StatusCode::NOT_FOUND)]`. The
/// response body's `details` is the `details = "..."` argument when given, else the variant's
/// `Display` text. A variant that carries data must give `details`: its `Display` text may
/// be built from a cause, which never reaches a response.
///
/// The derived `IntoResponse` impl maps each variant to its HTTP status code and
/// returns a JSON body using `ErrorResponse`, with a `reason` field set to the enum
/// variant's name (e.g. `"NotFound"`), so callers can distinguish variants that share a status code.
///
/// By default the error response type is `::common::model::error_response::ErrorResponse`. Override with the
/// `#[error_response_type(path::to::MyErrorResponse)]` attribute on the enum. The error response type
/// must have a `fn new(impl Into<String>, impl Into<String>) -> Self` constructor taking
/// `(details, reason)` and implement `Serialize`.
///
/// # Example
///
/// ```
/// # use thiserror::Error;
/// # use axum::http::StatusCode;
/// # use serde::Serialize;
/// #
/// # #[derive(Serialize)]
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
#[proc_macro_derive(ErrorResponses, attributes(error_response, error_response_type))]
pub fn derive_error_responses(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(&input) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn parse_error_response_type(attrs: &[syn::Attribute]) -> syn::Result<syn::Path> {
    attrs
        .iter()
        .find(|a| a.path().is_ident("error_response_type"))
        .map(|a| a.parse_args::<syn::Path>())
        .transpose()
        .map(|path| {
            path.unwrap_or_else(|| {
                syn::parse_quote!(::common::model::error_response::ErrorResponse)
            })
        })
}

fn expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;

    let syn::Data::Enum(data_enum) = &input.data else {
        return Err(syn::Error::new_spanned(
            input,
            "ErrorResponses can only be derived for enums",
        ));
    };

    let error_type = parse_error_response_type(&input.attrs)?;

    let mut variants = Vec::new();

    for variant in &data_enum.variants {
        for attr in &variant.attrs {
            if !attr.path().is_ident("error_response") {
                continue;
            }
            let args = attr.parse_args::<ErrorResponseArgs>()?;
            if args.details.is_none() && !matches!(variant.fields, Fields::Unit) {
                return Err(syn::Error::new_spanned(
                    attr,
                    "a variant that carries data needs `details = \"...\"`, so its cause stays out of the response",
                ));
            }
            variants.push(VariantInfo {
                ident: variant.ident.clone(),
                fields: variant.fields.clone(),
                status: args.status,
                details: args.details,
            });
        }
    }

    let into_response = generate_into_response(name, &variants, &error_type);
    Ok(into_response)
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

    let details_arms = variants.iter().map(|v| {
        let ident = &v.ident;
        match (&v.details, &v.fields) {
            (Some(details), Fields::Unit) => quote!(Self::#ident => #details.to_string(),),
            (Some(details), Fields::Unnamed(_)) => {
                quote!(Self::#ident(..) => #details.to_string(),)
            }
            (Some(details), Fields::Named(_)) => {
                quote!(Self::#ident { .. } => #details.to_string(),)
            }
            (None, _) => quote!(Self::#ident => self.to_string(),),
        }
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
                let details = match &self {
                    #(#details_arms)*
                };
                let body = #error_type::new(details, reason);
                (status, ::axum::Json(body)).into_response()
            }
        }
    }
}
