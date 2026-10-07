#[test]
fn a_variant_with_data_must_give_details() {
    trybuild::TestCases::new().compile_fail("tests/ui/data_without_details.rs");
}
