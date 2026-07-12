//! `lgtm compile` command implementations.

use std::io::{self, Write};

use thiserror::Error;

use crate::policy::{self, Rule};

mod packet;
mod plan;

pub use packet::{CompiledInstructions, compile_selected};
pub use plan::{ENFORCEMENT_PLAN_SCHEMA_JSON, EnforcementPlan};

#[cfg(test)]
mod instruction_tests;

/// Failure modes of the `compile --validate` path.
///
/// Distinguishes a registry that fails validation from an I/O failure while
/// writing the summary, so the reported message reflects the real cause instead
/// of misattributing a write error to the schema.
#[derive(Debug, Error)]
pub enum CompileError {
    /// The embedded registry failed to load or validate.
    #[error(transparent)]
    Registry(#[from] policy::RegistryError),
    /// Writing the summary table to the output failed.
    #[error("failed to write summary: {0}")]
    Write(io::Error),
}

/// Load and validate the embedded registry, then print a summary table.
///
/// Returns the validated rules on success. On failure the caller reports the
/// error and exits non-zero.
pub fn validate_registry(writer: &mut impl Write) -> Result<Vec<Rule>, CompileError> {
    let rules = policy::load_embedded_registry()?;
    write_summary_table(writer, &rules).map_err(CompileError::Write)?;
    Ok(rules)
}

/// Print a fixed-width summary table of the registry to the given writer.
fn write_summary_table(writer: &mut impl Write, rules: &[Rule]) -> io::Result<()> {
    let id_width = column_width(rules.iter().map(|rule| rule.id.len()), "ID".len());
    let level_width = column_width(
        rules.iter().map(|rule| rule.level.to_string().len()),
        "LEVEL".len(),
    );
    let severity_width = column_width(
        rules.iter().map(|rule| rule.severity.to_string().len()),
        "SEVERITY".len(),
    );
    let category_width = column_width(
        rules.iter().map(|rule| rule.category.to_string().len()),
        "CATEGORY".len(),
    );
    let mode_width = column_width(
        rules
            .iter()
            .map(|rule| rule.enforcement.mode.to_string().len()),
        "ENFORCEMENT".len(),
    );

    writeln!(
        writer,
        "{:<id_width$}  {:<level_width$}  {:<severity_width$}  {:<category_width$}  {:<mode_width$}",
        "ID", "LEVEL", "SEVERITY", "CATEGORY", "ENFORCEMENT"
    )?;
    for rule in rules {
        writeln!(
            writer,
            "{:<id_width$}  {:<level_width$}  {:<severity_width$}  {:<category_width$}  {:<mode_width$}",
            rule.id,
            rule.level.to_string(),
            rule.severity.to_string(),
            rule.category.to_string(),
            rule.enforcement.mode.to_string(),
        )?;
    }
    writeln!(writer, "\n{} rules validated.", rules.len())?;
    Ok(())
}

/// Widest cell in a column, floored at the header width.
fn column_width(cell_lengths: impl Iterator<Item = usize>, header: usize) -> usize {
    cell_lengths.max().unwrap_or(0).max(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_registry_writes_table_with_all_rule_ids() {
        let mut buffer = Vec::new();
        let rules = validate_registry(&mut buffer).expect("embedded registry must validate");
        let output = String::from_utf8(buffer).expect("summary must be valid UTF-8");

        assert!(output.contains("ID"));
        assert!(output.contains("ENFORCEMENT"));
        for rule in &rules {
            assert!(
                output.contains(&rule.id),
                "summary must list rule id {}",
                rule.id
            );
        }
        assert!(output.contains("22 rules validated."));
    }
}
