use crate::ParseError;

/// Embedded data with its original marker spelling retained for round trips.
#[derive(Debug, Eq, PartialEq)]
pub struct File {
    name: String,
    marker: String,
    data: String,
}

impl File {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn data(&self) -> &str {
        &self.data
    }
}

/// A UTF-8 txtar container. Duplicate names retain archive order.
#[derive(Debug, Eq, PartialEq)]
pub struct Archive {
    script: String,
    files: Vec<File>,
}

impl Archive {
    /// Parses LF text without normalizing file bytes. CRLF is rejected per the
    /// implementation decision for issue #210 recorded in spec 17.
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let mut archive = Self {
            script: String::new(),
            files: Vec::new(),
        };
        for (offset, line) in input.split_inclusive('\n').enumerate() {
            if line.ends_with("\r\n") {
                return Err(ParseError::new(
                    offset.saturating_add(1),
                    "CRLF line endings are not supported; preserve the LF corpus",
                ));
            }
            let body = line.strip_suffix('\n').unwrap_or(line);
            if let Some(name) = body.strip_prefix("-- ").and_then(|s| s.strip_suffix(" --")) {
                archive.files.push(File {
                    name: name.trim().to_owned(),
                    marker: line.to_owned(),
                    data: String::new(),
                });
            } else if let Some(file) = archive.files.last_mut() {
                file.data.push_str(line);
            } else {
                archive.script.push_str(line);
            }
        }
        Ok(archive)
    }

    pub fn script(&self) -> &str {
        &self.script
    }
    pub fn files(&self) -> &[File] {
        &self.files
    }

    /// Original flags, before runtime environment expansion. Empty shebangs
    /// return an empty vector. Quoting is deliberately not shell parsing here.
    pub fn flags(&self) -> Vec<&str> {
        self.script
            .split('\n')
            .next()
            .and_then(|line| line.strip_prefix("#!"))
            .map(|flags| {
                flags
                    .trim()
                    .split(' ')
                    .filter(|flag| !flag.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Reconstructs the unmodified archive byte for byte, including missing
    /// final newlines and marker whitespace. Update-mode rewriting is separate.
    pub fn serialize(&self) -> String {
        let mut output = self.script.clone();
        for file in &self.files {
            output.push_str(&file.marker);
            output.push_str(&file.data);
        }
        output
    }
}
