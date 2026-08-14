//! Content fingerprints for generated rule documents across template releases.

/// One release-specific digest for a generated rule document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TemplateDigest {
    pub(super) release: &'static str,
    pub(super) path: &'static str,
    pub(super) sha256: &'static str,
}

/// Digests for every rule document shipped by the v0.5.0 and v0.6.0 releases.
pub(super) const LEGACY_TEMPLATE_DIGESTS: &[TemplateDigest] = &[
    TemplateDigest {
        release: "v0.5.0",
        path: "standards.md",
        sha256: "95808e980e62717bf7375c14a788ccd997ba4e9acaa21732c8dc5eca27b6c374",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "c-cpp.md",
        sha256: "c97be46d9f6be83c016971835b36624a5910f73c459d4c235558c69a8c08c657",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "config.md",
        sha256: "c5b85c812f67ae840e5180fe17b6d4d5345def16fe9b5f8b20fec60826463528",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "csharp.md",
        sha256: "83f3216367c47adea22320bb4d7a7573307705d8f04be5f99c8748c0a82273c3",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "go.md",
        sha256: "ab3d95bbdc89dbb157c9c4763e1656ba306e88a5ddb9312803e7c16cafffe03a",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "infrastructure.md",
        sha256: "4c4052c8dd07f7374952546b3c7cf09dd8db461d8ef9ba3deb44766f35ee6fdf",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "jvm.md",
        sha256: "e2dc81e257fbbd9d5398983e99cf6a7141b64806de179e20a12f7ac921aff262",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "patterns/core.md",
        sha256: "9e683b33d4a4a9b4e7a18ca22120f0251efb6b8d1bf374f946ac27574d93d8fd",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "patterns/go.md",
        sha256: "f258264299dff9aa091c05efe47eff9e1acb362854569e833bfb61a352564e3a",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "patterns/python.md",
        sha256: "f0739e242ea8f20624373680235e452f43fe6b1860eeb44116b0bf95ea1d9502",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "patterns/react.md",
        sha256: "772711408f2122eafb5bb82e9e16d915e17506b7d9d920afb1e6009f4b0d0ad7",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "patterns/rust.md",
        sha256: "ad4c0869d1bc9f13a49c65d8b9362fa64cd729703c20aedcff09624b5d2b5b4f",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "patterns/sql.md",
        sha256: "a7a92c7b1a85c84364a3b787011abf4af8da0333fd17db1450995e80e7ab3aa5",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "patterns/testing.md",
        sha256: "0b366a2455c01188bb17c69067dce8a22dbc5273eca504c1047869b30fcce6ce",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "patterns/typescript.md",
        sha256: "e46557daa4ae235affbbdcb5d7a136433d98f1cc9cbba2909e5964b11eef62fd",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "python.md",
        sha256: "a80c2e77e1cd760385004bacf65fcc1fd044ada2c59033035604168fcfc01e32",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "react.md",
        sha256: "11f306003ff7201f9ce611528de4de3e87e0aa530227094a9254356a7240573e",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "rust.md",
        sha256: "78daa0590f22a7007017e6fb7b31d89d50c30ecf3813fa60d9fa24ee72a4e6c5",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "shell.md",
        sha256: "3c77bf73bb5d4890d8e84d7001bdd45ba3ea75b999238e3c86f2389e20409078",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "sql.md",
        sha256: "ca2b09ec6dadd89124ca08e59d27d98aed60979449c387d6d09a725edbd07e4f",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "testing.md",
        sha256: "5c4b17ce8e22a5ce1f8b526ca0cefeeee133a8a536b73c69fe6732ebcf17ba8b",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "typescript.md",
        sha256: "48b040c6b9e590dfecb7d4b9c1b929b148740e95bbff583774d21dc0058e2ce9",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "web-ui.md",
        sha256: "728cb6c2c8653e1d2c922c9aaede03502996c650394069355ff5288dc9149c79",
    },
    TemplateDigest {
        release: "v0.5.0",
        path: "AGENTS.md",
        sha256: "42a14d9fa7763677aac1ff3a5852d8009688711772213e98a5cf9125498c6f18",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "standards.md",
        sha256: "95808e980e62717bf7375c14a788ccd997ba4e9acaa21732c8dc5eca27b6c374",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "c-cpp.md",
        sha256: "c97be46d9f6be83c016971835b36624a5910f73c459d4c235558c69a8c08c657",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "config.md",
        sha256: "c5b85c812f67ae840e5180fe17b6d4d5345def16fe9b5f8b20fec60826463528",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "csharp.md",
        sha256: "83f3216367c47adea22320bb4d7a7573307705d8f04be5f99c8748c0a82273c3",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "go.md",
        sha256: "ab3d95bbdc89dbb157c9c4763e1656ba306e88a5ddb9312803e7c16cafffe03a",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "infrastructure.md",
        sha256: "4c4052c8dd07f7374952546b3c7cf09dd8db461d8ef9ba3deb44766f35ee6fdf",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "jvm.md",
        sha256: "e2dc81e257fbbd9d5398983e99cf6a7141b64806de179e20a12f7ac921aff262",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "patterns/core.md",
        sha256: "9e683b33d4a4a9b4e7a18ca22120f0251efb6b8d1bf374f946ac27574d93d8fd",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "patterns/go.md",
        sha256: "f258264299dff9aa091c05efe47eff9e1acb362854569e833bfb61a352564e3a",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "patterns/python.md",
        sha256: "f0739e242ea8f20624373680235e452f43fe6b1860eeb44116b0bf95ea1d9502",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "patterns/react.md",
        sha256: "772711408f2122eafb5bb82e9e16d915e17506b7d9d920afb1e6009f4b0d0ad7",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "patterns/rust.md",
        sha256: "ad4c0869d1bc9f13a49c65d8b9362fa64cd729703c20aedcff09624b5d2b5b4f",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "patterns/sql.md",
        sha256: "a7a92c7b1a85c84364a3b787011abf4af8da0333fd17db1450995e80e7ab3aa5",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "patterns/testing.md",
        sha256: "0b366a2455c01188bb17c69067dce8a22dbc5273eca504c1047869b30fcce6ce",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "patterns/typescript.md",
        sha256: "e46557daa4ae235affbbdcb5d7a136433d98f1cc9cbba2909e5964b11eef62fd",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "python.md",
        sha256: "a80c2e77e1cd760385004bacf65fcc1fd044ada2c59033035604168fcfc01e32",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "react.md",
        sha256: "11f306003ff7201f9ce611528de4de3e87e0aa530227094a9254356a7240573e",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "rust.md",
        sha256: "78daa0590f22a7007017e6fb7b31d89d50c30ecf3813fa60d9fa24ee72a4e6c5",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "shell.md",
        sha256: "3c77bf73bb5d4890d8e84d7001bdd45ba3ea75b999238e3c86f2389e20409078",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "sql.md",
        sha256: "ca2b09ec6dadd89124ca08e59d27d98aed60979449c387d6d09a725edbd07e4f",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "testing.md",
        sha256: "5c4b17ce8e22a5ce1f8b526ca0cefeeee133a8a536b73c69fe6732ebcf17ba8b",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "typescript.md",
        sha256: "48b040c6b9e590dfecb7d4b9c1b929b148740e95bbff583774d21dc0058e2ce9",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "web-ui.md",
        sha256: "728cb6c2c8653e1d2c922c9aaede03502996c650394069355ff5288dc9149c79",
    },
    TemplateDigest {
        release: "v0.6.0",
        path: "AGENTS.md",
        sha256: "42a14d9fa7763677aac1ff3a5852d8009688711772213e98a5cf9125498c6f18",
    },
];

/// Digests for the currently embedded templates, used to keep this ledger in sync.
#[cfg(test)]
pub(super) const CURRENT_TEMPLATE_DIGESTS: &[TemplateDigest] = &[
    TemplateDigest {
        release: "current",
        path: "standards.md",
        sha256: "009c709b343c43080d02382943c0914eb34fefec64f0dfbc2186fe1d2972bf78",
    },
    TemplateDigest {
        release: "current",
        path: "c-cpp.md",
        sha256: "6addfba1ebb854acb9a1b77605cfb3410147d33c257667ca46f9e5474ed8bf2b",
    },
    TemplateDigest {
        release: "current",
        path: "anti-slop.md",
        sha256: "a03d97e0e9acaea127576f6bdce40cef6e6b3912c0ca6bfa98d660621c350122",
    },
    TemplateDigest {
        release: "current",
        path: "code-organization.md",
        sha256: "42c41fafcf2015c85cfcd19c4320acd31c4345795278c54cdf87936644c8d955",
    },
    TemplateDigest {
        release: "current",
        path: "config.md",
        sha256: "b42379e20cc83bc4162565c5aab2c5571bfba979c8c7f1cf64018d22988a5b59",
    },
    TemplateDigest {
        release: "current",
        path: "csharp.md",
        sha256: "d6c759e95b09a0814fda22ce9d4b31912fc587228c113bdd6f83b634a2cf7e4f",
    },
    TemplateDigest {
        release: "current",
        path: "error-handling.md",
        sha256: "823aef7c16baac8168ee32d5918cb9d79bcde1f784bc986c103e6a2e03287d19",
    },
    TemplateDigest {
        release: "current",
        path: "go.md",
        sha256: "fb5ff86f5242223f6403c078cbf5c605d91b09c2ff247f4625a1026c3364317e",
    },
    TemplateDigest {
        release: "current",
        path: "infrastructure.md",
        sha256: "ad3510989b23286f33fd9aa77ee2f61d127ade352759d6cc50cb2e3c8336f936",
    },
    TemplateDigest {
        release: "current",
        path: "jvm.md",
        sha256: "4ccb87e5e50c07a9b4cd9e9fd3924bd2531bd7097bb5e46bfc0589b356a4d04e",
    },
    TemplateDigest {
        release: "current",
        path: "naming.md",
        sha256: "90a01b52aa0061aaa08270171c9f66aabab27e2ed87b7ce942aef51f05cf645e",
    },
    TemplateDigest {
        release: "current",
        path: "observability.md",
        sha256: "d1bbf443d0320cc1636bc33c620461418f141d4e9c63bfe548e533fe2a538839",
    },
    TemplateDigest {
        release: "current",
        path: "performance.md",
        sha256: "da4e7611b528f5c905a3d4978c39b835584d00c360828dacd9db10b1445b76fd",
    },
    TemplateDigest {
        release: "current",
        path: "python.md",
        sha256: "fd87b12f5af2568d53c387153f8a88f108974567fd2f3fe06772f1d7f2df3410",
    },
    TemplateDigest {
        release: "current",
        path: "react.md",
        sha256: "e87aa7dc5c4913b2e1a59fd028dad224ff249db2e671cb320f2716a92bbdf8c6",
    },
    TemplateDigest {
        release: "current",
        path: "rust.md",
        sha256: "9acaec62929a35b6b9694623223e155383b1620e3073a2b603eb57745fcf97bb",
    },
    TemplateDigest {
        release: "current",
        path: "security.md",
        sha256: "ab983b3ce007a7cd26524cf09f5e518651dd846aa99e0a7522857fb3991dfc12",
    },
    TemplateDigest {
        release: "current",
        path: "shell.md",
        sha256: "c5c0ec4dbe57e0d7b9f27fb6db7d996db0f9ca40e43854c5cd13e29429a9f473",
    },
    TemplateDigest {
        release: "current",
        path: "sql.md",
        sha256: "ca3af5012939e08108afc498fe7073f1a8f772d975341591c9635b19f9d1e42b",
    },
    TemplateDigest {
        release: "current",
        path: "testing.md",
        sha256: "439210dfa5776715435a9501db98b88a6cdf2d90ca406ffbef6035873017a41c",
    },
    TemplateDigest {
        release: "current",
        path: "typescript.md",
        sha256: "e1dfda85e2edd678ca61d30634b8e44608f46b88c79aaae05553dbab596aecbd",
    },
    TemplateDigest {
        release: "current",
        path: "web-ui.md",
        sha256: "a028491f79be7e4af94505f0b78318cd2c87fa2f1e7d6076c4fedbdc81962833",
    },
    TemplateDigest {
        release: "current",
        path: "patterns/core.md",
        sha256: "bb5347275e813f50c9ac28d15b85130133e4410b4cdb8657f95b643f786ac2ee",
    },
    TemplateDigest {
        release: "current",
        path: "patterns/go.md",
        sha256: "4af1dfedfe72c43f27c7915bdf2c7062fda10f54da70cff327005a52030102af",
    },
    TemplateDigest {
        release: "current",
        path: "patterns/python.md",
        sha256: "de378434f85fb37937b1a763f45866cc6fc6c7fc7226a390034619c9f0932df0",
    },
    TemplateDigest {
        release: "current",
        path: "patterns/react.md",
        sha256: "16f7adc9a69d57d89019a7aab7706acdeea725aae2b1aa3fa6631dc2f21da3aa",
    },
    TemplateDigest {
        release: "current",
        path: "patterns/rust.md",
        sha256: "d00d4368d3497dec05c68d40459a8d74107355e31d9117b5d28a18cf7e316865",
    },
    TemplateDigest {
        release: "current",
        path: "patterns/sql.md",
        sha256: "4edc3aac40ab7baacd3641daba10648bb9bf2bbcd8d0a514be07757d085b633d",
    },
    TemplateDigest {
        release: "current",
        path: "patterns/testing.md",
        sha256: "9bf11fc38587d86da6d88761d43cfbd361b0b9c06ecf3faf620a3f205a52f0d9",
    },
    TemplateDigest {
        release: "current",
        path: "patterns/typescript.md",
        sha256: "b0dbfe9a47943f2f4d59b8ea78c06b480d9c2f1bf8d92a032feb000fcd7668d6",
    },
];

/// Digest for the currently rendered concatenated Codex guidance document.
#[cfg(test)]
pub(super) const CURRENT_GENERATED_DOCUMENT_DIGESTS: &[TemplateDigest] = &[TemplateDigest {
    release: "current",
    path: "AGENTS.md",
    sha256: "0688a63bf06089e5bacf458ab5ebf1dbf846ae64efc264bf72959980b82caea6",
}];

/// Return the recorded digest for one currently embedded template path.
#[cfg(test)]
pub(super) fn current_template_digest(path: &str) -> Option<&'static str> {
    CURRENT_TEMPLATE_DIGESTS
        .iter()
        .find(|record| record.path == path)
        .map(|record| record.sha256)
}
