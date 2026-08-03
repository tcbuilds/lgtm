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
        sha256: "da12d4a454b4553f18750fffb8bc4f86360b8dbb7b1c75e104add777ef1e5e52",
    },
    TemplateDigest {
        release: "current",
        path: "c-cpp.md",
        sha256: "5eb8162c1a2d24cdca00796db4d311c518dbf91598d54af40a05e5f1b44bdd65",
    },
    TemplateDigest {
        release: "current",
        path: "anti-slop.md",
        sha256: "cf4cc62512c3c7146e8995c0d8c39e8c65f943e57ecedc994d3071c9645ea5af",
    },
    TemplateDigest {
        release: "current",
        path: "code-organization.md",
        sha256: "6c48ca4769288c096af98818c3143cc5252ae94d6f034c199c64ad492c3beb97",
    },
    TemplateDigest {
        release: "current",
        path: "config.md",
        sha256: "5123c88e7df7808e798f2cbc16683f8f1f59b6cc1f4a0681a4133cd88cf80486",
    },
    TemplateDigest {
        release: "current",
        path: "csharp.md",
        sha256: "2090b9ed3b2252fc72455eba5bf3cf52d3a8c072067daff0822c7431313f8432",
    },
    TemplateDigest {
        release: "current",
        path: "error-handling.md",
        sha256: "b2c7a6e631e2d7a9c29faf4dd4f5b07c12b6cb1c15c13d3f478115270af592e8",
    },
    TemplateDigest {
        release: "current",
        path: "go.md",
        sha256: "ab0f9eed5709e286c5f6133f909f22fb16913a2aaf16c6b5838d3b0e1700ec6e",
    },
    TemplateDigest {
        release: "current",
        path: "infrastructure.md",
        sha256: "9207aebe8a0cbe01531caa45a9e69adc4524d6b541ec827e4d3229e3c7afc297",
    },
    TemplateDigest {
        release: "current",
        path: "jvm.md",
        sha256: "77f6304d5e2847cc93a09144d66b21d8b6fa2d1859205b949ad20ac4dab25876",
    },
    TemplateDigest {
        release: "current",
        path: "naming.md",
        sha256: "92e3e8a64f8bf1204042522b1ad8e0f07a7e5b73f75f58c5a4d62b6c0c6db301",
    },
    TemplateDigest {
        release: "current",
        path: "observability.md",
        sha256: "7d0d3b847544c5f8ed31fca6dffb824bc0b5a10584c90d5859411728a3652164",
    },
    TemplateDigest {
        release: "current",
        path: "performance.md",
        sha256: "40be928bd99f5f83d5665b5efd7446d5f3be9c126bc9c8ddcb26302f5f4d4b58",
    },
    TemplateDigest {
        release: "current",
        path: "python.md",
        sha256: "cef8d4377a3e076071a1cb28981823c6d45f3410e052756074a386ac76d0b46d",
    },
    TemplateDigest {
        release: "current",
        path: "react.md",
        sha256: "f7bd30882db897ef38b54b3b4ea6aec7dd717e46b453792290ce3a5f5165e709",
    },
    TemplateDigest {
        release: "current",
        path: "rust.md",
        sha256: "b25580b1376aa4978110c14b54b2bfb494487780370581c84fb46b7356e5891f",
    },
    TemplateDigest {
        release: "current",
        path: "security.md",
        sha256: "4e0b8ff87875aa578a667118bba96ee8d8768bc4e2b20f583198e4e4ff9cd31e",
    },
    TemplateDigest {
        release: "current",
        path: "shell.md",
        sha256: "9de95d2e4ce52c28cde9237ab5bc9b8c48826223d89353c3eaade43adf24c356",
    },
    TemplateDigest {
        release: "current",
        path: "sql.md",
        sha256: "58035093281716a42670df7a76139c64d3a23c52cd0eb5c14dd1830c375350de",
    },
    TemplateDigest {
        release: "current",
        path: "testing.md",
        sha256: "9a238ffd91dc90b383c71720c0c1b80aa5f897bce150804a49d91d0a1d7b89b4",
    },
    TemplateDigest {
        release: "current",
        path: "typescript.md",
        sha256: "882e0aed9482db528ce57228d076021fbf7773fb7447bfb7562fe2cb723a5315",
    },
    TemplateDigest {
        release: "current",
        path: "web-ui.md",
        sha256: "6e2d4b398348154239cc44a3a16b50d216a4a0d9ccb82d9192b11db0439b7308",
    },
    TemplateDigest {
        release: "current",
        path: "patterns/core.md",
        sha256: "78573723914b08daf4df2d7370a97b97fe8a43a0fcb7bc93786aa1e1778ce537",
    },
    TemplateDigest {
        release: "current",
        path: "patterns/go.md",
        sha256: "d5e0c3ca2a3c0e543d95149254bb95b79e9bc042c14d5ded810dd4eb0abc9362",
    },
    TemplateDigest {
        release: "current",
        path: "patterns/python.md",
        sha256: "d8dc05edb9c59a92eb350001e10817db8485594f52fe255b2bd1c4e60b15cb3d",
    },
    TemplateDigest {
        release: "current",
        path: "patterns/react.md",
        sha256: "6540083a2992f6a4ab7ffa364030086f6c646c2fae295e15ce24825a3d77041e",
    },
    TemplateDigest {
        release: "current",
        path: "patterns/rust.md",
        sha256: "cc0d82cd42a7ebd076d6ef9f749fe781ae30db085ee057f56155c5f723313084",
    },
    TemplateDigest {
        release: "current",
        path: "patterns/sql.md",
        sha256: "f047bf8e5637fd088a2147da266b7fb43fddafcae67ea35d59ad9e699e6df207",
    },
    TemplateDigest {
        release: "current",
        path: "patterns/testing.md",
        sha256: "6b0ccd0621e59540b5b620edd9acb138c1ff7f8c96352e2109cf0fbfbe5c4e5f",
    },
    TemplateDigest {
        release: "current",
        path: "patterns/typescript.md",
        sha256: "67718b7d9a8fa7580887525dada8a0948a06561b15154c9c3a51c935b283035b",
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
