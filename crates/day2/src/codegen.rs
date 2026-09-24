use crate::schema::{Kind, Record, Schema};
use anyhow::{Context, Result};
use std::collections::BTreeSet;

impl Schema {
    fn value_type(&self, record: &Record) -> Result<String> {
        if let Some(name) = &record.roc_type {
            return Ok(name.clone());
        }
        let fields = record
            .fields
            .iter()
            .map(|(name, kind)| {
                let ty = match kind {
                    Kind::Reference { target } | Kind::ModelReference { target, .. } => format!(
                        "Ref({})",
                        self.models[target]
                            .roc_type
                            .as_ref()
                            .context("nominal reference target")?
                    ),
                    Kind::TextDomain { roc_type } => roc_type.clone(),
                    Kind::StandardText { domain } => format!("Text({domain})"),
                    Kind::WebUrl => "WebUrl".into(),
                    Kind::Cursor | Kind::IdCursor => "Cursor".into(),
                    Kind::PageSize => "PageSize".into(),
                    Kind::RowVersion => "RowVersion".into(),
                    _ => kind.wire_type(false).into(),
                };
                Ok(format!("{name} : {ty}"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(format!("{{ {} }}", fields.join(", ")))
    }

    fn imports(&self) -> String {
        let mut modules = BTreeSet::new();
        for record in self.models.values().chain(self.inputs.values()) {
            if let Some(name) = &record.roc_type {
                modules.insert(name.split('.').next().unwrap());
            }
            for kind in record.fields.values() {
                if let Kind::StandardText { domain } = kind {
                    modules.insert("pf.Text");
                    modules.insert("Domains");
                    modules.insert(domain.split('.').next().unwrap());
                }
                if let Kind::TextDomain { roc_type } = kind {
                    modules.insert(roc_type.split('.').next().unwrap());
                }
                if matches!(kind, Kind::RowVersion) {
                    modules.insert("pf.RowVersion");
                }
                // Generated decoders construct the nominal wrappers, so their
                // modules must be imported wherever a structured input uses one.
                if let Kind::InputShape { shape, .. } = kind {
                    if shape.mentions_map() {
                        modules.insert("pf.TextMap");
                    }
                    if shape.mentions_set() {
                        modules.insert("pf.TextSet");
                    }
                }
            }
        }
        modules
            .into_iter()
            .map(|name| format!("import {name}\n"))
            .collect()
    }

    /// A field whose shape is exactly a nominal collection. These are the only
    /// structured inputs whose handler type differs from their wire type, so they
    /// are the only ones needing a construction step in the generated decoder.
    fn nominal_collection(kind: &Kind) -> Option<(&'static str, &'static str, &'static str)> {
        match kind {
            Kind::InputShape { shape, .. } => match shape {
                crate::output_schema::Type::Map(_) => Some(("TextMap", "from_entries", "entries")),
                crate::output_schema::Type::Set => Some(("TextSet", "from_list", "members")),
                _ => None,
            },
            _ => None,
        }
    }

    fn decoder(&self, record: &Record, input: bool) -> String {
        let fields = record
            .fields
            .iter()
            .map(|(name, kind)| match kind {
                Kind::InputShape { shape, .. } if Self::nominal_collection(kind).is_some() => {
                    format!("{name} : {}", shape.wire_annotation())
                }
                _ => format!("{name} : {}", kind.wire_type(input)),
            })
            .collect::<Vec<_>>()
            .join(", ");
        // App fields cannot use the reserved prefix, so decoder locals never shadow them.
        let decoded = if record.fields.is_empty() {
            "_day2_value"
        } else {
            "day2_value"
        };
        let mut code = format!(
            "|day2_raw| {{\n        day2_dto : Try({{ {fields} }}, _)\n        day2_dto = Json.parse(day2_raw)\n        {decoded} = day2_dto.map_err(|_| \"invalid_record\")?\n"
        );
        for (name, kind) in &record.fields {
            match kind {
                Kind::ModelReference { prefix, .. } => code.push_str(&format!("        {name} = Ref.for_model(\"{prefix}\", day2_value.{name}).map_err(|_| \"invalid_reference\")?\n")),
                Kind::Reference { .. } => code.push_str(&format!("        {name} = Ref.{}(day2_value.{name}).map_err(|_| \"invalid_reference\")?\n", if input { "from_str" } else { "from_i64" })),
                Kind::TextDomain { roc_type } => code.push_str(&format!("        {name} = {roc_type}.from_str(day2_value.{name}).map_err(|_| \"invalid_domain_value\")?\n")),
                Kind::StandardText { domain } => {
                    let key = self.domains.iter().find(|(_, tag)| *tag == domain).expect("validated domain").0;
                    code.push_str(&format!("        {name} = Domains.{key}(day2_value.{name})?\n"));
                }
                Kind::WebUrl => code.push_str(&format!("        {name} = WebUrl.from_str(day2_value.{name}).map_err(|_| \"invalid_url\")?\n")),
                Kind::Cursor | Kind::IdCursor => code.push_str(&format!("        {name} = Cursor.from_str(day2_value.{name}).map_err(|_| \"invalid_cursor\")?\n")),
                Kind::PageSize => code.push_str(&format!("        {name} = PageSize.from_i64(day2_value.{name}).map_err(|_| \"invalid_page_size\")?\n")),
                Kind::RowVersion => code.push_str(&format!("        {name} = RowVersion.from_u64(day2_value.{name}).map_err(|_| \"invalid_row_version\")?\n")),
                _ => match Self::nominal_collection(kind) {
                    Some((module, constructor, payload)) => code.push_str(&format!(
                        "        {name} = {module}.{constructor}(day2_value.{name}.{payload}).map_err(|_| \"invalid_{payload}\")?\n"
                    )),
                    None => code.push_str(&format!("        {name} = day2_value.{name}\n")),
                },
            }
        }
        let fields = record
            .fields
            .keys()
            .map(|name| format!("{name}: {name}"))
            .collect::<Vec<_>>()
            .join(", ");
        code.push_str(&format!("        Ok({{ {fields} }})\n    }}"));
        code
    }

    fn encoder(record: &Record, input: bool) -> String {
        let fields = record
            .fields
            .iter()
            .map(|(name, kind)| {
                let expression = match kind {
                    Kind::Reference { .. } => format!(
                        "Ref.{}(value.{name})",
                        if input { "to_str" } else { "to_i64" }
                    ),
                    Kind::TextDomain { roc_type } => format!("{roc_type}.to_str(value.{name})"),
                    Kind::StandardText { .. } => format!("Text.to_str(value.{name})"),
                    Kind::WebUrl => format!("WebUrl.to_str(value.{name})"),
                    Kind::Cursor | Kind::IdCursor => format!("Cursor.to_str(value.{name})"),
                    Kind::ModelReference { .. } => format!("Ref.to_str(value.{name})"),
                    Kind::PageSize => format!("PageSize.to_i64(value.{name})"),
                    Kind::RowVersion => format!("RowVersion.to_u64(value.{name})"),
                    _ => match Self::nominal_collection(kind) {
                        Some((module, _, payload)) => {
                            let accessor = if payload == "entries" {
                                "to_entries"
                            } else {
                                "to_list"
                            };
                            format!("{{ {payload}: {module}.{accessor}(value.{name}) }}")
                        }
                        None => format!("value.{name}"),
                    },
                };
                format!("{name}: {expression}")
            })
            .collect::<Vec<_>>()
            .join(", ");
        let value = if record.fields.is_empty() {
            "_value"
        } else {
            "value"
        };
        format!("|{value}| Json.to_str({{ {fields} }})")
    }

    pub fn data_module(&self) -> Result<String> {
        self.data_module_profile(false)
    }

    pub(crate) fn admission_data_module(&self) -> Result<String> {
        self.data_module_profile(true)
    }

    fn data_module_profile(&self, admission: bool) -> Result<String> {
        self.validate_typed()?;
        let prefix = if admission { "admission_" } else { "" };
        let mut result = format!(
            "import pf.Model\nimport pf.Ref\nimport pf.Selection\nimport pf.Predicate\nimport pf.Order\nimport pf.Cursor\nimport pf.PageSize\nimport pf.WebUrl\n{}\nData :: [].{{\n",
            self.imports()
        );
        for (name, record) in &self.models {
            let ty = self.value_type(record)?;
            let body = format!(
                "Model.{prefix}define(\"{name}\", \"{}\", {}, {})",
                record.identity.as_ref().map_or("", |id| id.prefix.as_str()),
                self.decoder(record, false),
                Self::encoder(record, false)
            );
            result.push_str(&format!("    {name} : Model({ty})\n    {name} = {body}\n"));
            let body = format!("|after, limit| Selection.{prefix}all({name}, after, limit)");
            result.push_str(&format!(
                "    all_{name} : Cursor, PageSize -> Selection({ty})\n    all_{name} = {body}\n"
            ));
            for (field, kind) in &record.fields {
                let field_type = match kind {
                    Kind::Reference { target } | Kind::ModelReference { target, .. } => format!(
                        "Ref({})",
                        self.models[target]
                            .roc_type
                            .as_ref()
                            .context("nominal reference target")?
                    ),
                    Kind::TextDomain { roc_type } => roc_type.clone(),
                    Kind::StandardText { domain } => format!("Text({domain})"),
                    Kind::WebUrl => "WebUrl".into(),
                    Kind::RowVersion => "RowVersion".into(),
                    _ => kind.wire_type(false).into(),
                };
                let encoded = match kind {
                    Kind::Reference { .. } | Kind::ModelReference { .. } => {
                        "Ref.to_str(value)".into()
                    }
                    Kind::TextDomain { roc_type } => format!("{roc_type}.to_str(value)"),
                    Kind::StandardText { .. } => "Text.to_str(value)".into(),
                    Kind::WebUrl => "WebUrl.to_str(value)".into(),
                    Kind::RowVersion => "RowVersion.to_u64(value)".into(),
                    _ => "value".into(),
                };
                result.push_str(&format!(
                    "    {name}_{field}_equal : {field_type} -> Predicate({ty})\n    {name}_{field}_equal = |value| Predicate.{prefix}define({name}, \"{field}\", \"equal\", Json.to_str({encoded}))\n"
                ));
                if matches!(
                    kind,
                    Kind::Text
                        | Kind::OptionalText
                        | Kind::TextDomain { .. }
                        | Kind::StandardText { .. }
                        | Kind::WebUrl
                ) {
                    result.push_str(&format!(
                        "    {name}_{field}_like : Str -> Predicate({ty})\n    {name}_{field}_like = |value| Predicate.{prefix}define({name}, \"{field}\", \"like\", Json.to_str(value))\n"
                    ));
                }
                for (suffix, descending) in [("asc", "Bool.False"), ("desc", "Bool.True")] {
                    result.push_str(&format!(
                        "    {name}_{field}_{suffix} : Order({ty})\n    {name}_{field}_{suffix} = Order.{prefix}define({name}, \"{field}\", {descending})\n"
                    ));
                }
                if let Kind::Reference { target } | Kind::ModelReference { target, .. } = kind {
                    let target_type = self.models[target]
                        .roc_type
                        .as_ref()
                        .context("nominal reference target")?;
                    let body = format!(
                        "|value, after, limit| Selection.{prefix}indexed({name}, \"{field}\", Ref.to_str(value), after, limit)"
                    );
                    result.push_str(&format!("    {name}_by_{field} : Ref({target_type}), Cursor, PageSize -> Selection({ty})\n    {name}_by_{field} = {body}\n"));
                }
            }
            // Deletion is deliberately absent from these handles. It is a
            // scope on the selection, not a field on the row: `deleted_at` has
            // no predicate handle because there must be exactly one way to say
            // "deleted", and no order handle because an unindexed column is not
            // a sort key the host will plan. A trash view says
            // `Selection.only_deleted` and orders by something it declared.
            for field in ["id", "version", "created_at"] {
                let (field_type, encoded) = match field {
                    "id" => (format!("Ref({ty})"), "Ref.to_str(value)"),
                    "version" => ("U64".into(), "value"),
                    _ => ("I64".into(), "value"),
                };
                result.push_str(&format!(
                    "    {name}_{field}_equal : {field_type} -> Predicate({ty})\n    {name}_{field}_equal = |value| Predicate.{prefix}define({name}, \"{field}\", \"equal\", Json.to_str({encoded}))\n"
                ));
                for (suffix, descending) in [("asc", "Bool.False"), ("desc", "Bool.True")] {
                    result.push_str(&format!(
                        "    {name}_{field}_{suffix} : Order({ty})\n    {name}_{field}_{suffix} = Order.{prefix}define({name}, \"{field}\", {descending})\n"
                    ));
                }
            }
        }
        // Rollups read like models but have no writes, no metadata handles beyond
        // the implied id order, and no place in the property snapshot.
        for rollup in &self.rollups {
            let name = rollup.table();
            let record = rollup.record(&self.models[&rollup.model]);
            let ty = self.value_type(&record)?;
            let body = format!(
                "Model.{prefix}define(\"{name}\", \"{}\", {}, {})",
                rollup.prefix(),
                self.decoder(&record, false),
                Self::encoder(&record, false)
            );
            result.push_str(&format!("    {name} : Model({ty})\n    {name} = {body}\n"));
            result.push_str(&format!(
                "    all_{name} : Cursor, PageSize -> Selection({ty})\n    all_{name} = |after, limit| Selection.{prefix}all({name}, after, limit)\n"
            ));
            for (field, kind) in &record.fields {
                let (field_type, encoded) = match kind {
                    Kind::TextDomain { roc_type } => {
                        (roc_type.clone(), format!("{roc_type}.to_str(value)"))
                    }
                    Kind::StandardText { domain } => {
                        (format!("Text({domain})"), "Text.to_str(value)".into())
                    }
                    _ => (kind.wire_type(false).into(), "value".into()),
                };
                result.push_str(&format!(
                    "    {name}_{field}_equal : {field_type} -> Predicate({ty})\n    {name}_{field}_equal = |value| Predicate.{prefix}define({name}, \"{field}\", \"equal\", Json.to_str({encoded}))\n"
                ));
                if matches!(
                    kind,
                    Kind::Text | Kind::TextDomain { .. } | Kind::StandardText { .. }
                ) {
                    result.push_str(&format!(
                        "    {name}_{field}_like : Str -> Predicate({ty})\n    {name}_{field}_like = |value| Predicate.{prefix}define({name}, \"{field}\", \"like\", Json.to_str(value))\n"
                    ));
                }
                for (suffix, descending) in [("asc", "Bool.False"), ("desc", "Bool.True")] {
                    result.push_str(&format!(
                        "    {name}_{field}_{suffix} : Order({ty})\n    {name}_{field}_{suffix} = Order.{prefix}define({name}, \"{field}\", {descending})\n"
                    ));
                }
            }
        }
        let snapshot_fields = self
            .models
            .iter()
            .map(|(name, record)| {
                Ok(format!(
                    "{name} : List(Model.Entity({}))",
                    self.value_type(record)?
                ))
            })
            .collect::<Result<Vec<_>>>()?
            .join(", ");
        result.push_str(&format!(
            "    Snapshot : {{ {snapshot_fields} }}\n    snapshot : Str -> Try(Snapshot, Str)\n"
        ));
        result.push_str("    snapshot = |raw| {\n");
        let wire_fields = self
            .models
            .keys()
            .map(|name| {
                format!(
                    "{name} : List({{ id : Str, version : I64, created_at : I64, data : Str }})"
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        result.push_str(&format!("        dto : Try({{ {wire_fields} }}, _)\n        dto = Json.parse(raw)\n        rows = dto.map_err(|_| \"invalid_snapshot\")?\n"));
        for name in self.models.keys() {
            result.push_str(&format!("        if rows.{name}.len() > {} {{ return Err(\"snapshot_row_budget\") }}\n        {name}_rows = rows.{name}.map_try(|row| Model.decode_row({name}, row))?\n", crate::properties::MAX_ROWS_PER_MODEL));
        }
        let values = self
            .models
            .keys()
            .map(|name| format!("{name}: {name}_rows"))
            .collect::<Vec<_>>()
            .join(", ");
        result.push_str(&format!("        Ok({{ {values} }})\n    }}\n}}\n"));
        Ok(result)
    }

    pub fn inputs_module(&self) -> Result<String> {
        self.inputs_module_profile(false)
    }

    pub(crate) fn admission_inputs_module(&self) -> Result<String> {
        self.inputs_module_profile(true)
    }

    fn inputs_module_profile(&self, admission: bool) -> Result<String> {
        self.validate_typed()?;
        let prefix = if admission { "admission_" } else { "" };
        let mut result = format!(
            "import pf.Input\nimport pf.Ref\nimport pf.Field\nimport pf.WebUrl\nimport pf.Cursor\nimport pf.PageSize\n{}\nInputs :: [].{{\n",
            self.imports()
        );
        for (name, record) in &self.inputs {
            let body = format!(
                "Input.{prefix}define(\"{name}\", {}, {})",
                self.decoder(record, true),
                Self::encoder(record, true)
            );
            result.push_str(&format!(
                "    {name} : Input({})\n    {name} = {body}\n",
                self.value_type(record)?
            ));
            for field in record.fields.keys() {
                let body = format!("Field.{prefix}define(\"{field}\")");
                result.push_str(&format!(
                    "    {name}_{field} : Field({})\n    {name}_{field} = {body}\n",
                    self.value_type(record)?
                ));
            }
        }
        result.push_str("}\n");
        Ok(result)
    }
}
