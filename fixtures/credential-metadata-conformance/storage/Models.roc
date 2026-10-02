import pf.Table

Models :: [].{
	Entry := { note : Str }.{
		table : Table(Entry, _)
		table = Table.keyed(|_row| {})
	}

	UseReceipt := { note : Str }.{
		table : Table(UseReceipt, _)
		table = Table.keyed(|_row| {})
	}
}
