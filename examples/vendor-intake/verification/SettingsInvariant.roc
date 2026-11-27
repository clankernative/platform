import pf.Api
import Data
import IntakePolicy

SettingsInvariant :: [].{
	settings =
		Api.invariant(
			Data.settings,
			"The installation has at most one immutable, complete configuration.",
			Data.snapshot,
			|
				state,
			|
				state.settings.len()
					<= 1
					and state
						.settings
						.all(
							|
								row,
							|
								row.version.to_u64()
									== 1
									and row.value.install_key
										== 1
										and IntakePolicy.valid({
											product_owners: row.value.product_owners,
											reviewer: row.value.reviewer,
											contract_folder: row.value.contract_folder,
										}),
						),
		)
}
