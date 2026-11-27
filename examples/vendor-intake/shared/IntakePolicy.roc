import pf.Context
import pf.Model
import pf.Query
import pf.Selection
import ConfigureTypes
import Data
import Models

IntakePolicy :: [].{
	# These values are used only for contract examples and verification.
	reviewer = "grace@synthetic.example"

	contract_folder = "https://drive.google.com/drive/folders/synthetic_vendor_contracts"

	example : {} -> ConfigureTypes.Input
	example = |_| { product_owners: "product-owners@synthetic.example", reviewer, contract_folder }

	selection : {} -> Selection(Models.Setting)
	selection = |_| Selection.filter(Data.settings, Data.settings_install_key_equal(1))

	read : {} -> Query([Some(Model.Entity(Models.Setting)), None])
	read = |_| Query.find(selection({}))

	direct : Context -> Bool
	direct = |context| match (context.authentication(), context.acting()) {
		(Request, Directly) => Bool.True
		_ => Bool.False
	}

	direct_reviewer : Context, Str -> Bool
	direct_reviewer = |context, subject| direct(context) and context.actor() == subject

	letter : U8 -> Bool
	letter = |b| b >= 97 and b <= 122

	digit : U8 -> Bool
	digit = |b| b >= 48 and b <= 57

	email : Str -> Bool
	email = |value| match value.split_on("@") {
		[local, domain] => {
			labels = domain.split_on(".")
			value.count_utf8_bytes()
				<= 254
				and !local.is_empty()
					and local.count_utf8_bytes()
						<= 64
						and local.to_utf8().all(|b| letter(b) or digit(b) or b == 45 or b == 46 or b == 95 or b == 43)
							and labels.len()
								>= 2
								and labels
									.all(
										|
											label,
										|
											!label.is_empty()
												and !label.starts_with("-")
													and !label.ends_with("-")
														and label.to_utf8().all(|b| letter(b) or digit(b) or b == 45),
									)
		}
		_ => Bool.False
	}

	valid : ConfigureTypes.Input -> Bool
	valid = |input| {
		folder = match input.contract_folder.split_on("/") {
			["https:", "", "drive.google.com", "drive", "folders", id] => !id.is_empty()
				and id.count_utf8_bytes()
					<= 200
					and id.to_utf8().all(|b| letter(b) or (b >= 65 and b <= 90) or digit(b) or b == 45 or b == 95)
			_ => Bool.False
		}
		email(input.reviewer) and email(input.product_owners) and input.reviewer != input.product_owners and folder
	}
}
