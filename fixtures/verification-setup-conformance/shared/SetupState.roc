import pf.Selection
import pf.Tx
import Data

SetupState :: [].{
	invalidate : Str -> Tx({ stage : U64, fail_second : Bool })
	invalidate = |actor| {
		selection = Selection.filter(Data.actor_states, Data.actor_states_actor_equal(actor))
		Tx.find(selection).and_then(
			|found| match found {
				Some(row) => Tx.update(Data.actor_states, row, { ..row.value, stage: 0 })
				None => Tx.create(Data.actor_states, { actor, stage: 0, fail_second: Bool.False })
			},
		).map(|row| { stage: row.value.stage, fail_second: row.value.fail_second })
	}

	configure_failure : Str, Bool -> Tx({ stage : U64, fail_second : Bool })
	configure_failure = |actor, fail_second| {
		selection = Selection.filter(Data.actor_states, Data.actor_states_actor_equal(actor))
		Tx.find(selection).and_then(
			|found| match found {
				Some(row) => Tx.update(Data.actor_states, row, { ..row.value, fail_second })
				None => Tx.create(Data.actor_states, { actor, stage: 0, fail_second })
			},
		).map(|row| { stage: row.value.stage, fail_second: row.value.fail_second })
	}

	prepare_first : Str -> Tx({ stage : U64, fail_second : Bool })
	prepare_first = |actor| {
		selection = Selection.filter(Data.actor_states, Data.actor_states_actor_equal(actor))
		Tx.find(selection).and_then(
			|found| match found {
				Some(row) => Tx.update(Data.actor_states, row, { ..row.value, stage: 1 })
				None => Tx.create(Data.actor_states, { actor, stage: 1, fail_second: Bool.False })
			},
		).map(|row| { stage: row.value.stage, fail_second: row.value.fail_second })
	}
}
