import Write
import Read

# Schema reflection sees only nominal type witnesses, never callable codecs.
Declaration :: [].{
	Command(input, output) :: { input_witness : List(input), output_witness : List(output) }.{}

	Query(input, output) :: { input_witness : List(input), output_witness : List(output) }.{}

	# Generated registry conversions prove declarations and runtime handles agree.
	command : Write(input, output) -> Command(input, output)
	command = |_handle| { input_witness: [], output_witness: [] }

	query : Read(input, output) -> Query(input, output)
	query = |_handle| { input_witness: [], output_witness: [] }
}
