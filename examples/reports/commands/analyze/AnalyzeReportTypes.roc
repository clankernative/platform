import pf.Text
import Document
import Models
import pf.Ref
import pf.RowVersion

AnalyzeReportTypes :: [].{
	Input := { report_id : Ref(Models.Report), expected_version : RowVersion, text : Text(Document) }

	# Prepared facts are private values, not a separately registered operation codec.
	Result : { bytes : U64, lines : U64 }
}
